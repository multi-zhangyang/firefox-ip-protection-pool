"""Persistent, non-secret state for ProxyPass renewal.

The state file deliberately contains no account identifiers or credentials.  It
exists so a restarted service continues to respect Guardian cooldowns and so an
operator can distinguish a healthy automatic renewal loop from a session that
needs interactive re-authentication.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux is the recommended service platform.
    fcntl = None


SCHEMA_VERSION = 1
RESULTS = {
    "never",
    "in_progress",
    "fresh",
    "success",
    "busy",
    "backoff",
    "rate_limited",
    "reauth_required",
    "no_entitlement",
    "missing_credentials",
    "transient_error",
    "protocol_error",
}
FAILURE_RESULTS = {
    "rate_limited",
    "reauth_required",
    "no_entitlement",
    "missing_credentials",
    "transient_error",
    "protocol_error",
}
_PROCESS_STATE_LOCK = threading.RLock()


def empty_refresh_state() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "result": "never",
        "last_attempt_at": None,
        "last_success_at": None,
        "proxy_pass_expires_at": None,
        "next_attempt_at": None,
        "consecutive_failures": 0,
        "http_status": None,
        "generation": 0,
    }


def _timestamp(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return None
    return numeric


def load_refresh_state(path: Path) -> dict[str, Any]:
    state = empty_refresh_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return state
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA_VERSION:
        return state

    result = raw.get("result")
    if isinstance(result, str) and result in RESULTS:
        state["result"] = result
    for name in (
        "last_attempt_at",
        "last_success_at",
        "proxy_pass_expires_at",
        "next_attempt_at",
    ):
        state[name] = _timestamp(raw.get(name))
    failures = raw.get("consecutive_failures")
    if isinstance(failures, int) and not isinstance(failures, bool) and failures >= 0:
        state["consecutive_failures"] = failures
    status = raw.get("http_status")
    if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
        state["http_status"] = status
    generation = raw.get("generation")
    if isinstance(generation, int) and not isinstance(generation, bool) and generation >= 0:
        state["generation"] = generation
    return state


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
        # Make the rename durable as well as the file contents.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = -1
        if directory_fd >= 0:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def record_refresh_state(
    path: Path,
    result: str,
    *,
    now: float | None = None,
    http_status: int | None = None,
    next_attempt_at: float | None = None,
    proxy_pass_expires_at: float | None = None,
) -> dict[str, Any]:
    """Merge and atomically persist a sanitized refresh outcome."""
    if result not in RESULTS:
        raise ValueError(f"unknown refresh result: {result}")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with _PROCESS_STATE_LOCK:
        lock_handle = open(lock_path, "a+", encoding="utf-8")
        try:
            os.chmod(lock_path, 0o600)
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)

            current = time.time() if now is None else float(now)
            state = load_refresh_state(path)
            state["result"] = result
            if result != "never":
                state["last_attempt_at"] = current
            state["http_status"] = (
                http_status
                if isinstance(http_status, int)
                and not isinstance(http_status, bool)
                and 100 <= http_status <= 599
                else None
            )
            state["next_attempt_at"] = _timestamp(next_attempt_at)
            expiry = _timestamp(proxy_pass_expires_at)
            if expiry is not None:
                state["proxy_pass_expires_at"] = expiry

            if result == "success":
                state["last_success_at"] = current
                state["consecutive_failures"] = 0
                state["generation"] = int(state["generation"]) + 1
            elif result == "fresh":
                state["consecutive_failures"] = 0
            elif result in FAILURE_RESULTS:
                state["consecutive_failures"] = int(state["consecutive_failures"]) + 1

            _atomic_write_json(path, state)
            return state
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            lock_handle.close()


def retry_delay(failure_count: int, *, minimum: float = 5.0, maximum: float = 300.0) -> float:
    """Return a bounded exponential cooldown for transient renewal failures."""
    exponent = max(0, min(int(failure_count), 16))
    return min(maximum, minimum * (2**exponent))
