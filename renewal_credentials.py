"""Atomic storage for the long-lived Firefox Account renewal credentials."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
FILENAME = "renewal_credentials.json"
MAX_CREDENTIAL_BYTES = 16 * 1024


class RenewalCredentialsError(ValueError):
    """A sanitized credential-storage error."""


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, mode)
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


def validate_renewal_credentials(
    value: object,
    *,
    require_schema: bool = True,
    strict_tokens: bool = True,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RenewalCredentialsError("renewal credentials must be a JSON object")
    expected = {"schema", "email", "uid", "session_token"}
    if require_schema:
        if set(value) != expected or value.get("schema") != SCHEMA_VERSION:
            raise RenewalCredentialsError("unsupported renewal credential schema")
    email = value.get("email")
    uid = value.get("uid")
    session_token = value.get("session_token")
    if (
        not isinstance(email, str)
        or len(email) > 320
        or not re.fullmatch(r"[^\s@]+@[^\s@]+", email)
    ):
        raise RenewalCredentialsError("renewal credentials contain an invalid email")
    if not isinstance(uid, str) or not uid or len(uid) > 256 or any(c.isspace() for c in uid):
        raise RenewalCredentialsError("renewal credentials contain an invalid uid")
    if (
        not isinstance(session_token, str)
        or not session_token
        or len(session_token) > 4096
        or any(c.isspace() for c in session_token)
    ):
        raise RenewalCredentialsError("renewal credentials contain an invalid session token")
    if strict_tokens:
        if not re.fullmatch(r"[0-9a-fA-F]{32}", uid):
            raise RenewalCredentialsError("renewal credentials contain an invalid Firefox Account uid")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", session_token):
            raise RenewalCredentialsError("renewal credentials contain an invalid FxA session token")
    return {
        "email": email,
        "uid": uid.lower() if strict_tokens else uid,
        "session_token": session_token.lower() if strict_tokens else session_token,
    }


def _read_regular_file(
    path: Path,
    *,
    maximum: int,
    require_private_mode: bool,
) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RenewalCredentialsError("renewal credential file is not a safe regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RenewalCredentialsError("renewal credential file must be a regular file")
        if require_private_mode and os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RenewalCredentialsError("renewal credential file permissions must be 0600")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > maximum:
        raise RenewalCredentialsError("renewal credential file is too large")
    return raw


def write_renewal_credentials(
    token_dir: Path,
    *,
    email: str,
    uid: str,
    session_token: str,
) -> Path:
    credentials = validate_renewal_credentials(
        {
            "schema": SCHEMA_VERSION,
            "email": email,
            "uid": uid,
            "session_token": session_token,
        }
    )
    destination = token_dir / FILENAME
    atomic_write_text(
        destination,
        json.dumps(
            {"schema": SCHEMA_VERSION, **credentials},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    return destination


def load_renewal_credentials(token_dir: Path) -> dict[str, str]:
    """Load the canonical record, with read-only compatibility for legacy files."""
    canonical = token_dir / FILENAME
    try:
        raw = _read_regular_file(
            canonical,
            maximum=MAX_CREDENTIAL_BYTES,
            require_private_mode=True,
        )
    except FileNotFoundError:
        raw = None
    if raw is not None:
        try:
            value: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RenewalCredentialsError("renewal credential file is not valid UTF-8 JSON") from exc
        return validate_renewal_credentials(value)

    meta_path = token_dir / "account_meta.json"
    session_path = token_dir / "session_token.txt"
    try:
        metadata_raw = _read_regular_file(
            meta_path,
            maximum=MAX_CREDENTIAL_BYTES,
            require_private_mode=False,
        )
        session_raw = _read_regular_file(
            session_path,
            maximum=4096,
            require_private_mode=False,
        )
    except FileNotFoundError as exc:
        raise RenewalCredentialsError(
            "missing renewal_credentials.json or legacy "
            "account_meta.json/session_token.txt"
        ) from exc
    try:
        metadata = json.loads(metadata_raw.decode("utf-8"))
        session_token = session_raw.decode("utf-8").strip()
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RenewalCredentialsError("legacy renewal credentials are invalid") from exc
    if not isinstance(metadata, dict):
        raise RenewalCredentialsError("legacy account metadata must be a JSON object")
    return validate_renewal_credentials(
        {
            "email": metadata.get("email"),
            "uid": metadata.get("uid"),
            "session_token": session_token,
        },
        require_schema=False,
        strict_tokens=False,
    )
