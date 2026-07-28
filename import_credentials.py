#!/usr/bin/env python3
"""Import the minimal Firefox Account renewal bundle on the Linux host."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from renewal_credentials import FILENAME as RENEWAL_CREDENTIALS_FILENAME
from renewal_credentials import write_renewal_credentials
from refresh_state import FAILURE_RESULTS, load_refresh_state, record_refresh_state, refresh_lock


ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "tokens"
BUNDLE_SCHEMA = "firefox-ip-protection-renewal-credentials-v1"
MAX_BUNDLE_BYTES = 16 * 1024
REQUIRED_FIELDS = frozenset({"schema", "email", "uid", "session_token"})
EX_TEMPFAIL = 75
VERIFY_BUSY_TIMEOUT_SECONDS = 45.0
VERIFY_STATE_POLL_SECONDS = 0.2
PENDING_VERIFICATION_RESULTS = frozenset({"credentials_imported", "in_progress"})
TEMPORARY_FAILURE_RESULTS = frozenset(
    {"rate_limited", "oauth_rate_limited", "transient_error"}
)


@dataclass(frozen=True)
class PublishedImport:
    """Non-secret identity for one canonical credential publication."""

    generation: int
    canonical_marker: tuple[int, int, int, int, int]


class CredentialImportError(ValueError):
    """A safe import error that never contains credential material."""


class CredentialVerificationError(CredentialImportError):
    """A sanitized verification failure with a suitable process exit code."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _read_limited(stream: Any) -> bytes:
    data = stream.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise CredentialImportError("credential bundle is larger than 16 KiB")
    return data


def load_bundle(source: str) -> dict[str, str]:
    """Read and validate a minimal credential bundle from a file or stdin."""
    if source == "-":
        raw = _read_limited(sys.stdin.buffer)
    else:
        path = Path(source)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise CredentialImportError("cannot open the credential bundle") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CredentialImportError("credential bundle must be a regular file")
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise CredentialImportError(
                    "credential bundle permissions are too broad; run chmod 600 first"
                )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                raw = _read_limited(handle)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialImportError("credential bundle is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CredentialImportError("credential bundle must be a JSON object")
    if set(value) != REQUIRED_FIELDS:
        raise CredentialImportError(
            "credential bundle has missing or unexpected fields; export it again"
        )
    if value.get("schema") != BUNDLE_SCHEMA:
        raise CredentialImportError("unsupported credential bundle schema")

    email = value.get("email")
    uid = value.get("uid")
    session_token = value.get("session_token")
    if (
        not isinstance(email, str)
        or len(email) > 320
        or not re.fullmatch(r"[^\s@]+@[^\s@]+", email)
    ):
        raise CredentialImportError("credential bundle contains an invalid email")
    if not isinstance(uid, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", uid):
        raise CredentialImportError("credential bundle contains an invalid Firefox Account uid")
    if not isinstance(session_token, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", session_token
    ):
        raise CredentialImportError("credential bundle contains an invalid FxA session token")
    return {
        "schema": BUNDLE_SCHEMA,
        "email": email,
        "uid": uid.lower(),
        "session_token": session_token.lower(),
    }


def _canonical_marker(path: Path) -> tuple[int, int, int, int, int]:
    """Return a non-secret marker that changes when the canonical file is replaced."""
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise CredentialImportError("cannot inspect the published credential record") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CredentialImportError("published credential record is not a regular file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_ctime_ns,
        metadata.st_mtime_ns,
        metadata.st_size,
    )


def _remove_legacy_credentials(token_dir: Path) -> None:
    """Remove superseded split credential files without hiding cleanup failures."""
    for name in ("session_token.txt", "account_meta.json"):
        try:
            (token_dir / name).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise CredentialImportError(
                "canonical credentials were published, but legacy credentials could not be removed"
            ) from exc


def publish_bundle(
    bundle: dict[str, str], token_dir: Path = TOKENS
) -> PublishedImport:
    """Publish one atomic renewal-credential record under the shared lock."""
    with refresh_lock(token_dir, blocking=True):
        canonical = write_renewal_credentials(
            token_dir,
            email=bundle["email"],
            uid=bundle["uid"],
            session_token=bundle["session_token"],
        )
        # Keep new tunnels paused until this exact credential publication has
        # produced a later successful refresh.  Record the pending state before
        # removing legacy secrets or authorization markers so every cleanup
        # failure remains fail-closed.
        state = record_refresh_state(
            token_dir / "refresh_state.json",
            "credentials_imported",
            next_attempt_at=None,
        )
        _remove_legacy_credentials(token_dir)
        try:
            (token_dir / "rejected_proxy_pass.sha256").unlink()
        except FileNotFoundError:
            pass
        return PublishedImport(
            generation=int(state["generation"]),
            canonical_marker=_canonical_marker(canonical),
        )


def _wait_for_concurrent_verification(
    published: PublishedImport,
    token_dir: Path,
    *,
    timeout: float | None = None,
    poll_interval: float | None = None,
) -> None:
    """Adopt one concurrent verifier's result without issuing another force request."""
    if timeout is None:
        timeout = VERIFY_BUSY_TIMEOUT_SECONDS
    if poll_interval is None:
        poll_interval = VERIFY_STATE_POLL_SECONDS
    deadline = time.monotonic() + max(0.0, float(timeout))
    canonical = token_dir / RENEWAL_CREDENTIALS_FILENAME
    while True:
        if _canonical_marker(canonical) != published.canonical_marker:
            raise CredentialVerificationError(
                "renewal credentials were replaced by another import before verification"
            )

        state = load_refresh_state(token_dir / "refresh_state.json")
        result = str(state.get("result") or "never")
        generation = int(state.get("generation") or 0)
        # generation is a persisted monotonic success counter.  Unlike wall
        # clock timestamps, it remains reliable if NTP adjusts the system time
        # while a concurrent verifier is running.
        if result == "success" and generation > published.generation:
            return

        if result in FAILURE_RESULTS:
            exit_code = EX_TEMPFAIL if result in TEMPORARY_FAILURE_RESULTS else 1
            raise CredentialVerificationError(
                f"renewal check ended with state {result}",
                exit_code=exit_code,
            )

        if result not in PENDING_VERIFICATION_RESULTS:
            raise CredentialVerificationError(
                "renewal check ended without validating the imported credentials"
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CredentialVerificationError(
                "timed out waiting for the concurrent renewal check",
                exit_code=EX_TEMPFAIL,
            )
        time.sleep(min(max(0.01, float(poll_interval)), remaining))


def _delete_source(source: str) -> None:
    if source == "-":
        return
    try:
        Path(source).unlink()
    except OSError as exc:
        raise CredentialImportError(
            "credentials were imported, but the source bundle could not be deleted"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import Firefox desktop renewal credentials and verify ProxyPass renewal"
    )
    parser.add_argument(
        "bundle",
        help="path to fxa-renewal-credentials.json, or '-' to read JSON from stdin",
    )
    parser.add_argument(
        "--delete-source",
        action="store_true",
        help="delete the transferred bundle after a successful renewal check",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="publish credentials without requesting a fresh ProxyPass",
    )
    parser.add_argument(
        "--token-dir",
        type=Path,
        default=TOKENS,
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        bundle = load_bundle(args.bundle)
        published = publish_bundle(bundle, args.token_dir)
    except CredentialImportError as exc:
        print(f"[!] import failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[!] import failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    if not args.no_verify:
        if args.token_dir.resolve() != TOKENS.resolve():
            print("[!] automatic verification only supports the project token directory", file=sys.stderr)
            return 2
        try:
            completed = subprocess.run(
                [sys.executable, str(ROOT / "refresh_tokens.py"), "--force"],
                check=False,
            )
        except OSError:
            print(
                "[!] credentials were imported, but the renewal check could not start; "
                "the source bundle was kept",
                file=sys.stderr,
            )
            return 1
        if completed.returncode == 0:
            try:
                _wait_for_concurrent_verification(
                    published,
                    args.token_dir,
                    timeout=0,
                )
            except CredentialVerificationError as exc:
                print(
                    f"[!] credentials were imported, but verification failed: {exc}; "
                    "the source bundle was kept",
                    file=sys.stderr,
                )
                return exc.exit_code
        elif completed.returncode == EX_TEMPFAIL:
            print("[*] another renewal check is active; waiting for its result")
            try:
                _wait_for_concurrent_verification(published, args.token_dir)
            except CredentialVerificationError as exc:
                print(
                    f"[!] credentials were imported, but verification failed: {exc}; "
                    "the source bundle was kept",
                    file=sys.stderr,
                )
                return exc.exit_code
        elif completed.returncode != 0:
            print(
                "[!] credentials were imported, but the renewal check failed; "
                "the source bundle was kept",
                file=sys.stderr,
            )
            return completed.returncode or 1

    if args.delete_source:
        try:
            _delete_source(args.bundle)
        except CredentialImportError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
    if args.no_verify:
        print("[+] Firefox renewal credentials imported; renewal verification is pending")
    else:
        print("[+] Firefox renewal credentials imported and verified successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
