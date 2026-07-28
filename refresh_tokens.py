#!/usr/bin/env python3
"""Long-lived token refresh for Firefox IP Protection.

Uses a stored FxA sessionToken (tokens/session_token.txt + account_meta.json)
to mint a fresh OAuth access token, then Guardian ProxyPass JWT.

Cron:
  */4 * * * * cd /path/to/firefox-ip-protection-pool && .venv/bin/python refresh_tokens.py >> logs/refresh.log 2>&1
"""

from __future__ import annotations

import base64
import binascii
import email.utils
import fcntl
import json
import math
import os
import sys
import tempfile
import time
from datetime import timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from fxa.core import Session as FxSession, StretchedPassword
from fxa.oauth import Client as OAuthClient
from fxa._utils import APIClient

ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "tokens"
LOGS = ROOT / "logs"
FX_CLIENT_ID = "5882386c6d801776"
SCOPES = "profile https://identity.mozilla.com/apps/vpn"
GUARDIAN = "https://vpn.mozilla.org"
HTTP_ATTEMPTS = 3
HTTP_RETRY_BUDGET = 30.0


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            fd = -1
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, path)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


class ProxyPassValidationError(ValueError):
    """Raised when Guardian returns a malformed or unusable ProxyPass JWT."""


class GuardianRequestError(RuntimeError):
    """A sanitized Guardian network error safe to include in local logs."""


def _decode_jwt_segment(segment: str, label: str) -> bytes:
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not segment or any(character not in allowed for character in segment):
        raise ProxyPassValidationError(f"invalid JWT {label} encoding")
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.b64decode(segment + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProxyPassValidationError(f"invalid JWT {label} encoding") from exc
    if not decoded:
        raise ProxyPassValidationError(f"empty JWT {label}")
    return decoded


def _decode_jwt_json(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_decode_jwt_segment(segment, label).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProxyPassValidationError(f"JWT {label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProxyPassValidationError(f"JWT {label} must be a JSON object")
    return value


def validate_proxy_pass_jwt(
    token: str,
    now: float | None = None,
    guardian: str = GUARDIAN,
) -> dict[str, Any]:
    """Validate JWT structure and time claims without logging token material."""
    if not isinstance(token, str):
        raise ProxyPassValidationError("ProxyPass token is not a string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ProxyPassValidationError("ProxyPass JWT must contain three segments")

    header = _decode_jwt_json(parts[0], "header")
    payload = _decode_jwt_json(parts[1], "payload")
    _decode_jwt_segment(parts[2], "signature")
    if not isinstance(header.get("alg"), str) or not header["alg"] or header["alg"].lower() == "none":
        raise ProxyPassValidationError("JWT header has an invalid alg")

    required = ("sub", "aud", "iat", "nbf", "exp", "iss")
    missing = [claim for claim in required if claim not in payload]
    if missing:
        raise ProxyPassValidationError(f"ProxyPass JWT is missing claims: {', '.join(missing)}")
    for claim in ("sub", "iss"):
        if not isinstance(payload[claim], str) or not payload[claim].strip():
            raise ProxyPassValidationError(f"ProxyPass JWT has an invalid {claim} claim")
    audience = payload["aud"]
    if not (
        (isinstance(audience, str) and audience.strip())
        or (
            isinstance(audience, list)
            and audience
            and all(isinstance(item, str) and item.strip() for item in audience)
        )
    ):
        raise ProxyPassValidationError("ProxyPass JWT has an invalid aud claim")

    guardian_parts = urlsplit(guardian if "://" in guardian else f"https://{guardian}")
    expected_host = (guardian_parts.hostname or "").lower()
    expected_url = f"{guardian_parts.scheme or 'https'}://{guardian_parts.netloc}".rstrip("/").lower()
    issuer = payload["iss"].rstrip("/").lower()
    if not expected_host or issuer not in {expected_host, expected_url}:
        raise ProxyPassValidationError("ProxyPass JWT issuer does not match Guardian")
    audiences = audience if isinstance(audience, list) else [audience]
    normalized_audiences = {item.rstrip("/").lower() for item in audiences}
    if expected_url not in normalized_audiences and expected_host not in normalized_audiences:
        raise ProxyPassValidationError("ProxyPass JWT audience does not match Guardian")

    timestamps: dict[str, float] = {}
    for claim in ("iat", "nbf", "exp"):
        value = payload[claim]
        try:
            numeric_value = float(value)
        except (TypeError, ValueError, OverflowError):
            raise ProxyPassValidationError(f"ProxyPass JWT has an invalid {claim} claim")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(numeric_value):
            raise ProxyPassValidationError(f"ProxyPass JWT has an invalid {claim} claim")
        timestamps[claim] = numeric_value
    if timestamps["nbf"] >= timestamps["exp"] or timestamps["iat"] > timestamps["exp"]:
        raise ProxyPassValidationError("ProxyPass JWT has inconsistent time claims")

    current = time.time() if now is None else now
    if timestamps["nbf"] > current:
        skew = int(math.ceil(timestamps["nbf"] - current))
        raise ProxyPassValidationError(f"ProxyPass JWT is not valid yet; check system clock ({skew}s)")
    if current >= timestamps["exp"]:
        age = int(math.floor(current - timestamps["exp"]))
        raise ProxyPassValidationError(f"ProxyPass JWT is expired ({age}s); check system clock")
    return payload


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
        return max(0.0, seconds) if math.isfinite(seconds) else None
    except ValueError:
        try:
            retry_at = email.utils.parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(0.0, retry_at.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


def guardian_request(method: str, path: str, *, headers: dict[str, str], label: str) -> requests.Response:
    """Perform a bounded Guardian request retrying rate limits and transient failures."""
    started = time.monotonic()
    deadline = started + HTTP_RETRY_BUDGET
    last_error: requests.RequestException | None = None
    request_headers = dict(headers)
    request_headers.setdefault("Accept", "application/json")
    request_headers.setdefault("Content-Type", "application/json")
    request_headers.setdefault("Cache-Control", "no-cache")
    request_headers.setdefault("Pragma", "no-cache")
    for attempt in range(1, HTTP_ATTEMPTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            response = requests.request(
                method,
                f"{GUARDIAN}{path}",
                headers=request_headers,
                timeout=(min(5.0, remaining), min(15.0, remaining)),
            )
        except requests.RequestException as exc:
            last_error = exc
            if attempt == HTTP_ATTEMPTS:
                break
            delay = min(float(2 ** (attempt - 1)), HTTP_RETRY_BUDGET)
            remaining = deadline - time.monotonic()
            if delay > remaining:
                break
            print(time.strftime("%F %T"), label, f"network error ({type(exc).__name__}); retrying in {delay:g}s")
            time.sleep(delay)
            continue

        if response.status_code != 429 and not 500 <= response.status_code <= 599:
            return response
        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
        delay = retry_after if retry_after is not None else float(2 ** (attempt - 1))
        remaining = deadline - time.monotonic()
        if attempt == HTTP_ATTEMPTS or delay > remaining:
            if response.status_code == 429:
                suffix = f"; retry after {delay:g}s" if retry_after is not None else ""
                print(time.strftime("%F %T"), label, f"rate limited (HTTP 429){suffix}", file=sys.stderr)
            else:
                print(time.strftime("%F %T"), label, f"transient Guardian error HTTP {response.status_code}", file=sys.stderr)
            return response
        print(time.strftime("%F %T"), label, f"HTTP {response.status_code}; retrying in {delay:g}s")
        time.sleep(delay)

    kind = type(last_error).__name__ if last_error is not None else "network error"
    raise GuardianRequestError(f"{label} failed after bounded retries ({kind})")


def load_account() -> dict:
    meta = TOKENS / "account_meta.json"
    if meta.exists():
        data = json.loads(meta.read_text(encoding="utf-8"))
        if data.get("sessionToken") or (TOKENS / "session_token.txt").exists():
            return data
    st = ROOT / "data" / "ff_storage.json"
    if not st.exists():
        raise SystemExit("no account_meta.json / ff_storage.json")
    data = json.loads(st.read_text(encoding="utf-8"))
    for o in data.get("origins", []):
        for item in o.get("localStorage", []):
            if item["name"] == "__fxa_storage.accounts":
                acc = list(json.loads(item["value"]).values())[0]
                return {
                    "email": acc["email"],
                    "uid": acc["uid"],
                    "sessionToken": acc["sessionToken"],
                }
    raise SystemExit("session not found")


def jwt_seconds_left(token: str) -> int | None:
    try:
        body = validate_proxy_pass_jwt(token)
        return int(float(body["exp"]) - time.time())
    except ProxyPassValidationError:
        return None


def main() -> int:
    TOKENS.mkdir(exist_ok=True)
    LOGS.mkdir(exist_ok=True)

    lock_path = TOKENS / ".refresh.lock"
    lock_fh = open(lock_path, "a+", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    try:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(time.strftime("%F %T"), "another refresh in progress, skip")
        return 0

    try:
        # Skip if current proxy pass still fresh (>3 min)
        existing = TOKENS / "proxy_pass.jwt"
        if existing.exists():
            left = jwt_seconds_left(existing.read_text(encoding="utf-8").strip())
            if left is not None and left > 180:
                print(time.strftime("%F %T"), f"proxy_pass still fresh ({left}s left), skip")
                return 0

        acc = load_account()
        session_path = TOKENS / "session_token.txt"
        session_token = (
            session_path.read_text(encoding="utf-8").strip()
            if session_path.exists()
            else (acc.get("sessionToken") or "")
        )
        if not session_token:
            print("missing session token", file=sys.stderr)
            return 1
        email = acc.get("email") or ""
        uid = acc.get("uid") or ""
        if not email or not uid:
            print("missing email/uid in account meta", file=sys.stderr)
            return 1

        server = "https://api.accounts.firefox.com/v1"
        apiclient = APIClient(server)
        sp = StretchedPassword(1, email, None, "x", None)

        class Dummy:
            def __init__(self):
                self.apiclient = apiclient
                self.server_url = server

        session = FxSession(
            Dummy(),
            email,
            sp.v1,
            uid,
            session_token,
            verified=False,
            auth_timestamp=int(time.time() * 1000),
        )
        oauth = OAuthClient(client_id=FX_CLIENT_ID, server_url="https://oauth.accounts.firefox.com/v1")
        access = oauth.authorize_token(session, scope=SCOPES, client_id=FX_CLIENT_ID)

        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "firefox-ip-protection-pool/1.0",
        }
        r = guardian_request("GET", "/api/v1/fpn/token", headers=headers, label="fpn/token")
        if r.status_code in (401, 403, 404):
            ar = guardian_request("POST", "/api/v1/fpn/activate", headers=headers, label="fpn/activate")
            print(time.strftime("%F %T"), "fpn/activate", f"HTTP {ar.status_code}")
            if not ar.ok:
                retry_after = _retry_after_seconds(ar.headers.get("Retry-After"))
                suffix = f"; retry after {retry_after:g}s" if ar.status_code == 429 and retry_after is not None else ""
                print(time.strftime("%F %T"), f"fpn/activate failed: HTTP {ar.status_code}{suffix}", file=sys.stderr)
                return 1
            r = guardian_request("GET", "/api/v1/fpn/token", headers=headers, label="fpn/token")
        if not r.ok:
            retry_after = _retry_after_seconds(r.headers.get("Retry-After"))
            suffix = f"; retry after {retry_after:g}s" if r.status_code == 429 and retry_after is not None else ""
            print(time.strftime("%F %T"), f"fpn/token failed: HTTP {r.status_code}{suffix}", file=sys.stderr)
            return 1
        try:
            token_response = r.json()
        except requests.exceptions.JSONDecodeError:
            print(time.strftime("%F %T"), "fpn/token returned invalid JSON", file=sys.stderr)
            return 1
        tok = token_response.get("token") if isinstance(token_response, dict) else None
        if not isinstance(tok, str) or not tok:
            print(time.strftime("%F %T"), "fpn/token response has no token field", file=sys.stderr)
            return 1
        try:
            claims = validate_proxy_pass_jwt(tok)
        except ProxyPassValidationError as exc:
            print(time.strftime("%F %T"), f"rejected ProxyPass JWT: {exc}", file=sys.stderr)
            return 1

        # Commit the access token only after its corresponding ProxyPass passes validation.
        atomic_write_text(TOKENS / "fxa_token.txt", access + "\n")
        atomic_write_text(TOKENS / "proxy_pass.jwt", tok + "\n")
        atomic_write_text(TOKENS / "session_token.txt", session_token + "\n")
        # keep account meta in sync
        acc["sessionToken"] = session_token
        atomic_write_text(TOKENS / "account_meta.json", json.dumps(acc, indent=2) + "\n")
        quota = {k: v for k, v in r.headers.items() if k.lower().startswith("x-quota")}
        print(
            time.strftime("%F %T"),
            "refreshed proxy_pass; seconds_left=",
            int(float(claims["exp"]) - time.time()),
            "quota",
            quota,
        )
        return 0
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        lock_fh.close()


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        print(time.strftime("%F %T"), f"token refresh failed ({type(exc).__name__})", file=sys.stderr)
        exit_code = 1
    raise SystemExit(exit_code)
