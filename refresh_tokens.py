#!/usr/bin/env python3
"""Long-lived token refresh for Firefox IP Protection.

Uses the stored FxA renewal credentials to mint a fresh OAuth access token,
then a Guardian ProxyPass JWT.  The main service runs this helper automatically.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import email.utils
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from fxa.core import Session as FxSession, StretchedPassword
from fxa.oauth import Client as OAuthClient
from fxa._utils import APIClient

from renewal_credentials import (
    RenewalCredentialsError,
    atomic_write_text,
    load_renewal_credentials,
)
from refresh_state import load_refresh_state, record_refresh_state, refresh_lock, retry_delay

ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "tokens"
LOGS = ROOT / "logs"
FX_CLIENT_ID = "5882386c6d801776"
SCOPES = "profile https://identity.mozilla.com/apps/vpn"
GUARDIAN = "https://vpn.mozilla.org"
HTTP_ATTEMPTS = 3
HTTP_RETRY_BUDGET = 30.0
ROTATE_BEFORE_SECONDS = 120
FXA_HTTP_TIMEOUT = (3.0, 7.0)
EX_TEMPFAIL = 75
REFRESH_STATE_FILE = TOKENS / "refresh_state.json"
REVALIDATE_RESULTS = {
    "credentials_imported",
    "rate_limited",
    "reauth_required",
    "no_entitlement",
}


def bounded_fxa_api_client(server_url: str) -> APIClient:
    """Build a PyFxA client without adapter retries and with finite I/O."""
    session = requests.Session()
    client = APIClient(server_url, session=session)
    client.timeout = FXA_HTTP_TIMEOUT
    return client


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
    min_ttl: float = 0,
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
    if current + max(0.0, float(min_ttl)) >= timestamps["exp"]:
        age = int(math.floor(current - timestamps["exp"]))
        if current >= timestamps["exp"]:
            raise ProxyPassValidationError(f"ProxyPass JWT is expired ({age}s); check system clock")
        raise ProxyPassValidationError("ProxyPass JWT is too close to expiry")
    return payload


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
        # RFC 9110 delay-seconds is a non-negative decimal integer.  We accept
        # finite fractional values for robustness, but a negative value is not
        # a valid "retry now" instruction: falling back to exponential
        # backoff avoids a tight refresh loop on a malformed response.
        return seconds if math.isfinite(seconds) and seconds >= 0 else None
    except ValueError:
        try:
            retry_at = email.utils.parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(0.0, retry_at.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


def _quota_reset_seconds(value: str | None, *, now: float | None = None) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    current = time.time() if now is None else float(now)
    return max(0.0, parsed.timestamp() - current)


def guardian_request(method: str, path: str, *, headers: dict[str, str], label: str) -> requests.Response:
    """Perform a bounded Guardian request, retrying only transient failures.

    Firefox treats a token-endpoint 429 as quota exhaustion.  Returning it
    immediately lets the caller persist a single cooldown instead of turning a
    quota response into a request storm.
    """
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
            # requests applies connect and read timeouts separately.  Split the
            # remaining wall-clock budget between them so one attempt cannot
            # intentionally consume two full budgets.
            connect_timeout = min(5.0, max(0.1, remaining / 3.0))
            read_timeout = max(0.1, remaining - connect_timeout)
            response = requests.request(
                method,
                f"{GUARDIAN}{path}",
                headers=request_headers,
                timeout=(connect_timeout, read_timeout),
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

        if response.status_code == 429:
            return response
        if not 500 <= response.status_code <= 599:
            return response
        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
        delay = retry_after if retry_after is not None else float(2 ** (attempt - 1))
        remaining = deadline - time.monotonic()
        if attempt == HTTP_ATTEMPTS or delay > remaining:
            print(
                time.strftime("%F %T"),
                label,
                f"transient Guardian error HTTP {response.status_code}",
                file=sys.stderr,
            )
            return response
        print(time.strftime("%F %T"), label, f"HTTP {response.status_code}; retrying in {delay:g}s")
        time.sleep(delay)

    kind = type(last_error).__name__ if last_error is not None else "network error"
    raise GuardianRequestError(f"{label} failed after bounded retries ({kind})")


def load_account() -> dict:
    try:
        return load_renewal_credentials(TOKENS)
    except RenewalCredentialsError as exc:
        raise SystemExit(str(exc)) from exc


def jwt_seconds_left(token: str, *, now: float | None = None) -> int | None:
    try:
        current = time.time() if now is None else float(now)
        body = validate_proxy_pass_jwt(token, now=current)
        return int(float(body["exp"]) - current)
    except ProxyPassValidationError:
        return None


def _remove_legacy_access_token() -> bool:
    """Remove the formerly persisted OAuth token without reading it."""
    try:
        (TOKENS / "fxa_token.txt").unlink()
    except FileNotFoundError:
        return True
    except OSError as exc:
        print(
            time.strftime("%F %T"),
            f"could not remove legacy OAuth cache ({type(exc).__name__})",
            file=sys.stderr,
        )
        return False
    return True


def _exception_status(error: BaseException) -> int | None:
    value = getattr(error, "code", None)
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return None


def _record_failure(
    result: str,
    state: dict[str, Any],
    *,
    now: float,
    http_status: int | None = None,
    retry_after: float | None = None,
    terminal: bool = False,
) -> int:
    failures = int(state.get("consecutive_failures") or 0)
    delay = (
        max(0.0, float(retry_after))
        if retry_after is not None
        else (300.0 if terminal else retry_delay(failures))
    )
    record_refresh_state(
        REFRESH_STATE_FILE,
        result,
        now=now,
        http_status=http_status,
        next_attempt_at=now + delay,
    )
    status_text = f" http={http_status}" if http_status is not None else ""
    print(
        time.strftime("%F %T"),
        f"refresh result={result}{status_text}; retry in {int(math.ceil(delay))}s",
        file=sys.stderr,
    )
    return EX_TEMPFAIL if result in {"rate_limited", "oauth_rate_limited", "transient_error"} else 1


def _refresh_once(*, force: bool) -> int:
    now = time.time()
    state = load_refresh_state(REFRESH_STATE_FILE)
    next_attempt_at = state.get("next_attempt_at")
    if (
        isinstance(next_attempt_at, (int, float))
        and not isinstance(next_attempt_at, bool)
        and math.isfinite(float(next_attempt_at))
        and float(next_attempt_at) > now
    ):
        wait = int(math.ceil(float(next_attempt_at) - now))
        print(time.strftime("%F %T"), f"refresh deferred by persisted cooldown ({wait}s)")
        return EX_TEMPFAIL

    # A blocking result may only be cleared by a real end-to-end renewal.
    # In particular, a newly imported session must never inherit a still-fresh
    # ProxyPass that was issued for the previous session merely because this
    # helper was invoked without --force.
    force = force or state.get("result") in REVALIDATE_RESULTS

    existing = TOKENS / "proxy_pass.jwt"
    if existing.exists() and not force:
        try:
            existing_token = existing.read_text(encoding="utf-8").strip()
            claims = validate_proxy_pass_jwt(existing_token, now=now)
        except (OSError, ProxyPassValidationError):
            pass
        else:
            expires_at = float(claims["exp"])
            remaining = expires_at - now
            seconds_left = int(math.ceil(remaining))
            if remaining > ROTATE_BEFORE_SECONDS:
                record_refresh_state(
                    REFRESH_STATE_FILE,
                    "fresh",
                    now=now,
                    proxy_pass_expires_at=expires_at,
                )
                print(time.strftime("%F %T"), f"proxy_pass still fresh ({seconds_left}s left), skip")
                return 0

    record_refresh_state(REFRESH_STATE_FILE, "in_progress", now=now)

    try:
        acc = load_account()
    except (SystemExit, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _record_failure(
            "missing_credentials",
            state,
            now=time.time(),
            terminal=True,
        )

    session_token = str(acc.get("session_token") or "").strip()
    email = str(acc.get("email") or "").strip()
    uid = str(acc.get("uid") or "").strip()
    if not session_token or not email or not uid:
        return _record_failure(
            "missing_credentials",
            state,
            now=time.time(),
            terminal=True,
        )

    server = "https://api.accounts.firefox.com/v1"
    oauth: OAuthClient | None = None
    access: str | None = None
    try:
        apiclient = bounded_fxa_api_client(server)
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
        oauth_server = "https://oauth.accounts.firefox.com/v1"
        oauth = OAuthClient(client_id=FX_CLIENT_ID, server_url=oauth_server)
        # OAuthClient creates a retrying APIClient internally.  Replace it so
        # the helper has a predictable total runtime and the supervising
        # service does not kill a legitimate slow refresh halfway through.
        oauth.apiclient = bounded_fxa_api_client(oauth_server)
        try:
            access_value = oauth.authorize_token(session, scope=SCOPES, client_id=FX_CLIENT_ID)
        except Exception as exc:
            status = _exception_status(exc)
            if status == 429:
                # FxA OAuth throttling does not prove that Guardian proxy
                # traffic quota is exhausted.  Keep its cooldown, but do not
                # hard-pause a still-usable last-good ProxyPass.
                result = "oauth_rate_limited"
            elif status is not None and 400 <= status <= 499:
                result = "reauth_required"
            else:
                result = "transient_error"
            return _record_failure(
                result,
                state,
                now=time.time(),
                http_status=status,
                terminal=result == "reauth_required",
            )
        if not isinstance(access_value, str) or not access_value.strip():
            return _record_failure(
                "reauth_required",
                state,
                now=time.time(),
                terminal=True,
            )
        access = access_value.strip()

        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "firefox-ip-protection-pool/1.0",
        }
        try:
            response = guardian_request(
                "GET",
                "/api/v1/fpn/token",
                headers=headers,
                label="fpn/token",
            )
        except GuardianRequestError:
            return _record_failure(
                "transient_error",
                state,
                now=time.time(),
            )

        status = int(response.status_code)
        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
        if status == 429:
            if retry_after is None:
                retry_after = _quota_reset_seconds(
                    response.headers.get("X-Quota-Reset"),
                    now=time.time(),
                )
            return _record_failure(
                "rate_limited",
                state,
                now=time.time(),
                http_status=status,
                retry_after=retry_after,
            )
        if status == 401:
            return _record_failure(
                "reauth_required",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )
        if status == 403:
            return _record_failure(
                "no_entitlement",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )
        if status == 404:
            return _record_failure(
                "protocol_error",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )
        if 500 <= status <= 599:
            return _record_failure(
                "transient_error",
                state,
                now=time.time(),
                http_status=status,
                retry_after=retry_after,
            )
        if status != 200:
            return _record_failure(
                "protocol_error",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )

        try:
            token_response = response.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            return _record_failure(
                "protocol_error",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )
        tok = token_response.get("token") if isinstance(token_response, dict) else None
        if not isinstance(tok, str) or not tok:
            return _record_failure(
                "protocol_error",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )
        try:
            validation_now = time.time()
            claims = validate_proxy_pass_jwt(
                tok,
                now=validation_now,
                min_ttl=ROTATE_BEFORE_SECONDS,
            )
        except ProxyPassValidationError:
            return _record_failure(
                "protocol_error",
                state,
                now=time.time(),
                http_status=status,
                terminal=True,
            )

        atomic_write_text(TOKENS / "proxy_pass.jwt", tok + "\n")
        expires_at = float(claims["exp"])
        record_refresh_state(
            REFRESH_STATE_FILE,
            "success",
            now=time.time(),
            http_status=status,
            proxy_pass_expires_at=expires_at,
        )
        print(
            time.strftime("%F %T"),
            "refreshed proxy_pass; seconds_left=",
            int(expires_at - time.time()),
        )
        return 0
    finally:
        if oauth is not None and access:
            try:
                oauth.destroy_token(access)
            except Exception as exc:
                print(
                    time.strftime("%F %T"),
                    f"OAuth token destroy failed ({type(exc).__name__})",
                    file=sys.stderr,
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh a Firefox IP Protection ProxyPass")
    parser.add_argument(
        "--force",
        action="store_true",
        help="request a new ProxyPass even if the current pass is fresh (cooldowns still apply)",
    )
    args = parser.parse_args(argv)

    TOKENS.mkdir(exist_ok=True)
    LOGS.mkdir(exist_ok=True)
    try:
        with refresh_lock(TOKENS, blocking=False):
            if not _remove_legacy_access_token():
                state = load_refresh_state(REFRESH_STATE_FILE)
                return _record_failure(
                    "transient_error",
                    state,
                    now=time.time(),
                )
            try:
                return _refresh_once(force=args.force)
            except Exception as exc:
                print(
                    time.strftime("%F %T"),
                    f"token refresh failed ({type(exc).__name__})",
                    file=sys.stderr,
                )
                try:
                    state = load_refresh_state(REFRESH_STATE_FILE)
                    return _record_failure(
                        "transient_error",
                        state,
                        now=time.time(),
                    )
                except Exception:
                    return EX_TEMPFAIL
    except BlockingIOError:
        print(time.strftime("%F %T"), "another refresh is in progress", file=sys.stderr)
        return EX_TEMPFAIL


if __name__ == "__main__":
    raise SystemExit(main())
