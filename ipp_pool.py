#!/usr/bin/env python3
"""Firefox IP Protection → public SOCKS5/HTTP proxy pool.

Upstream:
  FxA session/OAuth → Guardian ProxyPass JWT
  → HTTPS CONNECT to *.m1.fastly-masque.net:2499
  → Proxy-Authorization: Bearer <JWT>

Local:
  each exit → SOCKS5 + HTTP on bind address
  optional rotating front port
  optional username/password auth for public exposure
"""

from __future__ import annotations

import argparse
import base64
import email.utils
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import random
import re
import select
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urlsplit

from refresh_state import load_refresh_state, record_refresh_state, retry_delay

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
EXPORT = ROOT / "export"
LOGS = ROOT / "logs"
TOKENS = ROOT / "tokens"
SERVERLIST_CACHE = DATA / "vpn-serverlist.json"
SERVERLIST_META = DATA / "vpn-serverlist.meta.json"
PORT_MAP_FILE = DATA / "port-map.json"
REFRESH_STATE_FILE = TOKENS / "refresh_state.json"
RENEWAL_BLOCK_RESULTS = {"rate_limited", "reauth_required", "no_entitlement"}

DEFAULT_GUARDIAN = "https://vpn.mozilla.org"
DEFAULT_RS = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main"
    "/collections/vpn-serverlist/records"
)
DEFAULT_SOCKS_BASE = 21000
DEFAULT_HTTP_BASE = 31000
DEFAULT_BIND = "127.0.0.1"
DEFAULT_ROTATOR = "127.0.0.1:1090"
DEFAULT_HTTP_ROTATOR = "127.0.0.1:8080"
DEFAULT_FIREFOX_VERSION = "155.0a1"
MAX_FORWARD_BODY = 8 * 1024 * 1024
MAX_PROBE_RESPONSE = 64 * 1024
# refresh_tokens.py bounds Guardian work to 30 seconds and gives each PyFxA
# request a 3-second connect plus 7-second read timeout.  PyFxA may repeat a
# request once for clock-skew correction, so the supervisor leaves enough
# room for the complete authorize/fetch/destroy flow without waiting forever.
REFRESH_HELPER_TIMEOUT_SECONDS = 100
DISABLED_LISTENERS = {"off", "none", "false"}
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}



def ensure_dirs() -> None:
    for p in (DATA, EXPORT, LOGS, TOKENS):
        p.mkdir(parents=True, exist_ok=True)


def load_token_file(path: Path) -> str | None:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
    return None


def atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """Atomically replace a text file with explicit, predictable permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
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
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise OSError on EOF/timeout."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def recv_until(sock: socket.socket, marker: bytes, max_size: int = 65536) -> bytes:
    buf = bytearray()
    while marker not in buf:
        if len(buf) >= max_size:
            raise OSError("response too large")
        chunk = sock.recv(min(4096, max_size - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def parse_listen_auth_file(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None
    user = pwd = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("USER="):
            user = line.split("=", 1)[1].strip()
        elif line.startswith("PASS="):
            pwd = line.split("=", 1)[1].strip()
    return user or None, pwd or None


def parse_authority(value: str, default_port: int | None = None) -> tuple[str, int]:
    """Parse a CONNECT/listen authority without accepting request-line injection."""
    if not value or any(ch in value for ch in "\r\n\0/@?#"):
        raise ValueError("invalid authority")
    host: str
    port_s: str | None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("invalid bracketed IPv6 authority")
        host = value[1:end]
        suffix = value[end + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:]:
                raise ValueError("invalid authority port")
            port_s = suffix[1:]
        else:
            port_s = None
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError("invalid IPv6 address") from exc
    else:
        if value.count(":") > 1:
            raise ValueError("IPv6 addresses must be enclosed in brackets")
        host, sep, port_s = value.rpartition(":")
        if not sep:
            host, port_s = value, None
        if not host or any(ord(ch) < 33 or ord(ch) == 127 for ch in host):
            raise ValueError("invalid authority host")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("invalid DNS hostname") from exc
            if len(host) > 253 or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[A-Za-z0-9-]+", label)
                for label in host.rstrip(".").split(".")
            ):
                raise ValueError("invalid DNS hostname")
    if port_s is None:
        if default_port is None:
            raise ValueError("authority port is required")
        port = default_port
    else:
        if not port_s.isdigit():
            raise ValueError("invalid authority port")
        port = int(port_s)
    if not 1 <= port <= 65535:
        raise ValueError("authority port is out of range")
    return host, port


def format_authority(host: str, port: int) -> str:
    try:
        is_v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_v6 = False
    return f"[{host}]:{port}" if is_v6 else f"{host}:{port}"


def is_loopback_bind(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def listener_is_disabled(value: str | None) -> bool:
    return value is not None and value.lower() in DISABLED_LISTENERS


def validate_bind_host(value: str) -> str:
    """Validate a bind-only host and return its normalized authority host."""
    host, _ = parse_authority(format_authority(value, 1))
    return host


def resolve_listener(value: str | None, bind: str, port: int) -> tuple[str | None, str | None]:
    """Resolve an optional aggregate listener and validate its authority."""
    listen = format_authority(bind, port) if value is None else value
    if listener_is_disabled(listen):
        return listen, None
    host, _ = parse_authority(listen)
    return listen, host


def _prepare_forward_request(handler: BaseHTTPRequestHandler) -> tuple[str, int, bytes]:
    parsed = urlsplit(handler.path)
    if parsed.scheme.lower() != "http" or not parsed.hostname:
        raise ValueError("only absolute-form http:// URLs are supported; use CONNECT for HTTPS")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("userinfo and fragments are not valid proxy targets")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("invalid destination port") from exc
    host, port = parse_authority(format_authority(parsed.hostname, port))

    transfer_encoding = handler.headers.get("Transfer-Encoding")
    content_lengths = handler.headers.get_all("Content-Length") or []
    if transfer_encoding:
        raise NotImplementedError("Transfer-Encoding is not supported")
    if len(content_lengths) > 1 and len(set(content_lengths)) != 1:
        raise ValueError("conflicting Content-Length headers")
    try:
        length = int(content_lengths[0]) if content_lengths else 0
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc
    if length < 0 or length > MAX_FORWARD_BODY:
        raise ValueError(f"Content-Length must be between 0 and {MAX_FORWARD_BODY}")
    body = handler.rfile.read(length) if length else b""
    if len(body) != length:
        raise ValueError("request body ended before Content-Length")

    connection_tokens = {
        token.strip().lower()
        for value in handler.headers.get_all("Connection") or []
        for token in value.split(",")
        if token.strip()
    }
    excluded = HOP_BY_HOP_HEADERS | connection_tokens | {"host"}
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    default_port = port == 80
    authority = parsed.hostname if default_port else format_authority(parsed.hostname, port)
    if ":" in parsed.hostname and default_port:
        authority = f"[{parsed.hostname}]"
    request_lines = [f"{handler.command} {path} HTTP/1.1", f"Host: {authority}"]
    for key, value in handler.headers.items():
        if key.lower() not in excluded:
            request_lines.append(f"{key}: {value}")
    request_lines.append("Connection: close")
    request_lines.extend(("", ""))
    return host, port, "\r\n".join(request_lines).encode("iso-8859-1") + body


def _forward_http(
    handler: BaseHTTPRequestHandler,
    connector: "FastlyConnectClient",
    node: "ExitNode",
    prepared: tuple[str, int, bytes] | None = None,
) -> None:
    remote: socket.socket | None = None
    destination_host, destination_port, request = prepared or _prepare_forward_request(handler)
    try:
        # Failover is safe only before a tunnel is established. Once bytes may
        # have crossed an upstream tunnel, retrying a POST/PUT could duplicate
        # a non-idempotent operation.
        remote = connector.open_tunnel(node.hostname, node.port, destination_host, destination_port)
        try:
            remote.sendall(request)
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                handler.connection.sendall(chunk)
        except Exception as exc:
            raise ForwardRequestError("upstream request/response failed after tunnel establishment") from exc
    finally:
        if remote is not None:
            try:
                remote.close()
            except OSError:
                pass


class ForwardRequestError(RuntimeError):
    """An upstream failure after a tunnel may have received request bytes."""



def b64url_decode(s: str) -> bytes:
    """Decode one unpadded base64url JWT segment without accepting junk."""
    if not isinstance(s, str) or not s or not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        raise ValueError("invalid base64url segment")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid base64url segment") from exc


def _jwt_header_claims(token: str) -> tuple[dict, dict]:
    parts = token.strip().split(".") if isinstance(token, str) else []
    if len(parts) != 3 or not all(parts):
        raise ValueError("not a JWT")
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        # We intentionally do not verify the signature here, but its segment
        # must still be valid non-empty base64url so malformed responses fail closed.
        b64url_decode(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed JWT encoding") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("JWT header and payload must be objects")
    return header, claims


def jwt_claims(token: str) -> dict:
    return _jwt_header_claims(token)[1]


def validate_proxy_pass_jwt(
    token: str,
    guardian: str = DEFAULT_GUARDIAN,
    now: float | None = None,
    min_ttl: int = 0,
) -> dict:
    """Validate ProxyPass structure and claims (not the cryptographic signature)."""
    header, claims = _jwt_header_claims(token)
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm.strip() or algorithm.lower() == "none":
        raise ValueError("ProxyPass JWT has an invalid signing algorithm")
    required = {"sub", "aud", "iat", "nbf", "exp", "iss"}
    missing = sorted(k for k in required if claims.get(k) is None or claims.get(k) == "")
    if missing:
        raise ValueError(f"ProxyPass JWT missing claims: {', '.join(missing)}")
    for claim in ("sub", "iss"):
        if not isinstance(claims[claim], str) or not claims[claim].strip():
            raise ValueError(f"ProxyPass JWT has an invalid {claim} claim")
    audience_claim = claims["aud"]
    audiences = audience_claim if isinstance(audience_claim, list) else [audience_claim]
    if not audiences or not all(isinstance(item, str) and item.strip() for item in audiences):
        raise ValueError("ProxyPass JWT has an invalid aud claim")
    try:
        timestamps = {
            name: float(claims[name])
            for name in ("iat", "nbf", "exp")
        }
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("ProxyPass JWT timestamps must be integers") from exc
    if any(
        isinstance(claims[name], bool)
        or not isinstance(claims[name], (int, float))
        or not math.isfinite(timestamps[name])
        for name in ("iat", "nbf", "exp")
    ):
        raise ValueError("ProxyPass JWT timestamps must be integers")
    issued, not_before, expires = (timestamps[name] for name in ("iat", "nbf", "exp"))
    if not_before >= expires or issued > expires:
        raise ValueError("ProxyPass JWT has inconsistent timestamps")
    current = float(time.time() if now is None else now)
    if not_before > current:
        raise ValueError(f"ProxyPass JWT is not valid yet (clock skew {int(not_before - current)}s)")
    if expires <= current + min_ttl:
        raise ValueError("ProxyPass JWT is expired or too close to expiry")

    guardian_parts = urlsplit(guardian if "://" in guardian else f"https://{guardian}")
    expected_host = (guardian_parts.hostname or "").lower()
    expected_url = f"{guardian_parts.scheme or 'https'}://{guardian_parts.netloc}".rstrip("/")
    issuer = str(claims["iss"]).rstrip("/").lower()
    if issuer not in {expected_host, expected_url.lower()}:
        raise ValueError("ProxyPass JWT issuer does not match Guardian")
    normalized_aud = {item.rstrip("/").lower() for item in audiences}
    if expected_url.lower() not in normalized_aud and expected_host not in normalized_aud:
        raise ValueError("ProxyPass JWT audience does not match Guardian")
    return claims


def jwt_summary(token: str) -> dict:
    try:
        c = validate_proxy_pass_jwt(token)
        now = int(time.time())
        exp = int(c.get("exp") or 0)
        return {
            "sub": c.get("sub"),
            "iss": c.get("iss"),
            "aud": c.get("aud"),
            "exp": exp,
            "nbf": c.get("nbf"),
            "seconds_left": exp - now if exp else None,
            "valid": bool(exp and exp > now),
        }
    except Exception as e:
        return {"error": str(e), "valid": False}


def safe_jwt_summary(token: str) -> dict:
    """Return operational JWT timing without the account subject identifier."""
    summary = jwt_summary(token)
    summary.pop("sub", None)
    return summary


def _retry_after_seconds(value: str | None, now: float | None = None) -> int | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return max(0, int(value))
    try:
        when = email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None
    return max(0, int(when - (time.time() if now is None else now)))


def _quota_reset_seconds(value: str | None, now: float | None = None) -> int | None:
    """Convert Guardian's timezone-aware quota reset into a safe delay."""
    if not value:
        return None
    normalized = value.strip()
    try:
        reset = datetime.fromisoformat(
            normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
        )
    except (TypeError, ValueError, OverflowError):
        return None
    if reset.tzinfo is None:
        return None
    current = time.time() if now is None else now
    return max(0, int(reset.timestamp() - current))


@dataclass
class ProxyUsage:
    unlimited: bool | None = None
    limit: int | None = None
    remaining: int | None = None
    reset: str | None = None
    retry_after: int | None = None

    @classmethod
    def from_headers(cls, headers, *, require_quota: bool = True) -> "ProxyUsage":
        normalized = {str(k).lower(): str(v) for k, v in (headers.items() if headers else [])}

        def integer(name: str) -> int:
            try:
                value = int(normalized[name])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid or missing Guardian header: {name}") from exc
            if value < 0:
                raise ValueError(f"Guardian header {name} must be non-negative")
            return value

        unlimited_raw = normalized.get("x-quota-unlimited")
        if unlimited_raw is not None:
            unlimited_value = unlimited_raw.strip().lower()
            if unlimited_value not in {"true", "false"}:
                if require_quota:
                    raise ValueError("invalid Guardian header: x-quota-unlimited")
                return cls(retry_after=_retry_after_seconds(normalized.get("retry-after")))
            if unlimited_value == "true":
                return cls(
                    unlimited=True,
                    retry_after=_retry_after_seconds(normalized.get("retry-after")),
                )

        quota_headers = ("x-quota-limit", "x-quota-remaining", "x-quota-reset")
        if not all(normalized.get(name, "").strip() for name in quota_headers):
            if require_quota:
                missing = [name for name in quota_headers if not normalized.get(name, "").strip()]
                raise ValueError(f"missing Guardian quota header(s): {', '.join(missing)}")
            return cls(retry_after=_retry_after_seconds(normalized.get("retry-after")))

        limit = integer("x-quota-limit")
        remaining = integer("x-quota-remaining")
        if remaining > limit:
            raise ValueError("Guardian quota remaining cannot exceed limit")
        reset = normalized["x-quota-reset"].strip()
        try:
            parsed_reset = datetime.fromisoformat(reset[:-1] + "+00:00" if reset.endswith("Z") else reset)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("invalid Guardian quota reset timestamp") from exc
        if parsed_reset.tzinfo is None:
            raise ValueError("Guardian quota reset timestamp must include a timezone")
        return cls(
            unlimited=False,
            limit=limit,
            remaining=remaining,
            reset=reset,
            retry_after=_retry_after_seconds(normalized.get("retry-after")),
        )


def guardian_headers(access_token: str) -> dict[str, str]:
    """Return the current Firefox Desktop Guardian request headers."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "firefox-ip-protection-pool/2.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


class TokenStore:
    """Thread-safe ProxyPass holder with non-blocking state reads and single-flight renewal."""

    def __init__(
        self,
        proxy_pass: str | None = None,
        fxa_token: str | None = None,
        guardian: str = DEFAULT_GUARDIAN,
        rotate_skew: int = 120,
        usable_skew: int = 5,
        token_dir: Path | None = None,
        refresh_state_file: Path | None = None,
    ) -> None:
        self._lock = threading.RLock()
        # Slow helper/network work is serialized separately and never runs
        # while the state lock is held.
        self._refresh_lock = threading.Lock()
        self._proxy_pass = (proxy_pass or "").strip() or None
        self._proxy_pass_explicit = bool(self._proxy_pass)
        self._fxa_token = (fxa_token or "").strip() or None
        self._fxa_token_explicit = bool(self._fxa_token)
        self._fxa_token_from_file = False
        self.guardian = guardian.rstrip("/")
        self.rotate_skew = max(0, int(rotate_skew))
        self.usable_skew = max(0, int(usable_skew))
        self.last_error: str | None = None
        self.usage_headers: dict[str, str] = {}
        self.quota = ProxyUsage()
        self._refreshing = False
        token_root = token_dir or TOKENS
        self._proxy_file = token_root / "proxy_pass.jwt"
        self._rejected_file = token_root / "rejected_proxy_pass.sha256"
        self._fxa_file = token_root / "fxa_token.txt"
        self._session_file = token_root / "session_token.txt"
        self._account_meta_file = token_root / "account_meta.json"
        self._refresh_state_file = refresh_state_file or token_root / "refresh_state.json"
        self._rejected_token_digests = self._load_rejected_digests()
        self._proxy_marker: tuple[int, int, int] | None = self._file_marker(self._proxy_file)
        self.refresh_state = load_refresh_state(self._refresh_state_file)
        self.last_refresh = self.refresh_state.get("last_success_at")
        self.last_status = self.refresh_state.get("http_status")
        self.retry_at = self.refresh_state.get("next_attempt_at")
        if self._proxy_pass:
            try:
                validate_proxy_pass_jwt(self._proxy_pass, guardian=self.guardian)
            except ValueError:
                self.last_error = "ignored malformed ProxyPass JWT provided in configuration"
                self._proxy_pass = None
            else:
                if self._is_rejected_unlocked(self._proxy_pass):
                    self.last_error = "ignored a previously rejected ProxyPass JWT"
                    self._proxy_pass = None
        # An explicit CLI/environment token wins at startup.  Record the
        # current file marker so only a later atomic refresh may replace it.
        self._reload_from_disk(force=not self._proxy_pass_explicit)

    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _is_rejected_unlocked(self, token: str | None) -> bool:
        return bool(token) and self._token_digest(token) in self._rejected_token_digests

    def _load_rejected_digests(self) -> list[str]:
        try:
            values = self._rejected_file.read_text(encoding="ascii").splitlines()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return []
        return [
            value.lower()
            for value in values[-32:]
            if re.fullmatch(r"[0-9a-fA-F]{64}", value)
        ]

    def _persist_rejected_digests_unlocked(self) -> None:
        atomic_write_text(
            self._rejected_file,
            "".join(f"{digest}\n" for digest in self._rejected_token_digests),
            mode=0o600,
        )

    def _clear_rejected_digests_unlocked(self) -> None:
        self._rejected_token_digests.clear()
        try:
            self._rejected_file.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.last_error = f"could not clear rejected ProxyPass marker: {type(exc).__name__}"

    def _mark_rejected_unlocked(self, token: str) -> None:
        digest = self._token_digest(token)
        added = False
        if digest not in self._rejected_token_digests:
            self._rejected_token_digests.append(digest)
            del self._rejected_token_digests[:-32]
            added = True
        if self._proxy_pass and hmac.compare_digest(self._proxy_pass, token):
            self._proxy_pass = None
        if added:
            self._persist_rejected_digests_unlocked()

    def _file_marker(self, path: Path) -> tuple[int, int, int] | None:
        try:
            stat_result = path.stat()
            return (stat_result.st_ino, stat_result.st_mtime_ns, stat_result.st_size)
        except OSError:
            return None

    def _reload_from_disk(self, force: bool = False) -> None:
        for digest in self._load_rejected_digests():
            if digest not in self._rejected_token_digests:
                self._rejected_token_digests.append(digest)
        del self._rejected_token_digests[:-32]
        if self._proxy_pass and self._is_rejected_unlocked(self._proxy_pass):
            self._proxy_pass = None
        marker = self._file_marker(self._proxy_file)
        if force or marker != self._proxy_marker:
            proxy_pass = load_token_file(self._proxy_file)
            if proxy_pass and not self._is_rejected_unlocked(proxy_pass):
                try:
                    validate_proxy_pass_jwt(proxy_pass, guardian=self.guardian)
                except ValueError:
                    self.last_error = "ignored malformed ProxyPass JWT on disk"
                else:
                    self._proxy_pass = proxy_pass
            self._proxy_marker = marker
        if not self._fxa_token_explicit:
            fxa_token = load_token_file(self._fxa_file)
            if fxa_token:
                self._fxa_token = fxa_token
                self._fxa_token_from_file = True
            elif self._fxa_token_from_file:
                self._fxa_token = None
                self._fxa_token_from_file = False

    def _session_refresh_available(self) -> bool:
        helper = ROOT / "refresh_tokens.py"
        return helper.exists() and bool(
            load_token_file(self._session_file) or self._account_meta_file.exists()
        )

    def _automatic_renewal_ready(self) -> bool:
        session_token = load_token_file(self._session_file)
        try:
            metadata = json.loads(self._account_meta_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(metadata, dict):
            return False
        return bool(
            session_token
            and str(metadata.get("email") or "").strip()
            and str(metadata.get("uid") or "").strip()
        )

    def _sync_refresh_state(self) -> dict:
        """Reload non-secret renewal state written by another process."""
        state = load_refresh_state(self._refresh_state_file)
        with self._lock:
            previous_retry = self.retry_at
            self.refresh_state = state
            self.last_refresh = state.get("last_success_at")
            self.last_status = state.get("http_status")
            persisted_retry = state.get("next_attempt_at")
            if (
                persisted_retry is None
                and state.get("result") in {"never", "in_progress"}
                and isinstance(previous_retry, (int, float))
                and previous_retry > time.time()
            ):
                self.retry_at = previous_retry
            else:
                self.retry_at = persisted_retry
        return state

    def _renewal_block_unlocked(self) -> tuple[str, float | None] | None:
        result = self.refresh_state.get("result")
        if result not in RENEWAL_BLOCK_RESULTS:
            return None
        next_attempt = self.refresh_state.get("next_attempt_at")
        deadline = (
            float(next_attempt)
            if isinstance(next_attempt, (int, float)) and not isinstance(next_attempt, bool)
            else None
        )
        return str(result), deadline

    def _usable_unlocked(self, token: str | None = None) -> bool:
        candidate = self._proxy_pass if token is None else token
        if not candidate or self._is_rejected_unlocked(candidate):
            return False
        try:
            validate_proxy_pass_jwt(
                candidate,
                guardian=self.guardian,
                min_ttl=self.usable_skew,
            )
            return True
        except Exception:
            return False

    def is_usable(self) -> bool:
        with self._lock:
            self._reload_from_disk()
            return self._usable_unlocked()

    def should_refresh_unlocked(self) -> bool:
        renewal_block = self._renewal_block_unlocked()
        if renewal_block is not None:
            _, next_attempt = renewal_block
            return next_attempt is None or next_attempt <= time.time()
        if not self._proxy_pass or self._is_rejected_unlocked(self._proxy_pass):
            return True
        try:
            validate_proxy_pass_jwt(
                self._proxy_pass,
                guardian=self.guardian,
                min_ttl=self.rotate_skew,
            )
            return False
        except Exception:
            return True

    # Backward-compatible name used by existing callers.
    def needs_refresh_unlocked(self) -> bool:
        return self.should_refresh_unlocked()

    def should_refresh(self) -> bool:
        self._sync_refresh_state()
        with self._lock:
            self._reload_from_disk()
            return self.should_refresh_unlocked()

    def needs_refresh(self) -> bool:
        return self.should_refresh()

    def current(self) -> str | None:
        with self._lock:
            self._reload_from_disk()
            return self._proxy_pass

    def ensure(self) -> str:
        # A still-usable last-good is returned immediately. Proactive renewal
        # belongs to the background worker and must not add minutes of latency
        # to a proxy request.
        self._sync_refresh_state()
        recover_blocked_state = False
        with self._lock:
            self._reload_from_disk()
            renewal_block = self._renewal_block_unlocked()
            if renewal_block is not None:
                result, next_attempt = renewal_block
                now = time.time()
                if next_attempt is not None and next_attempt > now:
                    wait = max(1, int(next_attempt - now))
                    raise RuntimeError(
                        f"automatic renewal is paused ({result}); retry in {wait}s"
                    )
                recover_blocked_state = True
            elif self._usable_unlocked():
                return self._proxy_pass or ""
        try:
            return self.refresh(force=recover_blocked_state)
        except Exception as exc:
            self._sync_refresh_state()
            with self._lock:
                self._reload_from_disk()
                if self._renewal_block_unlocked() is None and self._usable_unlocked():
                    return self._proxy_pass or ""
                message = self.last_error or str(exc)
            raise RuntimeError(
                message or "no ProxyPass JWT; run refresh_tokens.py or set tokens/proxy_pass.jwt"
            ) from exc

    def _record_state(
        self,
        result: str,
        *,
        http_status: int | None = None,
        next_attempt_at: float | None = None,
        proxy_pass_expires_at: float | None = None,
    ) -> None:
        try:
            state = record_refresh_state(
                self._refresh_state_file,
                result,
                http_status=http_status,
                next_attempt_at=next_attempt_at,
                proxy_pass_expires_at=proxy_pass_expires_at,
            )
        except OSError:
            return
        with self._lock:
            self.refresh_state = state
            self.last_refresh = state.get("last_success_at")
            self.last_status = state.get("http_status")
            self.retry_at = state.get("next_attempt_at")

    def _record_failure(
        self,
        result: str,
        message: str,
        *,
        http_status: int | None = None,
        delay: float | None = None,
    ) -> None:
        now = time.time()
        with self._lock:
            failures = int(self.refresh_state.get("consecutive_failures") or 0)
        cooldown = retry_delay(failures) if delay is None else max(1.0, float(delay))
        next_attempt = now + cooldown
        with self._lock:
            self.last_error = message
            self.last_status = http_status
            self.retry_at = next_attempt
        self._record_state(
            result,
            http_status=http_status,
            next_attempt_at=next_attempt,
        )

    def _accept_token(
        self,
        token: str,
        *,
        persist: bool,
        record_success: bool = True,
    ) -> str:
        claims = validate_proxy_pass_jwt(
            token,
            guardian=self.guardian,
            min_ttl=self.rotate_skew,
        )
        if self._token_digest(token) in self._rejected_token_digests:
            raise ValueError("Guardian returned a previously rejected ProxyPass JWT")
        if persist:
            atomic_write_text(self._proxy_file, token + "\n", mode=0o600)
        now = time.time()
        with self._lock:
            self._proxy_pass = token
            self._proxy_marker = self._file_marker(self._proxy_file)
            self.last_refresh = now
            self.last_error = None
            self.retry_at = None
            self._clear_rejected_digests_unlocked()
        if record_success:
            self._record_state(
                "success",
                http_status=self.last_status,
                proxy_pass_expires_at=float(claims["exp"]),
            )
        return token

    def _adopt_helper_state(self) -> bool:
        state = load_refresh_state(self._refresh_state_file)
        if state.get("result") in {"never", "in_progress"}:
            return False
        with self._lock:
            self.refresh_state = state
            self.last_refresh = state.get("last_success_at")
            self.last_status = state.get("http_status")
            self.retry_at = state.get("next_attempt_at")
            self.last_error = f"refresh helper result: {state.get('result')}"
        return True

    def _refresh_via_helper(self, *, force: bool) -> str | None:
        helper = ROOT / "refresh_tokens.py"
        command = [sys.executable, str(helper)]
        if force:
            command.append("--force")
        try:
            completed = subprocess.run(
                command,
                cwd=str(ROOT),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=REFRESH_HELPER_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._record_failure(
                "transient_error",
                f"refresh_tokens.py failed: {type(exc).__name__}",
            )
            return None
        if completed.returncode == 75:
            if self._adopt_helper_state():
                return None
            # Do not persist a competing "busy" result. The lock owner may
            # be about to write a longer Guardian Retry-After; overwriting it
            # here would re-enable requests too early. Keep only a short local
            # wait and let the owner publish the authoritative state.
            with self._lock:
                self.last_error = "another token refresh is in progress"
                self.retry_at = time.time() + 5
            return None
        if completed.returncode != 0:
            if self._adopt_helper_state():
                return None
            self._record_failure(
                "transient_error",
                f"refresh_tokens.py failed with status {completed.returncode}",
            )
            return None
        candidate = load_token_file(self._proxy_file)
        if candidate:
            try:
                helper_recorded_success = self._adopt_helper_state() and (
                    self.refresh_state.get("result") == "success"
                )
                token = self._accept_token(
                    candidate,
                    persist=False,
                    record_success=not helper_recorded_success,
                )
                with self._lock:
                    self.last_error = None
                return token
            except ValueError:
                pass
        self._record_failure(
            "protocol_error",
            "refresh_tokens.py did not produce a valid fresh ProxyPass JWT",
        )
        return None

    def _set_usage(self, headers, *, require_quota: bool) -> None:
        selected = {
            k: v
            for k, v in (headers.items() if headers else [])
            if k.lower().startswith("x-quota") or k.lower() == "retry-after"
        }
        quota = ProxyUsage.from_headers(headers, require_quota=require_quota)
        with self._lock:
            self.usage_headers = selected
            self.quota = quota

    def _refresh_direct(self, fxa_token: str) -> str | None:
        request = urllib.request.Request(
            f"{self.guardian}/api/v1/fpn/token",
            headers=guardian_headers(fxa_token),
            method="GET",
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status = getattr(response, "status", 200)
                    with self._lock:
                        self.last_status = status
                    try:
                        self._set_usage(response.headers, require_quota=True)
                    except ValueError as quota_error:
                        with self._lock:
                            self.quota = ProxyUsage()
                        warnings.warn(f"invalid Guardian quota headers ignored: {quota_error}")
                    data = json.loads(response.read().decode("utf-8"))
                    token = data.get("token") if isinstance(data, dict) else None
                    if not isinstance(token, str):
                        raise ValueError("no token in Guardian response")
                    return self._accept_token(token, persist=True)
            except urllib.error.HTTPError as exc:
                retry_after = _retry_after_seconds(
                    exc.headers.get("Retry-After") if exc.headers else None
                )
                quota_reset = _quota_reset_seconds(
                    exc.headers.get("X-Quota-Reset") if exc.headers else None
                )
                with self._lock:
                    self.last_status = exc.code
                try:
                    self._set_usage(exc.headers, require_quota=False)
                except ValueError as quota_error:
                    with self._lock:
                        self.quota = ProxyUsage(retry_after=retry_after)
                    warnings.warn(f"invalid Guardian quota headers ignored: {quota_error}")
                if exc.code == 429:
                    delay = next(
                        (
                            max(1, candidate)
                            for candidate in (retry_after, quota_reset)
                            if candidate is not None
                        ),
                        None,
                    )
                    self._record_failure(
                        "rate_limited",
                        "Guardian quota exhausted (HTTP 429); cooldown scheduled",
                        http_status=429,
                        delay=delay,
                    )
                    return None
                if exc.code in {401, 403}:
                    result = "reauth_required" if exc.code == 401 else "no_entitlement"
                    self._record_failure(
                        result,
                        f"Guardian token request failed with HTTP {exc.code}",
                        http_status=exc.code,
                        delay=60,
                    )
                    return None
                if 500 <= exc.code < 600 and retry_after is not None:
                    self._record_failure(
                        "transient_error",
                        f"Guardian token request failed with HTTP {exc.code}",
                        http_status=exc.code,
                        delay=max(1, retry_after),
                    )
                    return None
                if 500 <= exc.code < 600 and attempt < 2:
                    time.sleep(0.5 * (2**attempt))
                    continue
                self._record_failure(
                    "transient_error",
                    f"Guardian token request failed with HTTP {exc.code}",
                    http_status=exc.code,
                )
                return None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(0.5 * (2**attempt))
                    continue
                self._record_failure(
                    "transient_error",
                    f"Guardian token request failed: {type(exc).__name__}",
                )
                return None
            except (ValueError, json.JSONDecodeError) as exc:
                self._record_failure(
                    "protocol_error",
                    f"invalid Guardian token response: {exc}",
                )
                return None
        return None

    def refresh(
        self,
        force: bool = False,
        rejected_token: str | None = None,
    ) -> str:
        rejected = (rejected_token or "").strip() or None
        with self._lock:
            self._reload_from_disk()
            observed = self._proxy_pass
            if rejected:
                self._mark_rejected_unlocked(rejected)
        with self._refresh_lock:
            # A cron job or another service process may have written a
            # cooldown after this TokenStore was created.  Refresh the
            # non-secret state before making any network decision so a
            # restart or cross-process race cannot erase Retry-After.
            persisted_state = self._sync_refresh_state()
            with self._lock:
                self._reload_from_disk()
                if rejected:
                    self._mark_rejected_unlocked(rejected)
                    if self._usable_unlocked():
                        replacement = self._proxy_pass or ""
                        if replacement and not hmac.compare_digest(replacement, rejected):
                            self._clear_rejected_digests_unlocked()
                        return replacement
                elif force and observed is not None and self._proxy_pass != observed and self._usable_unlocked():
                    return self._proxy_pass or ""
                elif (
                    not force
                    and self._renewal_block_unlocked() is None
                    and not self.should_refresh_unlocked()
                ):
                    return self._proxy_pass or ""
                now = time.time()
                next_attempt = self.refresh_state.get("next_attempt_at") or self.retry_at
                if isinstance(next_attempt, (int, float)) and next_attempt > now:
                    wait = max(1, int(next_attempt - now))
                    self.last_error = f"Guardian refresh is in backoff; retry in {wait}s"
                    raise RuntimeError(self.last_error)
                recovering_blocked_state = self._renewal_block_unlocked() is not None
                self._refreshing = True
                fxa_token = self._fxa_token
                force_helper = (
                    force
                    or bool(rejected)
                    or bool(self._rejected_token_digests)
                    or recovering_blocked_state
                )

            session_refresh = self._session_refresh_available()
            # The helper owns the cross-process lock and records its own
            # in-progress state.  Writing that state here could race a helper
            # that has just persisted a cooldown and accidentally clear it.
            if not session_refresh:
                self._record_state("in_progress", next_attempt_at=None)
            try:
                if session_refresh:
                    token = self._refresh_via_helper(force=force_helper)
                elif fxa_token:
                    token = self._refresh_direct(fxa_token)
                else:
                    self._record_failure(
                        "missing_credentials",
                        "missing FxA token / session",
                        delay=60,
                    )
                    token = None
            except Exception as exc:
                self._record_failure(
                    "transient_error",
                    f"token refresh failed: {type(exc).__name__}",
                )
                token = None
            finally:
                with self._lock:
                    self._refreshing = False

            if token:
                return token
            with self._lock:
                error = self.last_error or "refresh failed"
            raise RuntimeError(error)

    def usage(self) -> ProxyUsage:
        with self._lock:
            fxa_token = self._fxa_token
        if not fxa_token:
            raise RuntimeError("missing FxA access token for Guardian usage query")
        req = urllib.request.Request(
            f"{self.guardian}/api/v1/fpn/token",
            headers=guardian_headers(fxa_token),
            method="HEAD",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                with self._lock:
                    self.last_status = getattr(resp, "status", 200)
                self._set_usage(resp.headers, require_quota=True)
        except urllib.error.HTTPError as exc:
            retry_after = _retry_after_seconds(
                exc.headers.get("Retry-After") if exc.headers else None
            )
            quota_reset = _quota_reset_seconds(
                exc.headers.get("X-Quota-Reset") if exc.headers else None
            )
            with self._lock:
                self.last_status = exc.code
            try:
                self._set_usage(exc.headers, require_quota=False)
            except ValueError:
                with self._lock:
                    self.quota = ProxyUsage(retry_after=retry_after)
            if exc.code == 429:
                delay = next(
                    (
                        max(1, candidate)
                        for candidate in (retry_after, quota_reset)
                        if candidate is not None
                    ),
                    None,
                )
                self._record_failure(
                    "rate_limited",
                    "Guardian usage request was rate-limited",
                    http_status=429,
                    delay=delay,
                )
            raise RuntimeError(f"Guardian usage request failed with HTTP {exc.code}") from exc
        with self._lock:
            return self.quota

    def status(self) -> dict:
        automatic_ready = self._automatic_renewal_ready()
        self._sync_refresh_state()
        with self._lock:
            self._reload_from_disk()
            proxy_pass = self._proxy_pass
            summary = safe_jwt_summary(proxy_pass) if proxy_pass else None
            return {
                "has_proxy_pass": bool(proxy_pass),
                "has_fxa_token": bool(self._fxa_token),
                "automatic_renewal_ready": automatic_ready,
                "refresh_in_progress": self._refreshing,
                "proxy_pass": summary,
                "last_refresh": self.last_refresh,
                "last_status": self.last_status,
                "last_error": self.last_error,
                "usage_headers": dict(self.usage_headers),
                "quota": asdict(self.quota),
                "retry_at": self.retry_at,
                "refresh_state": dict(self.refresh_state),
                "guardian": self.guardian,
            }


class TokenRefreshWorker:
    """Named, testable lifecycle wrapper for proactive ProxyPass renewal."""

    def __init__(
        self,
        tokens: TokenStore,
        stop_event: threading.Event,
        interval: float = 30.0,
        logger=print,
    ) -> None:
        self.tokens = tokens
        self.stop_event = stop_event
        self.interval = max(0.01, float(interval))
        self.logger = logger
        self.thread: threading.Thread | None = None

    def start(self) -> "TokenRefreshWorker":
        if self.thread is not None and self.thread.is_alive():
            return self
        self.thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="token-refresh-worker",
        )
        self.thread.start()
        return self

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                if self.tokens.should_refresh():
                    token = self.tokens.refresh()
                    self.logger(f"[*] token refreshed: {json.dumps(safe_jwt_summary(token))}")
            except Exception as exc:
                self.logger(f"[!] token refresh error: {exc}")
            self.stop_event.wait(self.interval)

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        thread = self.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))

    def is_alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


@dataclass
class ExitNode:
    country: str
    country_name: str
    city: str
    city_name: str
    hostname: str
    port: int = 443
    quarantined: bool = False
    protocols: list[dict] = field(default_factory=list)
    protocol: str = "connect"
    scheme: str = "https"
    locked: bool = False
    supported: bool = True
    unsupported_reason: str | None = None
    record_id: str = ""
    filter_expression: str | None = None
    last_modified: int | None = None
    filter_matched: bool = True

    @property
    def name(self) -> str:
        return f"{self.country}-{self.city}-{self.hostname.split('.')[0]}".lower()

    @property
    def label(self) -> str:
        return f"{self.country_name}/{self.city_name} ({self.hostname})"

    @property
    def stable_id(self) -> str:
        record = self.record_id or "record"
        return (
            f"{record}:{self.country.upper()}:{self.city.upper()}:"
            f"{self.hostname.lower()}:{self.port}:{self.protocol.lower()}"
        )


def _firefox_version_key(value: str) -> tuple[tuple[int, ...], int, int]:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+)?)?\s*", value, re.I)
    if not match:
        raise ValueError(f"unsupported Firefox version: {value!r}")
    numbers = tuple(int(part) for part in match.group(1).split("."))
    qualifier = (match.group(2) or "").lower()
    rank = {"a": 0, "b": 1, "rc": 2, "": 3}[qualifier]
    qualifier_number = int(match.group(3) or 0)
    return numbers, rank, qualifier_number


def compare_firefox_versions(left: str, right: str) -> int:
    left_numbers, left_rank, left_pre = _firefox_version_key(left)
    right_numbers, right_rank, right_pre = _firefox_version_key(right)
    width = max(len(left_numbers), len(right_numbers))
    left_numbers += (0,) * (width - len(left_numbers))
    right_numbers += (0,) * (width - len(right_numbers))
    left_key = (left_numbers, left_rank, left_pre)
    right_key = (right_numbers, right_rank, right_pre)
    return (left_key > right_key) - (left_key < right_key)


_VERSION_FILTER = re.compile(
    r'^env\.version\|versionCompare\("([0-9A-Za-z.]+)"\)\s*(>=|<=|==|!=|>|<)\s*0$'
)
_COUNTRY_FILTER = re.compile(r'^env\.country\s*(==|!=)\s*"([A-Za-z]{2,3})"$')


def evaluate_filter_expression(
    expression: str | None,
    firefox_version: str = DEFAULT_FIREFOX_VERSION,
    client_country: str = "",
) -> bool:
    """Evaluate the small, known-safe JEXL subset used by vpn-serverlist."""
    if not expression or not expression.strip():
        return True
    for term in (part.strip() for part in expression.split("&&")):
        version_match = _VERSION_FILTER.fullmatch(term)
        if version_match:
            comparison = compare_firefox_versions(firefox_version, version_match.group(1))
            operator = version_match.group(2)
            result = {
                ">=": comparison >= 0,
                "<=": comparison <= 0,
                "==": comparison == 0,
                "!=": comparison != 0,
                ">": comparison > 0,
                "<": comparison < 0,
            }[operator]
        else:
            country_match = _COUNTRY_FILTER.fullmatch(term)
            if country_match:
                operator, expected = country_match.groups()
                equal = client_country.upper() == expected.upper()
                result = equal if operator == "==" else not equal
            else:
                warnings.warn(
                    f"unsupported vpn-serverlist filter expression; record ignored: {term!r}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                return False
        if not result:
            return False
    return True


def _select_server_protocol(server: dict) -> tuple[str, int, str, str, bool, str | None]:
    hostname = str(server.get("hostname") or "").strip()
    try:
        port = int(server.get("port") or 443)
    except (TypeError, ValueError):
        port = 0
    protocols = server.get("protocols") or []
    if not protocols:
        return hostname, port, "connect", "https", True, None

    normalized: list[tuple[str, dict]] = []
    for item in protocols:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("protocol") or "").lower()
        if name:
            normalized.append((name, item))
    for name, item in normalized:
        if name != "connect":
            continue
        selected_host = str(item.get("host") or item.get("hostname") or hostname).strip()
        try:
            selected_port = int(item.get("port") or port or 443)
        except (TypeError, ValueError):
            selected_port = 0
        scheme = str(item.get("scheme") or "https").lower()
        if scheme != "https":
            return selected_host, selected_port, name, scheme, False, f"unsupported CONNECT scheme: {scheme}"
        return selected_host, selected_port, name, scheme, True, None

    name, item = normalized[0] if normalized else ("unknown", {})
    selected_host = str(item.get("host") or item.get("hostname") or hostname).strip()
    try:
        selected_port = int(item.get("port") or port or 443)
    except (TypeError, ValueError):
        selected_port = 0
    scheme = str(item.get("scheme") or "https").lower()
    return (
        selected_host,
        selected_port,
        name,
        scheme,
        False,
        f"unsupported upstream protocol chain (first available: {name})",
    )


def parse_serverlist(
    data: dict | list,
    firefox_version: str = DEFAULT_FIREFOX_VERSION,
    client_country: str = "",
    include_locked: bool = False,
) -> list[ExitNode]:
    records = data.get("data", data) if isinstance(data, dict) else data
    if not isinstance(records, list):
        raise ValueError("vpn-serverlist data must be a list")
    nodes: list[ExitNode] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        code = str(record.get("code") or "?").upper()
        cname = str(record.get("name") or code)
        expression = record.get("filter_expression")
        eligible = evaluate_filter_expression(expression, firefox_version, client_country)
        record_locked = bool(record.get("locked")) or not eligible
        if record_locked and not include_locked:
            continue
        for city in record.get("cities") or []:
            if not isinstance(city, dict):
                continue
            city_code = str(city.get("code") or "?")
            city_name = str(city.get("name") or city_code)
            city_locked = record_locked or bool(city.get("locked"))
            if city_locked and not include_locked:
                continue
            for server in city.get("servers") or []:
                if not isinstance(server, dict) or bool(server.get("quarantined")):
                    continue
                server_locked = city_locked or bool(server.get("locked"))
                if server_locked and not include_locked:
                    continue
                hostname, port, protocol, scheme, supported, reason = _select_server_protocol(server)
                if not hostname or not 1 <= port <= 65535:
                    continue
                try:
                    normalized_hostname, _ = parse_authority(format_authority(hostname, port))
                    hostname = normalized_hostname
                except ValueError:
                    warnings.warn(
                        f"invalid vpn-serverlist hostname ignored: {hostname!r}",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                    continue
                record_id = str(record.get("id") or "")
                identity = f"{record_id}:{code}:{city_code}:{hostname}:{port}:{protocol}"
                if identity in seen:
                    continue
                seen.add(identity)
                nodes.append(
                    ExitNode(
                        country=code,
                        country_name=cname,
                        city=city_code,
                        city_name=city_name,
                        hostname=hostname,
                        port=port,
                        quarantined=False,
                        protocols=list(server.get("protocols") or []),
                        protocol=protocol,
                        scheme=scheme,
                        locked=server_locked,
                        supported=supported,
                        unsupported_reason=reason,
                        record_id=record_id,
                        filter_expression=str(expression) if expression else None,
                        last_modified=record.get("last_modified"),
                        filter_matched=eligible,
                    )
                )
    return nodes


def _load_json_file(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _serverlist_snapshot(nodes: Iterable[ExitNode]) -> dict[str, dict]:
    return {
        node.stable_id: {
            "country": node.country,
            "city": node.city,
            "hostname": node.hostname,
            "port": node.port,
            "protocol": node.protocol,
            "scheme": node.scheme,
            "locked": node.locked,
            "supported": node.supported,
        }
        for node in nodes
    }


def fetch_serverlist(
    url: str = DEFAULT_RS,
    force: bool = False,
    firefox_version: str = DEFAULT_FIREFOX_VERSION,
    client_country: str = "",
    include_locked: bool = False,
) -> list[ExitNode]:
    """Fetch Remote Settings with ETag and last-known-good cache fallback."""
    ensure_dirs()
    cached = _load_json_file(SERVERLIST_CACHE)
    metadata = _load_json_file(SERVERLIST_META)
    if not isinstance(metadata, dict):
        metadata = {}

    def parse_and_validate(raw: dict | list | None) -> list[ExitNode]:
        if raw is None:
            raise ValueError("no cached vpn-serverlist")
        parsed = parse_serverlist(raw, firefox_version, client_country, include_locked)
        if not any(node.supported and not node.locked for node in parsed):
            raise ValueError("vpn-serverlist contains no usable CONNECT nodes")
        return parsed

    if cached is not None and not force:
        fetched_at = float(metadata.get("fetched_at") or SERVERLIST_CACHE.stat().st_mtime)
        if time.time() - fetched_at < 3600:
            try:
                return parse_and_validate(cached)
            except ValueError:
                pass

    headers = {"User-Agent": "firefox-ip-protection-pool/2.0"}
    if metadata.get("etag"):
        headers["If-None-Match"] = str(metadata["etag"])
    request = urllib.request.Request(url, headers=headers)
    downloaded: dict | list | None = None
    response_headers = None
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_headers = response.headers
            downloaded = json.loads(response.read().decode("utf-8"))
            nodes = parse_and_validate(downloaded)
    except urllib.error.HTTPError as exc:
        if exc.code != 304:
            if cached is None:
                raise
            nodes = parse_and_validate(cached)
            warnings.warn(f"vpn-serverlist fetch failed (HTTP {exc.code}); using last-known-good cache")
            return nodes
        nodes = parse_and_validate(cached)
        metadata["fetched_at"] = time.time()
        metadata["not_modified_at"] = time.time()
        atomic_write_text(SERVERLIST_META, json.dumps(metadata, indent=2) + "\n")
        return nodes
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        if cached is None:
            raise
        nodes = parse_and_validate(cached)
        warnings.warn(f"vpn-serverlist fetch/validation failed ({type(exc).__name__}); using last-known-good cache")
        return nodes

    old_snapshot = metadata.get("snapshot") if isinstance(metadata.get("snapshot"), dict) else {}
    new_snapshot = _serverlist_snapshot(nodes)
    old_keys, new_keys = set(old_snapshot), set(new_snapshot)
    changed = sorted(key for key in old_keys & new_keys if old_snapshot[key] != new_snapshot[key])
    now = time.time()
    new_metadata = {
        "version": 1,
        "url": url,
        "etag": response_headers.get("ETag") if response_headers else None,
        "last_modified": response_headers.get("Last-Modified") if response_headers else None,
        "fetched_at": now,
        "last_successful_parse": now,
        "firefox_version": firefox_version,
        "client_country": client_country,
        "snapshot": new_snapshot,
        "diff": {
            "added": sorted(new_keys - old_keys),
            "removed": sorted(old_keys - new_keys),
            "changed": changed,
        },
    }
    atomic_write_text(SERVERLIST_CACHE, json.dumps(downloaded, indent=2, ensure_ascii=False) + "\n")
    atomic_write_text(SERVERLIST_META, json.dumps(new_metadata, indent=2, ensure_ascii=False) + "\n")
    return nodes


class PortMap:
    """Persist node/listener assignments so Remote Settings reordering is harmless."""

    def __init__(self, path: Path, socks_base: int, http_base: int) -> None:
        self.path = path
        self.socks_base = socks_base
        self.http_base = http_base

    def _load(self) -> dict[str, dict]:
        payload = _load_json_file(self.path)
        if not isinstance(payload, dict):
            return {}
        if (
            payload.get("version") != 1
            or payload.get("socks_base") != self.socks_base
            or payload.get("http_base") != self.http_base
            or not isinstance(payload.get("assignments"), dict)
        ):
            return {}
        valid: dict[str, dict] = {}
        used_socks: set[int] = set()
        used_http: set[int] = set()
        for stable_id, entry in payload["assignments"].items():
            if not isinstance(entry, dict):
                continue
            try:
                socks, http = int(entry["socks"]), int(entry["http"])
            except (KeyError, TypeError, ValueError):
                continue
            if (
                not self.socks_base <= socks <= 65535
                or not self.http_base <= http <= 65535
                or socks in used_socks
                or http in used_http
            ):
                continue
            used_socks.add(socks)
            used_http.add(http)
            valid[str(stable_id)] = dict(entry, socks=socks, http=http)
        return valid

    def _migrate_legacy(self, nodes: list[ExitNode]) -> dict[str, dict]:
        if self.path != PORT_MAP_FILE:
            return {}
        legacy = _load_json_file(EXPORT / "pool.json")
        if not isinstance(legacy, list):
            return {}
        by_host = {node.hostname: node for node in nodes}
        migrated: dict[str, dict] = {}
        for item in legacy:
            if not isinstance(item, dict) or item.get("hostname") not in by_host:
                continue
            node = by_host[str(item["hostname"])]
            try:
                _, socks = parse_authority(str(item.get("socks") or ""))
                _, http = parse_authority(str(item.get("http") or ""))
            except ValueError:
                continue
            if socks < self.socks_base or http < self.http_base:
                continue
            migrated[node.stable_id] = self._entry(node, socks, http)
        return migrated

    @staticmethod
    def _entry(node: ExitNode, socks: int, http: int) -> dict:
        return {
            "socks": socks,
            "http": http,
            "country": node.country,
            "city": node.city,
            "hostname": node.hostname,
            "record_id": node.record_id,
        }

    def assign(self, nodes: Iterable[ExitNode]) -> dict[str, tuple[int, int]]:
        materialized = list(nodes)
        assignments = self._load()
        if not assignments:
            assignments = self._migrate_legacy(materialized)
        used_socks = {int(entry["socks"]) for entry in assignments.values()}
        used_http = {int(entry["http"]) for entry in assignments.values()}

        def next_free(base: int, used: set[int]) -> int:
            value = base
            while value in used and value <= 65535:
                value += 1
            if value > 65535:
                raise RuntimeError("listener port range exhausted")
            used.add(value)
            return value

        result: dict[str, tuple[int, int]] = {}
        for node in materialized:
            entry = assignments.get(node.stable_id)
            if entry is None:
                identity_matches = [
                    (key, old)
                    for key, old in assignments.items()
                    if old.get("country") == node.country and old.get("city") == node.city
                ]
                if len(identity_matches) == 1 and identity_matches[0][0] not in result:
                    old_key, entry = identity_matches[0]
                    assignments.pop(old_key, None)
                    assignments[node.stable_id] = entry
                else:
                    entry = self._entry(
                        node,
                        next_free(self.socks_base, used_socks),
                        next_free(self.http_base, used_http),
                    )
                    assignments[node.stable_id] = entry
            entry.update(
                country=node.country,
                city=node.city,
                hostname=node.hostname,
                record_id=node.record_id,
            )
            result[node.stable_id] = (int(entry["socks"]), int(entry["http"]))

        payload = {
            "version": 1,
            "socks_base": self.socks_base,
            "http_base": self.http_base,
            "assignments": assignments,
        }
        atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        return result


def relay(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            r, _, x = select.select(sockets, [], sockets, 300)
            if x or not r:
                break
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


class FastlyConnectClient:
    def __init__(self, tokens: TokenStore, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.tokens = tokens
        self.ssl_ctx = ssl_ctx or ssl.create_default_context()

    def open_tunnel(
        self,
        exit_host: str,
        exit_port: int,
        dest_host: str,
        dest_port: int,
        timeout: float = 20.0,
        _retry: bool = True,
    ) -> socket.socket:
        token = self.tokens.ensure()
        # CONNECT target: host:port (IPv6 as [addr]:port)
        if ":" in dest_host and not dest_host.startswith("["):
            try:
                socket.inet_pton(socket.AF_INET6, dest_host)
                target = f"[{dest_host}]:{dest_port}"
            except OSError:
                target = f"{dest_host}:{dest_port}"
        else:
            target = f"{dest_host}:{dest_port}"

        raw = socket.create_connection((exit_host, exit_port), timeout=timeout)
        try:
            ssock = self.ssl_ctx.wrap_socket(raw, server_hostname=exit_host)
        except Exception:
            raw.close()
            raise
        ssock.settimeout(timeout)
        req = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Bearer {token}\r\n"
            f"\r\n"
        ).encode("ascii", "strict")
        try:
            ssock.sendall(req)
            buf = recv_until(ssock, b"\r\n\r\n", max_size=65536)
        except Exception:
            try:
                ssock.close()
            except OSError:
                pass
            raise
        status = buf.split(b"\r\n", 1)[0]
        ok = b" 200 " in status or status.endswith(b" 200") or status.upper().startswith(b"HTTP/1.1 200")
        if not ok:
            try:
                ssock.close()
            except OSError:
                pass
            status_code = 0
            try:
                status_code = int(status.split()[1])
            except (IndexError, ValueError):
                pass
            if _retry and status_code in {401, 403, 407}:
                try:
                    self.tokens.refresh(force=True, rejected_token=token)
                    return self.open_tunnel(
                        exit_host, exit_port, dest_host, dest_port, timeout, _retry=False
                    )
                except Exception:
                    pass
            if status_code == 403:
                raise OSError(f"upstream entitlement rejected via {exit_host} (HTTP 403)")
            raise OSError(f"upstream CONNECT failed via {exit_host}: HTTP {status_code or 'invalid'}")
        ssock.settimeout(None)
        return ssock


def socks5_auth_ok(client: socket.socket, username: str | None, password: str | None) -> bool:
    """Consume SOCKS5 greeting methods and optionally do user/pass auth."""
    try:
        head = recv_exact(client, 2)
    except OSError:
        return False
    if head[0] != 5:
        return False
    nmethods = head[1]
    try:
        methods = set(recv_exact(client, nmethods)) if nmethods else set()
    except OSError:
        return False
    if username is not None or password is not None:
        if not username or not password:
            try:
                client.sendall(b"\x05\xff")
            except OSError:
                pass
            return False
        if 2 not in methods:
            try:
                client.sendall(b"\x05\xff")
            except OSError:
                pass
            return False
        try:
            client.sendall(b"\x05\x02")
            ver_ulen = recv_exact(client, 2)
            if ver_ulen[0] != 1:
                return False
            ulen = ver_ulen[1]
            uname = recv_exact(client, ulen).decode("utf-8", "ignore") if ulen else ""
            plen = recv_exact(client, 1)[0]
            passwd = recv_exact(client, plen).decode("utf-8", "ignore") if plen else ""
        except OSError:
            return False
        credentials_match = hmac.compare_digest(uname, username) and hmac.compare_digest(
            passwd, password
        )
        if credentials_match:
            try:
                client.sendall(b"\x01\x00")
            except OSError:
                return False
            return True
        try:
            client.sendall(b"\x01\x01")
        except OSError:
            pass
        return False
    if 0 not in methods:
        try:
            client.sendall(b"\x05\xff")
        except OSError:
            pass
        return False
    try:
        client.sendall(b"\x05\x00")
    except OSError:
        return False
    return True


def socks5_read_connect(client: socket.socket) -> tuple[str, int] | None:
    try:
        req = recv_exact(client, 4)
    except OSError:
        return None
    if req[0] != 5:
        return None
    if req[1] != 1:
        try:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        return None
    atyp = req[3]
    try:
        if atyp == 1:
            dst_host = socket.inet_ntoa(recv_exact(client, 4))
        elif atyp == 3:
            ln = recv_exact(client, 1)[0]
            if not ln:
                return None
            raw_host = recv_exact(client, ln)
            try:
                dst_host = raw_host.decode("utf-8")
                dst_host, _ = parse_authority(dst_host, default_port=1)
            except (UnicodeDecodeError, ValueError):
                return None
        elif atyp == 4:
            dst_host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return None
        dst_port = struct.unpack("!H", recv_exact(client, 2))[0]
    except OSError:
        return None
    if not dst_host or dst_port <= 0:
        return None
    return dst_host, dst_port


class Socks5BackendHandler(socketserver.BaseRequestHandler):
    exit_node: ExitNode
    connector: FastlyConnectClient
    auth_user: str | None = None
    auth_pass: str | None = None

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(30)
        try:
            if not socks5_auth_ok(client, self.auth_user, self.auth_pass):
                return
            target = socks5_read_connect(client)
            if not target:
                return
            dst_host, dst_port = target
            remote = self.connector.open_tunnel(
                self.exit_node.hostname, self.exit_node.port, dst_host, dst_port
            )
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            relay(client, remote)
        except Exception:
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass


class ThreadedSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def http_proxy_authorized(handler: BaseHTTPRequestHandler, user: str | None, password: str | None) -> bool:
    if user is None and password is None:
        return True
    if not user or not password:
        return False
    hdr = handler.headers.get("Proxy-Authorization") or ""
    if not hdr.lower().startswith("basic "):
        return False
    try:
        raw = base64.b64decode(hdr.split(" ", 1)[1], validate=True).decode("utf-8")
        u, separator, p = raw.partition(":")
        return bool(separator) and hmac.compare_digest(u, user) and hmac.compare_digest(p, password)
    except Exception:
        return False


class HTTPProxyHandler(BaseHTTPRequestHandler):
    exit_node: ExitNode
    connector: FastlyConnectClient
    auth_user: str | None = None
    auth_pass: str | None = None
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _require_auth(self) -> bool:
        if http_proxy_authorized(self, self.auth_user, self.auth_pass):
            return True
        self.send_response(407, "Proxy Authentication Required")
        self.send_header("Proxy-Authenticate", 'Basic realm="ipp-pool"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_CONNECT(self) -> None:  # noqa: N802
        if not self._require_auth():
            return
        try:
            host, port = parse_authority(self.path, default_port=443)
            remote = self.connector.open_tunnel(
                self.exit_node.hostname, self.exit_node.port, host, port
            )
            self.send_response(200, "Connection Established")
            self.send_header("Proxy-Agent", "firefox-ip-protection-pool")
            self.end_headers()
            self.connection.settimeout(None)
            relay(self.connection, remote)
        except Exception as e:
            try:
                self.send_error(502, f"upstream failed: {e}")
            except Exception:
                pass

    def do_GET(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy_http()

    def _proxy_http(self) -> None:
        if not self._require_auth():
            return
        try:
            prepared = _prepare_forward_request(self)
        except NotImplementedError as exc:
            self.send_error(501, str(exc))
            return
        except ValueError as exc:
            self.send_error(400, str(exc))
            return
        try:
            _forward_http(self, self.connector, self.exit_node, prepared)
        except Exception:
            self.send_error(502, "upstream connection failed")


class ThreadedHTTPProxy(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(30)
        return request, client_address

    def handle_error(self, request, client_address) -> None:
        # Remote scanners and early disconnects are normal for an internet-facing proxy.
        return


class BackendPool:
    def __init__(self, nodes: list[ExitNode], mode: str = "rr") -> None:
        if mode not in {"rr", "random"}:
            raise ValueError(f"unsupported rotation mode: {mode}")
        self.nodes = nodes
        self.mode = mode
        self._idx = 0
        self._node_idx: dict[str, int] = {}
        self._lock = threading.Lock()

        self._countries: list[str] = []
        self._by_country: dict[str, list[ExitNode]] = {}
        for node in nodes:
            country = node.country.upper()
            if country not in self._by_country:
                self._countries.append(country)
                self._by_country[country] = []
                self._node_idx[country] = 0
            self._by_country[country].append(node)

    def next(self) -> ExitNode:
        return self.candidates(attempts=1)[0]

    def candidates(self, attempts: int | None = None) -> list[ExitNode]:
        with self._lock:
            if not self.nodes:
                raise RuntimeError("no backends")
            count = len(self.nodes) if attempts is None else min(len(self.nodes), attempts)
            if count <= 0:
                return []
            if self.mode == "random":
                countries = random.sample(self._countries, len(self._countries))
            else:
                start = self._idx % len(self._countries)
                countries = [
                    self._countries[(start + offset) % len(self._countries)]
                    for offset in range(len(self._countries))
                ]
            # Advance the aggregate primary once per client request. Countries,
            # not raw node counts, receive equal primary selection weight.
            self._idx += 1

            result: list[ExitNode] = []
            used: set[str] = set()
            for country in countries:
                group = self._by_country[country]
                if self.mode == "random":
                    node = random.choice(group)
                else:
                    node_index = self._node_idx[country] % len(group)
                    node = group[node_index]
                    self._node_idx[country] += 1
                result.append(node)
                used.add(node.stable_id)
                if len(result) == count:
                    return result

            # If fewer countries than the retry budget exist, fill remaining
            # slots with other unique nodes without changing country primaries.
            remaining = [node for node in self.nodes if node.stable_id not in used]
            if self.mode == "random":
                random.shuffle(remaining)
            result.extend(remaining[: count - len(result)])
            return result


class RotatingSocksHandler(socketserver.BaseRequestHandler):
    pool: BackendPool
    connector: FastlyConnectClient
    auth_user: str | None = None
    auth_pass: str | None = None

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(30)
        try:
            if not socks5_auth_ok(client, self.auth_user, self.auth_pass):
                return
            target = socks5_read_connect(client)
            if not target:
                return
            dst_host, dst_port = target
            remote = None
            for node in self.pool.candidates(attempts=3):
                try:
                    remote = self.connector.open_tunnel(node.hostname, node.port, dst_host, dst_port)
                    break
                except (OSError, TimeoutError):
                    continue
            if remote is None:
                raise OSError("all rotator backends failed")
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            relay(client, remote)
        except Exception:
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass



class RotatingHTTPHandler(BaseHTTPRequestHandler):
    pool: BackendPool
    connector: FastlyConnectClient
    auth_user: str | None = None
    auth_pass: str | None = None
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _require_auth(self) -> bool:
        if http_proxy_authorized(self, self.auth_user, self.auth_pass):
            return True
        self.send_response(407, "Proxy Authentication Required")
        self.send_header("Proxy-Authenticate", 'Basic realm="ipp-pool"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_CONNECT(self) -> None:  # noqa: N802
        if not self._require_auth():
            return
        try:
            host, port = parse_authority(self.path, default_port=443)
            remote = None
            for node in self.pool.candidates(attempts=3):
                try:
                    remote = self.connector.open_tunnel(node.hostname, node.port, host, port)
                    break
                except (OSError, TimeoutError):
                    continue
            if remote is None:
                raise OSError("all rotator backends failed")
            self.send_response(200, "Connection Established")
            self.send_header("Proxy-Agent", "firefox-ip-protection-pool")
            self.end_headers()
            self.connection.settimeout(None)
            relay(self.connection, remote)
        except Exception as e:
            try:
                self.send_error(502, f"upstream failed: {e}")
            except Exception:
                pass

    def do_GET(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy_http()

    def _proxy_http(self) -> None:
        if not self._require_auth():
            return
        try:
            prepared = _prepare_forward_request(self)
        except NotImplementedError as exc:
            self.send_error(501, str(exc))
            return
        except ValueError as exc:
            self.send_error(400, str(exc))
            return
        last_error: Exception | None = None
        for node in self.pool.candidates(attempts=3):
            try:
                _forward_http(self, self.connector, node, prepared)
                return
            except ForwardRequestError as exc:
                # The request may already have reached the destination. Never
                # replay it through another backend.
                last_error = exc
                break
            except (OSError, TimeoutError) as exc:
                last_error = exc
        self.send_error(502, f"all rotator backends failed: {type(last_error).__name__}")


@dataclass
class RunningNode:
    node: ExitNode
    socks: str | None
    http: str | None
    socks_server: ThreadedSocksServer | None = None
    http_server: ThreadedHTTPProxy | None = None
    socks_thread: threading.Thread | None = None
    http_thread: threading.Thread | None = None


class Pool:
    def __init__(
        self,
        tokens: TokenStore,
        nodes: list[ExitNode],
        bind: str = DEFAULT_BIND,
        socks_base: int = DEFAULT_SOCKS_BASE,
        http_base: int = DEFAULT_HTTP_BASE,
        enable_socks: bool = True,
        enable_http: bool = True,
        auth_user: str | None = None,
        auth_pass: str | None = None,
        advertise_host: str | None = None,
        port_map_file: Path = PORT_MAP_FILE,
        include_locked: bool = False,
    ) -> None:
        self.tokens = tokens
        self.nodes = nodes
        self.bind = bind
        self.socks_base = socks_base
        self.http_base = http_base
        self.enable_socks = enable_socks
        self.enable_http = enable_http
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.advertise_host = advertise_host or bind
        self.port_map_file = port_map_file
        self.include_locked = include_locked
        self.connector = FastlyConnectClient(tokens)
        self.running: list[RunningNode] = []
        self.rotator_socks: str | None = None
        self.rotator_http: str | None = None
        self.rotator_socks_mode: str | None = None
        self.rotator_http_mode: str | None = None
        # Keep ownership of the front-door servers in the Pool so shutdown
        # can close their listening sockets as well as the per-node servers.
        self.rotator_socks_server: ThreadedSocksServer | None = None
        self.rotator_http_server: ThreadedHTTPProxy | None = None
        self.rotator_socks_thread: threading.Thread | None = None
        self.rotator_http_thread: threading.Thread | None = None
        self.refresh_worker: TokenRefreshWorker | None = None
        self._lifecycle_lock = threading.RLock()
        self._stop = threading.Event()

    def start_refresh_worker(
        self,
        interval: float = 30.0,
        logger=print,
    ) -> TokenRefreshWorker:
        with self._lifecycle_lock:
            if self.refresh_worker is not None:
                raise RuntimeError("token refresh worker is already running")
            if self._stop.is_set():
                raise RuntimeError("cannot start token refresh worker after pool shutdown")
            worker = TokenRefreshWorker(
                self.tokens,
                self._stop,
                interval=interval,
                logger=logger,
            )
            self.refresh_worker = worker
            worker.start()
            return worker

    def _start(
        self,
        limit: int | None = None,
        countries: set[str] | None = None,
        recommended: bool = False,
    ) -> list[RunningNode]:
        selected: list[ExitNode] = []
        eligible = [
            n
            for n in self.nodes
            if not n.quarantined
            and (not n.locked or (self.include_locked and n.filter_matched))
            and n.supported
            and n.protocol == "connect"
        ]
        if countries is not None:
            normalized_countries = {c.upper() for c in countries}
            selected = [n for n in eligible if n.country.upper() in normalized_countries]
        elif recommended:
            selected = [n for n in eligible if n.country.upper() == "REC"]
        else:
            selected = [n for n in eligible if n.country.upper() != "REC"]
        selected.sort(key=lambda node: (node.country.upper(), node.city.upper(), node.stable_id))
        if limit is not None:
            selected = selected[:limit]

        port_map = PortMap(self.port_map_file, self.socks_base, self.http_base)
        assignments = port_map.assign(selected)

        for node in selected:
            rn = RunningNode(node=node, socks=None, http=None)
            socks_port, http_port = assignments[node.stable_id]
            if self.enable_socks:
                port = socks_port
                handler = type(
                    f"Socks_{node.name}",
                    (Socks5BackendHandler,),
                    {
                        "exit_node": node,
                        "connector": self.connector,
                        "auth_user": self.auth_user,
                        "auth_pass": self.auth_pass,
                    },
                )
                try:
                    srv = ThreadedSocksServer((self.bind, port), handler)
                    th = threading.Thread(target=srv.serve_forever, daemon=True, name=f"socks-{node.name}")
                    th.start()
                    rn.socks = f"{self.advertise_host}:{port}"
                    rn.socks_server = srv
                    rn.socks_thread = th
                except OSError as e:
                    print(f"[!] socks bind failed {self.bind}:{port} ({node.name}): {e}")
            if self.enable_http:
                port = http_port
                handler = type(
                    f"HTTP_{node.name}",
                    (HTTPProxyHandler,),
                    {
                        "exit_node": node,
                        "connector": self.connector,
                        "auth_user": self.auth_user,
                        "auth_pass": self.auth_pass,
                    },
                )
                try:
                    srv = ThreadedHTTPProxy((self.bind, port), handler)
                    th = threading.Thread(target=srv.serve_forever, daemon=True, name=f"http-{node.name}")
                    th.start()
                    rn.http = f"{self.advertise_host}:{port}"
                    rn.http_server = srv
                    rn.http_thread = th
                except OSError as e:
                    print(f"[!] http bind failed {self.bind}:{port} ({node.name}): {e}")
            if rn.socks or rn.http:
                self.running.append(rn)
                print(
                    f"[+] {node.name:28} socks={rn.socks or '-':24} http={rn.http or '-':24} {node.label}"
                )
        self.export()
        return self.running

    def start(
        self,
        limit: int | None = None,
        countries: set[str] | None = None,
        recommended: bool = False,
    ) -> list[RunningNode]:
        return self._start(limit=limit, countries=countries, recommended=recommended)

    def start_rotator(self, listen: str = DEFAULT_ROTATOR, mode: str = "random") -> ThreadedSocksServer:
        with self._lifecycle_lock:
            if self.rotator_socks_server is not None:
                raise RuntimeError("SOCKS rotator is already running")
            host, port = parse_authority(listen)
            nodes = [rn.node for rn in self.running if rn.node.country.upper() != "REC"]
            if not nodes:
                raise RuntimeError("cannot start rotator without running backends")
            pool = BackendPool(nodes, mode=mode)
            handler = type(
                "Rot",
                (RotatingSocksHandler,),
                {
                    "pool": pool,
                    "connector": self.connector,
                    "auth_user": self.auth_user,
                    "auth_pass": self.auth_pass,
                },
            )
            srv = ThreadedSocksServer((host, port), handler)
            adv = (
                f"{self.advertise_host}:{port}"
                if host in {"0.0.0.0", "::"}
                else format_authority(host, port)
            )
            th: threading.Thread | None = None
            try:
                th = threading.Thread(target=srv.serve_forever, daemon=True, name="rotator-socks")
                # Publish ownership before starting the thread so a signal
                # arriving during startup can still close this listener.
                self.rotator_socks_server = srv
                self.rotator_socks_thread = th
                self.rotator_socks = adv
                self.rotator_socks_mode = mode
                th.start()
                # Pool.start() runs before rotators are created. Refresh the
                # export now so public_endpoints.txt contains this listener.
                self.export()
            except Exception:
                self._close_server(srv, th)
                self.rotator_socks_server = None
                self.rotator_socks_thread = None
                self.rotator_socks = None
                self.rotator_socks_mode = None
                raise
            print(f"[*] rotator SOCKS5 on {listen} advertise={adv} backends={len(nodes)} mode={mode}")
            return srv

    def start_http_rotator(self, listen: str = DEFAULT_HTTP_ROTATOR, mode: str = "random") -> ThreadedHTTPProxy:
        with self._lifecycle_lock:
            if self.rotator_http_server is not None:
                raise RuntimeError("HTTP rotator is already running")
            host, port = parse_authority(listen)
            nodes = [rn.node for rn in self.running if rn.node.country.upper() != "REC"]
            if not nodes:
                raise RuntimeError("cannot start rotator without running backends")
            pool = BackendPool(nodes, mode=mode)
            handler = type(
                "RotHTTP",
                (RotatingHTTPHandler,),
                {
                    "pool": pool,
                    "connector": self.connector,
                    "auth_user": self.auth_user,
                    "auth_pass": self.auth_pass,
                },
            )
            srv = ThreadedHTTPProxy((host, port), handler)
            adv = (
                f"{self.advertise_host}:{port}"
                if host in {"0.0.0.0", "::"}
                else format_authority(host, port)
            )
            th: threading.Thread | None = None
            try:
                th = threading.Thread(target=srv.serve_forever, daemon=True, name="rotator-http")
                # Publish ownership before starting the thread for signal
                # safety during the startup window.
                self.rotator_http_server = srv
                self.rotator_http_thread = th
                self.rotator_http = adv
                self.rotator_http_mode = mode
                th.start()
                # Keep the exported front-door list in sync with the live
                # listener; Pool.start() exported before this method ran.
                self.export()
            except Exception:
                self._close_server(srv, th)
                self.rotator_http_server = None
                self.rotator_http_thread = None
                self.rotator_http = None
                self.rotator_http_mode = None
                raise
            print(f"[*] rotator HTTP on {listen} advertise={adv} backends={len(nodes)} mode={mode}")
            return srv

    def export(self) -> None:
        ensure_dirs()
        socks_lines, http_lines, socks_urls, http_urls = [], [], [], []
        meta = []
        auth_prefix = ""
        if self.auth_user and self.auth_pass:
            auth_prefix = f"{quote(self.auth_user, safe='')}:{quote(self.auth_pass, safe='')}@"
        for rn in self.running:
            if rn.socks:
                socks_lines.append(rn.socks)
                socks_urls.append(f"socks5h://{auth_prefix}{rn.socks}")
            if rn.http:
                http_lines.append(rn.http)
                http_urls.append(f"http://{auth_prefix}{rn.http}")
            meta.append(
                {
                    "name": rn.node.name,
                    "country": rn.node.country,
                    "city": rn.node.city,
                    "hostname": rn.node.hostname,
                    "port": rn.node.port,
                    "record_id": rn.node.record_id,
                    "protocol": rn.node.protocol,
                    "scheme": rn.node.scheme,
                    "locked": rn.node.locked,
                    "supported": rn.node.supported,
                    "socks": rn.socks,
                    "http": rn.http,
                    "label": rn.node.label,
                }
            )
        atomic_write_text(EXPORT / "socks5.txt", "\n".join(socks_lines) + ("\n" if socks_lines else ""))
        atomic_write_text(EXPORT / "http.txt", "\n".join(http_lines) + ("\n" if http_lines else ""))
        atomic_write_text(
            EXPORT / "socks5_urls.txt",
            "\n".join(socks_urls) + ("\n" if socks_urls else ""),
            mode=0o600 if auth_prefix else 0o644,
        )
        atomic_write_text(
            EXPORT / "http_urls.txt",
            "\n".join(http_urls) + ("\n" if http_urls else ""),
            mode=0o600 if auth_prefix else 0o644,
        )
        atomic_write_text(EXPORT / "pool.json", json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
        lines = [f"public_ip_or_host={self.advertise_host}"]
        if self.rotator_socks:
            aggregate_socks = f"socks5h://{auth_prefix}{self.rotator_socks}"
            lines.extend(
                [
                    f"aggregate_socks5={aggregate_socks}",
                    f"aggregate_socks5_mode={self.rotator_socks_mode or ''}",
                ]
            )
            if self.rotator_socks_mode == "random":
                lines.append(f"aggregate_random_socks5={aggregate_socks}")
            # Keep the historical key for existing consumers.
            lines.append(f"rotator_socks5={aggregate_socks}")
        if self.rotator_http:
            aggregate_http = f"http://{auth_prefix}{self.rotator_http}"
            lines.extend(
                [
                    f"aggregate_http={aggregate_http}",
                    f"aggregate_http_mode={self.rotator_http_mode or ''}",
                ]
            )
            if self.rotator_http_mode == "random":
                lines.append(f"aggregate_random_http={aggregate_http}")
            # Keep the historical key for existing consumers.
            lines.append(f"rotator_http={aggregate_http}")
        lines.extend(
            [
                f"auth_user={self.auth_user or ''}",
                f"auth_pass={self.auth_pass or ''}",
                "",
                "# per-country socks:",
                *socks_urls,
                "",
                "# per-country http:",
                *http_urls,
                "",
            ]
        )
        atomic_write_text(
            EXPORT / "public_endpoints.txt",
            "\n".join(
                lines
            ),
            mode=0o600 if auth_prefix else 0o644,
        )
        print(f"[*] exported {len(meta)} nodes → {EXPORT}")

    @staticmethod
    def _close_server(
        srv: socketserver.BaseServer | None,
        thread: threading.Thread | None = None,
    ) -> None:
        """Stop a listener and always release its bound socket."""
        if srv is None:
            return
        # BaseServer.shutdown() waits for serve_forever() and deadlocks when
        # a thread failed before entering that loop. In that case closing the
        # socket is sufficient; a live serving thread still gets a graceful
        # shutdown first.
        serving = True
        # CPython's BaseServer marks this event set until serve_forever has
        # entered its loop (and again after it exits). Reading it avoids a
        # shutdown() deadlock in the small window between Thread.start() and
        # the loop's first instruction.
        loop_event = getattr(srv, "_BaseServer__is_shut_down", None)
        if loop_event is not None:
            try:
                serving = not bool(loop_event.is_set())
            except Exception:
                serving = True
        elif thread is None:
            serving = False
        else:
            try:
                serving = bool(thread.is_alive())
            except Exception:
                # Test doubles and non-standard thread wrappers may not
                # expose is_alive(); retain the historical safe assumption.
                serving = True
        if serving:
            try:
                srv.shutdown()
            except Exception:
                pass
        try:
            srv.server_close()
        except Exception:
            pass
        if thread is not None and thread is not threading.current_thread():
            try:
                thread.join(timeout=2)
            except Exception:
                pass

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            refresh_worker = self.refresh_worker
            self.refresh_worker = None
            # Stop front doors first so no new request can race backend
            # teardown. Clear references before closing for idempotence.
            rotators = [
                (self.rotator_socks_server, self.rotator_socks_thread),
                (self.rotator_http_server, self.rotator_http_thread),
            ]
            self.rotator_socks_server = None
            self.rotator_http_server = None
            self.rotator_socks_thread = None
            self.rotator_http_thread = None
            self.rotator_socks = None
            self.rotator_http = None
            self.rotator_socks_mode = None
            self.rotator_http_mode = None
            running = self.running
            self.running = []
        if refresh_worker is not None:
            refresh_worker.stop()
        for srv, thread in rotators:
            self._close_server(srv, thread)
        for rn in running:
            for srv, thread in (
                (rn.socks_server, rn.socks_thread),
                (rn.http_server, rn.http_thread),
            ):
                self._close_server(srv, thread)



def detect_public_ip() -> str:
    for url in ("https://ifconfig.me", "https://api.ipify.org", "https://ipinfo.io/ip"):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    # fallback local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def build_tokens(args: argparse.Namespace) -> TokenStore:
    ensure_dirs()
    proxy_pass = (
        args.proxy_pass_jwt
        or os.environ.get("IPP_PROXY_PASS_JWT")
        or load_token_file(TOKENS / "proxy_pass.jwt")
    )
    fxa = (
        args.fxa_token
        or os.environ.get("IPP_FXA_TOKEN")
    )
    return TokenStore(proxy_pass=proxy_pass, fxa_token=fxa, guardian=args.guardian)


def cmd_sync(args: argparse.Namespace) -> int:
    nodes = fetch_serverlist(
        args.serverlist_url,
        force=True,
        firefox_version=args.firefox_version,
        client_country=args.client_country,
        include_locked=args.include_locked,
    )
    active = [n for n in nodes if not n.quarantined and n.supported and not n.locked]
    print(f"[*] serverlist: {len(nodes)} total, {len(active)} active")
    by: dict[str, int] = {}
    for n in active:
        by[n.country] = by.get(n.country, 0) + 1
    for c, cnt in sorted(by.items()):
        print(f"    {c}: {cnt}")
    atomic_write_text(
        EXPORT / "exits.json",
        json.dumps([asdict(n) for n in nodes], indent=2, ensure_ascii=False) + "\n",
    )
    return 0


def cmd_token_status(args: argparse.Namespace) -> int:
    print(json.dumps(build_tokens(args).status(), indent=2, ensure_ascii=False))
    return 0


def cmd_usage(args: argparse.Namespace) -> int:
    ts = build_tokens(args)
    try:
        usage = ts.usage()
    except Exception as exc:
        print(f"[!] usage query failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(usage), indent=2, ensure_ascii=False))
    return 0


def cmd_how_to_token(args: argparse.Namespace) -> int:
    """Print a read-only token acquisition guide without exposing credentials."""
    del args
    print(
        """ProxyPass 凭据说明（本命令不会读取本地凭据）

长期运行请不要手工抓取或定期替换 ProxyPass JWT。推荐流程：
1. 安装 requirements-bootstrap.txt 和 Playwright Firefox。
2. 运行：python3 login_and_bootstrap.py --email you@example.com
3. 在终端完成一次密码、邮箱验证码和可能的 CAPTCHA 交互。
4. 强制验收：python3 refresh_tokens.py --force
5. 检查：python3 ipp_pool.py token-status
6. 常驻运行 ipp_pool.py run；后台 worker 会自动长期续期，无需 cron。

只有临时调试时，才从你自己的 Guardian /api/v1/fpn/token 响应中取出
token 并以 0600 保存到 tokens/proxy_pass.jwt。单独的 ProxyPass 很快到期，
不能用于无人值守部署。不要把 JWT、session、密码或验证码粘贴到日志、
shell 历史、issue 或公共节点列表中。
"""
    )
    return 0


def cmd_token_refresh(args: argparse.Namespace) -> int:
    ts = build_tokens(args)
    try:
        tok = ts.refresh(force=bool(getattr(args, "force", False)))
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    print(f"[+] refreshed ({len(tok)} chars)")
    print(json.dumps(ts.status(), indent=2, ensure_ascii=False))
    return 0


def probe_node(node: ExitNode, connector: FastlyConnectClient) -> str:
    """Fetch a small public egress summary without exposing tokens in argv."""
    remote: socket.socket | None = None
    response: http.client.HTTPResponse | None = None
    try:
        # The proxy hop is already protected by TLS. The probe response only
        # contains public egress metadata, so plain HTTP inside CONNECT avoids
        # unsafe TLS-in-TLS socket wrapping and keeps the token in this process.
        remote = connector.open_tunnel(
            node.hostname,
            node.port,
            "ipinfo.io",
            80,
            timeout=25,
        )
        remote.settimeout(25)
        remote.sendall(
            b"GET /json HTTP/1.1\r\n"
            b"Host: ipinfo.io\r\n"
            b"User-Agent: firefox-ip-protection-pool/2.0\r\n"
            b"Accept: application/json\r\n"
            b"Accept-Encoding: identity\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = http.client.HTTPResponse(remote)
        response.begin()
        if response.status != 200:
            raise OSError(f"probe endpoint returned HTTP {response.status}")
        payload = response.read(MAX_PROBE_RESPONSE + 1)
        if len(payload) > MAX_PROBE_RESPONSE:
            raise OSError("probe response exceeded size limit")
        return payload.decode("utf-8", "strict")
    finally:
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        if remote is not None:
            try:
                remote.close()
            except OSError:
                pass


def cmd_probe(args: argparse.Namespace) -> int:
    ts = build_tokens(args)
    nodes = fetch_serverlist(
        args.serverlist_url,
        force=False,
        firefox_version=args.firefox_version,
        client_country=args.client_country,
        include_locked=args.include_locked,
    )
    if args.country:
        nodes = [
            n
            for n in nodes
            if n.country.upper() == args.country.upper()
            and not n.quarantined
            and n.supported
            and not n.locked
        ]
    else:
        active = [
            n
            for n in nodes
            if not n.quarantined
            and n.supported
            and not n.locked
            and n.country.upper() != "REC"
        ]
        countries = sorted({n.country.upper() for n in active})
        if countries:
            selected_country = random.choice(countries)
            nodes = [n for n in active if n.country.upper() == selected_country]
        else:
            nodes = []
    if not nodes:
        print("[!] no nodes", file=sys.stderr)
        return 1
    node = random.choice(nodes)
    print(f"[*] probing {node.label}")
    try:
        token = ts.ensure()
    except Exception as e:
        print(f"[!] token: {e}", file=sys.stderr)
        return 1
    print(f"[*] proxy_pass: {json.dumps(safe_jwt_summary(token))}")
    try:
        out = probe_node(node, FastlyConnectClient(ts))
    except Exception as e:
        print(f"[!] probe failed: {e}", file=sys.stderr)
        return 1
    try:
        probe_data = json.loads(out)
    except (TypeError, ValueError):
        print(str(out)[:1000])
    else:
        if isinstance(probe_data, dict):
            fields = ("ip", "country", "region", "city", "org")
            print(json.dumps({key: probe_data.get(key) for key in fields if key in probe_data}, ensure_ascii=False))
        else:
            print(str(out)[:1000])
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    countries: set[str] | None = None
    if args.countries is not None:
        countries = {c.strip().upper() for c in args.countries.split(",") if c.strip()}
        if not countries:
            print("[!] --countries must contain at least one country code", file=sys.stderr)
            return 2
        if args.recommended:
            print("[!] --countries and --recommended cannot be used together", file=sys.stderr)
            return 2
        if "REC" in countries:
            print("[!] REC is not a country; use --recommended instead", file=sys.stderr)
            return 2
    if args.limit is not None and args.limit <= 0:
        print("[!] --limit must be a positive integer", file=sys.stderr)
        return 2
    if args.no_socks and args.no_http:
        print("[!] --no-socks and --no-http cannot be used together", file=sys.stderr)
        return 2
    if args.recommended:
        for option, value in (
            ("--rotator", args.rotator),
            ("--http-rotator", args.http_rotator),
        ):
            if value is not None and not listener_is_disabled(str(value)):
                print(f"[!] {option} is unavailable in independent REC mode", file=sys.stderr)
                return 2

    try:
        bind_host = validate_bind_host(args.bind)
        rotator_listen, rotator_host = resolve_listener(
            "off" if args.recommended else args.rotator,
            bind_host,
            1090,
        )
        http_rotator_listen, http_rotator_host = resolve_listener(
            "off" if args.recommended else args.http_rotator,
            bind_host,
            8080,
        )
    except ValueError as exc:
        print(f"[!] invalid listener configuration: {exc}", file=sys.stderr)
        return 2

    ensure_dirs()
    public_ip = args.advertise_host or os.environ.get("IPP_ADVERTISE_HOST") or args.bind
    auth_user = args.auth_user or os.environ.get("IPP_LISTEN_USER")
    auth_pass = args.auth_pass or os.environ.get("IPP_LISTEN_PASS")
    if not auth_user or not auth_pass:
        auth_file = TOKENS / "proxy_listen_auth.txt"
        fu, fp = parse_listen_auth_file(auth_file)
        auth_user = auth_user or fu
        auth_pass = auth_pass or fp
        if args.require_auth and (not auth_user or not auth_pass):
            auth_user = auth_user or "ipp"
            auth_pass = auth_pass or base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
            atomic_write_text(auth_file, f"USER={auth_user}\nPASS={auth_pass}\n", mode=0o600)

    if (auth_user is None) != (auth_pass is None):
        print("[!] both listen username and password are required", file=sys.stderr)
        return 2
    exposed_listeners = [
        name
        for name, host in (
            ("per-node", bind_host),
            ("SOCKS5 aggregate", rotator_host),
            ("HTTP aggregate", http_rotator_host),
        )
        if host is not None and not is_loopback_bind(host)
    ]
    if exposed_listeners and not (auth_user and auth_pass) and not args.allow_open_proxy:
        print(
            "[!] refusing unauthenticated non-loopback listener(s): "
            + ", ".join(exposed_listeners)
            + "; configure auth or pass --allow-open-proxy",
            file=sys.stderr,
        )
        return 2

    ts = build_tokens(args)
    try:
        tok = ts.ensure()
        print(f"[*] proxy_pass: {json.dumps(safe_jwt_summary(tok))}")
    except Exception as e:
        print(f"[!] token not ready: {e}", file=sys.stderr)
        if not args.allow_no_token:
            return 1

    nodes = fetch_serverlist(
        args.serverlist_url,
        force=args.force_sync,
        firefox_version=args.firefox_version,
        client_country=args.client_country,
        include_locked=args.include_locked,
    )
    pool = Pool(
        tokens=ts,
        nodes=nodes,
        bind=args.bind,
        socks_base=args.socks_base,
        http_base=args.http_base,
        enable_socks=not args.no_socks,
        enable_http=not args.no_http,
        auth_user=auth_user,
        auth_pass=auth_pass,
        advertise_host=public_ip,
        include_locked=args.include_locked,
    )
    pool.start(limit=args.limit, countries=countries, recommended=args.recommended)
    if not pool.running:
        print("[!] no listeners started", file=sys.stderr)
        return 1

    if rotator_host is not None:
        pool.start_rotator(rotator_listen, mode=args.rotate_mode)
    if http_rotator_host is not None:
        pool.start_http_rotator(http_rotator_listen, mode=args.rotate_mode)

    pool.start_refresh_worker()

    print("[*] pool running. Ctrl+C / SIGTERM to stop.")
    print(f"    public host: {public_ip}")
    if auth_user and auth_pass:
        print(f"    auth: configured for user {auth_user!r} (secret omitted)")
        print(f"    example: curl --proxy-user 'USER:PASSWORD' -x socks5h://{public_ip}:{args.socks_base} https://ipinfo.io/json")
        if pool.rotator_socks:
            print(f"    rotator socks: curl --proxy-user 'USER:PASSWORD' -x socks5h://{pool.rotator_socks} https://ipinfo.io/ip")
        if pool.rotator_http:
            print(f"    rotator http : curl --proxy-user 'USER:PASSWORD' -x http://{pool.rotator_http} https://ipinfo.io/ip")
    else:
        print(f"    example: curl -x socks5h://{public_ip}:{args.socks_base} https://ipinfo.io/json")
        print("    WARNING: no auth configured; proxy is intentionally open")
    print(f"    endpoints: {EXPORT / 'public_endpoints.txt'}")

    def _stop(*_a):
        print("\n[*] stopping...")
        pool.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    while True:
        time.sleep(3600)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Firefox IP Protection multi-exit → SOCKS5/HTTP pool")

    def add_common(sp: argparse.ArgumentParser) -> None:
        defaults = argparse.SUPPRESS
        sp.add_argument("--guardian", default=defaults)
        sp.add_argument("--serverlist-url", default=defaults)
        sp.add_argument("--proxy-pass-jwt", default=defaults)
        sp.add_argument("--fxa-token", default=defaults)
        sp.add_argument("--bind", default=defaults, help="listen address (default: 127.0.0.1)")
        sp.add_argument("--advertise-host", default=defaults)
        sp.add_argument("--socks-base", type=int, default=defaults)
        sp.add_argument("--http-base", type=int, default=defaults)
        sp.add_argument("--limit", type=int, default=defaults)
        sp.add_argument("--countries", default=defaults)
        sp.add_argument("--no-socks", action="store_true", default=defaults)
        sp.add_argument("--no-http", action="store_true", default=defaults)
        sp.add_argument("--rotator", default=defaults)
        sp.add_argument("--http-rotator", default=defaults)
        sp.add_argument("--rotate-mode", choices=["rr", "random"], default=defaults)
        sp.add_argument("--force-sync", action="store_true", default=defaults)
        sp.add_argument("--allow-no-token", action="store_true", default=defaults)
        sp.add_argument("--country", default=defaults)
        sp.add_argument("--auth-user", default=defaults)
        sp.add_argument("--auth-pass", default=defaults)
        sp.add_argument("--require-auth", action="store_true", default=defaults)
        sp.add_argument("--allow-open-proxy", action="store_true", default=defaults)
        sp.add_argument("--firefox-version", default=defaults)
        sp.add_argument("--client-country", default=defaults)
        sp.add_argument("--include-locked", action="store_true", default=defaults)
        sp.add_argument("--recommended", action="store_true", default=defaults)

    add_common(p)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync")
    add_common(s)
    s.set_defaults(func=cmd_sync)

    s = sub.add_parser("token-status")
    add_common(s)
    s.set_defaults(func=cmd_token_status)

    s = sub.add_parser("token-refresh")
    add_common(s)
    s.add_argument(
        "--force",
        action="store_true",
        help="request a new ProxyPass even when the current pass is still fresh",
    )
    s.set_defaults(func=cmd_token_refresh)

    s = sub.add_parser("usage")
    add_common(s)
    s.set_defaults(func=cmd_usage)

    s = sub.add_parser("how-to-token", help="show the safe, read-only token setup guide")
    add_common(s)
    s.set_defaults(func=cmd_how_to_token)

    s = sub.add_parser("probe")
    add_common(s)
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("run")
    add_common(s)
    s.set_defaults(func=cmd_run)

    p.set_defaults(
        guardian=os.environ.get("IPP_GUARDIAN", DEFAULT_GUARDIAN),
        serverlist_url=DEFAULT_RS,
        proxy_pass_jwt=None,
        fxa_token=None,
        bind=DEFAULT_BIND,
        advertise_host=None,
        socks_base=DEFAULT_SOCKS_BASE,
        http_base=DEFAULT_HTTP_BASE,
        limit=None,
        countries=None,
        no_socks=False,
        no_http=False,
        rotator=None,
        http_rotator=None,
        rotate_mode="random",
        force_sync=False,
        allow_no_token=False,
        country=None,
        auth_user=None,
        auth_pass=None,
        require_auth=False,
        allow_open_proxy=False,
        firefox_version=os.environ.get("IPP_FIREFOX_VERSION", DEFAULT_FIREFOX_VERSION),
        client_country=os.environ.get("IPP_CLIENT_COUNTRY", ""),
        include_locked=False,
        recommended=False,
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
