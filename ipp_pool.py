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
import json
import os
import random
import select
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
EXPORT = ROOT / "export"
LOGS = ROOT / "logs"
TOKENS = ROOT / "tokens"
SERVERLIST_CACHE = DATA / "vpn-serverlist.json"

DEFAULT_GUARDIAN = "https://vpn.mozilla.org"
DEFAULT_RS = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main"
    "/collections/vpn-serverlist/records"
)
DEFAULT_SOCKS_BASE = 21000
DEFAULT_HTTP_BASE = 31000
DEFAULT_BIND = "0.0.0.0"
DEFAULT_ROTATOR = "0.0.0.0:1090"
DEFAULT_HTTP_ROTATOR = "0.0.0.0:8080"



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


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


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



def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    return json.loads(b64url_decode(parts[1]))


def jwt_summary(token: str) -> dict:
    try:
        c = jwt_claims(token)
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


class TokenStore:
    """Thread-safe ProxyPass holder with single-flight refresh."""

    def __init__(
        self,
        proxy_pass: str | None = None,
        fxa_token: str | None = None,
        guardian: str = DEFAULT_GUARDIAN,
        rotate_skew: int = 120,
    ) -> None:
        self._lock = threading.RLock()
        self._proxy_pass = (proxy_pass or "").strip() or None
        self._fxa_token = (fxa_token or "").strip() or None
        self.guardian = guardian.rstrip("/")
        self.rotate_skew = rotate_skew
        self.last_error: str | None = None
        self.last_refresh: float | None = None
        self.usage_headers: dict[str, str] = {}
        self._refreshing = False
        self._proxy_file = TOKENS / "proxy_pass.jwt"
        self._fxa_file = TOKENS / "fxa_token.txt"
        self._proxy_mtime = 0.0
        self._reload_from_disk(force=True)

    def _file_mtime(self, path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    def _reload_from_disk(self, force: bool = False) -> None:
        m = self._file_mtime(self._proxy_file)
        if force or m > self._proxy_mtime:
            pp = load_token_file(self._proxy_file)
            if pp:
                self._proxy_pass = pp
            self._proxy_mtime = m
        fx = load_token_file(self._fxa_file)
        if fx:
            self._fxa_token = fx

    def current(self) -> str | None:
        with self._lock:
            self._reload_from_disk()
            return self._proxy_pass

    def needs_refresh(self) -> bool:
        with self._lock:
            self._reload_from_disk()
            if not self._proxy_pass:
                return True
            try:
                exp = int(jwt_claims(self._proxy_pass).get("exp") or 0)
                return time.time() >= (exp - self.rotate_skew)
            except Exception:
                return True

    def ensure(self) -> str:
        with self._lock:
            self._reload_from_disk()
            if self._proxy_pass and not self.needs_refresh_unlocked():
                return self._proxy_pass
            self._refresh_locked()
            if not self._proxy_pass:
                raise RuntimeError(
                    self.last_error
                    or "no ProxyPass JWT; run refresh_tokens.py or set tokens/proxy_pass.jwt"
                )
            return self._proxy_pass

    def needs_refresh_unlocked(self) -> bool:
        if not self._proxy_pass:
            return True
        try:
            exp = int(jwt_claims(self._proxy_pass).get("exp") or 0)
            return time.time() >= (exp - self.rotate_skew)
        except Exception:
            return True

    def refresh(self) -> str:
        with self._lock:
            self._refresh_locked()
            if not self._proxy_pass:
                raise RuntimeError(self.last_error or "refresh failed")
            return self._proxy_pass

    def _refresh_locked(self) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        try:
            self._reload_from_disk(force=True)
            # Another process may have refreshed already
            if self._proxy_pass and not self.needs_refresh_unlocked():
                self.last_error = None
                return
            helper = ROOT / "refresh_tokens.py"
            if helper.exists() and (
                load_token_file(TOKENS / "session_token.txt") or (TOKENS / "account_meta.json").exists()
            ):
                try:
                    subprocess.check_call(
                        [sys.executable, str(helper)],
                        cwd=str(ROOT),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=90,
                    )
                    self._reload_from_disk(force=True)
                    if self._proxy_pass:
                        self.last_refresh = time.time()
                        self.last_error = None
                        return
                    self.last_error = "refresh_tokens.py produced no proxy_pass.jwt"
                except Exception as e:
                    self.last_error = f"refresh_tokens.py failed: {e}"
            # Fallback: Guardian with current FxA access token
            if not self._fxa_token:
                if not self.last_error:
                    self.last_error = "missing FxA token / session"
                return
            url = f"{self.guardian}/api/v1/fpn/token"
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self._fxa_token}",
                    "Accept": "application/json",
                    "User-Agent": "firefox-ip-protection-pool/1.0",
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self.usage_headers = {
                        k: v
                        for k, v in resp.headers.items()
                        if k.lower().startswith("x-quota") or k.lower() == "retry-after"
                    }
                    data = json.loads(resp.read().decode("utf-8"))
                    token = data.get("token")
                    if not token:
                        self.last_error = "no token in guardian response"
                        return
                    self._proxy_pass = token
                    self.last_refresh = time.time()
                    self.last_error = None
                    atomic_write_text(self._proxy_file, token + "\n")
                    self._proxy_mtime = self._file_mtime(self._proxy_file)
            except Exception as e:
                self.last_error = str(e)
        finally:
            self._refreshing = False

    def status(self) -> dict:
        with self._lock:
            self._reload_from_disk()
            pp = self._proxy_pass
            return {
                "has_proxy_pass": bool(pp),
                "has_fxa_token": bool(self._fxa_token),
                "proxy_pass": jwt_summary(pp) if pp else None,
                "last_refresh": self.last_refresh,
                "last_error": self.last_error,
                "usage_headers": self.usage_headers,
                "guardian": self.guardian,
            }


@dataclass
class ExitNode:
    country: str
    country_name: str
    city: str
    city_name: str
    hostname: str
    port: int = 2499
    quarantined: bool = False
    protocols: list[dict] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"{self.country}-{self.city}-{self.hostname.split('.')[0]}".lower()

    @property
    def label(self) -> str:
        return f"{self.country_name}/{self.city_name} ({self.hostname})"


def fetch_serverlist(url: str = DEFAULT_RS, force: bool = False) -> list[ExitNode]:
    ensure_dirs()
    if SERVERLIST_CACHE.exists() and not force:
        age = time.time() - SERVERLIST_CACHE.stat().st_mtime
        if age < 3600:
            return parse_serverlist(json.loads(SERVERLIST_CACHE.read_text(encoding="utf-8")))
    req = urllib.request.Request(url, headers={"User-Agent": "firefox-ip-protection-pool/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    atomic_write_text(SERVERLIST_CACHE, json.dumps(data, indent=2) + "\n")
    return parse_serverlist(data)


def parse_serverlist(data: dict | list) -> list[ExitNode]:
    records = data.get("data", data) if isinstance(data, dict) else data
    nodes: list[ExitNode] = []
    for country in records:
        code = country.get("code") or "?"
        cname = country.get("name") or code
        for city in country.get("cities") or []:
            city_code = city.get("code") or "?"
            city_name = city.get("name") or city_code
            for s in city.get("servers") or []:
                nodes.append(
                    ExitNode(
                        country=code,
                        country_name=cname,
                        city=city_code,
                        city_name=city_name,
                        hostname=s.get("hostname") or "",
                        port=int(s.get("port") or 2499),
                        quarantined=bool(s.get("quarantined")),
                        protocols=list(s.get("protocols") or []),
                    )
                )
    seen: set[str] = set()
    out: list[ExitNode] = []
    for n in nodes:
        if not n.hostname or n.hostname in seen:
            continue
        seen.add(n.hostname)
        out.append(n)
    return out


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
            if _retry and (b"401" in status or b"407" in status or b"400" in status):
                try:
                    self.tokens.refresh()
                    return self.open_tunnel(
                        exit_host, exit_port, dest_host, dest_port, timeout, _retry=False
                    )
                except Exception:
                    pass
            raise OSError(f"upstream CONNECT failed via {exit_host}: {status!r}")
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
    if username and password:
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
        if uname == username and passwd == password:
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
            dst_host = recv_exact(client, ln).decode("utf-8", "ignore")
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
    if not user or not password:
        return True
    hdr = handler.headers.get("Proxy-Authorization") or ""
    if not hdr.lower().startswith("basic "):
        return False
    try:
        raw = base64.b64decode(hdr.split(" ", 1)[1]).decode("utf-8", "ignore")
        u, _, p = raw.partition(":")
        return u == user and p == password
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
            host, _, port_s = self.path.partition(":")
            port = int(port_s or "443")
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
            parsed = urlsplit(self.path)
            if not parsed.hostname:
                self.send_error(400, "absolute URL required")
                return
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            # For http:// targets, open TCP tunnel then send plain HTTP
            remote = self.connector.open_tunnel(
                self.exit_node.hostname, self.exit_node.port, parsed.hostname, port
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in {"proxy-connection", "connection", "proxy-authorization"}
            }
            headers["Connection"] = "close"
            body = b""
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                body = self.rfile.read(length)
            req = f"{self.command} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
            for k, v in headers.items():
                if k.lower() == "host":
                    continue
                req += f"{k}: {v}\r\n"
            req += "\r\n"
            remote.sendall(req.encode("iso-8859-1") + body)
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                self.connection.sendall(chunk)
            remote.close()
        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass


class ThreadedHTTPProxy(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class BackendPool:
    def __init__(self, nodes: list[ExitNode], mode: str = "rr") -> None:
        self.nodes = nodes
        self.mode = mode
        self._idx = 0
        self._lock = threading.Lock()

    def next(self) -> ExitNode:
        with self._lock:
            if not self.nodes:
                raise RuntimeError("no backends")
            if self.mode == "random":
                return random.choice(self.nodes)
            n = self.nodes[self._idx % len(self.nodes)]
            self._idx += 1
            return n


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
            node = self.pool.next()
            remote = self.connector.open_tunnel(node.hostname, node.port, dst_host, dst_port)
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
            host, _, port_s = self.path.partition(":")
            port = int(port_s or "443")
            node = self.pool.next()
            remote = self.connector.open_tunnel(node.hostname, node.port, host, port)
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
            parsed = urlsplit(self.path)
            if not parsed.hostname:
                self.send_error(400, "absolute URL required")
                return
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            node = self.pool.next()
            remote = self.connector.open_tunnel(
                node.hostname, node.port, parsed.hostname, port
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in {"proxy-connection", "connection", "proxy-authorization"}
            }
            headers["Connection"] = "close"
            body = b""
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                body = self.rfile.read(length)
            req = f"{self.command} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
            for k, v in headers.items():
                if k.lower() == "host":
                    continue
                req += f"{k}: {v}\r\n"
            req += "\r\n"
            remote.sendall(req.encode("iso-8859-1") + body)
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                self.connection.sendall(chunk)
            remote.close()
        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass


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
        self.connector = FastlyConnectClient(tokens)
        self.running: list[RunningNode] = []
        self._stop = threading.Event()

    def start(self, limit: int | None = None, countries: set[str] | None = None) -> list[RunningNode]:
        selected: list[ExitNode] = []
        for n in self.nodes:
            if n.quarantined:
                continue
            if countries and n.country.upper() not in countries and n.country != "REC":
                continue
            selected.append(n)
        if limit is not None:
            selected = selected[:limit]

        for i, node in enumerate(selected):
            rn = RunningNode(node=node, socks=None, http=None)
            if self.enable_socks:
                port = self.socks_base + i
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
                port = self.http_base + i
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

    def start_rotator(self, listen: str = DEFAULT_ROTATOR, mode: str = "rr") -> ThreadedSocksServer:
        host, _, port_s = listen.rpartition(":")
        port = int(port_s)
        nodes = [rn.node for rn in self.running] or [n for n in self.nodes if not n.quarantined]
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
        th = threading.Thread(target=srv.serve_forever, daemon=True, name="rotator-socks")
        th.start()
        adv = f"{self.advertise_host}:{port}" if host in {"0.0.0.0", "::"} else f"{host}:{port}"
        print(f"[*] rotator SOCKS5 on {listen} advertise={adv} backends={len(nodes)} mode={mode}")
        return srv

    def start_http_rotator(self, listen: str = DEFAULT_HTTP_ROTATOR, mode: str = "rr") -> ThreadedHTTPProxy:
        host, _, port_s = listen.rpartition(":")
        port = int(port_s)
        nodes = [rn.node for rn in self.running] or [n for n in self.nodes if not n.quarantined]
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
        th = threading.Thread(target=srv.serve_forever, daemon=True, name="rotator-http")
        th.start()
        adv = f"{self.advertise_host}:{port}" if host in {"0.0.0.0", "::"} else f"{host}:{port}"
        print(f"[*] rotator HTTP on {listen} advertise={adv} backends={len(nodes)} mode={mode}")
        return srv

    def export(self) -> None:
        ensure_dirs()
        socks_lines, http_lines, socks_urls, http_urls = [], [], [], []
        meta = []
        auth_prefix = ""
        if self.auth_user and self.auth_pass:
            auth_prefix = f"{self.auth_user}:{self.auth_pass}@"
        for rn in self.running:
            if rn.socks:
                socks_lines.append(rn.socks)
                socks_urls.append(f"socks5://{auth_prefix}{rn.socks}")
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
                    "socks": rn.socks,
                    "http": rn.http,
                    "label": rn.node.label,
                }
            )
        (EXPORT / "socks5.txt").write_text("\n".join(socks_lines) + ("\n" if socks_lines else ""), encoding="utf-8")
        (EXPORT / "http.txt").write_text("\n".join(http_lines) + ("\n" if http_lines else ""), encoding="utf-8")
        (EXPORT / "socks5_urls.txt").write_text("\n".join(socks_urls) + ("\n" if socks_urls else ""), encoding="utf-8")
        (EXPORT / "http_urls.txt").write_text("\n".join(http_urls) + ("\n" if http_urls else ""), encoding="utf-8")
        (EXPORT / "pool.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (EXPORT / "public_endpoints.txt").write_text(
            "\n".join(
                [
                    f"public_ip_or_host={self.advertise_host}",
                    f"rotator_socks5=socks5://{auth_prefix}{self.advertise_host}:1090",
                    f"rotator_http=http://{auth_prefix}{self.advertise_host}:8080",
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
            ),
            encoding="utf-8",
        )
        print(f"[*] exported {len(meta)} nodes → {EXPORT}")

    def stop(self) -> None:
        self._stop.set()
        for rn in self.running:
            for srv in (rn.socks_server, rn.http_server):
                if not srv:
                    continue
                try:
                    srv.shutdown()
                except Exception:
                    pass
                try:
                    srv.server_close()
                except Exception:
                    pass
        self.running.clear()



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
        or load_token_file(TOKENS / "fxa_token.txt")
    )
    return TokenStore(proxy_pass=proxy_pass, fxa_token=fxa, guardian=args.guardian)


def cmd_sync(args: argparse.Namespace) -> int:
    nodes = fetch_serverlist(args.serverlist_url, force=True)
    active = [n for n in nodes if not n.quarantined]
    print(f"[*] serverlist: {len(nodes)} total, {len(active)} active")
    by: dict[str, int] = {}
    for n in active:
        by[n.country] = by.get(n.country, 0) + 1
    for c, cnt in sorted(by.items()):
        print(f"    {c}: {cnt}")
    (EXPORT / "exits.json").write_text(
        json.dumps([asdict(n) for n in nodes], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


def cmd_token_status(args: argparse.Namespace) -> int:
    print(json.dumps(build_tokens(args).status(), indent=2, ensure_ascii=False))
    return 0


def cmd_token_refresh(args: argparse.Namespace) -> int:
    ts = build_tokens(args)
    try:
        tok = ts.refresh()
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    print(f"[+] refreshed ({len(tok)} chars)")
    print(json.dumps(ts.status(), indent=2, ensure_ascii=False))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    ts = build_tokens(args)
    nodes = fetch_serverlist(args.serverlist_url, force=False)
    if args.country:
        nodes = [n for n in nodes if n.country.upper() == args.country.upper() and not n.quarantined]
    else:
        active = [n for n in nodes if not n.quarantined]
        preferred = [n for n in active if n.country in {"US", "REC"}]
        nodes = preferred or active
    if not nodes:
        print("[!] no nodes", file=sys.stderr)
        return 1
    node = nodes[0]
    print(f"[*] probing {node.label}")
    try:
        token = ts.ensure()
    except Exception as e:
        print(f"[!] token: {e}", file=sys.stderr)
        return 1
    print(f"[*] proxy_pass: {json.dumps(jwt_summary(token))}")
    curl = shutil.which("curl")
    if not curl:
        print("[!] curl not found", file=sys.stderr)
        return 1
    cmd = [
        curl,
        "-sS",
        "--max-time",
        "25",
        "--http1.1",
        "-x",
        f"https://{node.hostname}:{node.port}",
        "--proxy-header",
        f"Proxy-Authorization: Bearer {token}",
        "https://ipinfo.io/json",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=30)
    except Exception as e:
        print(f"[!] probe failed: {getattr(e, 'output', e)}", file=sys.stderr)
        return 1
    print(out[:1000])
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    ensure_dirs()
    ts = build_tokens(args)
    try:
        tok = ts.ensure()
        print(f"[*] proxy_pass: {json.dumps(jwt_summary(tok))}")
    except Exception as e:
        print(f"[!] token not ready: {e}", file=sys.stderr)
        if not args.allow_no_token:
            return 1

    public_ip = args.advertise_host or os.environ.get("IPP_ADVERTISE_HOST") or detect_public_ip()
    auth_user = args.auth_user or os.environ.get("IPP_LISTEN_USER")
    auth_pass = args.auth_pass or os.environ.get("IPP_LISTEN_PASS")
    if args.require_auth and (not auth_user or not auth_pass):
        auth_file = TOKENS / "proxy_listen_auth.txt"
        fu, fp = parse_listen_auth_file(auth_file)
        auth_user = auth_user or fu
        auth_pass = auth_pass or fp
        if not auth_user or not auth_pass:
            auth_user = auth_user or "ipp"
            auth_pass = auth_pass or base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
            atomic_write_text(auth_file, f"USER={auth_user}\nPASS={auth_pass}\n")
            os.chmod(auth_file, 0o600)

    nodes = fetch_serverlist(args.serverlist_url, force=args.force_sync)
    countries = None
    if args.countries:
        countries = {c.strip().upper() for c in args.countries.split(",") if c.strip()}

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
    )
    pool.start(limit=args.limit, countries=countries)
    if not pool.running:
        print("[!] no listeners started", file=sys.stderr)
        return 1

    rotator_listen = args.rotator
    if rotator_listen is None:
        rotator_listen = f"{args.bind}:1090"
    http_rotator_listen = getattr(args, "http_rotator", None)
    if http_rotator_listen is None:
        http_rotator_listen = f"{args.bind}:8080"
    rotator_srv = None
    http_rotator_srv = None
    if rotator_listen and rotator_listen.lower() not in {"off", "none", "false"}:
        rotator_srv = pool.start_rotator(rotator_listen, mode=args.rotate_mode)
    if http_rotator_listen and str(http_rotator_listen).lower() not in {"off", "none", "false"}:
        http_rotator_srv = pool.start_http_rotator(http_rotator_listen, mode=args.rotate_mode)

    def refresher() -> None:
        while not pool._stop.is_set():  # noqa: SLF001
            try:
                if ts.needs_refresh():
                    ts.refresh()
                    print(f"[*] token refreshed: {json.dumps(jwt_summary(ts.current() or ''))}")
            except Exception as e:
                print(f"[!] token refresh error: {e}")
            pool._stop.wait(30)  # noqa: SLF001

    threading.Thread(target=refresher, daemon=True).start()

    print("[*] pool running. Ctrl+C / SIGTERM to stop.")
    print(f"    public host: {public_ip}")
    if auth_user and auth_pass:
        print(f"    auth: {auth_user} / {auth_pass}")
        print(f"    example: curl -x socks5h://{auth_user}:{auth_pass}@{public_ip}:{args.socks_base} https://ipinfo.io/json")
        print(f"    rotator socks: curl -x socks5h://{auth_user}:{auth_pass}@{public_ip}:1090 https://ipinfo.io/ip")
        print(f"    rotator http : curl -x http://{auth_user}:{auth_pass}@{public_ip}:8080 https://ipinfo.io/ip")
    else:
        print(f"    example: curl -x socks5h://{public_ip}:{args.socks_base} https://ipinfo.io/json")
        print("    WARNING: no auth configured; public proxy is open")
    print(f"    endpoints: {EXPORT / 'public_endpoints.txt'}")

    def _stop(*_a):
        print("\n[*] stopping...")
        pool.stop()
        if rotator_srv:
            rotator_srv.shutdown()
        if http_rotator_srv:
            http_rotator_srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    while True:
        time.sleep(3600)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Firefox IP Protection multi-exit → SOCKS5/HTTP pool")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--guardian", default=os.environ.get("IPP_GUARDIAN", DEFAULT_GUARDIAN))
        sp.add_argument("--serverlist-url", default=DEFAULT_RS)
        sp.add_argument("--proxy-pass-jwt", default=None)
        sp.add_argument("--fxa-token", default=None)
        sp.add_argument("--bind", default=DEFAULT_BIND, help="listen address, default 0.0.0.0")
        sp.add_argument("--advertise-host", default=None, help="public IP/host written into export lists")
        sp.add_argument("--socks-base", type=int, default=DEFAULT_SOCKS_BASE)
        sp.add_argument("--http-base", type=int, default=DEFAULT_HTTP_BASE)
        sp.add_argument("--limit", type=int, default=None)
        sp.add_argument("--countries", default=None)
        sp.add_argument("--no-socks", action="store_true")
        sp.add_argument("--no-http", action="store_true")
        sp.add_argument("--rotator", default=None, help="socks rotator host:port or off")
        sp.add_argument("--http-rotator", default=None, help="http rotator host:port or off")
        sp.add_argument("--rotate-mode", choices=["rr", "random"], default="rr")
        sp.add_argument("--force-sync", action="store_true")
        sp.add_argument("--allow-no-token", action="store_true")
        sp.add_argument("--country", default=None)
        sp.add_argument("--auth-user", default=None)
        sp.add_argument("--auth-pass", default=None)
        sp.add_argument("--require-auth", action="store_true", help="force listen auth (default for public)")

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
    s.set_defaults(func=cmd_token_refresh)

    s = sub.add_parser("probe")
    add_common(s)
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("run")
    add_common(s)
    s.set_defaults(func=cmd_run)

    return p


def main(argv: list[str] | None = None) -> int:
    ensure_dirs()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
