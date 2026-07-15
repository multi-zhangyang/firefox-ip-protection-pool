#!/usr/bin/env python3
"""Long-lived token refresh for Firefox IP Protection.

Uses a stored FxA sessionToken (tokens/session_token.txt + account_meta.json)
to mint a fresh OAuth access token, then Guardian ProxyPass JWT.

Cron:
  */4 * * * * cd /root/re-workspace/firefox-ip-protection-pool && .venv/bin/python refresh_tokens.py >> logs/refresh.log 2>&1
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from pathlib import Path

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


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


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
        import base64

        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        body = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        exp = int(body.get("exp") or 0)
        return exp - int(time.time())
    except Exception:
        return None


def main() -> int:
    TOKENS.mkdir(exist_ok=True)
    LOGS.mkdir(exist_ok=True)

    lock_path = TOKENS / ".refresh.lock"
    lock_fh = open(lock_path, "a+", encoding="utf-8")
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
        atomic_write_text(TOKENS / "fxa_token.txt", access + "\n")

        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/json",
            "User-Agent": "firefox-ip-protection-pool/1.0",
        }
        r = requests.get(f"{GUARDIAN}/api/v1/fpn/token", headers=headers, timeout=30)
        if r.status_code in (401, 403, 404):
            ar = requests.post(f"{GUARDIAN}/api/v1/fpn/activate", headers=headers, timeout=30)
            print(time.strftime("%F %T"), "activate", ar.status_code, ar.text[:120])
            r = requests.get(f"{GUARDIAN}/api/v1/fpn/token", headers=headers, timeout=30)
        if not r.ok:
            print(time.strftime("%F %T"), "fpn/token failed", r.status_code, r.text[:300])
            return 1
        tok = r.json().get("token")
        if not tok:
            print(time.strftime("%F %T"), "no token field", r.text[:200])
            return 1
        atomic_write_text(TOKENS / "proxy_pass.jwt", tok + "\n")
        atomic_write_text(TOKENS / "session_token.txt", session_token + "\n")
        # keep account meta in sync
        acc["sessionToken"] = session_token
        atomic_write_text(TOKENS / "account_meta.json", json.dumps(acc, indent=2) + "\n")
        quota = {k: v for k, v in r.headers.items() if k.lower().startswith("x-quota")}
        print(
            time.strftime("%F %T"),
            "refreshed proxy_pass len=",
            len(tok),
            "left=",
            jwt_seconds_left(tok),
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
    raise SystemExit(main())
