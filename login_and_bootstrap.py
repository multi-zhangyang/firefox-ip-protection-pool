#!/usr/bin/env python3
"""Bootstrap long-lived FxA/IP-Protection auth on this VPS.

Flow:
1) Pass Fastly challenge on accounts.firefox.com (POW + vision captcha)
2) Sign in with email/password
3) Submit email 6-digit code (CLI arg or tokens/email_code.txt)
4) Exchange session -> OAuth access token (profile + vpn scopes)
5) Activate Guardian if needed, fetch ProxyPass JWT
6) Save tokens for ipp_pool.py auto-refresh

Usage:
  . .venv/bin/activate
  python login_and_bootstrap.py --email you@example.com --password '...' --code 123456
  # or after code arrives:
  python login_and_bootstrap.py --email you@example.com --password '...' --wait-code-file
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
import re
import string
import sys
import time
from pathlib import Path

import requests
from fxa.core import Session as FxSession, StretchedPassword
from fxa.oauth import Client as OAuthClient
from fxa._utils import APIClient
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "tokens"
DATA = ROOT / "data"
LOGS = ROOT / "logs"
for p in (TOKENS, DATA, LOGS):
    p.mkdir(exist_ok=True)

FX_CLIENT_ID = "5882386c6d801776"
VPN_CLIENT_ID = "e6eb0d1e856335fc"
SCOPES = "profile https://identity.mozilla.com/apps/vpn"
GUARDIAN = "https://vpn.mozilla.org"
ALPH = string.ascii_letters + string.digits


def solve_pow(base: str, target: str) -> str:
    target = target.lower()
    for a, b in itertools.product(ALPH, repeat=2):
        if hashlib.sha256((base + a + b).encode()).hexdigest() == target:
            return a + b
    raise RuntimeError("pow not found")


def vision_captcha(img: bytes) -> str:
    api_base = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL") or os.environ.get("OPENAI_MODEL") or "grok-4.5"
    if not api_base or not api_key:
        raise RuntimeError("need ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN for captcha vision")
    b64 = base64.b64encode(img).decode()
    r = requests.post(
        f"{api_base}/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "temperature": 0,
            "max_tokens": 32,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Read CAPTCHA characters exactly. Return only characters, no spaces.",
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{b64}"},
                        },
                    ],
                }
            ],
        },
        timeout=60,
    )
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"]
    return re.sub(r"[^A-Za-z0-9]", "", text.strip())


def pass_fastly_and_login(page, email: str, password: str) -> None:
    state = {"prefix": None, "ch": None}

    def on_response(resp):
        if "fst-post-back" in resp.url:
            m = re.search(r"(/_fs-ch-[^/]+)", resp.url)
            if m:
                state["prefix"] = m.group(1)
            try:
                state["ch"] = resp.json()
            except Exception:
                pass

    page.on("response", on_response)
    page.goto("https://accounts.firefox.com/", wait_until="domcontentloaded", timeout=120000)
    page.wait_for_timeout(3000)
    ch = state["ch"]
    for _ in range(8):
        if not ch:
            page.wait_for_timeout(500)
            ch = state["ch"]
        if not ch:
            break
        if ch.get("status") == "success":
            break
        answers = []
        captcha = None
        for c in ch.get("ch") or []:
            ty, data = c.get("ty"), c.get("data") or {}
            if ty == "pow":
                ans = solve_pow(data["base"], data["hash"])
                answers.append(
                    {
                        "ty": "pow",
                        "base": data["base"],
                        "answer": ans,
                        "hmac": data.get("hmac"),
                        "expires": data.get("expires"),
                    }
                )
            elif ty == "clientmetrics":
                answers.append({"ty": "clientmetrics", "client_data": "{}", "error_trace": None})
            elif ty == "captcha":
                captcha = data.get("image_b64")
        if captcha:
            raw = base64.b64decode(captcha.split(",", 1)[1])
            guess = vision_captcha(raw)
            print("[*] captcha:", guess)
            answers.append({"ty": "captcha", "answer": guess})
        url = f"https://accounts.firefox.com{state['prefix']}/fst-post-back"
        r = page.request.post(
            url,
            data=json.dumps({"token": ch["tok"], "data": answers}),
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        res = r.json()
        print("[*] challenge post", r.status, res.get("status"), [c.get("ty") for c in res.get("ch") or []])
        if res.get("status") == "success":
            break
        ch = res

    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(3000)
    page.locator('input[name="email"], input[type="email"]').first.fill(email)
    page.locator('button[type="submit"]').first.click()
    page.wait_for_timeout(3000)
    page.locator('input[type="password"]').first.fill(password)
    page.locator('button[type="submit"]').first.click()
    page.wait_for_timeout(6000)
    page.screenshot(path=str(LOGS / "bootstrap_after_password.png"), full_page=True)
    print("[*] after password:", page.url)


def submit_email_code(page, code: str) -> None:
    code = re.sub(r"\D", "", code)[:6]
    if len(code) != 6:
        raise ValueError("code must be 6 digits")
    filled = False
    for sel in [
        'input[name="code"]',
        'input[inputmode="numeric"]',
        'input[maxlength="6"]',
        'input[type="tel"]',
        'input[type="text"]',
    ]:
        if page.locator(sel).count() and page.locator(sel).first.is_visible():
            page.fill(sel, code)
            filled = True
            break
    if not filled and page.locator('input[maxlength="1"]').count() >= 6:
        for i, ch in enumerate(code):
            page.locator('input[maxlength="1"]').nth(i).fill(ch)
        filled = True
    if not filled:
        raise RuntimeError("cannot find code input; are we on signin_token_code page?")
    for sel in [
        'button[type="submit"]',
        'button:has-text("Confirm")',
        'button:has-text("Continue")',
        'button:has-text("Submit")',
    ]:
        if page.locator(sel).count() and page.locator(sel).first.is_visible():
            page.click(sel)
            break
    page.wait_for_timeout(8000)
    page.screenshot(path=str(LOGS / "bootstrap_after_code.png"), full_page=True)
    print("[*] after code:", page.url)
    print(page.inner_text("body")[:500])


def api_login_with_page(page, email: str, password: str) -> dict:
    cr = page.request.post(
        "https://api.accounts.firefox.com/v1/account/credentials/status",
        data=json.dumps({"email": email}),
        headers={"content-type": "application/json", "accept": "application/json"},
    )
    print("[*] credentials/status", cr.status, cr.text()[:200])
    salt = None
    if cr.status == 200:
        salt = cr.json().get("clientSalt")
    if not salt:
        # fallback known salt from earlier probe if any
        salt = "identity.mozilla.com/picl/v1/quickStretchV2:937e93ab0bf3781ff7a0f8c07e8a29b9"
    sp = StretchedPassword(2, email, salt, password, None)
    lr = page.request.post(
        "https://api.accounts.firefox.com/v1/account/login",
        data=json.dumps({"email": email, "authPW": sp.get_auth_pw_v2(), "reason": "login"}),
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "origin": "https://accounts.firefox.com",
            "referer": "https://accounts.firefox.com/",
        },
    )
    print("[*] account/login", lr.status, lr.text()[:300])
    if lr.status != 200:
        # maybe already logged in via UI and session cookies exist; still need sessionToken
        raise RuntimeError(f"account/login failed: {lr.status} {lr.text()[:200]}")
    data = lr.json()
    (TOKENS / "session.json").write_text(json.dumps(data, indent=2))
    return data


def oauth_and_proxy_pass(session_json: dict) -> None:
    session_token = session_json["sessionToken"]
    email = session_json.get("email") or ""
    server = "https://api.accounts.firefox.com/v1"
    apiclient = APIClient(server)

    class DummyClient:
        def __init__(self):
            self.apiclient = apiclient
            self.server_url = server

    session = FxSession(
        DummyClient(),
        email,
        session_token,
        uid=session_json.get("uid"),
        verified=session_json.get("verified", True),
        auth_timestamp=int(time.time() * 1000),
    )
    access = None
    last_err = None
    for client_id in (FX_CLIENT_ID, VPN_CLIENT_ID):
        try:
            oauth = OAuthClient(client_id=client_id, server_url="https://oauth.accounts.firefox.com/v1")
            access = oauth.authorize_token(session, scope=SCOPES, client_id=client_id)
            print(f"[+] oauth access via {client_id}, len={len(access)}")
            break
        except Exception as e:
            last_err = e
            print(f"[!] oauth {client_id} failed: {e}")
    if not access:
        raise RuntimeError(f"oauth failed: {last_err}")
    (TOKENS / "fxa_token.txt").write_text(access + "\n")

    # try refresh token if authorize_code path exposes it - PyFxA authorize_token may not
    # Guardian
    headers = {
        "Authorization": f"Bearer {access}",
        "Accept": "application/json",
        "User-Agent": "firefox-ip-protection-pool/1.0",
    }
    st = requests.get(f"{GUARDIAN}/api/v1/fpn/status", headers=headers, timeout=30)
    print("[*] fpn/status", st.status_code, st.text[:300])
    if st.status_code in (401, 403, 404):
        ar = requests.post(f"{GUARDIAN}/api/v1/fpn/activate", headers=headers, timeout=30)
        print("[*] fpn/activate", ar.status_code, ar.text[:300])
    tr = requests.get(f"{GUARDIAN}/api/v1/fpn/token", headers=headers, timeout=30)
    print("[*] fpn/token", tr.status_code, tr.text[:300])
    if not tr.ok:
        raise RuntimeError(f"proxy pass failed: {tr.status_code} {tr.text[:200]}")
    tok = tr.json().get("token")
    if not tok:
        raise RuntimeError("no token in fpn response")
    (TOKENS / "proxy_pass.jwt").write_text(tok + "\n")
    print("[+] saved tokens/proxy_pass.jwt")


def wait_code_file(path: Path, timeout: int = 600) -> str:
    print(f"[*] waiting for code file {path} (timeout {timeout}s)")
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            code = path.read_text(encoding="utf-8").strip()
            if re.fullmatch(r"\d{6}", re.sub(r"\D", "", code)[:6] or ""):
                return re.sub(r"\D", "", code)[:6]
        time.sleep(2)
    raise TimeoutError("code file not provided in time")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", default=os.environ.get("IPP_EMAIL"))
    ap.add_argument("--password", default=os.environ.get("IPP_PASSWORD"))
    ap.add_argument("--code", default=None, help="6-digit Mozilla email code")
    ap.add_argument("--wait-code-file", action="store_true")
    ap.add_argument("--code-file", default=str(TOKENS / "email_code.txt"))
    args = ap.parse_args()
    if not args.email or not args.password:
        print("need --email and --password (or IPP_EMAIL / IPP_PASSWORD)", file=sys.stderr)
        return 2

    code = args.code
    if not code and Path(args.code_file).exists():
        code = Path(args.code_file).read_text(encoding="utf-8").strip()
    if not code and args.wait_code_file:
        # start browser first then wait
        pass

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, locale="en-US")
        page = context.new_page()
        pass_fastly_and_login(page, args.email, args.password)

        if "signin_token_code" in page.url or "confirmation code" in page.inner_text("body").lower():
            if not code and args.wait_code_file:
                code = wait_code_file(Path(args.code_file))
            if not code:
                print(
                    "[!] Mozilla sent a 6-digit email code. Put it in tokens/email_code.txt or pass --code",
                    file=sys.stderr,
                )
                print(f"    page={page.url}", file=sys.stderr)
                context.storage_state(path=str(DATA / "fxa_pending_code.json"))
                browser.close()
                return 3
            submit_email_code(page, code)

        # Prefer API login using challenged browser cookies after verified session
        try:
            session_json = api_login_with_page(page, args.email, args.password)
        except Exception as e:
            print("[!] api login after code failed:", e)
            # If UI is logged in, user may still need another path
            context.storage_state(path=str(DATA / "fxa_after_code.json"))
            browser.close()
            return 4

        context.storage_state(path=str(DATA / "fxa_logged_in.json"))
        browser.close()

    oauth_and_proxy_pass(session_json)
    print("[*] bootstrap complete. Next:")
    print("    python ipp_pool.py token-status")
    print("    python ipp_pool.py probe --country US")
    print("    python ipp_pool.py run --limit 20 --rotator 127.0.0.1:1090")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
