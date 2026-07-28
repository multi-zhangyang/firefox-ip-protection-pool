#!/usr/bin/env python3
"""Interactively bootstrap long-lived FxA/IP-Protection credentials.

Flow:
1) Pass Fastly challenge on accounts.firefox.com (POW + vision captcha)
2) Sign in with email/password
3) Read and submit the 6-digit email code interactively when requested
4) Exchange session -> OAuth access token (profile + vpn scopes)
5) Activate Guardian only when status explicitly reports not registered (404)
6) Fetch an initial ProxyPass, destroy the short-lived OAuth token, and save
   only the FxA session material required by refresh_tokens.py

Usage:
  . .venv/bin/activate
  python login_and_bootstrap.py --email you@example.com

The password and email verification code are read from the terminal. They are
not accepted through command-line options or environment variables.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import itertools
import json
import os
import re
import string
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from fxa.core import Session as FxSession, StretchedPassword
from fxa.oauth import Client as OAuthClient

from refresh_state import record_refresh_state
from refresh_tokens import (
    ProxyPassValidationError,
    ROTATE_BEFORE_SECONDS,
    _retry_after_seconds,
    atomic_write_text,
    bounded_fxa_api_client,
    guardian_request,
    refresh_lock,
    validate_proxy_pass_jwt,
)

ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "tokens"
DATA = ROOT / "data"
LOGS = ROOT / "logs"
for p in (TOKENS, DATA, LOGS):
    p.mkdir(exist_ok=True)

FX_CLIENT_ID = "5882386c6d801776"
SCOPES = "profile https://identity.mozilla.com/apps/vpn"
GUARDIAN = "https://vpn.mozilla.org"
ALPH = string.ascii_letters + string.digits


def safe_page_location(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def prompt_password() -> str:
    """Read the Firefox Account password without exposing it in argv or env."""
    try:
        password = getpass.getpass("Firefox Account password: ")
    except (EOFError, OSError) as exc:
        raise RuntimeError("an interactive terminal is required to read the password") from exc
    if not password:
        raise RuntimeError("password cannot be empty")
    return password


def prompt_email_code() -> str:
    """Read a six-digit email verification code from the terminal."""
    for _ in range(3):
        try:
            code = input("Mozilla 6-digit email code: ").strip()
        except EOFError as exc:
            raise RuntimeError("an interactive terminal is required to read the email code") from exc
        if re.fullmatch(r"\d{6}", code):
            return code
        print("[!] email code must contain exactly 6 digits", file=sys.stderr)
    raise RuntimeError("no valid 6-digit email code was provided")


def cleanup_legacy_credential_cache(*, remove_browser_storage: bool = False) -> None:
    """Remove obsolete credentials without destroying pre-bootstrap recovery data."""
    legacy_files = (
        TOKENS / "fxa_token.txt",
        TOKENS / "session.json",
        TOKENS / "email_code.txt",
        DATA / "fxa_pending_code.json",
        DATA / "fxa_after_code.json",
        DATA / "fxa_logged_in.json",
        LOGS / "bootstrap_after_password.png",
        LOGS / "bootstrap_after_code.png",
    )
    if remove_browser_storage:
        # Old versions used this full browser storage dump as a credential
        # fallback.  Keep it until a new renewable session has been published
        # successfully, then remove it without ever reading it.
        legacy_files += (DATA / "ff_storage.json",)
    for path in legacy_files:
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            print(f"[!] could not remove obsolete private cache: {path.name}", file=sys.stderr)
    for path in TOKENS.glob(".bootstrap-captcha-*.jpg"):
        try:
            path.unlink()
        except OSError:
            pass


def solve_pow(base: str, target: str) -> str:
    target = target.lower()
    for a, b in itertools.product(ALPH, repeat=2):
        if hashlib.sha256((base + a + b).encode()).hexdigest() == target:
            return a + b
    raise RuntimeError("pow not found")


def vision_captcha(img: bytes) -> str:
    api_base = (
        os.environ.get("ANTHROPIC_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or ""
    ).rstrip("/")
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL") or os.environ.get("OPENAI_MODEL") or "grok-4.5"
    if not api_base or not api_key:
        fd, image_name = tempfile.mkstemp(
            prefix=".bootstrap-captcha-",
            suffix=".jpg",
            dir=TOKENS,
        )
        image_path = Path(image_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(img)
                handle.flush()
                os.fsync(handle.fileno())
            print(f"[*] CAPTCHA image saved temporarily at {image_path}")
            answer = input("CAPTCHA characters (open the image locally if needed): ").strip()
            answer = re.sub(r"[^A-Za-z0-9]", "", answer)
            if not answer:
                raise RuntimeError("CAPTCHA answer cannot be empty")
            return answer
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                image_path.unlink()
            except FileNotFoundError:
                pass
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
            print("[*] captcha answer obtained")
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
    print("[*] after password:", safe_page_location(page.url))


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
    print("[*] after code:", safe_page_location(page.url))


def api_login_with_page(page, email: str, password: str) -> dict:
    cr = page.request.post(
        "https://api.accounts.firefox.com/v1/account/credentials/status",
        data=json.dumps({"email": email}),
        headers={"content-type": "application/json", "accept": "application/json"},
    )
    print("[*] credentials/status", cr.status)
    salt = None
    if cr.status == 200:
        try:
            status_data = cr.json()
        except Exception as exc:
            raise RuntimeError("credentials/status returned invalid JSON") from exc
        salt = status_data.get("clientSalt") if isinstance(status_data, dict) else None
    if not salt:
        raise RuntimeError("credentials/status did not return a clientSalt; refusing stale fallback")
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
    print("[*] account/login", lr.status)
    if lr.status != 200:
        # maybe already logged in via UI and session cookies exist; still need sessionToken
        raise RuntimeError(f"account/login failed: HTTP {lr.status}")
    data = lr.json()
    if not isinstance(data, dict):
        raise RuntimeError("account/login returned an invalid response")
    data.setdefault("email", email)
    return data


def persist_bootstrap_credentials(
    *,
    session_token: str,
    email: str,
    uid: str,
    proxy_pass: str,
    expires_at: float,
    http_status: int,
    token_dir: Path | None = None,
) -> None:
    """Publish a new renewable session without racing the refresh helper."""
    # Wait only at publication time.  The interactive browser flow does not
    # hold the lock, but any old helper must finish before this new session and
    # success state become visible.  Later helpers see all files atomically
    # replaced while protected by the same cross-process lock.
    destination = TOKENS if token_dir is None else token_dir
    with refresh_lock(destination, blocking=True):
        atomic_write_text(destination / "session_token.txt", session_token + "\n")
        atomic_write_text(
            destination / "account_meta.json",
            json.dumps({"email": email, "uid": uid}, indent=2) + "\n",
        )
        atomic_write_text(destination / "proxy_pass.jwt", proxy_pass + "\n")
        # A successful interactive login supersedes proxy authorization
        # failures associated with the former session.  Remove only the
        # non-secret digest marker; a restarted TokenStore will then accept
        # the freshly bootstrapped pass even if Guardian reissued the same JWT.
        try:
            (destination / "rejected_proxy_pass.sha256").unlink()
        except FileNotFoundError:
            pass
        record_refresh_state(
            destination / "refresh_state.json",
            "success",
            http_status=http_status,
            proxy_pass_expires_at=expires_at,
        )


def oauth_and_proxy_pass(session_json: dict) -> None:
    session_token = session_json.get("sessionToken") or ""
    email = session_json.get("email") or ""
    uid = session_json.get("uid") or ""
    if not email or not uid or not session_token:
        raise RuntimeError("account/login response is missing email, uid, or sessionToken")
    server = "https://api.accounts.firefox.com/v1"
    apiclient = bounded_fxa_api_client(server)
    sp = StretchedPassword(1, email, None, "x", None)

    class DummyClient:
        def __init__(self):
            self.apiclient = apiclient
            self.server_url = server

    session = FxSession(
        DummyClient(),
        email,
        sp.v1,
        uid,
        session_token,
        verified=session_json.get("verified", True),
        auth_timestamp=int(time.time() * 1000),
    )
    access = None
    oauth_client = None
    last_err = None
    # Use the same current Firefox Desktop client as refresh_tokens.py so a
    # bootstrap success is meaningful for subsequent unattended renewal.
    for client_id in (FX_CLIENT_ID,):
        try:
            oauth_server = "https://oauth.accounts.firefox.com/v1"
            oauth = OAuthClient(client_id=client_id, server_url=oauth_server)
            oauth.apiclient = bounded_fxa_api_client(oauth_server)
            access = oauth.authorize_token(session, scope=SCOPES, client_id=client_id)
            oauth_client = oauth
            print(f"[+] oauth access granted via client {client_id}")
            break
        except Exception as e:
            last_err = e
            print(f"[!] oauth {client_id} failed ({type(e).__name__})")
    if not access:
        kind = type(last_err).__name__ if last_err is not None else "unknown error"
        raise RuntimeError(f"oauth failed ({kind})")

    try:
        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "firefox-ip-protection-pool/1.0",
        }
        st = guardian_request("GET", "/api/v1/fpn/status", headers=headers, label="fpn/status")
        print("[*] fpn/status", f"HTTP {st.status_code}")
        if st.status_code == 401:
            raise RuntimeError("Guardian authentication rejected the OAuth token (HTTP 401)")
        if st.status_code == 403:
            raise RuntimeError("this Firefox Account is not eligible for IP Protection (HTTP 403)")
        if st.status_code == 429 or 500 <= st.status_code <= 599:
            retry_after = _retry_after_seconds(st.headers.get("Retry-After"))
            suffix = (
                f"; retry after {retry_after:g}s"
                if st.status_code == 429 and retry_after is not None
                else ""
            )
            raise RuntimeError(f"fpn/status failed: HTTP {st.status_code}{suffix}")
        if st.status_code == 404:
            ar = guardian_request("POST", "/api/v1/fpn/activate", headers=headers, label="fpn/activate")
            print("[*] fpn/activate", f"HTTP {ar.status_code}")
            if ar.status_code == 401:
                raise RuntimeError("Guardian authentication failed during activation (HTTP 401)")
            if ar.status_code == 403:
                raise RuntimeError("this Firefox Account is not eligible for activation (HTTP 403)")
            if not 200 <= ar.status_code < 300:
                retry_after = _retry_after_seconds(ar.headers.get("Retry-After"))
                suffix = (
                    f"; retry after {retry_after:g}s"
                    if ar.status_code == 429 and retry_after is not None
                    else ""
                )
                raise RuntimeError(f"fpn/activate failed: HTTP {ar.status_code}{suffix}")
        elif not 200 <= st.status_code < 300:
            raise RuntimeError(f"fpn/status failed: HTTP {st.status_code}")

        tr = guardian_request("GET", "/api/v1/fpn/token", headers=headers, label="fpn/token")
        print("[*] fpn/token", f"HTTP {tr.status_code}")
        if tr.status_code == 401:
            raise RuntimeError("Guardian authentication rejected the OAuth token (HTTP 401)")
        if tr.status_code == 403:
            raise RuntimeError("this Firefox Account is not eligible for a ProxyPass (HTTP 403)")
        if tr.status_code == 404:
            raise RuntimeError("Guardian registration is unavailable after activation (HTTP 404)")
        if not 200 <= tr.status_code < 300:
            retry_after = _retry_after_seconds(tr.headers.get("Retry-After"))
            suffix = (
                f"; retry after {retry_after:g}s"
                if tr.status_code == 429 and retry_after is not None
                else ""
            )
            raise RuntimeError(f"proxy pass failed: HTTP {tr.status_code}{suffix}")
        try:
            token_response = tr.json()
        except requests.exceptions.JSONDecodeError as exc:
            raise RuntimeError("fpn/token returned invalid JSON") from exc
        tok = token_response.get("token") if isinstance(token_response, dict) else None
        if not isinstance(tok, str) or not tok:
            raise RuntimeError("fpn/token response has no token field")
        try:
            claims = validate_proxy_pass_jwt(tok, min_ttl=ROTATE_BEFORE_SECONDS)
        except ProxyPassValidationError as exc:
            raise RuntimeError(f"rejected ProxyPass JWT: {exc}") from exc

        # Publish only the long-lived session inputs plus the initial,
        # replaceable ProxyPass cache.  The short-lived OAuth access token is
        # never written.  Publication also supersedes an old session's
        # persisted cooldown under the same lock used by the helper.
        persist_bootstrap_credentials(
            session_token=session_token,
            email=email,
            uid=uid,
            proxy_pass=tok,
            expires_at=float(claims["exp"]),
            http_status=tr.status_code,
        )
        print("[+] saved long-lived session credentials and initial ProxyPass")
    finally:
        if oauth_client is not None and access:
            try:
                oauth_client.destroy_token(access)
                print("[+] destroyed temporary OAuth access token")
            except Exception as exc:
                print(
                    f"[!] could not destroy temporary OAuth token ({type(exc).__name__}); it was not saved",
                    file=sys.stderr,
                )
            access = None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Interactively save the FxA session required for automatic ProxyPass renewal"
    )
    ap.add_argument("--email", help="Firefox Account email (prompted when omitted)")
    args = ap.parse_args()

    if not sys.stdin.isatty():
        print(
            "[!] bootstrap requires an interactive terminal; passwords are not accepted from pipes",
            file=sys.stderr,
        )
        return 2

    email = (args.email or input("Firefox Account email: ")).strip()
    if not email:
        print("email cannot be empty", file=sys.stderr)
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "[!] Playwright is required; install requirements-bootstrap.txt first",
            file=sys.stderr,
        )
        return 2
    try:
        password = prompt_password()
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    with sync_playwright() as p:
        # This intentionally launches Playwright Firefox, not Chromium.
        browser = p.firefox.launch(headless=True)
        try:
            context = browser.new_context(viewport={"width": 1280, "height": 900}, locale="en-US")
            page = context.new_page()
            pass_fastly_and_login(page, email, password)

            if "signin_token_code" in page.url or "confirmation code" in page.inner_text("body").lower():
                submit_email_code(page, prompt_email_code())

            try:
                session_json = api_login_with_page(page, email, password)
            except Exception as exc:
                print(f"[!] API login after verification failed ({type(exc).__name__})", file=sys.stderr)
                return 4
        finally:
            password = ""
            browser.close()

    try:
        oauth_and_proxy_pass(session_json)
    except RuntimeError as exc:
        print(f"[!] bootstrap token exchange failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] bootstrap token exchange failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    cleanup_legacy_credential_cache(remove_browser_storage=True)
    print("[*] bootstrap complete. Next:")
    print("    python refresh_tokens.py --force")
    print("    python ipp_pool.py token-status")
    print("    python ipp_pool.py run")
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        print(f"[!] bootstrap failed ({type(exc).__name__})", file=sys.stderr)
        exit_code = 1
    raise SystemExit(exit_code)
