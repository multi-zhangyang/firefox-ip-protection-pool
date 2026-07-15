# firefox-ip-protection-pool

Turn **Firefox IP Protection** (the browser built-in VPN / IP protection feature) multi-country exits into a local or public **SOCKS5 + HTTP proxy pool**.

> For users who already have legitimate access to Firefox IP Protection.  
> This tool does **not** bypass eligibility, quotas, or Mozilla account protections.

## What this is

Firefox IP Protection is **not** the standalone Mozilla VPN / WireGuard product.

Under the hood it works roughly like:

```text
Firefox Account (FxA)
  -> Guardian API (vpn.mozilla.org) issues short-lived ProxyPass JWT
  -> browser uses HTTPS CONNECT (and can use MASQUE) to Fastly exits
  -> destinations see Fastly egress IPs
```

This repo recreates that path outside the browser:

```text
your app
  -> local SOCKS5/HTTP (per-country or rotating front)
  -> this pool opens TLS + CONNECT to *.m1.fastly-masque.net:2499
  -> Proxy-Authorization: Bearer <ProxyPass JWT>
  -> Fastly exit reaches the target site
```

## Features

- Multi-country exits from Firefox Remote Settings (`vpn-serverlist`)
- Per-country **SOCKS5** and **HTTP** listeners
- Single rotating front for all countries:
  - SOCKS5 rotator (default `:1090`)
  - HTTP rotator (default `:8080`)
- Optional listen auth (username/password) for public exposure
- Automatic ProxyPass refresh from a stored FxA session token
- systemd-friendly long-running mode
- No secrets committed — runtime credentials stay in local `tokens/`

## Requirements

- Python 3.10+
- Linux recommended
- A Firefox Account that can use IP Protection
- Network access to:
  - `api.accounts.firefox.com`
  - `oauth.accounts.firefox.com`
  - `vpn.mozilla.org`
  - `*.m1.fastly-masque.net`

Install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional (bootstrap automation only):

```bash
playwright install firefox
```

## Quick start

### 1) Prepare auth material

You need either:

- **A.** ProxyPass JWT (short-lived), or
- **B.** FxA session token (recommended for long-running refresh)

Place files under `tokens/` (never commit them):

```bash
mkdir -p tokens

# recommended for long-running mode
echo 'YOUR_FXA_SESSION_TOKEN' > tokens/session_token.txt

cat > tokens/account_meta.json <<'JSON'
{
  "email": "you@example.com",
  "uid": "your-fxa-uid",
  "sessionToken": "YOUR_FXA_SESSION_TOKEN"
}
JSON

# optional direct ProxyPass JWT
# echo 'eyJ...' > tokens/proxy_pass.jwt
```

Examples:

- `tokens/account_meta.example.json`
- `tokens/proxy_listen_auth.example.txt`

### 2) Refresh ProxyPass

```bash
python refresh_tokens.py
python ipp_pool.py token-status
python ipp_pool.py probe --country US
```

### 3) Run the pool (localhost)

```bash
python ipp_pool.py run \
  --bind 127.0.0.1 \
  --advertise-host 127.0.0.1 \
  --limit 15 \
  --countries US,JP,DE,SG,GB,FR,NL,CA,AU,SE,IE,IT,ES,BE,DK \
  --rotator 127.0.0.1:1090 \
  --http-rotator 127.0.0.1:8080
```

Test:

```bash
curl -x socks5h://127.0.0.1:21000 https://ipinfo.io/json
curl -x http://127.0.0.1:31000 https://ipinfo.io/json
curl -x socks5h://127.0.0.1:1090 https://ipinfo.io/ip
curl -x http://127.0.0.1:8080 https://ipinfo.io/ip
```

### 4) Public exposure (optional)

If you bind on `0.0.0.0`, **use listen auth**:

```bash
cat > tokens/proxy_listen_auth.txt <<'EOF'
USER=ipp
PASS=change-me-to-a-strong-password
EOF
chmod 600 tokens/proxy_listen_auth.txt

python ipp_pool.py run \
  --bind 0.0.0.0 \
  --advertise-host YOUR.PUBLIC.IP \
  --require-auth \
  --auth-user ipp \
  --auth-pass 'change-me-to-a-strong-password' \
  --limit 15 \
  --countries US,JP,DE,SG,GB,FR,NL,CA,AU,SE,IE,IT,ES,BE,DK \
  --rotator 0.0.0.0:1090 \
  --http-rotator 0.0.0.0:8080
```

Then:

```bash
curl -x socks5h://ipp:change-me@YOUR.PUBLIC.IP:1090 https://ipinfo.io/ip
curl -x http://ipp:change-me@YOUR.PUBLIC.IP:8080 https://ipinfo.io/ip
```

Open firewall ports as needed: `1090`, `8080`, `21000-21030`, `31000-31030`.

## systemd (recommended for always-on)

```bash
# install project somewhere stable, e.g. /opt/firefox-ip-protection-pool
cp examples/ipp-pool.service /etc/systemd/system/ipp-pool.service
# edit WorkingDirectory / ExecStart paths if needed
systemctl daemon-reload
systemctl enable --now ipp-pool.service
systemctl status ipp-pool
```

Helper scripts:

- `run_service.sh` — used by systemd
- `start_pool.sh` — simple restart wrapper (expects systemd unit)

Cron refresh (optional; pool also refreshes itself):

```cron
*/4 * * * * cd /path/to/firefox-ip-protection-pool && .venv/bin/python refresh_tokens.py >> logs/refresh.log 2>&1
```

## Port layout

| Kind | Default |
|------|---------|
| Per-country SOCKS5 | `21000+` |
| Per-country HTTP | `31000+` |
| All-country SOCKS rotator | `1090` |
| All-country HTTP rotator | `8080` |

Exports after start:

```text
export/socks5.txt
export/http.txt
export/socks5_urls.txt
export/http_urls.txt
export/pool.json
export/public_endpoints.txt
```

## CLI

```bash
python ipp_pool.py sync
python ipp_pool.py token-status
python ipp_pool.py token-refresh
python ipp_pool.py probe --country JP
python ipp_pool.py run --help
python refresh_tokens.py
python login_and_bootstrap.py --help
```

Useful `run` flags:

```text
--bind 0.0.0.0
--advertise-host 1.2.3.4
--limit 20
--countries US,JP,DE
--rotator 0.0.0.0:1090
--http-rotator 0.0.0.0:8080
--require-auth --auth-user USER --auth-pass PASS
```

## How auth refresh works

1. Read FxA `sessionToken` from `tokens/session_token.txt` / `account_meta.json`
2. Exchange for OAuth access token with scopes:
   - `profile`
   - `https://identity.mozilla.com/apps/vpn`
3. Call Guardian `GET /api/v1/fpn/token`
4. Save short-lived ProxyPass JWT to `tokens/proxy_pass.jwt`
5. Pool attaches `Proxy-Authorization: Bearer <jwt>` on each upstream CONNECT

ProxyPass JWT lifetime is short (minutes). Long-running mode relies on session-token refresh.

## Bootstrap notes

`login_and_bootstrap.py` can help obtain a session/token via browser automation, but:

- FxA may show CAPTCHA / email verification codes
- Some environments need extra anti-bot handling
- Prefer extracting tokens from your own already-logged-in Firefox when possible

Never commit:

- `tokens/session_token.txt`
- `tokens/fxa_token.txt`
- `tokens/proxy_pass.jwt`
- `tokens/proxy_listen_auth.txt`
- browser storage / cookies / logs

## Architecture notes

- Exit list source: Firefox Remote Settings collection `vpn-serverlist`
- Upstream host pattern: `*.m1.fastly-masque.net:2499`
- This implementation uses **HTTPS CONNECT** (TCP). Full MASQUE/UDP is not implemented.
- Same country can still rotate among multiple Fastly egress IPs.

## Security

- If exposed on the public internet, always enable listen auth.
- Rotate listen passwords regularly.
- Treat FxA session tokens as high-value secrets.
- This software is not a commercial residential proxy product.

## Disclaimer

This project is an independent tooling effort and is not affiliated with Mozilla or Fastly.  
Use only with accounts and networks you are authorized to use, and respect applicable terms of service and laws.

## License

MIT
