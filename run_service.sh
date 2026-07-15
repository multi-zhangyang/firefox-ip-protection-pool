#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PY="${PWD}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY=python3
fi
AUTH_FILE=tokens/proxy_listen_auth.txt
mkdir -p logs tokens data export

PUBLIC_IP=$(curl -4 -sS --max-time 8 https://ifconfig.me || curl -4 -sS --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')
if [[ ! -f "$AUTH_FILE" ]]; then
  echo "missing $AUTH_FILE (copy tokens/proxy_listen_auth.example.txt)" >&2
  exit 1
fi
AUTH_USER=$(awk -F= '/^USER=/{print $2}' "$AUTH_FILE" | tr -d '\r')
AUTH_PASS=$(awk -F= '/^PASS=/{print $2}' "$AUTH_FILE" | tr -d '\r')
if [[ -z "${AUTH_USER}" || -z "${AUTH_PASS}" ]]; then
  echo "missing listen auth in $AUTH_FILE" >&2
  exit 1
fi

$PY refresh_tokens.py >> logs/refresh.log 2>&1 || true

exec $PY ipp_pool.py run \
  --bind 0.0.0.0 \
  --advertise-host "$PUBLIC_IP" \
  --require-auth \
  --auth-user "$AUTH_USER" \
  --auth-pass "$AUTH_PASS" \
  --limit 15 \
  --countries US,JP,DE,SG,GB,FR,NL,CA,AU,SE,IE,IT,ES,BE,DK \
  --rotator 0.0.0.0:1090 \
  --http-rotator 0.0.0.0:8080
