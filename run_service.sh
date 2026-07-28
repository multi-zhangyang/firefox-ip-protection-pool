#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -n "${IPP_PYTHON:-}" ]]; then
  PYTHON_BIN="$IPP_PYTHON"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

if [[ "$PYTHON_BIN" == */* ]]; then
  if [[ ! -x "$PYTHON_BIN" ]]; then
    echo "Python executable is not available: $PYTHON_BIN" >&2
    exit 1
  fi
elif ! command -v -- "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable is not available: $PYTHON_BIN" >&2
  exit 1
fi

BIND="${IPP_BIND:-127.0.0.1}"
ADVERTISE_HOST="${IPP_ADVERTISE_HOST:-$BIND}"
COUNTRIES="${IPP_COUNTRIES:-}"
LIMIT="${IPP_LIMIT:-}"
ROTATE_MODE="${IPP_ROTATE_MODE:-random}"
REFRESH_BEFORE_START="${IPP_REFRESH_BEFORE_START:-1}"

case "$ROTATE_MODE" in
  random|rr) ;;
  *)
    echo "IPP_ROTATE_MODE must be 'random' or 'rr'" >&2
    exit 2
    ;;
esac

case "$REFRESH_BEFORE_START" in
  0|1) ;;
  *)
    echo "IPP_REFRESH_BEFORE_START must be '0' or '1'" >&2
    exit 2
    ;;
esac

if [[ -n "$LIMIT" && ( ! "$LIMIT" =~ ^[0-9]+$ || "$LIMIT" == 0 ) ]]; then
  echo "IPP_LIMIT must be a positive integer or empty" >&2
  exit 2
fi

listen_host="$BIND"
if [[ "$listen_host" == *:* && "$listen_host" != \[*\] ]]; then
  listen_host="[$listen_host]"
fi
ROTATOR="${IPP_ROTATOR:-$listen_host:1090}"
HTTP_ROTATOR="${IPP_HTTP_ROTATOR:-$listen_host:8080}"

mkdir -p logs tokens data export

if [[ "$REFRESH_BEFORE_START" == 1 ]]; then
  # Use TokenStore's full state machine.  A normal fresh cache avoids network
  # work, while an expired rate-limit/auth block is forced through real
  # revalidation instead of being cleared merely because the old JWT is fresh.
  # Diagnostics are sanitized and remain visible in the terminal/journal.
  if ! "$PYTHON_BIN" ipp_pool.py token-refresh; then
    echo "Startup token refresh failed; trying the last-known-good token" >&2
  fi
fi

cmd=(
  "$PYTHON_BIN" ipp_pool.py run
  --bind "$BIND"
  --advertise-host "$ADVERTISE_HOST"
  --rotator "$ROTATOR"
  --http-rotator "$HTTP_ROTATOR"
  --rotate-mode "$ROTATE_MODE"
)

if [[ -n "$COUNTRIES" ]]; then
  cmd+=(--countries "$COUNTRIES")
fi
if [[ -n "$LIMIT" ]]; then
  cmd+=(--limit "$LIMIT")
fi

# Listen credentials are read by ipp_pool.py from its auth file or environment,
# so passwords never need to be copied into process arguments here.
exec "${cmd[@]}"
