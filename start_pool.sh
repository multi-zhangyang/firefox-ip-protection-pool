#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
systemctl restart ipp-pool.service
sleep 2
systemctl --no-pager --full status ipp-pool.service | head -20
ss -lntp | grep -E '0.0.0.0:(1090|8080|21000|31000)' || true
echo "auth file: tokens/proxy_listen_auth.txt"
echo "endpoints: export/public_endpoints.txt"
