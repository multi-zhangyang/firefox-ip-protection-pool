#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SERVICE_NAME="${IPP_SERVICE_NAME:-ipp-pool.service}"

# This helper intentionally performs a systemd restart; use systemctl status for a read-only check.
systemctl restart "$SERVICE_NAME"
sleep 2
systemctl --no-pager --full status "$SERVICE_NAME"

echo "Authentication file, when used: tokens/proxy_listen_auth.txt (contents omitted)"
echo "Exported endpoints: export/public_endpoints.txt"
