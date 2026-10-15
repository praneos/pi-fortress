#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
echo "===== pi-fortress ====="
vagrant ssh pi -c "sudo /usr/local/sbin/pf status"
echo
echo "===== agent ====="
vagrant ssh agent -c "ip -br addr; echo; ip route; echo; cat /etc/resolv.conf"
