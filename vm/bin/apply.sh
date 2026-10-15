#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
if [[ "${1:-}" == "--local" ]]; then
  vagrant ssh pi -c "sudo /usr/local/sbin/pf apply --local"
  exit 0
fi
if command -v go >/dev/null 2>&1; then
  make split-bin
fi
vagrant ssh pi -c "sudo /usr/local/sbin/pf apply"
vagrant ssh agent -c "sudo bash /vagrant/vm/agent/routes.sh"
