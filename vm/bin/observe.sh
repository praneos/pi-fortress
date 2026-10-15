#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
cmd="${1:-once}"
vagrant ssh pi -c "sudo /usr/local/sbin/pf observe ${cmd}"
