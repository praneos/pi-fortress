#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
cmd="${1:-show}"

case "${cmd}" in
  show|once)
    vagrant ssh pi -c "sudo /usr/local/sbin/pf alert ${cmd}"
    ;;
  follow)
    echo "watching strips (ctrl-c to stop)"
    vagrant ssh pi -c "sudo /usr/local/sbin/pf alert watch" | while IFS= read -r line; do
      printf '\a'
      echo "${line}"
      if command -v notify-send >/dev/null 2>&1; then
        notify-send -u critical "pi-fortress" "${line}" || true
      fi
    done
    ;;
  *)
    echo "usage: $0 show|follow|once" >&2
    exit 2
    ;;
esac
