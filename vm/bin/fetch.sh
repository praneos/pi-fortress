#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
if [[ -x ./bin/pf ]]; then
  ./bin/pf fetch --policy vm/policy --out vm/policy/generated
else
  echo "bin/pf missing; run make pf" >&2
  exit 1
fi
