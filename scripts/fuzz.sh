#!/bin/bash
# Run every Fuzz* target in the module for a fixed time each.
# usage: scripts/fuzz.sh [seconds] [package-pattern]
set -euo pipefail

secs="${1:-15}"
pattern="${2:-./internal/...}"
go="${GO:-go}"

fail=0
for pkg in $("${go}" list "${pattern}"); do
  targets="$("${go}" test "${pkg}" -run '^$' -list '^Fuzz' 2>/dev/null | grep '^Fuzz' || true)"
  [[ -z "${targets}" ]] && continue
  for fz in ${targets}; do
    printf '%-32s %-30s ' "${pkg#pi-fortress/}" "${fz}"
    if out="$("${go}" test "${pkg}" -run '^$' -fuzz "^${fz}\$" -fuzztime "${secs}s" 2>&1)"; then
      # A target that calls f.Skip passes without a fuzz run, and prints no
      # progress line. Say so, and do not leave the row blank.
      line="$(echo "${out}" | grep -E '^fuzz: elapsed' | tail -1 | sed -E 's/.*execs: ([0-9]+).*new interesting: [0-9]+ \(total: ([0-9]+)\).*/execs=\1 corpus=\2/' || true)"
      echo "${line:-skipped (no fuzzing ran)}"
    else
      echo "FAIL"
      # All except the progress lines. Never let this pipeline decide the
      # fate of the script. A worker killed for memory prints no panic, no
      # stack and no assertion. So the old grep for those matched nothing and
      # exited 1. Under pipefail and set -e, that stopped the suite here,
      # before `fail=1`. It silently skipped each remaining target, but still
      # exited 1 like an ordinary failure.
      echo "${out}" | grep -vE '^fuzz: (elapsed|minimizing)' | sed 's/^/    /' || true
      fail=1
    fi
  done
done
exit "${fail}"
