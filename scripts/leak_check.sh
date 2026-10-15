#!/bin/bash
# Refuses anything in this public tree that belongs to the private
# workspace beside it: the private marker, a path into that workspace,
# the name of a doc that exists only there, a key, or a private detail.
# Each hit is named as file:line. No git, no network.
#
#   scripts/leak_check.sh                 the whole tree
#   scripts/leak_check.sh PATH...         only these files and directories
#   scripts/leak_check.sh -C DIR [PATH...]  paths relative to DIR, e.g. a
#                                         checkout of the index or a commit
#   LEAK_CHECK_PATTERNS=FILE ...          the owner's own details, one ERE
#                                         a line (# comments); default
#                                         ../private/security/leak_patterns.txt
#                                         beside the repo, skipped if absent
#
# The username, addresses and similar details of the owner are not in this
# file: a public scanner that names them publishes them.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
own_patterns="${LEAK_CHECK_PATTERNS:-${root}/../private/security/leak_patterns.txt}"
[[ "${own_patterns}" == /* ]] || own_patterns="${PWD}/${own_patterns}"
if [[ "${1:-}" == -C ]]; then
  [[ -n "${2:-}" ]] || { echo "usage: $0 [-C DIR] [PATH...]" >&2; exit 2; }
  root="$2"
  shift 2
fi
[[ "${1:-}" == -- ]] && shift
cd "${root}"

# Never published: excluded from the whole-tree walk and from a FILE list.
# .git is also pruned as a file: in a worktree, it names the main clone.
# The scanner and its test spell out each pattern below, so they are the
# only files exempt from it.
skip_prefixes=(.git/ vendor/ bin/ build/ dist/ vm/cloudlab/.vagrant/ .wrangler/)
self=(scripts/leak_check.sh scripts/leak_check_test.sh)

skipped() {
  local p="${1#./}" s
  for s in "${skip_prefixes[@]}"; do
    [[ "${p}" == "${s}"* ]] && return 0
  done
  for s in "${self[@]}"; do
    [[ "${p}" == "${s}" ]] && return 0
  done
  return 1
}

files=()
[[ $# -gt 0 ]] || set -- .
for f in "$@"; do
  if [[ -d "${f}" ]]; then
    while IFS= read -r -d '' g; do
      skipped "${g}" || files+=("${g#./}")
    done < <(find "${f}" \( -name .git -o -type d -name .vagrant \) -prune -o -type f -print0)
  # A FILE list from git can name a path the commit deletes.
  elif [[ -f "${f}" ]]; then
    skipped "${f}" || files+=("${f#./}")
  fi
done

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "leak_check: nothing to scan"
  exit 0
fi

# Assembled at run time so this file never carries the marker itself.
marker="pf-private-""do-not-publish"

# Docs that moved to the private workspace. A pointer to one is a dead
# link for each reader, and a map of what is not public.
private_docs='(^|[^A-Za-z0-9_])(TODO|PLAN|PRIORITY_TASKS|DESIGN|VISION|later|appliance)\.md|positioning_v0|suggested_fixes|docs/review|resource_limits_audit|codereview|glm_security_audit|pi_checklist|pi_validation|sandbox_today|threat_model|house_segment|pi5_setup|claude-tokens|(dot_native|go_dns|policed_segments|device_stats|ja4_anomaly|upgrade_rollback|vlan_split)_plan|README_internal|INDEX_internal'

# Fixtures that are secret-shaped on purpose: the tests of the scanner
# itself, and the fakes that the fence must redact. Exempt from the key rule only.
key_fixtures=(internal/secretscan/scan_test.go internal/backup/backup_test.go internal/fence/stream_long_test.go internal/fence/bench_test.go)

# One rule per index: a label for the report, the pattern, and what the
# pattern may match without a leak. A line is a hit when the pattern
# still matches after each allowed match is cut out of it. So a canary
# beside a real key on one line does not hide the key.
# A real Anthropic key is 40+ characters after its prefix. The examples in
# the docs are "..." or the all-A canary. A WireGuard key rendered from a
# variable, or the all-A test key, is not a key. /home/ is the home of a
# user, unless it is the user of a lab VM. abcd1234xyz is the placeholder
# Control D profile id of the docs.
labels=("private marker" "private workspace path" "private doc name" "key" "private detail")
patterns=(
  "${marker}"
  'private/(roadmap|security|ops)|\.\./private/'
  "${private_docs}"
  '-----BEGIN [A-Z ]*PRIVATE KEY|PrivateKey *=|sk-ant-[a-z]+[0-9]+-[A-Za-z0-9_-]{40,}|ghp_[A-Za-z0-9]{20}'
  '/home/[a-z]|[a-z0-9]{10}\.dns\.controld\.com|@gmail\.com'
)
allows=(
  ""
  ""
  ""
  'sk-ant-[a-z]+[0-9]+-A{40,}|PrivateKey *= *(\$\{?[A-Za-z_]+|A{43}=)'
  '/home/(vagrant|agent|tester)([^A-Za-z0-9_-]|$)|abcd1234xyz\.dns\.controld\.com'
)
if [[ -f "${own_patterns}" ]]; then
  own=""
  while IFS= read -r p || [[ -n "${p}" ]]; do
    [[ -z "${p}" || "${p}" == \#* ]] && continue
    own+="${own:+|}(${p})"
  done <"${own_patterns}"
  if [[ -n "${own}" ]]; then
    labels+=("owner detail")
    patterns+=("${own}")
    allows+=("")
  fi
fi

fixture() {
  local f
  for f in "${key_fixtures[@]}"; do
    [[ "$1" == "${f}" ]] && return 0
  done
  return 1
}

hits=""
for i in "${!labels[@]}"; do
  label="${labels[i]}" pattern="${patterns[i]}" allow="${allows[i]}"
  # grep exits 1 on no match and 2 on an error. Only 2 is a failure, so a
  # broken pattern can never read as "nothing found".
  rc=0
  out="$(grep -nHIE -e "${pattern}" -- "${files[@]}")" || rc=$?
  [[ "${rc}" -le 1 ]] || { echo "leak_check: scan failed for ${label}" >&2; exit 2; }
  [[ -n "${out}" ]] || continue
  while IFS= read -r line; do
    file="${line%%:*}"
    [[ "${label}" == key ]] && fixture "${file}" && continue
    if [[ -n "${allow}" ]]; then
      content="${line#*:}"
      content="${content#*:}"
      while [[ "${content}" =~ ${allow} ]]; do
        content="${content/"${BASH_REMATCH[0]}"/}"
      done
      [[ "${content}" =~ ${pattern} ]] || continue
    fi
    hits+="  ${label}: ${line:0:200}"$'\n'
  done <<<"${out}"
done

if [[ -n "${hits}" ]]; then
  printf 'leak_check: refusing, private content in the public tree:\n%s' "${hits}" >&2
  exit 1
fi
echo "leak_check: ${#files[@]} files clean"
