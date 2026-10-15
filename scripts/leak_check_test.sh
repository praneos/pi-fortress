#!/bin/bash
# leak_check.sh against a fake tree. Each refusal is proved: the test plants
# the thing that the scanner refuses, and checks that the report names the
# file and line. No git, no network.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
fail() { echo "leak_check_test: $*" >&2; exit 1; }

# The examples that the docs and lab legitimately carry, so a pass proves the
# allow rules and not only an empty tree.
fresh() {
  rm -rf "${tmp}/src"
  mkdir -p "${tmp}/src/scripts" "${tmp}/src/docs" "${tmp}/src/vm/agent" "${tmp}/src/vendor/x" "${tmp}/src/vm/cloudlab/.vagrant"
  cp "${here}/scripts/leak_check.sh" "${here}/scripts/leak_check_test.sh" "${tmp}/src/scripts/"
  cat >"${tmp}/src/docs/guide.md" <<'EOF'
# Guide

See docs/risk_model.md and docs/user_guide/home_network.md.
curl -H 'Authorization: Bearer sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' https://pf-open-echo.test/
HOUSE_DOT_AUTH_NAME=abcd1234xyz.dns.controld.com
Keys look like sk-ant-api03-... and stay on the Pi.
EOF
  cat >"${tmp}/src/vm/agent/provision.sh" <<'EOF'
install -m 0600 /home/vagrant/.ssh/authorized_keys /home/agent/.ssh/authorized_keys
PrivateKey = ${priv}
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
EOF
  # Never published, so never scanned.
  echo "see TODO.md" >"${tmp}/src/vendor/x/README"
  echo "/home/someone/.ssh" >"${tmp}/src/vm/cloudlab/.vagrant/state"
  mkdir -p "${tmp}/src/.wrangler/cache"
  echo "/home/someone/x" >"${tmp}/src/.wrangler/cache/wrangler-account.json"
  # In a worktree, .git is a file that names the path of the main clone.
  echo "gitdir: /home/someone/src/.git/worktrees/x" >"${tmp}/src/.git"
}
run() { "${tmp}/src/scripts/leak_check.sh" "$@" >"${tmp}/out.log" 2>&1; }

fresh
run || fail "a clean tree failed: $(cat "${tmp}/out.log")"

marker="pf-private-""do-not-publish"
key="sk-ant-api03-$(printf 'x%.0s' {1..48})"
for leak in \
  "<!-- ${marker} -->" \
  'design notes: ../private/roadmap/DESIGN.md' \
  'see private/security/review' \
  'order of work: `PLAN.md`' \
  'cutover: docs/house_segment.md' \
  'plan: docs/upgrade_rollback_plan.md' \
  'audit: docs/review/resource_limits_audit.md' \
  'checked by hand, pi_checklist section 3' \
  "${key}" \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ${key}" \
  'PrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=' \
  '-----BEGIN OPENSSH PRIVATE KEY-----' \
  'token ghp_ABCDEFGHIJKLMNOPQRST' \
  'see /home/someone/x' \
  'install /home/vagrant/x /home/owner/x' \
  'profile qwertyuiop.dns.controld.com' \
  'mail me at someone@gmail.com'; do
  fresh
  printf '\n%s\n' "${leak}" >>"${tmp}/src/docs/guide.md"
  ! run || fail "a leak passed: ${leak}"
  grep -qF 'docs/guide.md:8:' "${tmp}/out.log" || fail "the leak was not named as file:line: ${leak}: $(cat "${tmp}/out.log")"
done

# The details of the owner come from a file outside the public tree. Its
# comments are not patterns, and a broken pattern is an error, not a pass.
fresh
printf '# my login\nowner-login-x\n\n10\\.1\\.2\\.3\n' >"${tmp}/own.txt"
printf '\nssh owner-login-x@pi\n' >>"${tmp}/src/docs/guide.md"
run || fail "the owner's detail was flagged with no pattern file"
! LEAK_CHECK_PATTERNS="${tmp}/own.txt" run || fail "the owner's detail passed"
grep -qF 'owner detail: docs/guide.md:8:' "${tmp}/out.log" || fail "the owner's detail was not named: $(cat "${tmp}/out.log")"
fresh
printf '\n# my login\n' >>"${tmp}/src/docs/guide.md"
LEAK_CHECK_PATTERNS="${tmp}/own.txt" run || fail "a pattern file comment was used as a pattern: $(cat "${tmp}/out.log")"
printf '(unclosed\n' >"${tmp}/bad.txt"
rc=0
LEAK_CHECK_PATTERNS="${tmp}/bad.txt" run || rc=$?
[[ "${rc}" -eq 2 ]] || fail "a broken pattern did not stop the scan (exit ${rc})"

# A FILE list scans only those files, and skips a file that the commit
# deletes. It never scans the excluded trees, even when they are named.
fresh
printf '\nsee TODO.md\n' >>"${tmp}/src/docs/guide.md"
run -C "${tmp}/src" vm/agent/provision.sh docs/gone.md vendor/x/README || fail "a FILE list scanned beyond itself: $(cat "${tmp}/out.log")"
! run -C "${tmp}/src" docs/guide.md || fail "a leak in a listed file passed"
grep -qF 'docs/guide.md:8:' "${tmp}/out.log" || fail "a listed file's leak was not named"
! run -C "${tmp}/src" docs || fail "a leak under a listed directory passed"
grep -qF 'docs/guide.md:8:' "${tmp}/out.log" || fail "a listed directory's leak was not named"
run -C "${tmp}/src" vm vendor || fail "a directory list scanned beyond itself: $(cat "${tmp}/out.log")"

# -C points the scan at a different tree, as the hooks scan the index or
# a pushed commit instead of the working copy.
fresh
mkdir -p "${tmp}/other/docs"
echo "see later.md" >"${tmp}/other/docs/x.md"
! "${tmp}/src/scripts/leak_check.sh" -C "${tmp}/other" >"${tmp}/out.log" 2>&1 || fail "-C did not scan the other tree"
grep -qF 'docs/x.md:1:' "${tmp}/out.log" || fail "-C did not name the other tree's file"

echo "leak_check_test: ok"
