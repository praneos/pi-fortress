#!/bin/bash
# Proves that hygiene.list, seal-image.sh and image-lint.sh agree, on a
# fake root in a temp dir. A clean root passes. Each row, planted alone,
# fails the lint for its roles and not for the other role. seal-image on
# a root that has all rows makes it clean.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
list="${here}/hygiene.list"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() {
  echo "lint_test: $*" >&2
  exit 1
}

# fresh ROLE: an empty root with the role file and locked accounts.
fresh() {
  rm -rf "${tmp}/root"
  mkdir -p "${tmp}/root/etc/pi-fortress"
  echo "$1" >"${tmp}/root/etc/pi-fortress/appliance.role"
  printf 'root:!:19000::::::\nvagrant:*:19000::::::\ntester:!:19000::::::\n' >"${tmp}/root/etc/shadow"
}

# plant CHECK PATTERN: make the row fire under the fake root. A glob
# becomes one concrete name with every * replaced by x.
plant() {
  local check=$1 pattern=$2 p
  case "${check}" in
    absent | empty)
      p="${tmp}/root${pattern//\*/x}"
      mkdir -p "$(dirname "${p}")"
      echo leaked >"${p}"
      ;;
    locked)
      sed -i -E "s/^(${pattern}):[^:]*:/\1:\$6\$salt\$hash:/" "${tmp}/root/etc/shadow"
      ;;
  esac
}

lint() { bash "${here}/image-lint.sh" "$1" "${tmp}/root" 2>"${tmp}/lint.err" >/dev/null; }

for role in fence agent; do
  fresh "${role}"
  lint "${role}" || fail "clean ${role} root fails: $(cat "${tmp}/lint.err")"
done

rows=0
while read -r role check pattern; do
  [[ -z "${role}" || "${role}" == \#* ]] && continue
  rows=$((rows + 1))
  for target in fence agent; do
    fresh "${target}"
    plant "${check}" "${pattern}"
    if [[ "${role}" == both || "${role}" == "${target}" ]]; then
      if lint "${target}"; then
        fail "${target}: planted '${check} ${pattern}' and the lint passed"
      fi
      if [[ "${check}" != locked ]] && ! grep -qF "${pattern//\*/x}" "${tmp}/lint.err"; then
        fail "${target}: lint did not name ${pattern//\*/x}: $(cat "${tmp}/lint.err")"
      fi
    elif ! lint "${target}"; then
      fail "${target}: '${role} ${check} ${pattern}' is not its row, yet the lint failed: $(cat "${tmp}/lint.err")"
    fi
  done
done <"${list}"
[[ "${rows}" -gt 40 ]] || fail "only ${rows} rows read from ${list}"

# An empty password is an open login, not a locked one.
fresh agent
sed -i 's/^vagrant:\*:/vagrant::/' "${tmp}/root/etc/shadow"
lint agent && fail "empty vagrant password passed the lint"

for role in fence agent; do
  fresh "${role}"
  while read -r r check pattern; do
    [[ -z "${r}" || "${r}" == \#* ]] && continue
    plant "${check}" "${pattern}"
  done <"${list}"
  echo 'dot' >"${tmp}/root/vagrant/.hidden"
  lint "${role}" && fail "${role}: fully planted root passed before sealing"
  bash "${here}/seal-image.sh" "${role}" "${tmp}/root" >/dev/null ||
    fail "${role}: seal-image failed"
  lint "${role}" || fail "${role}: still dirty after seal-image: $(cat "${tmp}/lint.err")"
  [[ -f "${tmp}/root/etc/machine-id" && ! -s "${tmp}/root/etc/machine-id" ]] ||
    fail "${role}: machine-id should be kept and emptied"
done

fresh fence
bash "${here}/seal-image.sh" agent "${tmp}/root" >/dev/null 2>&1 &&
  fail "seal-image ran against a root installed as the other role"

echo "lint_test: ok (${rows} rows)"
