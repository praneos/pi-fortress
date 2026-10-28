#!/bin/bash
# Runs a full apply.sh (not --render-nft) as first boot does on a sealed
# fence, with no root, systemd or kernel. Each absolute path that the
# script touches moves under a fake root. The system commands are stubs.
# Two roots from one tree: lab, where /vagrant is the checkout, and
# appliance, with no /vagrant and the tree put in place by tree.sh. Both
# must apply, with a feed fetch that fails as it would offline. Both must
# write the same ruleset, generated configs and units.
set -euo pipefail

# apply.sh and its libs refuse to run when the user is not root on a
# gateway (vm/pi/lib/guard.sh). This harness runs them with stub tools in
# a fake root, so it lets them run.
export PF_TEST_HARNESS=1

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
PF_BIN="${PF_BIN:-${repo}/bin/pf}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() {
  echo "appliance apply_test: $*" >&2
  exit 1
}
[[ -x "${PF_BIN}" ]] || fail "no pf at ${PF_BIN} (make pf, or set PF_BIN)"

# render refuses a WAN_IF that the kernel does not have (net.InterfaceByName,
# so the ip stub cannot fake it). Use any real non-loopback name.
wan_if="$(ls /sys/class/net 2>/dev/null | grep -vx lo | head -1 || true)"
if [[ -z "${wan_if}" ]]; then
  echo "appliance apply_test: skipped, no non-loopback interface"
  exit 0
fi

# The checkout, with a stand-in feed and the files that must stay behind.
src="${tmp}/src"
mkdir -p "${src}/vm/agent" "${src}/bin"
cp -a "${repo}/vm/pi" "${repo}/vm/policy" "${src}/vm/"
cp "${repo}/vm/agent/setup.sh" "${src}/vm/agent/"
rm -rf "${src}/vm/pi/pf" "${src}/vm/policy/generated"
mkdir "${src}/vm/policy/generated"
echo 'blocked.example' >"${src}/vm/policy/generated/blacklist.domains"
echo '192.0.2.66' >"${src}/vm/policy/generated/blacklist.ips"
echo 'DECOY' >"${src}/vm/policy/alert.url"
for f in agent-env-1.sh agent-credentials-1.json mitm-ca.pem egress-ca.pem; do
  echo 'DECOY' >"${src}/vm/policy/generated/${f}"
done
# pf with a feed download that fails: a first boot behind a dead NAT
# adapter. apply gets the lists through pf feeds run.
printf '#!/bin/bash\n[[ "$1" == feeds ]] && exit 1\nexec %q "$@"\n' "${PF_BIN}" >"${src}/bin/pf"
chmod 0755 "${src}/bin/pf"

stubs="${tmp}/stubs"
mkdir "${stubs}"
for c in nft systemctl dnsmasq useradd groupadd usermod getent chown sysctl journalctl; do
  printf '#!/bin/sh\nexit 0\n' >"${stubs}/${c}"
done
printf '#!/bin/sh\necho "2: lo    inet 10.77.0.1/24"\n' >"${stubs}/ip"
# No pf-broker process survives the broker stop in a fake root.
printf '#!/bin/sh\nexit 1\n' >"${stubs}/pgrep"
cat >"${stubs}/install" <<'EOF'
#!/bin/bash
a=()
while [[ $# -gt 0 ]]; do
  case "$1" in -o | -g) shift 2 ;; *) a+=("$1"); shift ;; esac
done
exec /usr/bin/install "${a[@]}"
EOF
chmod 0755 "${stubs}"/*

# The PATH of the run is the stubs plus these host tools, and nothing else.
# Thus apply can never reach the nmcli, wg, ip or services of the host. On
# a desktop, the old ${PATH} tail let it reload NetworkManager.
safebin="${tmp}/safebin"
mkdir "${safebin}"
for c in bash sh env cat cp mv rm rmdir mkdir chmod ln ls sed grep awk head tail tr cut sort uniq wc date mktemp dirname basename readlink realpath touch cmp id sleep flock stat find diff tee xargs true false; do
  if p="$(type -P "${c}")"; then
    ln -s "${p}" "${safebin}/${c}"
  fi
done

# rewrite SCRIPT ROOT: apply.sh with its absolute paths under ROOT.
rewrite() {
  sed -E -e 's#"\$\{EUID\}" -ne 0#1 -ne 1#' \
    -e "s#(^|[^A-Za-z0-9_.~/-])/(etc|usr/local|var|run|vagrant)(/|[^A-Za-z0-9_.-]|\$)#\1$2/\2\3#g" "$1" >"$1.new"
  mv "$1.new" "$1"
}

# run ROOT: apply as pf apply execs it, lab first in the scriptDirs order.
run() {
  local root=$1 script=$1/usr/local/lib/pi-fortress/apply.sh
  [[ -f "$1/vagrant/vm/pi/apply.sh" ]] && script=$1/vagrant/vm/pi/apply.sh
  rewrite "${script}" "${root}"
  mkdir -p "${root}/usr/local/sbin" "${root}/etc/systemd/system"
  PATH="${stubs}:${safebin}" PF_ALLOW_ANY_HOST=1 PF_INT_IF=lo PF_WAN_IF="${wan_if}" \
    bash "${script}" >"${root}.log" 2>&1 || { tail -20 "${root}.log" >&2; fail "apply failed under ${root##*/}"; }
  if grep -q 'command not found' "${root}.log"; then
    grep 'command not found' "${root}.log" | sort -u >&2
    fail "apply under ${root##*/} reached a command that is neither stubbed nor allowed"
  fi
}

lab="${tmp}/lab"
mkdir -p "${lab}/vagrant"
cp -a "${src}/vm" "${src}/bin" "${lab}/vagrant/"
run "${lab}"

app="${tmp}/appliance"
bash "${here}/tree.sh" "${src}" "${app}" >/dev/null
install -D -m 0755 "${src}/bin/pf" "${app}/usr/local/sbin/pf"
[[ ! -e "${app}/vagrant" ]] || fail "the appliance root has a /vagrant"
run "${app}"
grep -q 'exported CA to .*/appliance/etc/pi-fortress/generated/egress-ca.pem' "${app}.log" ||
  fail "appliance apply did not take the /etc/pi-fortress branch"

# Same outputs, except the per-run CA and the alert.url that only the lab has.
cmp -s "${lab}/etc/nftables.conf" "${app}/etc/nftables.conf" || {
  diff -u "${lab}/etc/nftables.conf" "${app}/etc/nftables.conf" | head -20 >&2
  fail "the appliance ruleset differs from the lab's"
}
grep -q '192.0.2.66' "${app}/etc/nftables.conf" || fail "the seeded feed did not reach the ruleset"
n=0
while IFS= read -r rel; do
  case "${rel}" in *ca.pem | *ca-cert.pem | etc/pi-fortress/alert.url) continue ;; esac
  [[ -f "${app}/${rel}" ]] || fail "appliance apply did not write ${rel}"
  sed "s#${lab}/vagrant/vm/policy#P#g; s#${lab}/etc/pi-fortress#P#g; s#${lab}#R#g" "${lab}/${rel}" >"${tmp}/a"
  sed "s#${app}/etc/pi-fortress#P#g; s#${app}#R#g" "${app}/${rel}" >"${tmp}/b"
  diff -u "${tmp}/a" "${tmp}/b" >&2 || fail "${rel} differs between lab and appliance"
  n=$((n + 1))
done < <(cd "${lab}" && find etc/pi-fortress etc/systemd var/lib/pi-fortress/www -type f ! -path '*/broker/*' | sort)
[[ "${n}" -gt 20 ]] || fail "only ${n} files compared"
for u in broker engine www observe alert; do
  [[ -f "${app}/etc/systemd/system/pi-fortress-${u}.service" ]] || fail "appliance apply installed no pi-fortress-${u}.service"
done
if grep -rlq DECOY "${app}"; then
  fail "tree.sh copied a file that must stay behind: $(grep -rl DECOY "${app}" | head -3 | tr '\n' ' ')"
fi
echo "appliance apply_test: ok (${n} files match the lab)"
