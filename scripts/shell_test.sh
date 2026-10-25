#!/bin/bash
# Static robustness check over each shell script in the tree. The rest
# of the suite only examines RENDERED output (apply_test.sh greps
# nftables and rendered unit text). So a script that parses correctly and
# dies on the Pi passes it. netman.sh once shipped
#   local parent="$1" con="trunk-${parent}"
# and bash expands each argument to `local` before it assigns any of
# them. So con interpolated an empty parent, and set -u killed a real
# install. No root, no Pi, no network.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "${here}"

fail() { echo "shell_test: $*" >&2; exit 1; }

# The git hooks are also bash, under the names that git runs them by.
mapfile -t files < <({ find . -path ./vendor -prune -o -path ./dist -prune -o -name '*.sh' -print; find ./scripts/git-hooks -type f; } | sort)
[ "${#files[@]}" -gt 0 ] || fail "found no shell scripts"

for f in "${files[@]}"; do
  bash -n "${f}" || fail "${f}: syntax error"
done

# The shipped bug, checked directly so that it stays caught on a machine
# with no shellcheck. Flags a name assigned by local/export/... that a
# LATER assignment in the same statement reads back. The single-assignment
# `local PATH="$PATH:/x"` idiom reads the outer variable, and is fine.
selfref="$(awk '
/^[[:space:]]*(local|declare|typeset|export|readonly)[[:space:]]/ {
  n = 0; rest = $0; off = 0
  while (match(rest, /[A-Za-z_][A-Za-z0-9_]*=/)) {
    n++
    nm[n] = substr(rest, RSTART, RLENGTH - 1)
    at[n] = off + RSTART
    off += RSTART + RLENGTH - 1
    rest = substr(rest, RSTART + RLENGTH)
  }
  for (k = 1; k < n; k++) {
    tail = substr($0, at[k + 1])
    if (tail ~ ("\\$\\{?" nm[k] "([^A-Za-z0-9_]|$)"))
      printf "%s:%d: %s is read by a later assignment in the same statement; use two lines\n", FILENAME, FNR, nm[k]
  }
}' "${files[@]}")"
if [ -n "${selfref}" ]; then
  echo "${selfref}" >&2
  fail "self-referencing multi-assignment (see SC2318)"
fi

# Grandfathered: codes that the tree already trips. All else at each
# severity is enforced, so a new class of warning fails the suite.
exclude=SC1091,SC2001,SC2010,SC2015,SC2016,SC2030,SC2031,SC2034,SC2153

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shell_test: shellcheck not installed, skipping lint (apt install shellcheck)" >&2
  echo "shell_test: ${#files[@]} scripts parsed, self-reference check clean"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# One pass at each severity. The excluded codes are filtered after, so
# the backlog can be counted without a second shellcheck run.
# -s bash: some libraries are sourced and carry no shebang.
shellcheck -f gcc -s bash "${files[@]}" >"${tmp}/all" || true

if grep -vE "\[(${exclude//,/|})\]$" "${tmp}/all" | grep . >&2; then
  fail "shellcheck findings above"
fi

echo "shell_test: ${#files[@]} scripts clean (excluding ${exclude})"
# Informational only: an empty backlog must not fail the suite.
grep -o 'SC[0-9]*' "${tmp}/all" 2>/dev/null | sort | uniq -c | sort -rn |
  awk '{printf "  grandfathered backlog: %s x%s\n", $2, $1}' || true

# The refusals of install.sh itself (docs/gateway_install.md): no root, no
# network, no real Pi or second architecture needed. PF_TEST_UNAME_M,
# PF_TEST_OS_RELEASE and PF_TEST_MODEL are stand-ins for uname -m,
# /etc/os-release and /proc/device-tree/model, as the PF_TEST_MODEL of
# apply.sh is for apply_test.sh.
install_case() {
  local desc="$1" want="$2"
  shift 2
  local out status
  out="$("$@" 2>&1)" && status=0 || status=$?
  if [[ "${status}" -eq 0 ]]; then
    fail "install.sh ${desc}: expected a refusal, got exit 0: ${out}"
  fi
  if [[ "${out}" != *"${want}"* ]]; then
    fail "install.sh ${desc}: expected to see '${want}' in the refusal, got: ${out}"
  fi
}

supported_os="${tmp}/os-release-ubuntu2404"
cat >"${supported_os}" <<'EOF'
ID=ubuntu
VERSION_ID=24.04
VERSION_CODENAME=noble
EOF

old_os="${tmp}/os-release-ubuntu2004"
cat >"${old_os}" <<'EOF'
ID=ubuntu
VERSION_ID=20.04
VERSION_CODENAME=focal
EOF

install_case "with an unsupported architecture" "unsupported CPU architecture" \
  env PF_TEST_SKIP_ROOT=1 PF_TEST_UNAME_M=riscv64 bash install.sh

install_case "with an unsupported OS" "unsupported target" \
  env PF_TEST_SKIP_ROOT=1 PF_TEST_UNAME_M=x86_64 PF_TEST_OS_RELEASE="${old_os}" bash install.sh

# No settings: the tag comes from GitHub /releases/latest.
# PF_TEST_LATEST_URL stands in for that answer, so no case goes online.
gh=https://github.com/praneos/pi-fortress
bare=(env -u PF_RELEASE_URL -u PF_BUNDLE -u PF_VERSION PF_TEST_SKIP_ROOT=1 PF_TEST_UNAME_M=x86_64 PF_TEST_OS_RELEASE="${supported_os}")

install_case "with no release on GitHub yet" "no published release found" \
  "${bare[@]}" PF_TEST_LATEST_URL="${gh}/releases" bash install.sh

# The same refusal tells the user to build from source and where the
# steps are.
install_case "with no release on GitHub yet, the next step" "Build the bundle from source at the latest signed tag and install it with PF_BUNDLE; the steps are at https://pi-fortress.praneos.ai/pi_setup/" \
  "${bare[@]}" PF_TEST_LATEST_URL="${gh}/releases" bash install.sh

install_case "with a newest tag that is a path" "is not a release tag" \
  "${bare[@]}" PF_TEST_LATEST_URL="${gh}/releases/tag/../v1" bash install.sh

install_case "with its own PF_RELEASE_URL and no PF_VERSION" "with your own PF_RELEASE_URL" \
  "${bare[@]}" PF_RELEASE_URL=https://example.com/releases bash install.sh

# setsid: no controlling terminal, so the run stops at the terminal
# check, after the tag is chosen and before any download.
install_case "with no settings, the newest tag" "newest release is v0.9.0" \
  "${bare[@]}" PF_TEST_LATEST_URL="${gh}/releases/tag/v0.9.0" setsid -w bash install.sh

# A release-shaped bundle: the binary at vm/pi/pf and no bin/, named and
# listed in a signed SHA256SUMS as make release publishes it, and signed
# with a throwaway key. install.sh must verify it and give it to that
# binary.
rel="${tmp}/rel"
mkdir -p "${rel}/tree/vm/pi"
printf '#!/bin/sh\necho "fake pf $*"\n' >"${rel}/tree/vm/pi/pf"
chmod 0755 "${rel}/tree/vm/pi/pf"
b="${rel}/pf-bundle-v0.0.1-amd64.tar"
tar -cf "${b}" -C "${rel}/tree" vm
ssh-keygen -q -t ed25519 -N '' -C release@pi-fortress -f "${rel}/key"
ssh-keygen -q -Y sign -f "${rel}/key" -n pi-fortress-dist "${b}"
(cd "${rel}" && sha256sum pf-bundle-v0.0.1-amd64.tar >SHA256SUMS)
ssh-keygen -q -Y sign -f "${rel}/key" -n pi-fortress-dist "${rel}/SHA256SUMS"
out="$(env -u PF_RELEASE_URL PF_TEST_SKIP_ROOT=1 PF_TEST_UNAME_M=x86_64 PF_TEST_OS_RELEASE="${supported_os}" \
  PF_BUNDLE="${b}" PF_SIGNER_PUBKEY="$(cut -d' ' -f1,2 "${rel}/key.pub")" bash install.sh -yes 2>&1)" ||
  fail "install.sh: a signed release bundle without bin/ was refused: ${out}"
[[ "${out}" == *"fake pf install -bundle "* ]] || fail "install.sh: did not run the bundle's vm/pi/pf: ${out}"

echo "shell_test: install.sh refusals (arch, OS, newest-release defaults) clean"

# Tag and arch binding, https only, and no silent answers without a
# terminal, against a fake release and a fake curl.
bash scripts/install_test.sh

# The setup.sh of the agent refuses a ca.pem fetched over plain HTTP
# without the sha256 read from the Pi, and refuses before it fetches
# anything. Run from a copy with stubs for the root gate and the distro
# probe. A fake curl records whether it was called.
agent_setup="${tmp}/agent-setup.sh"
sed -e 's/^if \[\[ "\${EUID}" -ne 0 \]\]; then$/if false; then/' \
  -e 's/^FAMILY="\$(detect_family)"$/FAMILY=debian/' vm/agent/setup.sh >"${agent_setup}"
_stubs="$(grep -cE '^(if false; then|FAMILY=debian)$' "${agent_setup}" || true)"
[[ "${_stubs}" == 2 ]] || fail "agent setup.sh: the root gate or distro probe moved; update the stubs here"
mkdir -p "${tmp}/fakebin"
printf '#!/bin/sh\ntouch "%s/curl.ran"\nexit 22\n' "${tmp}" >"${tmp}/fakebin/curl"
chmod +x "${tmp}/fakebin/curl"
out="$(env -u PI_FORTRESS_CA PATH="${tmp}/fakebin:${PATH}" PI_FORTRESS_SKIP_NET=1 bash "${agent_setup}" 10.77.0.1 2>&1)" && status=0 || status=$?
[[ "${status}" -ne 0 ]] || fail "agent setup.sh: enrolled with no CA sha256: ${out}"
[[ "${out}" == *"sha256 is required"* ]] || fail "agent setup.sh: expected the missing-sha256 refusal, got: ${out}"
[[ ! -e "${tmp}/curl.ran" ]] || fail "agent setup.sh: fetched ca.pem before refusing for want of its sha256"
out="$(env -u PI_FORTRESS_CA PATH="${tmp}/fakebin:${PATH}" PI_FORTRESS_SKIP_NET=1 bash "${agent_setup}" 10.77.0.1 "$(printf 'ab%.0s' {1..32})" 2>&1)" || true
[[ -e "${tmp}/curl.ran" ]] || fail "agent setup.sh: did not fetch ca.pem with its sha256 given: ${out}"
rm -f "${tmp}/curl.ran"
out="$(env -u PI_FORTRESS_CA PATH="${tmp}/fakebin:${PATH}" PI_FORTRESS_SKIP_NET=1 INT_IF='eth0" accept' bash "${agent_setup}" 10.77.0.1 "$(printf 'ab%.0s' {1..32})" 2>&1)" && status=0 || status=$?
[[ "${status}" -ne 0 && "${out}" == *"is not an interface name"* ]] || fail "agent setup.sh: took an INT_IF the nft lock cannot carry: ${out}"
[[ ! -e "${tmp}/curl.ran" ]] || fail "agent setup.sh: fetched ca.pem before refusing a bad INT_IF"
echo "shell_test: agent setup.sh refuses an unpinned CA and a bad INT_IF clean"

# cut-nat.sh re-arms the NAT adapter of the agent VM when ssh on the
# sanctioned path fails, but only before that path was first proved. After
# that, a failed proof keeps it cut. A fake VBoxManage records what it was
# told, and a fake timeout makes each probe fail without network access.
cn="${tmp}/cutnat"
mkdir -p "${cn}/vm/agent" "${cn}/.vagrant" "${cn}/bin"
cp vm/agent/cut-nat.sh "${cn}/vm/agent/"
printf '#!/bin/sh\necho "$*" >>"%s/vbox.log"\n' "${cn}" >"${cn}/bin/VBoxManage"
printf '#!/bin/sh\nexit 1\n' >"${cn}/bin/timeout"
printf '#!/bin/sh\nexit 0\n' >"${cn}/bin/sleep"
chmod +x "${cn}/bin/"*
cutnat_case() {
  local desc="$1" marker="$2" want_rearm="$3" want_status="$4" out status
  rm -f "${cn}/vbox.log" "${cn}/.vagrant/pf-agent-provisioned"
  if [[ -n "${marker}" ]]; then
    printf '%s\n' "${marker}" >"${cn}/.vagrant/pf-agent-provisioned"
  fi
  out="$(PATH="${cn}/bin:${PATH}" bash "${cn}/vm/agent/cut-nat.sh" pi-fortress-agent 192.0.2.1 agent lab 2>&1)" && status=0 || status=$?
  [[ "${status}" == "${want_status}" ]] || fail "cut-nat.sh ${desc}: exit ${status}, want ${want_status}: ${out}"
  local log=""
  [[ -f "${cn}/vbox.log" ]] && log="$(<"${cn}/vbox.log")"
  if [[ "${want_rearm}" == 1 ]]; then
    [[ "${log}" == *"setlinkstate1 on"* ]] || fail "cut-nat.sh ${desc}: NAT adapter not re-armed: ${log}"
  else
    [[ "${log}" != *"setlinkstate1 on"* ]] || fail "cut-nat.sh ${desc}: NAT adapter re-armed: ${out}"
    [[ -f "${cn}/.vagrant/pf-agent-provisioned" ]] || fail "cut-nat.sh ${desc}: marker dropped"
  fi
}
cutnat_case "on a first proof that fails" "" 1 0
cutnat_case "with a marker from the other mode" "eth1" 1 0
cutnat_case "on a proved box whose ssh stopped answering" "lab" 0 1
echo "shell_test: cut-nat.sh keeps a proved box cut clean"
# lab_deps.sh trusts the HashiCorp apt key only when the file holds that
# one primary key: apt would also trust a second key. Throwaway keys in
# a scratch homedir, no network.
if command -v gpg >/dev/null 2>&1; then
  # shellcheck source=/dev/null
  source <(sed -n '/^key_fprs() {/,/^}/p' scripts/lab_deps.sh)
  declare -F key_fprs >/dev/null || fail "lab_deps.sh: key_fprs not found"
  g="${tmp}/gpg"
  mkdir -m 700 "${g}"
  gk() { gpg --homedir "${g}" --batch --quiet --pinentry-mode loopback --passphrase '' "$@" 2>/dev/null; }
  gk --quick-gen-key 'a <a@pf.test>' ed25519 sign never
  gk --quick-gen-key 'b <b@pf.test>' ed25519 sign never
  fa="$(gpg --homedir "${g}" --with-colons --list-keys a@pf.test 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
  gk --quick-add-key "${fa}" cv25519 encr never
  gk --armor --export a@pf.test >"${tmp}/a.asc"
  gk --armor --export a@pf.test b@pf.test >"${tmp}/ab.asc"
  echo 'not a key' >"${tmp}/junk.asc"
  gpgconf --homedir "${g}" --kill all 2>/dev/null || true
  [[ -n "${fa}" ]] || fail "lab_deps key check: could not make a test key"
  [[ "$(key_fprs "${g}" "${tmp}/a.asc")" == "${fa}" ]] || fail "lab_deps key check: one key with a subkey did not read as its primary fingerprint"
  [[ "$(key_fprs "${g}" "${tmp}/ab.asc")" != "${fa}" ]] || fail "lab_deps key check: a second key rode along unnoticed"
  [[ -z "$(key_fprs "${g}" "${tmp}/junk.asc")" ]] || fail "lab_deps key check: a non-key read as a fingerprint"
  echo "shell_test: lab_deps.sh apt key pin clean"
else
  echo "shell_test: gpg not installed, skipping the lab_deps.sh key check" >&2
fi

# vm/desk/setup.sh writes its interface names, VLAN ids and gateway into
# the boot-time nft lock, a root-run dispatcher and the restore wrapper.
# So it refuses anything that is not plainly one. A bogus subcommand
# stops at usage, after the check and before anything touches the host.
desk_case() {
  local want="$1" out status
  shift
  out="$(env -i PATH="${PATH}" "$@" bash vm/desk/setup.sh bogus 2>&1)" && status=0 || status=$?
  [[ "${out}" == *"${want}"* ]] || fail "desk setup.sh with $*: expected '${want}', got (exit ${status}): ${out}"
}
desk_case "not an interface name" PARENT='enp6s0" accept'
desk_case "not an interface name" PARENT="$(printf 'enp6s0\nx')"
desk_case "not an interface name" PARENT=abcdefghijklmnop
desk_case "not an interface name" PF_LAB=1 AGENT_IF='a|b'
desk_case "not a VLAN id" PARENT=enp6s0 AGENT_VLAN=4095
desk_case "not a VLAN id" PARENT=enp6s0 DESK_VLAN=07
desk_case "not an IPv4 address" PARENT=enp6s0 DESK_GW='10.79.0.1;x'
desk_case "usage:" PARENT=enp6s0
desk_case "usage:" PARENT=enp6s0 AGENT_VLAN=4094 DESK_VLAN=1 DESK_GW=10.79.0.1
desk_case "usage:" PF_LAB=1
echo "shell_test: vm/desk/setup.sh name refusals clean"

# The second-uplink check of vm/desk/setup.sh: lock refuses, and status
# reports, a host with a way out that is not the Pi. A fake sysfs
# (PF_TEST_SYSFS_NET) and a fake ip that prints canned route tables are
# stand-ins for the host. Each tool that status or lock would ask of the
# real host is a stub that fails.
up="${tmp}/uplinks"
mkdir -p "${up}/bin"
cat >"${up}/bin/ip" <<'IPEOF'
#!/bin/bash
case "$*" in
  "-o -4 route show table all") cat "${PF_FAKE_R4:-/dev/null}" ;;
  "-o -6 route show table all") cat "${PF_FAKE_R6:-/dev/null}" ;;
esac
exit 0
IPEOF
for t in nft systemctl sysctl resolvectl nmcli install modprobe chattr; do
  printf '#!/bin/sh\nexit 1\n' >"${up}/bin/${t}"
done
chmod +x "${up}/bin/"*
# nic CASE NAME CARRIER FLAGS [device|wifi|rfkill|lower_<dev>]...
nic() {
  local d="${up}/$1/sys/$2"
  mkdir -p "${d}"
  echo "$3" >"${d}/carrier"
  echo "$4" >"${d}/flags"
  shift 4
  local x
  for x in "$@"; do
    case "${x}" in
      device) mkdir -p "${d}/device" ;;
      wifi) mkdir -p "${d}/wireless" "${d}/phy80211" ;;
      rfkill) mkdir -p "${d}/phy80211/rfkill0" && echo 1 >"${d}/phy80211/rfkill0/soft" ;;
      lower_*) mkdir -p "${d}/${x}" ;;
    esac
  done
}
# The desktop as the runbook leaves it: trunk enp6s0, both VLANs, the
# default route via the Pi, the radio down and a spare port unplugged.
base() {
  local c="$1"
  nic "${c}" lo 1 0x9
  nic "${c}" enp6s0 1 0x1003 device
  nic "${c}" enp6s0.20 1 0x1003 lower_enp6s0
  nic "${c}" enp6s0.79 1 0x1003 lower_enp6s0
  nic "${c}" eno1 0 0x1003 device
  nic "${c}" wlp3s0 0 0x1002 wifi
  cat >"${up}/${c}/r4" <<'R4'
default via 10.79.0.1 dev enp6s0.79 proto static metric 50
10.79.0.0/30 dev enp6s0.79 proto kernel scope link src 10.79.0.2 metric 50
local 10.79.0.2 dev enp6s0.79 table local proto kernel scope host src 10.79.0.2
broadcast 10.79.0.3 dev enp6s0.79 table local proto kernel scope link src 10.79.0.2
local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1
R4
  cat >"${up}/${c}/r6" <<'R6'
unreachable default dev lo table unspec proto kernel metric 4294967295 error -101 pref medium
local ::1 dev lo table local proto kernel metric 0 pref medium
multicast ff00::/8 dev enp6s0 table local proto kernel metric 256 pref medium
R6
}
# uplinks_case DESC CASE SUBCOMMAND WANT_STATUS WANT [VAR=VALUE]...
uplinks_case() {
  local desc="$1" c="$2" cmd="$3" want_status="$4" want="$5" status
  shift 5
  upl_out="$(env -i PATH="${up}/bin:${PATH}" PF_TEST_SYSFS_NET="${up}/${c}/sys" PF_TEST_LAB_ENV="${up}/${c}/lab.env" \
    PF_FAKE_R4="${up}/${c}/r4" PF_FAKE_R6="${up}/${c}/r6" "$@" bash vm/desk/setup.sh "${cmd}" 2>&1)" && status=0 || status=$?
  [[ "${status}" == "${want_status}" ]] || fail "desk setup.sh ${cmd}, ${desc}: exit ${status}, want ${want_status}: ${upl_out}"
  [[ "${upl_out}" == *"${want}"* ]] || fail "desk setup.sh ${cmd}, ${desc}: expected '${want}', got: ${upl_out}"
}
upl_has() { [[ "${upl_out}" == *"$1"* ]] || fail "desk setup.sh: expected '$1' in: ${upl_out}"; }
upl_lacks() { [[ "${upl_out}" != *"$1"* ]] || fail "desk setup.sh: unexpected '$1' in: ${upl_out}"; }

base clean
uplinks_case "on a clean desk" clean uplinks 0 "ok: the only way out is enp6s0.79 via 10.79.0.1" PARENT=enp6s0
upl_lacks "SECOND UPLINK"

# What a dev box legitimately carries: docker, libvirt, VirtualBox
# host-only, a VM-only bridge and a tailnet with no exit node. None has a
# NIC of its own behind it, so none counts, with or without carrier and routes.
base bridges
nic bridges vethA 1 0x1003
nic bridges docker0 1 0x1003 lower_vethA
nic bridges vethB 1 0x1003
nic bridges br-1a2b3c4d5e6f 1 0x1003 lower_vethB
nic bridges vnet0 1 0x1003
nic bridges virbr0 1 0x1003 lower_vnet0
nic bridges vnet1 1 0x1003
nic bridges br0 1 0x1003 lower_vnet1
nic bridges vboxnet0 1 0x1003 device
nic bridges tailscale0 1 0x10d1
nic bridges wg0 1 0x10d1
cat >>"${up}/bridges/r4" <<'R4'
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
172.18.0.0/16 dev br-1a2b3c4d5e6f proto kernel scope link src 172.18.0.1
192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1
192.168.100.0/24 dev br0 proto kernel scope link src 192.168.100.1
192.168.56.0/24 dev vboxnet0 proto kernel scope link src 192.168.56.1
100.64.0.0/10 dev tailscale0 table 52
10.66.0.0/24 dev wg0 proto kernel scope link src 10.66.0.2
R4
uplinks_case "with docker, libvirt and VirtualBox bridges" bridges uplinks 0 "ok: the only way out" PARENT=enp6s0
upl_lacks "SECOND UPLINK"

base wifi
nic wifi wlp3s0 0 0x1003 wifi
uplinks_case "with Wi-Fi up" wifi uplinks 1 "SECOND UPLINK: wlp3s0: Wi-Fi is up" PARENT=enp6s0
upl_has "nmcli radio wifi off"
upl_has "disable Wi-Fi in the BIOS"
upl_has "PF_DESK_ALLOW_SECOND_UPLINK=1"
uplinks_case "with Wi-Fi up" wifi status 0 "SECOND UPLINK: wlp3s0" PARENT=enp6s0
upl_has "== uplinks =="

base rfkill
nic rfkill wlp3s0 0 0x1003 wifi rfkill
uplinks_case "with Wi-Fi up but its radio blocked" rfkill uplinks 0 "ok: the only way out" PARENT=enp6s0

base route
nic route eno1 1 0x1003 device
cat >>"${up}/route/r4" <<'R4'
default via 192.168.1.1 dev eno1 proto dhcp src 192.168.1.20 metric 100
192.168.1.0/24 dev eno1 proto kernel scope link src 192.168.1.20 metric 100
R4
echo 'default via fe80::1 dev eno1 proto ra metric 100 pref medium' >>"${up}/route/r6"
uplinks_case "with a second default route" route uplinks 1 "eno1: default route default via 192.168.1.1 dev eno1 (table main)" PARENT=enp6s0
upl_has "sudo ip -4 route del default via 192.168.1.1 dev eno1 table main"
upl_has "sudo ip -6 route del default via fe80::1 dev eno1"
upl_has "eno1: a second wired NIC with carrier and IPv4 routes (default 192.168.1.0/24)"

base exitnode
nic exitnode tailscale0 1 0x10d1
printf '%s\n' 'default dev tailscale0 table 52' '0.0.0.0/1 via 10.8.0.1 dev tun0' >>"${up}/exitnode/r4"
uplinks_case "with a tailnet exit node and a VPN's 0/1" exitnode uplinks 1 "tailscale0: default route default dev tailscale0 (table 52)" PARENT=enp6s0
upl_has "tun0: default route 0.0.0.0/1 via 10.8.0.1 dev tun0"

base tether
nic tether enx0a1b2c3d4e5f 1 0x1003 device
echo '192.168.42.0/24 dev enx0a1b2c3d4e5f proto kernel scope link src 192.168.42.7' >>"${up}/tether/r4"
uplinks_case "with a USB-tethered phone" tether uplinks 1 "enx0a1b2c3d4e5f: a second wired NIC" PARENT=enp6s0

uplinks_case "with Wi-Fi up and the override" wifi uplinks 0 "WARNING: PF_DESK_ALLOW_SECOND_UPLINK=1" PARENT=enp6s0 PF_DESK_ALLOW_SECOND_UPLINK=1
upl_has "SECOND UPLINK: wlp3s0"

# The local VirtualBox lab: the NAT adapter that Vagrant ssh uses is a way
# out by design, and PF_LAB=1 continues past it.
nic vbox lo 1 0x9
nic vbox eth0 1 0x1003 device
nic vbox eth1 1 0x1003 device
printf '%s\n' 'default via 10.79.0.1 dev eth1' '10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15' \
  '10.79.0.0/30 dev eth1 proto kernel scope link src 10.79.0.2' >"${up}/vbox/r4"
uplinks_case "in the VirtualBox lab" vbox uplinks 0 "PF_LAB=1: not refusing" PF_LAB=1 DESK_IF=eth1 DESK_GW=10.79.0.1
upl_has "SECOND UPLINK: eth0"

# The cloud lab desk runs tagged, without PF_LAB. Its management NIC is
# the one that /etc/pf-lab.env names, and only that file exempts it.
nic cloud lo 1 0x9
nic cloud ens5 1 0x1003 device
nic cloud ens6 1 0x1003 device
nic cloud ens6.20 1 0x1003 lower_ens6
nic cloud ens6.79 1 0x1003 lower_ens6
printf '%s\n' 'default via 10.79.0.1 dev ens6.79 proto static metric 50' \
  '192.168.121.0/24 dev ens5 proto kernel scope link src 192.168.121.40' \
  '10.79.0.0/30 dev ens6.79 proto kernel scope link src 10.79.0.2 metric 50' >"${up}/cloud/r4"
uplinks_case "in the cloud lab without its lab env" cloud uplinks 1 "SECOND UPLINK: ens5: a second wired NIC" PARENT=ens6
printf 'ROLE=desk\nLAB_IF=ens6\nMGMT_IF=ens5\n' >"${up}/cloud/lab.env"
uplinks_case "in the cloud lab" cloud uplinks 0 "ens5: the lab's management NIC" PARENT=ens6
upl_has "ok: the only way out is ens6.79 via 10.79.0.1"
uplinks_case "in the cloud lab" cloud status 0 "ens5: the lab's management NIC" PARENT=ens6

# lock itself, only as a non-root user: a lock that wrongly passed its
# gate as root would then rewrite this host.
if [[ "${EUID}" -ne 0 ]]; then
  uplinks_case "with Wi-Fi up" wifi lock 1 "refusing to lock" PARENT=enp6s0
  upl_lacks "run as root"
  uplinks_case "with Wi-Fi up and the override" wifi lock 1 "run as root" PARENT=enp6s0 PF_DESK_ALLOW_SECOND_UPLINK=1
  upl_has "WARNING: PF_DESK_ALLOW_SECOND_UPLINK=1"
  uplinks_case "on a clean desk" clean lock 1 "run as root" PARENT=enp6s0
fi
echo "shell_test: vm/desk/setup.sh second-uplink check clean"

# The owner placeholders (docs/release.md) stop make release and make
# docs-push alike. A scratch repo is a stand-in for the tree. Clean, it
# passes. One placeholder in any covered file, the site config included,
# refuses and names the file. A covered file that is gone refuses, and
# does not shrink the check.
ph="${tmp}/placeholders"
mkdir -p "${ph}/docs/user_guide"
for f in SECURITY.md README.md docs/challenge_rules.md docs/hall_of_fame.md docs/INDEX.md docs/user_guide/faq.md zensical.toml; do
  echo "filled" >"${ph}/${f}"
done
git -C "${ph}" init -q
ph_case() {
  local desc="$1" want_status="$2" want="$3" out status
  out="$(cd "${ph}" && bash "${here}/scripts/release.sh" placeholders 2>&1)" && status=0 || status=$?
  [[ "${status}" == "${want_status}" ]] || fail "release.sh placeholders ${desc}: exit ${status}, want ${want_status}: ${out}"
  [[ "${out}" == *"${want}"* ]] || fail "release.sh placeholders ${desc}: expected '${want}', got: ${out}"
}
ph_case "on a filled tree" 0 ""
echo 'site_url = "<DOCS_URL>"' >"${ph}/zensical.toml"
ph_case "with DOCS_URL unfilled" 1 "zensical.toml:1:"
echo 'filled' >"${ph}/zensical.toml"
echo 'From <WINDOW_START> to <WINDOW_END>' >"${ph}/docs/user_guide/faq.md"
ph_case "with the window unfilled on the site" 1 "docs/user_guide/faq.md:1:"
echo 'filled' >"${ph}/docs/user_guide/faq.md"
rm "${ph}/docs/hall_of_fame.md"
ph_case "with a covered file gone" 1 "docs/hall_of_fame.md is missing"
echo 'filled' >"${ph}/docs/hall_of_fame.md"

# site-placeholders covers only the site. A placeholder outside it passes.
# A link from the site into the repo refuses.
sp_case() {
  local desc="$1" want_status="$2" want="$3" out status
  out="$(cd "${ph}" && bash "${here}/scripts/release.sh" site-placeholders 2>&1)" && status=0 || status=$?
  [[ "${status}" == "${want_status}" ]] || fail "release.sh site-placeholders ${desc}: exit ${status}, want ${want_status}: ${out}"
  [[ "${out}" == *"${want}"* ]] || fail "release.sh site-placeholders ${desc}: expected '${want}', got: ${out}"
}
echo '<DISCLOSURE_EMAIL>' >"${ph}/SECURITY.md"
sp_case "with a placeholder outside the site" 0 ""
echo 'From <WINDOW_START>' >"${ph}/docs/user_guide/faq.md"
sp_case "with the window unfilled on the site" 1 "docs/user_guide/faq.md:1:"
echo 'the [policy](https://github.com/o/pi-fortress/blob/HEAD/SECURITY.md)' >"${ph}/docs/user_guide/faq.md"
sp_case "with a link into the repo" 1 "links into the repo"
echo 'repo_url = "https://github.com/o/pi-fortress"' >"${ph}/zensical.toml"
echo 'filled' >"${ph}/docs/user_guide/faq.md"
sp_case "with the repo button" 1 "links into the repo"
echo 'filled' >"${ph}/zensical.toml"

# docs-push runs both checks before it builds or deploys anything.
if command -v make >/dev/null 2>&1; then
  dp="$(make -n -C "${here}" --no-print-directory docs-push DOCS_PROJECT=shell-test 2>&1)" || fail "make -n docs-push failed: ${dp}"
  order="$(awk '/release\.sh (site-)?placeholders/ && !p { p = NR } /leak_check\.sh/ && !l { l = NR } /wrangler/ && !w { w = NR } END { print (p && l && w && p < w && l < w) ? "ok" : "bad" }' <<<"${dp}")"
  [[ "${order}" == ok ]] || fail "make docs-push does not run the placeholder and leak checks before wrangler: ${dp}"
fi
echo "shell_test: owner placeholder guard and docs-push gate clean"

# mermaid_check.sh refuses a ';' in sequence-diagram text and a '(' in an
# unquoted flowchart label, and names the line. An entity code, a quoted
# label and a cylinder shape pass.
mm="${tmp}/mermaid"
mkdir -p "${mm}"
printf '%s\n' '```mermaid' 'sequenceDiagram' '  A->>B: one #59; two' '```' \
  '```mermaid' 'flowchart LR' '  X["a; b"] --> Y{"f(x)?"} --> D[(db)]' '```' >"${mm}/good.md"
./scripts/mermaid_check.sh "${mm}" >/dev/null 2>&1 || fail "mermaid_check refuses a clean file"
printf '%s\n' '' '```mermaid' 'sequenceDiagram' '  Note over A: one; two' '```' \
  '```mermaid' 'flowchart TD' '  A --> B{f(x)?}' '```' >"${mm}/bad.md"
out="$(./scripts/mermaid_check.sh "${mm}" 2>&1)" && fail "mermaid_check passes a bad file"
[[ "${out}" == *"bad.md:4:"* ]] || fail "mermaid_check does not name the ; at bad.md:4: ${out}"
[[ "${out}" == *"bad.md:8:"* ]] || fail "mermaid_check does not name the ( at bad.md:8: ${out}"
echo "shell_test: mermaid guard clean"
