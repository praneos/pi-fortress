#!/bin/bash
# setup_test.sh: tests the second-uplink check of vm/desk/setup.sh and its
# boot run, with a fake sysfs and a fake ip, as scripts/shell_test.sh does.
# Never root, never the network of this host: each tool that could change
# the host is a stub that fails.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
setup="${here}/setup.sh"
t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT
fail() { echo "desk setup_test: $*" >&2; exit 1; }

mkdir -p "${t}/bin"
cat >"${t}/bin/ip" <<'EOF'
#!/bin/bash
case "$*" in
  "-o -4 route show table all") cat "${PF_FAKE_R4:-/dev/null}" ;;
  "-o -6 route show table all") cat "${PF_FAKE_R6:-/dev/null}" ;;
esac
exit 0
EOF
for x in nft systemctl sysctl resolvectl nmcli modprobe chattr systemd-run; do
  printf '#!/bin/sh\nexit 1\n' >"${t}/bin/${x}"
done
chmod +x "${t}/bin/"*

# nic CASE NAME CARRIER FLAGS [device|wifi|lower_<dev>]...
nic() {
  local d="${t}/$1/sys/$2" x
  mkdir -p "${d}"
  echo "$3" >"${d}/carrier"
  echo "$4" >"${d}/flags"
  shift 4
  for x in "$@"; do
    case "${x}" in
      device) mkdir -p "${d}/device" ;;
      wifi) mkdir -p "${d}/wireless" "${d}/phy80211" ;;
      lower_*) mkdir -p "${d}/${x}" ;;
    esac
  done
}
base() {
  local c="$1"
  nic "${c}" lo 1 0x9
  nic "${c}" enp6s0 1 0x1003 device
  nic "${c}" enp6s0.20 1 0x1003 lower_enp6s0
  nic "${c}" enp6s0.79 1 0x1003 lower_enp6s0
  nic "${c}" wlp3s0 0 0x1002 wifi
  printf '%s\n' 'default via 10.79.0.1 dev enp6s0.79 proto static metric 50' \
    '10.79.0.0/30 dev enp6s0.79 proto kernel scope link src 10.79.0.2 metric 50' >"${t}/${c}/r4"
  : >"${t}/${c}/r6"
}
run() {
  local c="$1" cmd="$2" status
  shift 2
  out="$(env -i PATH="${t}/bin:${PATH}" PF_TEST_SYSFS_NET="${t}/${c}/sys" PF_TEST_LAB_ENV=/nonexistent \
    PF_FAKE_R4="${t}/${c}/r4" PF_FAKE_R6="${t}/${c}/r6" PF_DESK_BOOT_STATE="${t}/${c}/run/boot-uplinks" \
    PARENT=enp6s0 "$@" bash "${setup}" "${cmd}" 2>&1)" && status=0 || status=$?
  rc="${status}"
}
has() { [[ "${out}" == *"$1"* ]] || fail "$2: expected '$1' in: ${out}"; }
lacks() { [[ "${out}" != *"$1"* ]] || fail "$2: unexpected '$1' in: ${out}"; }

base clean
run clean uplinks
[[ "${rc}" == 0 ]] || fail "clean desk refused: ${out}"
has "ok: the only way out is enp6s0.79" "clean desk"

# A real port enslaved to a bridge with an exempt name is still a port.
base bridged
nic bridged eno1 1 0x1003 device
nic bridged br-0a1b2c3d 1 0x1003 lower_eno1
echo '192.168.1.0/24 dev br-0a1b2c3d proto kernel scope link src 192.168.1.20' >>"${t}/bridged/r4"
run bridged uplinks
[[ "${rc}" == 1 ]] || fail "a bridge over a real NIC passed: ${out}"
has "SECOND UPLINK: br-0a1b2c3d: a second wired NIC" "bridge over eno1"

# A bridge over a VLAN of the trunk reaches only the Pi. The VirtualBox
# host-only adapter has its own device link. Neither counts.
base vmbridge
nic vmbridge br-agent 1 0x1003 lower_enp6s0.20
nic vmbridge vboxnet0 1 0x1003 device
printf '%s\n' '10.77.0.0/24 dev br-agent proto kernel scope link' '192.168.56.0/24 dev vboxnet0 proto kernel scope link src 192.168.56.1' >>"${t}/vmbridge/r4"
run vmbridge uplinks
[[ "${rc}" == 0 ]] || fail "a bridge over the agent VLAN or vboxnet0 counted: ${out}"

# A third VLAN on the trunk is not a VLAN of the Pi. A managed switch can
# carry it to the house LAN or the ISP. Only .20 and .79 are exempt.
base vlan
nic vlan enp6s0.100 1 0x1003 lower_enp6s0
echo '192.168.100.0/24 dev enp6s0.100 proto kernel scope link src 192.168.100.5' >>"${t}/vlan/r4"
run vlan uplinks
[[ "${rc}" == 1 ]] || fail "an unexpected VLAN of the trunk passed: ${out}"
has "SECOND UPLINK: enp6s0.100" "VLAN 100"
lacks "SECOND UPLINK: enp6s0.20" "VLAN 100"
lacks "SECOND UPLINK: enp6s0.79" "VLAN 100"

# The Wi-Fi hint stays after a reboot: the radio switch or rfkill, never
# a bare link down that NetworkManager reverses.
base wifi
nic wifi wlp3s0 0 0x1003 wifi
run wifi uplinks
has "nmcli radio wifi off" "Wi-Fi hint"
has "rfkill block wifi" "Wi-Fi hint"
has "remembered across reboots" "Wi-Fi hint"
lacks "(or sudo ip link set" "Wi-Fi hint"

# The boot run warns and never fails, and status shows what it found.
run wifi boot-check
[[ "${rc}" == 0 ]] || fail "boot-check failed on a finding (it must only warn): ${out}"
has "<2>pf-desk: SECOND UPLINK: wlp3s0" "boot-check"
has "Nothing was blocked" "boot-check"
grep -q '^SECOND UPLINK: wlp3s0' "${t}/wifi/run/boot-uplinks" || fail "boot-check left no state for status"
run wifi status
has "== uplinks at boot ==" "status"
has "WARNING: the boot check found a way out" "status"
run clean boot-check
[[ "${rc}" == 0 ]] || fail "boot-check failed on a clean desk: ${out}"
has "<6>pf-desk: ok:" "clean boot-check"
run clean status
has "ok: the only way out" "clean status"
lacks "WARNING: the boot check" "clean status"
rm -rf "${t}/vlan/run"
run vlan status
has "(no boot check this boot" "status without a boot run"

# The unit stays after an nftables restart. It schedules the warn-only
# boot check with each value that lock substitutes.
unit="${here}/desk-lock.service"
grep -qxF 'PartOf=nftables.service' "${unit}" || fail "desk-lock.service is not PartOf nftables.service"
grep -qE '^WantedBy=.*\bnftables\.service\b' "${unit}" || fail "desk-lock.service is not started again with nftables"
grep -qE '^ExecStartPost=-/usr/bin/systemd-run .*boot-check$' "${unit}" || fail "desk-lock.service does not schedule the boot check, or a failure there fails the lock"
for ph in @PARENT@ @AGENT_VLAN@ @DESK_VLAN@ @DESK_GW@ @RESTORE_LIB@; do
  grep -qF "${ph}" "${unit}" || fail "desk-lock.service lost ${ph}"
  grep -qF "s|${ph}|" "${setup}" || fail "lock does not substitute ${ph} into desk-lock.service"
done
# ca: the CA of the Pi in each store that the desk reads, and out again.
# All paths go under PF_TEST_ROOT. The update tool is a stub that records
# its call. No SUDO_USER, so the NSS step only gives its hint.
if command -v openssl >/dev/null 2>&1; then
  r="${t}/caroot"
  mkdir -p "${r}/etc" "${t}/pki"
  printf 'ID=ubuntu\nID_LIKE=debian\n' >"${r}/etc/os-release"
  # shellcheck disable=SC2016
  printf '#!/bin/sh\necho "$0 $*" >>%s/updates\n' "${t}" >"${t}/bin/update-ca-certificates"
  chmod +x "${t}/bin/update-ca-certificates"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=pf-test-ca \
    -addext basicConstraints=critical,CA:TRUE -keyout "${t}/pki/ca.key" -out "${t}/pki/ca-cert.pem" 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=leaf \
    -addext basicConstraints=critical,CA:FALSE -keyout "${t}/pki/leaf.key" -out "${t}/pki/leaf.pem" 2>/dev/null
  cat "${t}/pki/ca-cert.pem" "${t}/pki/ca.key" >"${t}/pki/ca.pem"
  sum="$(sha256sum "${t}/pki/ca-cert.pem" | cut -d' ' -f1)"
  runca() {
    out="$(env -i PATH="${t}/bin:${PATH}" PF_TEST_ROOT="${r}" PARENT=enp6s0 bash "${setup}" "$@" 2>&1)" && rc=0 || rc=$?
  }

  runca ca "${t}/pki/ca.pem"
  [[ "${rc}" != 0 ]] || fail "ca took a file with the CA key"
  has "holds a private key" "ca with key"
  : >"${t}/pki/empty.pem"
  runca ca "${t}/pki/empty.pem"
  [[ "${rc}" != 0 ]] || fail "ca took an empty file"
  has "ssh -t" "ca with an empty file"
  runca ca "${t}/pki/leaf.pem"
  [[ "${rc}" != 0 ]] || fail "ca took a certificate that is not a CA"
  runca ca "${t}/pki/ca-cert.pem" "$(printf '0%.0s' {1..64})"
  [[ "${rc}" != 0 ]] || fail "ca took a CA with the wrong sha256"
  has "does not match" "ca sha256"
  [[ ! -e "${r}/etc/pi-fortress/desk-ca.pem" ]] || fail "a refused CA was installed"

  runca ca "${t}/pki/ca-cert.pem" "${sum}"
  [[ "${rc}" == 0 ]] || fail "ca refused a good CA: ${out}"
  cmp -s "${t}/pki/ca-cert.pem" "${r}/usr/local/share/ca-certificates/pi-fortress-desk.crt" || fail "ca: not in the system store"
  grep -q 'update-ca-certificates' "${t}/updates" || fail "ca: the system store was not updated"
  grep -qx 'export NODE_EXTRA_CA_CERTS=/etc/pi-fortress/desk-ca.pem' "${r}/etc/profile.d/pi-fortress-desk-ca.sh" || fail "ca: no NODE_EXTRA_CA_CERTS for shells"
  for kv in REQUESTS_CA_BUNDLE PIP_CERT SSL_CERT_FILE CURL_CA_BUNDLE; do
    grep -qx "${kv}=/etc/ssl/certs/ca-certificates.crt" "${r}/etc/environment.d/90-pi-fortress-desk-ca.conf" || fail "ca: no ${kv} for desktop apps"
  done
  grep -qF '"Install": ["/etc/pi-fortress/desk-ca.pem"]' "${r}/etc/firefox/policies/policies.json" || fail "ca: no Firefox policy"
  has "run with sudo from your own user" "ca NSS hint"

  runca ca-remove
  [[ "${rc}" == 0 ]] || fail "ca-remove failed: ${out}"
  for f in etc/pi-fortress/desk-ca.pem usr/local/share/ca-certificates/pi-fortress-desk.crt etc/profile.d/pi-fortress-desk-ca.sh \
    etc/environment.d/90-pi-fortress-desk-ca.conf etc/firefox/policies/policies.json; do
    [[ ! -e "${r}/${f}" ]] || fail "ca-remove left /${f}"
  done

  # A Firefox policy that the operator wrote stays as it is.
  mkdir -p "${r}/etc/firefox/policies"
  echo '{"policies": {"DisableTelemetry": true}}' >"${r}/etc/firefox/policies/policies.json"
  runca ca "${t}/pki/ca-cert.pem"
  [[ "${rc}" == 0 ]] || fail "ca with a foreign Firefox policy failed: ${out}"
  has "has other policies" "foreign Firefox policy"
  grep -q DisableTelemetry "${r}/etc/firefox/policies/policies.json" || fail "ca overwrote the Firefox policy of the operator"
  runca ca-remove
  [[ -e "${r}/etc/firefox/policies/policies.json" ]] || fail "ca-remove deleted the Firefox policy of the operator"
else
  echo "desk setup_test: no openssl, ca not tested" >&2
fi
echo "desk setup_test: ok"
