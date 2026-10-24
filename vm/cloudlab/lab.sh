#!/usr/bin/env bash
# Cloud lab driver: the gateway, a house client, the desk seat and agent
# VMs on one KVM host, with the wiring of the Pi. Manual: docs/cloud_lab.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
export VAGRANT_CWD="${HERE}"
set -a
# shellcheck source=lab.env
. "${HERE}/lab.env"
set +a
SSH_CFG="${HERE}/.vagrant/ssh.config"
export PF_AGENT_COUNT="${PF_AGENT_COUNT:-2}"
VIRSH=(virsh -c qemu:///system)
BRIDGES=("${TRUNK_BR}" "${AGENT_BR}" "${HOUSE_BR}")

die() {
  echo "lab.sh: $*" >&2
  exit 1
}

[[ "${PF_AGENT_COUNT}" =~ ^[123]$ ]] || die "PF_AGENT_COUNT must be 1, 2 or 3"

clients() {
  local n
  echo house
  echo desk
  echo agent
  for ((n = 2; n <= PF_AGENT_COUNT; n++)); do echo "agent${n}"; done
}

# agent is .10, agentN is .(9+N), as in the Vagrantfile.
agent_host() {
  local n="${1#agent}"
  echo $((9 + ${n:-1}))
}

mgmt_mac() {
  case "$1" in
    house) echo "${HOUSE_MGMT_MAC}" ;;
    desk) echo "${DESK_MGMT_MAC}" ;;
    agent*) printf '%s:%02d\n' "${AGENT_MGMT_MAC_PREFIX}" "$(agent_host "$1")" ;;
  esac
}

lab_ip() {
  case "$1" in
    house) echo 10.78.0.20 ;;
    desk) echo 10.79.0.2 ;;
    agent*) echo "10.77.0.$(agent_host "$1")" ;;
  esac
}

created() { [[ -f "${HERE}/.vagrant/machines/$1/libvirt/id" ]]; }

lab_ssh() {
  [[ -f "${SSH_CFG}" ]] || cmd_ssh_config >/dev/null
  ssh -F "${SSH_CFG}" -o BatchMode=yes -o ConnectTimeout=15 "$@"
}

# Capture, then match. Under pipefail, `virsh | grep -q` fails when grep
# exits first and virsh dies of SIGPIPE. libvirt 12 does this each time.
net_active() {
  [[ "$("${VIRSH[@]}" net-info "$1" 2>/dev/null)" =~ Active:[[:space:]]+yes ]]
}

# host: isolated libvirt bridges (no host address, so the host is on no
# lab net). Also the veth that changes untagged agent frames into VLAN 20
# on the trunk. enp6s0.20 does this job on the desktop. Live state: run
# again after a host reboot.
cmd_host() {
  [[ ${EUID} -eq 0 ]] || die "host: run with sudo"
  [[ -e /dev/kvm ]] || die "no /dev/kvm: this machine cannot run KVM guests (docs/cloud_lab.md, Host)"
  command -v virsh >/dev/null || die "virsh missing: apt install libvirt-daemon-system"
  local br dev xml
  for br in "${BRIDGES[@]}"; do
    if ! "${VIRSH[@]}" net-info "${br}" >/dev/null 2>&1; then
      xml="$(mktemp)"
      printf "<network><name>%s</name><bridge name='%s' stp='off' delay='0'/></network>\n" "${br}" "${br}" >"${xml}"
      "${VIRSH[@]}" net-define "${xml}" >/dev/null
      rm -f "${xml}"
    fi
    "${VIRSH[@]}" net-autostart "${br}" >/dev/null
    net_active "${br}" || "${VIRSH[@]}" net-start "${br}" >/dev/null
  done
  ip link show "${VETH_TRUNK}" >/dev/null 2>&1 ||
    ip link add "${VETH_TRUNK}" type veth peer name "${VETH_AGENT}"
  ip link show "${VETH_AGENT}.${AGENT_VLAN}" >/dev/null 2>&1 ||
    ip link add link "${VETH_AGENT}" name "${VETH_AGENT}.${AGENT_VLAN}" type vlan id "${AGENT_VLAN}"
  ip link set "${VETH_TRUNK}" master "${TRUNK_BR}"
  ip link set "${VETH_AGENT}.${AGENT_VLAN}" master "${AGENT_BR}"
  for dev in "${BRIDGES[@]}" "${VETH_TRUNK}" "${VETH_AGENT}" "${VETH_AGENT}.${AGENT_VLAN}"; do
    sysctl -qw "net.ipv6.conf.${dev/./\/}.disable_ipv6=1" || true
    ip link set "${dev}" up
  done
  # Docker loads br_netfilter and sets FORWARD to drop. That would drop
  # frames bridged between two VMs.
  if [[ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" == 1 ]]; then
    for br in "${BRIDGES[@]}"; do
      iptables -C FORWARD -i "${br}" -o "${br}" -j ACCEPT 2>/dev/null ||
        iptables -I FORWARD -i "${br}" -o "${br}" -j ACCEPT
    done
  fi
  # The NIC MTU on GCP is 1460, 40 bytes less than the 1500 of the LAN
  # (docs/cloud_lab.md, Host). A guest that negotiates a 1460-unaware MSS on
  # egress blackholes if the path drops the PMTU ICMP. Thus this host clamps
  # the MSS of each TCP SYN that it forwards to the MTU of the outgoing
  # path, for each bridge or NAT network that the SYN leaves through.
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null ||
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  echo "host ready: ${BRIDGES[*]}, ${VETH_TRUNK} <-> ${VETH_AGENT}.${AGENT_VLAN}, TCP MSS clamped"
}

cmd_host_clean() {
  [[ ${EUID} -eq 0 ]] || die "host-clean: run with sudo"
  local br
  ip link del "${VETH_TRUNK}" 2>/dev/null || true
  for br in "${BRIDGES[@]}"; do
    iptables -D FORWARD -i "${br}" -o "${br}" -j ACCEPT 2>/dev/null || true
    "${VIRSH[@]}" net-destroy "${br}" >/dev/null 2>&1 || true
    "${VIRSH[@]}" net-undefine "${br}" >/dev/null 2>&1 || true
  done
  iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

preflight() {
  command -v vagrant >/dev/null || die "vagrant missing (docs/cloud_lab.md, Host)"
  command -v qemu-img >/dev/null || die "qemu-img missing: sudo apt install qemu-utils (libvirt needs it to import the box)"
  [[ "$(vagrant plugin list 2>/dev/null)" == *vagrant-libvirt* ]] ||
    die "plugin missing: vagrant plugin install vagrant-libvirt"
  ip link show "${VETH_AGENT}.${AGENT_VLAN}" >/dev/null 2>&1 || die "host networks missing: sudo $0 host"
  [[ ${EUID} -eq 0 || " $(id -nG) " == *" libvirt "* ]] ||
    die "add yourself to the libvirt group (sudo usermod -aG libvirt \$USER), then log in again"
}

# build: pf for the arch of this host, at the path where apply.sh looks (vm/pi/pf).
# PF_RACE=1 makes a race build (make pf RACE=1) for the race tier.
cmd_build() {
  make -C "${ROOT}" -s split-bin RACE="${PF_RACE:-0}"
}

cmd_up() {
  [[ "${PF_RACE:-0}" != 1 ]] || die "up: PF_RACE=1 is for sync only. Run $0 up, then PF_RACE=1 $0 sync"
  preflight
  local vm want=() rest=()
  if (($#)); then want=("$@"); else mapfile -t want < <(echo gw; clients); fi
  cmd_build
  cmd_uncut
  for vm in "${want[@]}"; do
    [[ "${vm}" == gw ]] || rest+=("${vm}")
  done
  if [[ " ${want[*]} " == *" gw "* ]]; then
    vagrant up --provider=libvirt gw
    # vagrant up skips the rsync and the provisioners of a gateway that
    # already runs. A first up that failed before its rsync leaves a
    # gateway with no /vagrant, and each later up keeps it so. Thus copy
    # the tree and provision again when the checkout is not there.
    if ! vagrant ssh gw -c 'test -d /vagrant/vm/pi && test -d /vagrant/vm/policy' >/dev/null 2>&1; then
      echo "lab.sh: gw has no checkout at /vagrant; rsync and provision again"
      vagrant rsync gw
      vagrant provision gw
    fi
  fi
  # The same for a client that already runs: up does not copy the tree,
  # and a provision from an empty /vagrant fails or is marked done.
  for vm in "${rest[@]}"; do
    created "${vm}" || continue
    if vagrant ssh "${vm}" -c true >/dev/null 2>&1 && ! vagrant ssh "${vm}" -c 'test -d /vagrant/vm' >/dev/null 2>&1; then
      echo "lab.sh: ${vm} has no checkout at /vagrant; rsync and provision again"
      vagrant rsync "${vm}"
      vagrant provision "${vm}"
    fi
  done
  # Clients start in parallel. Each client waits for the gateway itself.
  ((${#rest[@]} == 0)) || vagrant up --provider=libvirt "${rest[@]}"
  cmd_ssh_config >/dev/null
  cmd_cut
  echo "lab is up. Run: $0 test"
}

# ssh-config: pi is the gateway on the mgmt net. ssh reaches each client
# only through it, over the lab nets, as on the real Pi.
cmd_ssh_config() {
  local vm tmp="${SSH_CFG}.tmp"
  mkdir -p "$(dirname "${SSH_CFG}")"
  vagrant ssh-config gw --host pi >"${tmp}"
  for vm in $(clients); do
    created "${vm}" || continue
    cat >>"${tmp}" <<EOF

Host ${vm}
  HostName $(lab_ip "${vm}")
  User vagrant
  IdentityFile ${HERE}/.vagrant/machines/${vm}/libvirt/private_key
  IdentitiesOnly yes
  ProxyJump pi
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
  done
  mv "${tmp}" "${SSH_CFG}"
  echo "${SSH_CFG}"
}

setlink() {
  local vm
  for vm in $(clients); do
    created "${vm}" || continue
    "${VIRSH[@]}" domif-setlink "$(cat "${HERE}/.vagrant/machines/${vm}/libvirt/id")" "$(mgmt_mac "${vm}")" "$1" >/dev/null ||
      echo "lab.sh: ${vm}: mgmt link $1 failed (not running?)" >&2
  done
}

# cut: set the client mgmt links down. Then the only way out of a client
# is the gateway. Vagrant needs the links up (uncut) to ssh, rsync or provision.
cmd_cut() {
  local vm
  setlink down
  for vm in $(clients); do
    created "${vm}" || continue
    lab_ssh "${vm}" 'sudo sh -c ". /etc/pf-lab.env; while ip route del default dev \$MGMT_IF 2>/dev/null; do :; done"' ||
      echo "lab.sh: ${vm}: not reachable through the gateway" >&2
  done
}

# uncut: set the links up. The client asks again for a lease that expired
# during the cut. The dhclient hook stops the mgmt net from taking the default route.
cmd_uncut() {
  local vm
  setlink up
  for vm in $(clients); do
    created "${vm}" || continue
    lab_ssh "${vm}" 'sudo sh -c ". /etc/pf-lab.env; ip -4 addr show dev \$MGMT_IF | grep -q inet || timeout 60 dhclient -1 \$MGMT_IF"' ||
      true
  done
}

# Race tier (docs/cloud_lab.md). A race build of pf uses approximately 3
# to 5 times the memory of a normal build. The caps in vm/pi/*.service can
# stop it. Thus sync and ship write a lab-only drop-in on gw for each unit
# that runs pf. Nothing in vm/pi/ or in a bundle changes. These settings
# stay as they are:
# - LockPersonality: the race runtime of Go on amd64 does not call
#   personality(2). The re-exec without ASLR is only in the C/C++ TSan.
# - MemoryDenyWriteExecute: the race runtime maps its shadow memory
#   read-write. It maps no page that is writable and executable.
# - SystemCallFilter: the race runtime uses no syscall in @privileged, and
#   none outside @system-service on its normal path.
# A race build of pf under systemd-run with these settings started and
# reported a race. If a pf unit stops with SIGSYS or EPERM in a race run,
# examine this list again.
RACE_DROPIN=90-lab-race.conf
RACE_LOG="${HERE}/.vagrant/race.log"
RACE_JOURNAL="${HERE}/.vagrant/race-journal.log"

# race_bin FILE: true if FILE is a race build. Capture, then match (net_active).
race_bin() { [[ "$(GOTOOLCHAIN=local go version -m "$1" 2>/dev/null)" == *-race=true* ]]; }

# race_units: write or remove the drop-ins on gw. vm/pi/pf decides, because
# sync copies it and ship bundles it. The units are those of gw that run
# /usr/local/sbin/pf. A template drop-in covers each instance. Before an
# apply: apply restarts each pf unit, and the restart reads the drop-ins.
# GORACE: report each race and continue. Exit code 66 at the end shows a
# race. The reports go to stderr, thus to the journal.
race_units() {
  local race=0
  race_bin "${ROOT}/vm/pi/pf" && race=1
  # The script goes on stdin. Thus vagrant in cmd_ssh_config must not read it.
  [[ -f "${SSH_CFG}" ]] || cmd_ssh_config >/dev/null </dev/null
  lab_ssh pi "sudo bash -s ${race} ${RACE_DROPIN}" <<'EOF'
set -euo pipefail
race=$1 conf=$2
if [[ ${race} == 1 ]]; then
  for unit in $(grep -l /usr/local/sbin/pf /etc/systemd/system/pi-fortress-*.service); do
    install -d -m 0755 "${unit}.d"
    cat >"${unit}.d/${conf}" <<'UNIT'
# Lab only: vm/cloudlab/lab.sh writes this for a race build of pf.
[Service]
MemoryHigh=infinity
MemoryMax=infinity
TasksMax=infinity
Environment="GORACE=halt_on_error=0 exitcode=66"
UNIT
  done
  if [[ ! -d /var/log/journal ]]; then
    install -d -m 2755 -g systemd-journal /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal
    journalctl --flush
    echo "lab.sh: gw journal is now persistent, for the race check across a reboot"
  fi
else
  rm -f /etc/systemd/system/pi-fortress-*.service.d/"${conf}"
fi
systemctl daemon-reload
EOF
}

race_banner() {
  race_bin "${ROOT}/vm/pi/pf" || return 0
  cat >&2 <<EOF
lab.sh: ****************************************************************
lab.sh: gw now runs a RACE build of pf. It is for the lab only.
lab.sh: ${RACE_DROPIN} removes the memory and task caps of each pf unit.
lab.sh: To put a normal pf back: $0 sync (with no PF_RACE=1)
lab.sh: ****************************************************************
EOF
}

# race_check SINCE: race reports and exit code 66 in the gw journal since
# the epoch SINCE, written to RACE_LOG. Fails if it finds one, or if it
# cannot read the journal.
race_check() {
  local races exits
  if ! lab_ssh pi "sudo journalctl --since @$1 --no-pager -q" >"${RACE_JOURNAL}"; then
    echo "lab.sh: race check: cannot read the gw journal. The race result is not known." >&2
    return 1
  fi
  races="$(grep -c 'WARNING: DATA RACE' "${RACE_JOURNAL}" || true)"
  exits="$(grep -E 'status=66/' "${RACE_JOURNAL}" || true)"
  {
    grep -A40 'WARNING: DATA RACE' "${RACE_JOURNAL}" || true
    [[ -z "${exits}" ]] || printf '\n== pf units that exited with code 66 ==\n%s\n' "${exits}"
  } >"${RACE_LOG}"
  echo "lab.sh: race check: ${races} data race report(s) on gw. Report: ${RACE_LOG}"
  if [[ -n "${exits}" ]]; then
    echo "lab.sh: race check: a pf unit exited with code 66:" >&2
    printf '%s\n' "${exits}" >&2
  fi
  [[ "${races}" == 0 && -z "${exits}" ]]
}

cmd_sync() {
  cmd_build
  vagrant rsync gw
  race_units
  vagrant provision gw --provision-with apply
  race_banner
}

# ship: the same path that the Pi gets (docs/signed_ship.md), not the
# rsync loop that cmd_sync uses. It builds the amd64 bundle (pi-bundle
# takes GOARCH). It signs the bundle with a lab-only key generated under
# .vagrant (never ~/.ssh/pi_fortress_release). It makes gw trust that key,
# and gives gw a pfship user and key. Then it uploads through pfship
# exactly as `make pi-ship` does, and waits for the result.
LAB_KEY_DIR="${HERE}/.vagrant/lab-keys"
LAB_RELEASE_KEY="${LAB_KEY_DIR}/pf-lab-release"
LAB_SHIP_KEY="${LAB_KEY_DIR}/pf-lab-ship"

lab_keygen() {
  [[ -f "$1" ]] && return 0
  mkdir -p "$(dirname "$1")"
  ssh-keygen -t ed25519 -f "$1" -N '' -C "$2" -q
}

cmd_ship() {
  preflight
  created gw || die "ship: gw is not up (run: $0 up)"
  lab_keygen "${LAB_RELEASE_KEY}" pi-fortress-lab-release
  lab_keygen "${LAB_SHIP_KEY}" pfship-lab

  echo "lab.sh: building the amd64 bundle"
  make -s -C "${ROOT}" pi-bundle GOARCH=amd64
  local bundle="${ROOT}/bin/pf-bundle.tar"
  [[ -f "${bundle}" ]] || die "ship: ${bundle} missing after pi-bundle"
  rm -f "${bundle}.sig"
  ssh-keygen -Y sign -f "${LAB_RELEASE_KEY}" -n pi-fortress-release "${bundle}"

  echo "lab.sh: trusting the lab key on gw"
  local signers relpub shippub
  signers="release namespaces=\"pi-fortress-release\" $(cut -d' ' -f1,2 "${LAB_RELEASE_KEY}.pub")"
  shippub="$(cat "${LAB_SHIP_KEY}.pub")"
  lab_ssh pi "sudo install -d -m 0755 /etc/pi-fortress && echo '${signers}' | sudo tee /etc/pi-fortress/allowed_signers >/dev/null && sudo chmod 0644 /etc/pi-fortress/allowed_signers && sudo chown root:root /etc/pi-fortress/allowed_signers"
  lab_ssh pi "echo '${shippub}' | sudo tee /etc/pi-fortress/pfship.pub >/dev/null && sudo chmod 0644 /etc/pi-fortress/pfship.pub"
  # Runs the ship half of vm/pi/provision.sh again. That script is
  # idempotent. It creates pfship / writes its authorized_keys only when
  # the pubkey above is present (docs/signed_ship.md, Setup; vm/pi/provision.sh).
  lab_ssh pi "sudo PF_SHIP_PUBKEY=/etc/pi-fortress/pfship.pub PF_LAB=1 bash /vagrant/vm/pi/provision.sh"
  # pi-bundle refuses a race build. Thus this removes the drop-ins of an
  # earlier race sync before the ship installs a normal pf.
  race_units

  echo "lab.sh: uploading the signed bundle to pfship"
  local pi_host rsh
  pi_host="$(ssh -F "${SSH_CFG}" -G pi | awk '$1=="hostname"{print $2}')"
  rsh="ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${LAB_SHIP_KEY} -o IdentitiesOnly=yes"
  rsync -t -e "${rsh}" "${bundle}" "pfship@${pi_host}:"
  rsync -t -e "${rsh}" "${bundle}.sig" "pfship@${pi_host}:"

  echo "lab.sh: uploaded; waiting for a result in ship.jsonl"
  local i result=""
  for ((i = 0; i < 60; i++)); do
    result="$(lab_ssh pi 'sudo tail -1 /var/log/pi-fortress/ship.jsonl 2>/dev/null' || true)"
    [[ -n "${result}" ]] && break
    sleep 2
  done
  [[ -n "${result}" ]] || die "ship: no row appeared in ship.jsonl after the upload"
  echo "lab.sh: ${result}"
  [[ "${result}" == *'"result":"ok"'* ]] || die "ship: last ship.jsonl row is not ok"
}

# snapshot/restore/snapshots: libvirt snapshots of all lab VMs, to revert
# the full developer lab. This is not the rollback of the product:
# cmd_ship plus `pf rollback` on gw tests that (docs/signed_ship.md). The
# names have a prefix. Thus they show as the lab's own, different from
# all snapshots that virsh already has.
LAB_SNAP_PREFIX="pflab-"

domain_id() { cat "${HERE}/.vagrant/machines/$1/libvirt/id"; }

cmd_snapshot() {
  (($#)) || die "usage: $0 snapshot <name>"
  local vm id snap="${LAB_SNAP_PREFIX}$1"
  for vm in gw $(clients); do
    created "${vm}" || continue
    id="$(domain_id "${vm}")"
    "${VIRSH[@]}" snapshot-create-as --domain "${id}" --name "${snap}" --atomic
    echo "lab.sh: ${vm}: snapshot ${snap}"
  done
}

cmd_restore() {
  (($#)) || die "usage: $0 restore <name>"
  local vm id snap="${LAB_SNAP_PREFIX}$1"
  for vm in gw $(clients); do
    created "${vm}" || continue
    id="$(domain_id "${vm}")"
    if ! "${VIRSH[@]}" snapshot-info --domain "${id}" --snapshotname "${snap}" >/dev/null 2>&1; then
      echo "lab.sh: ${vm}: no snapshot ${snap}, skipping" >&2
      continue
    fi
    "${VIRSH[@]}" snapshot-revert --domain "${id}" --snapshotname "${snap}" --running 2>/dev/null ||
      "${VIRSH[@]}" snapshot-revert --domain "${id}" --snapshotname "${snap}"
    echo "lab.sh: ${vm}: reverted to ${snap}"
  done
  # A revert can change an address or a host key. Then the old ssh config
  # can be incorrect. Thus delete it. The next command makes it again.
  rm -f "${SSH_CFG}"
}

cmd_snapshots() {
  local vm id
  for vm in gw $(clients); do
    created "${vm}" || continue
    id="$(domain_id "${vm}")"
    echo "== ${vm} =="
    "${VIRSH[@]}" snapshot-list --domain "${id}" 2>/dev/null | grep -E "${LAB_SNAP_PREFIX}|Name" || echo "  (none)"
  done
}

cmd_provision() {
  (($#)) || die "usage: $0 provision <vm> [provisioner...]"
  local vm="$1" with=()
  shift
  (($#)) && with=(--provision-with "$(
    IFS=,
    echo "$*"
  )")
  [[ "${vm}" == gw ]] || cmd_uncut
  vagrant rsync "${vm}"
  vagrant provision "${vm}" "${with[@]}"
  [[ "${vm}" == gw ]] || cmd_cut
}

# test: with a race build on gw (only that build has the TSan runtime),
# it also runs race_check after go test, also when go test fails.
cmd_test() {
  cmd_ssh_config >/dev/null
  cmd_cut
  cd "${ROOT}"
  export PF_TARGET=cloudlab PF_SSH_CONFIG="${SSH_CFG}" PF_LAB_ENV="${HERE}/lab.env" \
    GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0
  set -- go test -tags=vagrant -count=1 -timeout 45m ./vm/itest "$@"
  lab_ssh pi 'grep -qa ThreadSanitizer /usr/local/sbin/pf' || exec "$@"
  local since rc=0
  since="$(lab_ssh pi 'date +%s')"
  echo "lab.sh: gw runs a race build of pf. The race check reads the gw journal from @${since}."
  lab_ssh pi 'test -d /var/log/journal' ||
    echo "lab.sh: WARNING: the gw journal is volatile. A reboot of gw loses the race reports before it." >&2
  "$@" || rc=$?
  race_check "${since}" || ((rc)) || rc=1
  exit "${rc}"
}

cmd_ssh() {
  (($#)) || die "usage: $0 ssh <pi|agent|agent2|house|desk> [command]"
  [[ -f "${SSH_CFG}" ]] || cmd_ssh_config >/dev/null
  exec ssh -F "${SSH_CFG}" "$@"
}

cmd_status() {
  vagrant status
  ip -br link show type bridge | grep -E "^(${TRUNK_BR}|${AGENT_BR}|${HOUSE_BR}) " || echo "no lab bridges: sudo $0 host"
}

cmd_down() { vagrant halt "$@"; }

cmd_destroy() {
  vagrant destroy -f "$@"
  rm -f "${SSH_CFG}"
}

usage() {
  cat <<EOF
usage: $0 <command>
  host              (sudo) lab bridges and the VLAN veth; rerun after a host reboot
  host-clean        (sudo) remove them
  up [vm...]        build pf, create and provision VMs (gw first), cut client mgmt links
  test [go args]    run the e2e suite, e.g. test -v -run 'TestLab/ops'
  sync              build pf, copy the repo to gw, rerun apply.sh (fast inner loop)
  ship              build the amd64 bundle, sign with a lab-only key, ship it
                    through pfship like a real Pi (docs/signed_ship.md)
  snapshot <name>   libvirt snapshot of every lab VM, prefixed pflab-
  restore <name>    revert every lab VM to that snapshot
  snapshots         list this lab's snapshots per VM
  provision <vm> [provisioner...]
                    copy the repo and rerun provisioners on one VM
  ssh <vm> [cmd]    pi, agent, agent2, house or desk
  ssh-config        write ${SSH_CFG}
  cut | uncut       client mgmt links down or up
  build | status | down [vm...] | destroy [vm...]
Env: PF_AGENT_COUNT (1-3, default 2), PF_BOX, PF_E2E_REBOOT=1,
     PF_RACE=1 (sync: race build of pf for the lab, docs/cloud_lab.md).
EOF
}

sub="${1:-help}"
shift || true
fn="cmd_${sub//-/_}"
if ! declare -F "${fn}" >/dev/null; then
  usage
  exit 2
fi
# Vagrant plugins are per user: root has no vagrant-libvirt. Only host and
# host-clean need sudo.
case "${sub}" in
  host | host-clean | help) ;;
  *) [[ ${EUID} -ne 0 ]] || die "${sub}: run without sudo (only host and host-clean need it)" ;;
esac
"${fn}" "$@"
