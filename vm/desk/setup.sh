#!/bin/bash
set -euo pipefail

# The desktop half of the VLAN split (docs/lab.md). One NIC carries two
# tagged segments to the Pi. VLAN 20 is the agent segment: the host has
# no address on it, and only lends it to VirtualBox and Docker. VLAN 79 is
# the desk segment: the uplink of the host itself through the Pi.
#
#   sudo vm/desk/setup.sh net       profiles, no default route yet
#   sudo vm/desk/setup.sh default   move the default route onto VLAN 79
#   sudo vm/desk/setup.sh lock      no forwarding, nothing on VLAN 20
#   sudo vm/desk/setup.sh status    what is in place now
#   vm/desk/setup.sh uplinks        is the Pi this host's only way out
#   setup.sh boot-check             pf-desk-lock's boot run of uplinks: warns, never blocks
#   sudo vm/desk/setup.sh restore   back to the Wi-Fi uplink, in one step
#   sudo pf-desk-restore            the same, installed by net and lock:
#                                   works with no repo, no DNS, no agent
#   sudo vm/desk/setup.sh ca <pem> [sha256]
#                                   trust the CA of the Pi (INSPECT=on)
#   sudo vm/desk/setup.sh ca-remove take that trust away again
#
# Run them in that order, and test after each. lock is last, because its
# forward drop cuts all containers that are still on the default docker
# bridge. This includes a sandbox in which an agent possibly runs.
#
# PF_LAB=1 runs the same three on an untagged adapter and without
# NetworkManager, as in the local VirtualBox lab. vm/desk/lab.sh is the
# wrapper that sets it.

# PF_LAB=1 is the local VirtualBox lab (tier 1). A VirtualBox internal
# network carries no 802.1Q tags. Thus there the desk segment is a plain
# adapter, not a child of a trunk, and the box has no NetworkManager. All
# above the link layer is the same run: the Pi-side plain segment, its
# NAT and isolation, the default route onto it, and the lock of this host.
# Tier 1 cannot replace the trunk and the agent VLAN: they do not exist
# here. Thus PARENT and AGENT_IF below name nothing, and the two drops
# that reference them have no effect. The forward-policy drop is the half
# that stops a container from routing around the Pi. It is real in both cases.
LAB="${PF_LAB:-0}"

AGENT_VLAN="${AGENT_VLAN:-20}"
DESK_VLAN="${DESK_VLAN:-79}"
DESK_ADDR="${DESK_ADDR:-10.79.0.2/30}"
DESK_GW="${DESK_GW:-10.79.0.1}"
# The Pi, not an upstream: the segment resolves through this box now, and
# the 80/443 gate opens only addresses that it saw resolved. A desk that
# points to 9.9.9.9 (the old default of this script) would still resolve
# names, and then find all of them unreachable.
DESK_DNS="${DESK_DNS:-${DESK_GW}}"

if [[ "${LAB}" == 1 ]]; then
  # No interface has these names. Thus the input and output drops load
  # and match nothing. The name of a real adapter would be false about
  # what tier 1 proves. The name of the VirtualBox NAT adapter would cut
  # the session that Vagrant provisions over. Both are inside IFNAMSIZ: nft
  # refuses an interface name of 16 characters or more, even one that is
  # fictional on purpose.
  PARENT="${PARENT:-pf-absent-trunk}"
  AGENT_IF="${AGENT_IF:-pf-absent-vlan}"
  # Find by address, not by name. The adapter that Vagrant puts the
  # segment on depends on how many adapters are attached.
  DESK_IF="${DESK_IF:-$(ip -4 -o addr show to "${DESK_ADDR%/*}/32" 2>/dev/null | awk '{sub(/@.*/, "", $2); print $2; exit}')}"
else
  PARENT="${PARENT:-enp6s0}"
  AGENT_IF="${PARENT}.${AGENT_VLAN}"
  DESK_IF="${PARENT}.${DESK_VLAN}"
fi
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { echo "desk: $*"; }
die() { echo "desk: $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "run as root"; }

con_exists() { nmcli -t -f NAME con show 2>/dev/null | grep -qx "$1"; }

# All profiles bound to an interface, active or not. The DEVICE column has
# a value only for active connections. Thus an autoconnect profile that is
# only idle needs connection.interface-name to be found.
holders() {
  local n
  {
    nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$1" '$2 == d {print $1}'
    while IFS= read -r n; do
      [[ -n "${n}" ]] || continue
      [[ "$(nmcli -g connection.interface-name con show "${n}" 2>/dev/null)" == "$1" ]] && printf '%s\n' "${n}"
    done < <(nmcli -t -f NAME con show 2>/dev/null)
  } | sort -u
}

do_net() {
  need_root
  if [[ "${LAB}" == 1 ]]; then
    # Nothing to build: the hypervisor already attached the adapter and
    # wrote the address. Assert it, do not configure it again. Thus a
    # second configurator never fights Vagrant for the interface.
    [[ -n "${DESK_IF}" ]] || die "no interface holds ${DESK_ADDR}; the lab's desk network did not come up"
    ip link set "${DESK_IF}" up
    say "up: ${DESK_IF} ${DESK_ADDR}, untagged (tier 1 has no trunk and no agent VLAN)"
    say "next: ping -c2 ${DESK_GW} and ssh the Pi at ${DESK_GW}, then '$0 default'"
    return
  fi
  command -v nmcli >/dev/null 2>&1 || die "NetworkManager (nmcli) is required"
  [[ -e "/sys/class/net/${PARENT}" ]] || die "${PARENT} does not exist; set PARENT=<nic>"

  modprobe 8021q 2>/dev/null || true
  install -d -m 0755 /etc/modules-load.d
  echo 8021q >/etc/modules-load.d/pf-desk.conf

  # The raw port carries tags only. Without its own profile, NetworkManager
  # makes a "Wired connection" that DHCPs on it. That profile can take the
  # device away from the VLAN children.
  local other
  # A netplan-generated profile is under /run. It comes back at the next
  # `netplan apply` or reboot, and then it would take the device from the
  # VLAN children again. A delete here would seem to work, and then fail
  # later. Thus change the YAML instead.
  while read -r other; do
    case "${other}" in
      netplan-*) die "${other} is generated by netplan and holds ${PARENT}. Remove the ${PARENT} entry from /etc/netplan/*.yaml, run 'sudo netplan apply', then run this again." ;;
    esac
  done < <(holders "${PARENT}")
  while read -r other; do
    [[ -n "${other}" && "${other}" != "trunk-${PARENT}" ]] || continue
    say "removing ${other}, which holds ${PARENT}"
    nmcli con delete "${other}" >/dev/null
  done < <(holders "${PARENT}")

  if con_exists "trunk-${PARENT}"; then
    nmcli con modify "trunk-${PARENT}" connection.interface-name "${PARENT}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  else
    nmcli con add type ethernet ifname "${PARENT}" con-name "trunk-${PARENT}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  fi

  # No address on the agent VLAN. The host is a wire here: VirtualBox
  # bridges onto this device, and Docker uses it as a macvlan parent.
  # Neither needs an address on the host for that.
  if con_exists agent-vlan; then
    nmcli con modify agent-vlan connection.interface-name "${AGENT_IF}" vlan.parent "${PARENT}" vlan.id "${AGENT_VLAN}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  else
    nmcli con add type vlan con-name agent-vlan ifname "${AGENT_IF}" dev "${PARENT}" id "${AGENT_VLAN}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  fi

  # never-default until `setup.sh default`. Start the segment and prove
  # that the Pi answers before it gets the default route. Thus a mistake
  # here leaves the current uplink working.
  if con_exists desk-vlan; then
    nmcli con modify desk-vlan connection.interface-name "${DESK_IF}" vlan.parent "${PARENT}" vlan.id "${DESK_VLAN}" ipv4.method manual ipv4.addresses "${DESK_ADDR}" ipv4.gateway "${DESK_GW}" ipv4.dns "${DESK_DNS}" ipv4.route-metric 50 ipv6.method disabled connection.autoconnect yes >/dev/null
  else
    nmcli con add type vlan con-name desk-vlan ifname "${DESK_IF}" dev "${PARENT}" id "${DESK_VLAN}" ipv4.method manual ipv4.addresses "${DESK_ADDR}" ipv4.gateway "${DESK_GW}" ipv4.dns "${DESK_DNS}" ipv4.route-metric 50 ipv4.never-default yes ipv6.method disabled connection.autoconnect yes >/dev/null
  fi

  install_restore

  nmcli con up "trunk-${PARENT}" >/dev/null 2>&1 || true
  nmcli con up agent-vlan >/dev/null || die "agent-vlan did not come up"
  nmcli con up desk-vlan >/dev/null || die "desk-vlan did not come up"

  say "up: ${PARENT} trunk, ${AGENT_IF} (no address), ${DESK_IF} ${DESK_ADDR}"
  say "next: ping -c2 ${DESK_GW} and ssh the Pi at ${DESK_GW}, then '$0 default'"
}

do_default() {
  need_root
  if [[ "${LAB}" == 1 ]]; then
    [[ -n "${DESK_IF}" ]] || die "no interface holds ${DESK_ADDR}; run '$0 net' first"
    ping -c2 -W2 "${DESK_GW}" >/dev/null 2>&1 || die "${DESK_GW} does not answer; not moving the default route"
    # The VirtualBox NAT adapter keeps its connected route. The ssh that
    # Vagrant provisions over needs only that. All other traffic goes to
    # the Pi, as the traffic of the desktop does after its Wi-Fi is off.
    while ip route del default >/dev/null 2>&1; do :; done
    ip route add default via "${DESK_GW}" dev "${DESK_IF}"
    # The Pi: the segment has its own resolver there. A lookup sent to a
    # different server gets a reject on the way out. Immutable, because
    # the DHCP client of the NAT adapter rewrites this file at each lease.
    chattr -i /etc/resolv.conf 2>/dev/null || true
    printf 'nameserver %s\n' "${DESK_DNS}" >/etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
    say "default route via ${DESK_GW}:"
    ip route show default
    return
  fi
  con_exists desk-vlan || die "no desk-vlan profile; run '$0 net' first"
  ping -c2 -W2 "${DESK_GW}" >/dev/null 2>&1 || die "${DESK_GW} does not answer; not moving the default route"
  # NM removes ipv4.gateway from a profile added with never-default yes.
  # Thus set the gateway again here, or no default route appears.
  # Before anything moves: the Pi resolver must answer this host. It is
  # the only resolver that the segment lets through.
  if command -v dig >/dev/null 2>&1; then
    [[ -n "$(dig +short +time=2 +tries=1 "@${DESK_DNS}" example.com 2>/dev/null)" ]] \
      || die "${DESK_DNS} does not resolve example.com for this host; not moving the default route"
  fi
  nmcli con modify desk-vlan ipv4.never-default no ipv4.gateway "${DESK_GW}" >/dev/null
  nmcli con up desk-vlan >/dev/null
  # The route is the easy half. The segment opens 443 only to addresses
  # that its own resolver gave. A host that resolves through a different
  # server loses all names immediately when the route moves. The usual
  # case is a DoH or DoT proxy on loopback that dials its upstream by
  # address (seen 2026-09-21: ctrld, dead two seconds after this step).
  # This step checks that, through the system resolver and with a new
  # name. A failure puts the Wi-Fi uplink back. It does not leave a
  # desktop that cannot look up how to fix itself.
  if ! egress_ok; then
    say "names do not resolve through the system resolver with the default route on ${DESK_GW}; putting it back"
    resolver_hint
    do_restore
    die "default route NOT moved. Point this host's resolver at ${DESK_DNS}, then run '$0 default' again."
  fi
  if ! resolver_state >/dev/null 2>&1; then
    say "egress works, but NOT through the Pi's resolver:"
    resolver_state || true
  fi
  say "default route via ${DESK_GW}:"
  ip route show default
  if ! route_via_desk; then
    say "egress through ${DESK_GW} works, but this host still leaves by $(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'): its route outranks the desk's for now."
    say "'nmcli radio wifi off' hands everything to ${DESK_GW}."
  fi
  say "next: verify egress (curl -s https://api.ipify.org), then turn the radio off with 'nmcli radio wifi off'"
  say "to undo at any point: sudo pf-desk-restore"
}

# A lookup that the cache must not answer, through the resolver of this
# host, and then a connection to the address that it returned.
egress_ok() {
  local i
  for i in 1 2 3; do
    if command -v resolvectl >/dev/null 2>&1; then
      resolvectl query --cache=no example.com >/dev/null 2>&1 && break
    else
      getent hosts example.com >/dev/null 2>&1 && break
    fi
    [[ "${i}" == 3 ]] && return 1
    sleep 2
  done
  # Pin to the desk link. With Wi-Fi still up, NetworkManager can give the
  # new route a metric above the Wi-Fi metric (20050 against 600, seen
  # 2026-09-22 while its connectivity check was pending). An unpinned
  # fetch then goes over Wi-Fi and proves nothing about the Pi.
  if command -v curl >/dev/null 2>&1; then
    curl -sS -o /dev/null --interface "${DESK_IF}" --connect-timeout 5 --max-time 8 https://example.com >/dev/null 2>&1 || return 1
  fi
  return 0
}

# The link that the traffic of this host leaves by now. If it is not the
# desk, this is only a warning: Wi-Fi wins until the radio is off, as expected.
route_via_desk() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ip route get 1.1.1.1 2>/dev/null | grep -q " dev ${DESK_IF} " && return 0
    sleep 1
  done
  return 1
}

# The resolver of this host. The gate of the segment opens 80/443 only to
# addresses that the Pi resolver gave. A host that resolves through a
# different server works only while that gate is off. It fails immediately
# when the gate is on. Seen 2026-09-22: ctrld was stopped for the cutover,
# but was still enabled. It came back with a reboot and put 127.0.0.1 on
# the desk link. Nothing detected it until BLOCK_DIRECT_IP was on and all
# names on the desktop failed at the same time.
resolver_state() {
  command -v resolvectl >/dev/null 2>&1 || { echo "(no resolvectl; check /etc/resolv.conf is ${DESK_DNS})"; return 0; }
  local global link bad=0
  global="$(resolvectl dns 2>/dev/null | awk -F': *' '/^Global/ {print $2}')"
  link="$(resolvectl dns "${DESK_IF}" 2>/dev/null | awk -F': *' '{print $2}')"
  echo "global: ${global:-(none)}"
  echo "${DESK_IF}: ${link:-(none)}"
  [[ -z "${global}" ]] || bad=1
  [[ "${link}" == "${DESK_DNS}" ]] || bad=1
  if [[ "${bad}" == 1 ]]; then
    echo "WARNING: this host does not resolve through ${DESK_DNS} alone. It works only while the"
    echo "segment's BLOCK_DIRECT_IP is off. A local proxy is the usual cause:"
    echo "  systemctl is-enabled ctrld   (disable it: sudo systemctl disable --now ctrld)"
    echo "then: sudo nmcli con up desk-vlan"
    return 1
  fi
  echo "ok: every name goes to ${DESK_DNS}"
}

resolver_hint() {
  command -v resolvectl >/dev/null 2>&1 || return 0
  local global
  global="$(resolvectl dns 2>/dev/null | awk -F': ' '/^Global/ {print $2}')"
  case "${global}" in
    127.*|::1*)
      say "the system resolver is a local proxy (${global}). It dials its own upstream, which this segment drops."
      say "the Pi already resolves over TLS for the desk. Stop the proxy (for ctrld: 'sudo ctrld stop') so the"
      say "desk-vlan profile's DNS, ${DESK_DNS}, is what the host uses."
      ;;
  esac
}

# The way back, installed where it stays without the repo. A desktop that
# lost its uplink cannot fetch a checkout, look up the command, or run
# the agent that knows it (2026-09-21: one hour of searches from a phone).
# A copy of this script plus a one-word wrapper. restore needs nothing
# else: no DNS and no file next to it. net and lock refresh it, so it
# follows the version that set up the desk.
RESTORE_LIB="${PF_DESK_RESTORE_LIB:-/usr/local/lib/pf-desk}"
RESTORE_BIN="${PF_DESK_RESTORE_BIN:-/usr/local/sbin/pf-desk-restore}"
install_restore() {
  # The lab is rebuilt with vagrant, and restore refuses to run there.
  [[ "${LAB}" == 1 ]] && return 0
  install -d -m 0755 "${RESTORE_LIB}" "${RESTORE_BIN%/*}"
  install -m 0755 "${HERE}/setup.sh" "${RESTORE_LIB}/setup.sh"
  cat >"${RESTORE_BIN}" <<EOF
#!/bin/sh
# Back to the Wi-Fi uplink in one step, whatever the desk VLAN did.
# Installed by pi-fortress vm/desk/setup.sh; needs no repo and no DNS.
exec env PARENT="${PARENT}" DESK_VLAN="${DESK_VLAN}" DESK_GW="${DESK_GW}" ${RESTORE_LIB}/setup.sh restore
EOF
  chmod 0755 "${RESTORE_BIN}"
  say "way back, from any terminal, no repo or DNS needed: sudo pf-desk-restore"
}

# One step back to a working desktop, from any state of the cutover. It
# undoes 'default' and 'lock' and keeps 'net': the VLAN profiles are safe
# without a default route, and the next attempt needs them. Each line is
# safe to run two times, and no line depends on DNS.
do_restore() {
  need_root
  if [[ "${LAB}" == 1 ]]; then
    die "restore is for the desktop; the lab is rebuilt with vagrant"
  fi
  # Loopback first. A desktop whose lo lost 127.0.0.1 sends the traffic of
  # its own stub resolver out of the uplink, and resolves nothing on any
  # network (seen 2026-09-21 after a netplan apply).
  ip link set lo up 2>/dev/null || true
  ip -4 addr show dev lo | grep -q 'inet 127\.0\.0\.1/' || ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
  ip -6 addr show dev lo | grep -q 'inet6 ::1/' || ip -6 addr add ::1/128 dev lo 2>/dev/null || true

  if systemctl is-enabled pf-desk-lock.service >/dev/null 2>&1 || systemctl is-active pf-desk-lock.service >/dev/null 2>&1; then
    systemctl disable --now pf-desk-lock.service >/dev/null 2>&1 || true
    systemctl stop pf-desk-uplink-check.timer >/dev/null 2>&1 || true
    say "pf-desk-lock.service stopped and disabled"
  fi
  nft delete table inet pf_desk_lock 2>/dev/null && say "pf_desk_lock table removed" || true
  if [[ -f /etc/sysctl.d/90-pf-desk.conf ]]; then
    rm -f /etc/sysctl.d/90-pf-desk.conf
    sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  fi
  rm -f /etc/NetworkManager/dispatcher.d/90-pf-desk

  if con_exists desk-vlan; then
    nmcli con modify desk-vlan ipv4.never-default yes ipv4.gateway "" >/dev/null 2>&1 || true
    nmcli con up desk-vlan >/dev/null 2>&1 || true
  fi
  ip route del default via "${DESK_GW}" 2>/dev/null || true

  nmcli radio wifi on >/dev/null 2>&1 || true
  local wifi i
  wifi="$(nmcli -t -f DEVICE,TYPE device 2>/dev/null | awk -F: '$2 == "wifi" {print $1; exit}')"
  if [[ -n "${wifi}" ]]; then
    nmcli device connect "${wifi}" >/dev/null 2>&1 || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
      ip route show default 2>/dev/null | grep -q "dev ${wifi}" && break
      sleep 1
    done
  fi
  systemctl try-restart systemd-resolved >/dev/null 2>&1 || true
  say "restored. lo: $(ip -br addr show lo | awk '{print $3, $4}')"
  say "default route: $(ip route show default | head -1)"
  ip route show default | grep -q . || say "NO default route: no Wi-Fi uplink came back. Check 'nmcli device' and the dongle."
}

# A second way out. The desk VLAN is the only uplink that the Pi can
# filter. A desktop that also has Wi-Fi, a USB-tethered phone or a
# different cable leaves by that path immediately when a route prefers
# it, past all rules on the Pi. (An agent that escapes its VM owns this
# host and selects the path.) lock refuses such a host. status reports it.
#
# Three findings, each with the name of the interface:
#   - a default route (or the 0/1 + 128/1 pair that a VPN uses instead)
#     in any routing table, v4 or v6, on any device except DESK_IF via
#     DESK_GW. That covers tailscale0 or wg* as an exit node; otherwise they pass.
#   - a wireless interface that is administratively up and not rfkill-blocked.
#   - a hardware-backed NIC other than the trunk, with carrier and an
#     IPv4 route in the main table. Hardware-backed means a device link
#     in sysfs, directly or through lower_* (a bridge or VLAN over a real
#     port). docker, libvirt, VirtualBox host-only and overlay devices
#     have none. The trunk and its two known VLAN children (AGENT_IF,
#     DESK_IF) belong to the Pi. The lower_* walk comes before the name
#     exemptions. Thus a br-* or docker* bridge with a real port enslaved
#     counts. A third VLAN on the trunk also counts (a managed switch can
#     carry it to a place where the Pi is not).
# The management NIC of the cloud lab is named in /etc/pf-lab.env, and it
# does not count. PF_TEST_SYSFS_NET and PF_TEST_LAB_ENV are for scripts/shell_test.sh.
SYSFS_NET="${PF_TEST_SYSFS_NET:-/sys/class/net}"
LAB_ENV_FILE="${PF_TEST_LAB_ENV:-/etc/pf-lab.env}"

lab_mgmt_if() {
  local v
  [[ -r "${LAB_ENV_FILE}" ]] || return 0
  v="$(sed -n 's/^MGMT_IF=//p' "${LAB_ENV_FILE}" 2>/dev/null | head -n1)"
  if [[ "${v}" =~ ^[A-Za-z][A-Za-z0-9._-]{0,14}$ ]]; then
    printf '%s\n' "${v}"
  fi
  return 0
}

# The trunk and everything above it reach only the Pi.
hw_backed() {
  local n="$1" depth="${2:-0}" l
  [[ "${n}" != "${PARENT}" ]] || return 1
  [[ ! -e "${SYSFS_NET}/${n}/device" ]] || return 0
  ((depth < 4)) || return 1
  for l in "${SYSFS_NET}/${n}"/lower_*; do
    [[ -e "${l}" || -L "${l}" ]] || continue
    if hw_backed "${l##*/lower_}" $((depth + 1)); then
      return 0
    fi
  done
  return 1
}

# A port below n, not n itself, is hardware-backed. This is how a bridge
# or a macvtap with a virtual-device name still reaches a real NIC.
hw_lower() {
  local l
  for l in "${SYSFS_NET}/$1"/lower_*; do
    [[ -e "${l}" || -L "${l}" ]] || continue
    if hw_backed "${l##*/lower_}" 1; then
      return 0
    fi
  done
  return 1
}

# Names that are virtual devices by convention. The VirtualBox vboxnet*
# devices have their own device link, so the name must exempt them. The
# check still catches a real port enslaved below one (hw_lower).
virtual_name() {
  case "$1" in
    lo | docker* | veth* | virbr* | vnet* | br-* | macvtap* | vboxnet* | vmnet* | tap* | lxcbr* | lxdbr* | incusbr* | podman* | cni* | tailscale* | wg* | tun* | zt*) return 0 ;;
  esac
  return 1
}

# Whether n could be a wired way out that is not the Pi.
wired_candidate() {
  local n="$1"
  if [[ "${n}" == "${DESK_IF}" || "${n}" == "${PARENT}" || "${n}" == "${AGENT_IF}" ]]; then
    return 1
  fi
  if [[ "${n}" == "${PARENT}".* ]]; then
    return 0
  fi
  if virtual_name "${n}"; then
    hw_lower "${n}"
    return
  fi
  hw_backed "${n}"
}

admin_up() {
  local f
  f="$(cat "$1/flags" 2>/dev/null)" || return 1
  [[ "${f}" =~ ^0x[0-9a-fA-F]+$ ]] || return 1
  (((f & 1) == 1))
}

rfkill_blocked() {
  local r
  for r in "$1"/phy80211/rfkill*/soft "$1"/phy80211/rfkill*/hard; do
    [[ "$(cat "${r}" 2>/dev/null)" == 1 ]] && return 0
  done
  return 1
}

# One line per finding, interface first. Never fails: status prints it
# under set -e.
second_uplinks() {
  local mgmt="$1" r4 r6 fam dest dev via table d n dests
  r4="$(ip -o -4 route show table all 2>/dev/null || true)"
  r6="$(ip -o -6 route show table all 2>/dev/null || true)"
  while read -r fam dest dev via table; do
    [[ -n "${dev}" && "${dev}" != lo && "${dev}" != "${mgmt}" ]] || continue
    if [[ "${dev}" == "${DESK_IF}" ]] && [[ "${fam}" == 6 || "${via}" == - || "${via}" == "${DESK_GW}" ]]; then
      continue
    fi
    local how="${dest}"
    [[ "${via}" == - ]] || how+=" via ${via}"
    echo "${dev}: default route ${how} dev ${dev} (table ${table}) bypasses ${DESK_GW}. Remove it: sudo ip -${fam} route del ${how} dev ${dev} table ${table}; and stop what adds it (a NetworkManager profile: nmcli con modify <profile> ipv${fam}.never-default yes; a VPN or tailnet: turn off its exit node or full tunnel)."
  done < <(
    for fam in 4 6; do
      if [[ "${fam}" == 4 ]]; then printf '%s\n' "${r4}"; else printf '%s\n' "${r6}"; fi |
        awk -v fam="${fam}" '
          $1 == "default" || $1 == "0.0.0.0/1" || $1 == "128.0.0.0/1" || $1 == "::/1" || $1 == "8000::/1" {
            tbl = "main"; via = "-"
            for (i = 2; i < NF; i++) if ($i == "table") tbl = $(i + 1)
            for (i = 2; i < NF; i++) {
              if ($i == "via") { via = $(i + 1); if (via == "inet" || via == "inet6") via = $(i + 2) }
              if ($i == "dev") { print fam, $1, $(i + 1), via, tbl; via = "-" }
            }
          }'
    done
  )

  for d in "${SYSFS_NET}"/*; do
    n="${d##*/}"
    [[ -e "${d}/wireless" || -e "${d}/phy80211" ]] || continue
    [[ "${n}" != "${mgmt}" ]] || continue
    admin_up "${d}" || continue
    rfkill_blocked "${d}" && continue
    echo "${n}: Wi-Fi is up. Turn the radio off: nmcli radio wifi off, or sudo rfkill block wifi; both are remembered across reboots, where 'ip link set ${n} down' is not (NetworkManager brings it back). For good, disable Wi-Fi in the BIOS or remove the card."
  done

  for d in "${SYSFS_NET}"/*; do
    n="${d##*/}"
    [[ -e "${d}" && "${n}" != "${mgmt}" ]] || continue
    [[ -e "${d}/wireless" || -e "${d}/phy80211" ]] && continue
    [[ "$(cat "${d}/carrier" 2>/dev/null)" == 1 ]] || continue
    wired_candidate "${n}" || continue
    dests="$(printf '%s\n' "${r4}" | awk -v d="${n}" '
      $1 ~ /^(local|broadcast|anycast|multicast|unreachable|blackhole|prohibit|throw|nat)$/ { next }
      / table / { next }
      { for (i = 2; i < NF; i++) if ($i == "dev" && $(i + 1) == d) { printf "%s ", $1; next } }')"
    [[ -n "${dests}" ]] || continue
    echo "${n}: a second wired NIC with carrier and IPv4 routes (${dests% }). Unplug it, or take it down: nmcli device disconnect ${n} and set its profile to connection.autoconnect no; or disable the port in the BIOS."
  done
  return 0
}

# Prints the findings, or a line that says there are none. Fails when there are findings.
uplink_report() {
  local mgmt found
  mgmt="$(lab_mgmt_if)"
  [[ -z "${mgmt}" ]] || echo "${mgmt}: the lab's management NIC (${LAB_ENV_FILE}), not counted"
  found="$(second_uplinks "${mgmt}")"
  if [[ -z "${found}" ]]; then
    echo "ok: the only way out is ${DESK_IF:-(no desk interface)} via ${DESK_GW}"
    return 0
  fi
  printf '%s\n' "${found}" | sed 's/^/SECOND UPLINK: /'
  return 1
}

# The gate of lock, and the uplinks subcommand. PF_LAB=1 continues: in
# both labs, the Vagrant management adapter is a second way out by design.
uplink_gate() {
  local out
  if out="$(uplink_report)"; then
    printf '%s\n' "${out}" | sed 's/^/desk: /'
    return 0
  fi
  printf '%s\n' "${out}" | sed 's/^/desk: /' >&2
  if [[ "${LAB}" == 1 ]]; then
    say "PF_LAB=1: not refusing; the lab's Vagrant management adapter is a way out by design, a real desktop has none"
    return 0
  fi
  if [[ "${PF_DESK_ALLOW_SECOND_UPLINK:-0}" == 1 ]]; then
    {
      echo "desk: ************************************************************"
      echo "desk: WARNING: PF_DESK_ALLOW_SECOND_UPLINK=1. This host has another way"
      echo "desk: out besides the Pi (above), and everything that takes it skips"
      echo "desk: every Pi rule: no filtering, no isolation, no logs. An agent that"
      echo "desk: escapes its VM can pick that path. Fine as a dev-box fallback;"
      echo "desk: not a desk you rely on."
      echo "desk: ************************************************************"
    } >&2
    return 0
  fi
  die "refusing to lock: this host has a way out that is not the Pi (above), and everything sent that way skips every Pi rule. Fix each line and run '$0 lock' again. A development box that keeps Wi-Fi as a fallback: sudo PF_DESK_ALLOW_SECOND_UPLINK=1 $0 lock"
}

# Where boot-check writes its findings for status. /run: new at each boot.
# Thus status never shows the answer of an old boot as the answer of this boot.
BOOT_STATE="${PF_DESK_BOOT_STATE:-/run/pf-desk/boot-uplinks}"

# pf-desk-lock schedules this some time after boot (desk-lock.service),
# after NetworkManager had time to autoconnect a Wi-Fi profile or a second
# cable. The lock itself runs before the network is up, when there is
# nothing to find. Warn only, never block: a boot check that cut egress
# could stop the only working uplink of a desk on a false positive, with
# nobody at the keyboard. "<2>" is the crit level of journald.
do_boot_check() {
  local out status=0 stamp
  out="$(uplink_report)" || status=1
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  if install -d -m 0755 "${BOOT_STATE%/*}" 2>/dev/null; then
    { echo "checked ${stamp}"; printf '%s\n' "${out}"; } >"${BOOT_STATE}" 2>/dev/null || true
  fi
  if [[ "${status}" == 1 ]]; then
    printf '%s\n' "${out}" | sed 's/^/<2>pf-desk: /' >&2
    echo "<2>pf-desk: this host has a way out that is not the Pi; everything sent that way skips every Pi rule. Nothing was blocked. 'sudo vm/desk/setup.sh status' shows it." >&2
  else
    printf '%s\n' "${out}" | sed 's/^/<6>pf-desk: /'
  fi
  return 0
}

do_lock() {
  uplink_gate
  need_root
  command -v nft >/dev/null 2>&1 || die "nftables (nft) is required"
  install -d -m 0755 /etc/pi-fortress

  sed -e "s|@PARENT@|${PARENT}|g" -e "s|@AGENT_IF@|${AGENT_IF}|g" \
    "${HERE}/desk-lock.nft" >/etc/pi-fortress/desk-lock.nft
  chmod 0644 /etc/pi-fortress/desk-lock.nft
  nft -c -f /etc/pi-fortress/desk-lock.nft

  # The dispatcher belongs to NetworkManager. A host without it (the lab,
  # or a systemd-networkd desktop) keeps the per-link sysctls that it can
  # set in sysctl.d. It loses only the sysctls for devices that appear
  # later. The nft table holds the line in both cases.
  if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
    sed -e "s|@PARENT@|${PARENT}|g" -e "s|@AGENT_IF@|${AGENT_IF}|g" \
      "${HERE}/90-pf-desk" >/etc/NetworkManager/dispatcher.d/90-pf-desk
    chmod 0755 /etc/NetworkManager/dispatcher.d/90-pf-desk
  else
    say "no NetworkManager dispatcher directory; the per-link guard is not installed"
  fi

  install -d -m 0755 /etc/sysctl.d
  cat >/etc/sysctl.d/90-pf-desk.conf <<EOF
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
EOF
  sysctl -q --system >/dev/null 2>&1 || true

  # Docker sets ip_forward=1 at each start. The nft forward chain is what
  # really holds the line. But a sysctl that flaps makes the state of the
  # host false about its own policy.
  if [[ -f /etc/docker/daemon.json ]] && command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import json, io
p = '/etc/docker/daemon.json'
try:
    with io.open(p) as f:
        cfg = json.load(f)
except Exception as e:
    raise SystemExit("desk: %s is not readable JSON (%s); add \"ip-forward\": false by hand" % (p, e))
if cfg.get('ip-forward') is not False:
    cfg['ip-forward'] = False
    with io.open(p, 'w') as f:
        json.dump(cfg, f, indent=2)
        f.write('\n')
    print('desk: set "ip-forward": false in %s; restart docker to apply' % p)
PY
  elif [[ ! -f /etc/docker/daemon.json ]]; then
    install -d -m 0755 /etc/docker
    printf '{\n  "ip-forward": false\n}\n' >/etc/docker/daemon.json
    say 'wrote /etc/docker/daemon.json with "ip-forward": false; restart docker to apply'
  else
    say 'no python3: add "ip-forward": false to /etc/docker/daemon.json by hand' >&2
  fi

  install_restore
  # The boot check runs the restore copy of this script. The lab does not
  # install that copy. The lab has its management adapter by design.
  if [[ "${LAB}" == 1 ]]; then
    sed '/boot-check/d' "${HERE}/desk-lock.service" >/etc/systemd/system/pf-desk-lock.service
  else
    sed -e "s|@PARENT@|${PARENT}|g" -e "s|@AGENT_VLAN@|${AGENT_VLAN}|g" -e "s|@DESK_VLAN@|${DESK_VLAN}|g" -e "s|@DESK_GW@|${DESK_GW}|g" \
      -e "s|@RESTORE_LIB@|${RESTORE_LIB}|g" "${HERE}/desk-lock.service" >/etc/systemd/system/pf-desk-lock.service
  fi
  chmod 0644 /etc/systemd/system/pf-desk-lock.service
  systemctl daemon-reload
  systemctl enable --now pf-desk-lock.service
  for dev in "${PARENT}" "${AGENT_IF}"; do
    [[ -e "/sys/class/net/${dev}" ]] || continue
    [[ -x /etc/NetworkManager/dispatcher.d/90-pf-desk ]] || continue
    /etc/NetworkManager/dispatcher.d/90-pf-desk "${dev}" up || true
  done
  if [[ -e /sys/class/net/tailscale0 ]]; then
    say "note: tailscale0 is present. Reaching the tailnet from this host still works; advertising subnet routes or acting as an exit node does not, because nothing on this host forwards any more."
  fi
  say "locked: no forwarding on this host, nothing in or out on ${PARENT} or ${AGENT_IF}"
}

do_status() {
  echo "== links =="
  ip -br link show "${PARENT}" 2>/dev/null || echo "${PARENT}: absent"
  ip -br addr show "${AGENT_IF}" 2>/dev/null || echo "${AGENT_IF}: absent"
  ip -br addr show "${DESK_IF}" 2>/dev/null || echo "${DESK_IF}: absent"
  echo
  echo "== routes =="
  ip route show default 2>/dev/null || true
  echo
  echo "== forwarding =="
  sysctl net.ipv4.ip_forward 2>/dev/null || true
  # The sysctl name of a dotted device changes the dot to a slash,
  # enp6s0/20. But the procfs directory keeps the real name.
  for dev in "${PARENT}" "${AGENT_IF}"; do
    key="${dev//./\/}"
    echo "net.ipv4.conf.${key}.forwarding = $(cat "/proc/sys/net/ipv4/conf/${dev}/forwarding" 2>/dev/null || echo "?")"
    echo "net.ipv6.conf.${key}.disable_ipv6 = $(cat "/proc/sys/net/ipv6/conf/${dev}/disable_ipv6" 2>/dev/null || echo "?")"
  done
  echo
  echo "== resolver =="
  resolver_state || true
  echo
  echo "== uplinks =="
  uplink_report || true
  echo
  echo "== uplinks at boot =="
  if [[ -r "${BOOT_STATE}" ]]; then
    cat "${BOOT_STATE}"
    grep -q '^SECOND UPLINK' "${BOOT_STATE}" && echo "WARNING: the boot check found a way out that is not the Pi (journalctl -b -u pf-desk-uplink-check)"
  else
    echo "(no boot check this boot: pf-desk-lock not enabled, or not run yet)"
  fi
  echo
  echo "== lock =="
  echo "pf-desk-lock.service: $(systemctl is-active pf-desk-lock.service 2>/dev/null || true), $(systemctl is-enabled pf-desk-lock.service 2>/dev/null || true) at boot"
  nft list table inet pf_desk_lock 2>/dev/null || echo "(pf_desk_lock not loaded)"
}

# INSPECT=on on the Pi sends all HTTPS of the desk through the engine.
# Then this host must trust the CA of the Pi, or no HTTPS works. 'ca'
# installs it in each store that desktop tools read: the system store,
# the environment of Node and Python, the NSS database of Chrome for the
# sudo user, and a Firefox policy. 'ca-remove' takes all of it out.
# 'restore' does not remove the CA: a desk that comes back to the Pi
# needs it again, and the CA is of no use to a path that is not the Pi.
# PF_TEST_ROOT puts each path under a test directory (setup_test.sh).
CA_ROOT="${PF_TEST_ROOT:-}"
CA_NAME="Pi Fortress desk CA"
CA_PEM="${CA_ROOT}/etc/pi-fortress/desk-ca.pem"
CA_PROFILE="${CA_ROOT}/etc/profile.d/pi-fortress-desk-ca.sh"
CA_ENVD="${CA_ROOT}/etc/environment.d/90-pi-fortress-desk-ca.conf"
CA_FIREFOX="${CA_ROOT}/etc/firefox/policies/policies.json"

ca_family() {
  local ids=""
  if [[ -r "${CA_ROOT}/etc/os-release" ]]; then
    # shellcheck source=/dev/null
    ids="$(. "${CA_ROOT}/etc/os-release" && printf '%s %s' "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
  fi
  case " ${ids} " in
    *" ubuntu "* | *" debian "* | *" linuxmint "* | *" pop "*) echo debian ;;
    *" fedora "* | *" rhel "* | *" centos "*) echo rhel ;;
    *" arch "*) echo arch ;;
    *" suse "* | *" opensuse "*) echo suse ;;
    *) echo unknown ;;
  esac
}

# ca_store FAMILY prints the anchor path, the update command and the
# bundle that the update writes, one in each line.
ca_store() {
  case "$1" in
    debian) printf '%s\n' "${CA_ROOT}/usr/local/share/ca-certificates/pi-fortress-desk.crt" update-ca-certificates /etc/ssl/certs/ca-certificates.crt ;;
    rhel) printf '%s\n' "${CA_ROOT}/etc/pki/ca-trust/source/anchors/pi-fortress-desk.crt" "update-ca-trust extract" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ;;
    arch) printf '%s\n' "${CA_ROOT}/etc/ca-certificates/trust-source/anchors/pi-fortress-desk.crt" update-ca-trust /etc/ca-certificates/extracted/tls-ca-bundle.pem ;;
    suse) printf '%s\n' "${CA_ROOT}/etc/pki/trust/anchors/pi-fortress-desk.pem" update-ca-certificates /var/lib/ca-certificates/ca-bundle.pem ;;
    *) return 1 ;;
  esac
}

# The user who ran sudo owns the NSS database of Chrome. Root has no
# browser session.
ca_user_home() {
  local u="${SUDO_USER:-}"
  [[ -n "${u}" && "${u}" != root ]] || return 1
  getent passwd "${u}" | cut -d: -f6
}

ca_firefox_policy() {
  printf '{\n  "policies": {\n    "Certificates": {\n      "Install": ["%s"]\n    }\n  }\n}\n' "${CA_PEM#"${CA_ROOT}"}"
}

do_ca() {
  local pem="${1:-}" want="${2:-}" family store anchor update bundle home
  [[ -n "${PF_TEST_ROOT:-}" ]] || need_root
  [[ -n "${pem}" ]] || die "usage: $0 ca <ca-cert.pem> [sha256]. Get it with: ssh -t <user>@<pi> 'sudo install -m 0644 /var/lib/pi-fortress/engine/ca-cert.pem /tmp/pf-ca.pem && sha256sum /tmp/pf-ca.pem', then scp <user>@<pi>:/tmp/pf-ca.pem ."
  [[ -r "${pem}" ]] || die "cannot read ${pem}"
  [[ -s "${pem}" ]] || die "${pem} is empty. A 'ssh <pi> sudo cat ... > file' with no terminal for sudo leaves an empty file: use ssh -t"
  if grep -q 'PRIVATE KEY' "${pem}"; then
    die "${pem} holds a private key. Copy ca-cert.pem, not ca.pem: the CA key stays on the Pi. Delete this copy now."
  fi
  [[ "$(grep -c 'BEGIN CERTIFICATE' "${pem}")" -eq 1 ]] || die "${pem} must hold one certificate"
  command -v openssl >/dev/null 2>&1 || die "openssl is required to check the certificate"
  openssl x509 -in "${pem}" -noout -text 2>/dev/null | grep -q 'CA:TRUE' || die "${pem} is not a CA certificate"
  if [[ -n "${want}" ]]; then
    [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "'${want}' is not a sha256"
    echo "${want}  ${pem}" | sha256sum -c --status || die "${pem} does not match the sha256 ${want}; not trusting it"
  fi
  family="$(ca_family)"
  store="$(ca_store "${family}")" || die "unknown distribution: install ${pem} in the system trust store by hand"
  anchor="$(sed -n 1p <<<"${store}")"
  update="$(sed -n 2p <<<"${store}")"
  bundle="$(sed -n 3p <<<"${store}")"

  install -d -m 0755 "${CA_PEM%/*}" "${anchor%/*}" "${CA_PROFILE%/*}" "${CA_ENVD%/*}"
  install -m 0644 "${pem}" "${CA_PEM}"
  install -m 0644 "${pem}" "${anchor}"
  # shellcheck disable=SC2086
  _out="$(${update} 2>&1)" || die "${update} failed; the CA is not in the system store: ${_out}"
  say "system store: ${anchor#"${CA_ROOT}"}"

  # Go, curl, git and the Python ssl module read the system store. Node
  # has its own roots and reads only NODE_EXTRA_CA_CERTS. Python requests,
  # httpx and pip read certifi unless these variables name the system
  # bundle. SSL_CERT_FILE also covers Go and OpenSSL when a tool has a
  # different default path.
  cat >"${CA_PROFILE}" <<EOF
export NODE_EXTRA_CA_CERTS=${CA_PEM#"${CA_ROOT}"}
export SSL_CERT_FILE=${bundle}
export REQUESTS_CA_BUNDLE=${bundle}
export PIP_CERT=${bundle}
export CURL_CA_BUNDLE=${bundle}
export AWS_CA_BUNDLE=${bundle}
EOF
  sed 's/^export //' "${CA_PROFILE}" >"${CA_ENVD}"
  chmod 0644 "${CA_PROFILE}" "${CA_ENVD}"
  say "environment: ${CA_PROFILE#"${CA_ROOT}"} (shells), ${CA_ENVD#"${CA_ROOT}"} (desktop apps); log out and in again"

  if home="$(ca_user_home)" && [[ -n "${home}" ]]; then
    if command -v certutil >/dev/null 2>&1; then
      # As the user, so that no directory in the home is left to root.
      runuser -u "${SUDO_USER}" -- mkdir -p -m 0700 "${CA_ROOT}${home}/.pki/nssdb"
      [[ -f "${CA_ROOT}${home}/.pki/nssdb/cert9.db" ]] || runuser -u "${SUDO_USER}" -- certutil -N -d "sql:${CA_ROOT}${home}/.pki/nssdb" --empty-password
      runuser -u "${SUDO_USER}" -- certutil -D -d "sql:${CA_ROOT}${home}/.pki/nssdb" -n "${CA_NAME}" >/dev/null 2>&1 || true
      runuser -u "${SUDO_USER}" -- certutil -A -d "sql:${CA_ROOT}${home}/.pki/nssdb" -n "${CA_NAME}" -t "C,," -i "${CA_PEM}" ||
        die "certutil could not add the CA for ${SUDO_USER}"
      say "Chrome and Chromium: added to ${home}/.pki/nssdb for ${SUDO_USER}"
    else
      say "Chrome and Chromium: install libnss3-tools (certutil) and run this again, or import ${CA_PEM#"${CA_ROOT}"} in the browser settings"
    fi
  else
    say "Chrome and Chromium: run with sudo from your own user to add the CA to your browser database"
  fi

  if [[ ! -e "${CA_FIREFOX}" ]] || grep -qF "${CA_PEM#"${CA_ROOT}"}" "${CA_FIREFOX}"; then
    install -d -m 0755 "${CA_FIREFOX%/*}"
    ca_firefox_policy >"${CA_FIREFOX}"
    chmod 0644 "${CA_FIREFOX}"
    say "Firefox: policy ${CA_FIREFOX#"${CA_ROOT}"}; restart Firefox"
  else
    say "Firefox: ${CA_FIREFOX#"${CA_ROOT}"} has other policies; add ${CA_PEM#"${CA_ROOT}"} to Certificates.Install there"
  fi
  say "Java and tools with their own roots need the CA in their own store"
  say "remove all of it: sudo $0 ca-remove"
}

do_ca_remove() {
  local family store anchor update home
  [[ -n "${PF_TEST_ROOT:-}" ]] || need_root
  family="$(ca_family)"
  if store="$(ca_store "${family}")"; then
    anchor="$(sed -n 1p <<<"${store}")"
    update="$(sed -n 2p <<<"${store}")"
    if [[ -e "${anchor}" ]]; then
      rm -f "${anchor}"
      # shellcheck disable=SC2086
      ${update} --fresh >/dev/null 2>&1 || ${update} >/dev/null || say "${update} failed; run it by hand"
    fi
  fi
  rm -f "${CA_PROFILE}" "${CA_ENVD}"
  if [[ -e "${CA_FIREFOX}" ]] && cmp -s "${CA_FIREFOX}" <(ca_firefox_policy); then
    rm -f "${CA_FIREFOX}"
  fi
  if home="$(ca_user_home)" && [[ -n "${home}" ]] && command -v certutil >/dev/null 2>&1; then
    runuser -u "${SUDO_USER}" -- certutil -D -d "sql:${CA_ROOT}${home}/.pki/nssdb" -n "${CA_NAME}" >/dev/null 2>&1 || true
  fi
  rm -f "${CA_PEM}"
  say "the Pi CA is removed. With INSPECT=on on the Pi, HTTPS from this desk now fails."
}

# These values go into the nft lock that loads at each boot, the
# dispatcher that root runs, and the restore wrapper. A stray quote or
# newline would be syntax there, not a name. Same interface grammar as render.
check_names() {
  local iface='^[A-Za-z][A-Za-z0-9._-]{0,14}$' vlan='^[1-9][0-9]{0,3}$' ip4='^([0-9]{1,3}\.){3}[0-9]{1,3}$' v
  for v in "${PARENT}" "${AGENT_IF}"; do
    [[ "${v}" =~ ${iface} ]] || die "not an interface name: '${v}'"
  done
  [[ -z "${DESK_IF}" || "${DESK_IF}" =~ ${iface} ]] || die "not an interface name: '${DESK_IF}'"
  for v in "${AGENT_VLAN}" "${DESK_VLAN}"; do
    [[ "${v}" =~ ${vlan} ]] && ((v <= 4094)) || die "not a VLAN id: '${v}'"
  done
  [[ "${DESK_GW}" =~ ${ip4} ]] || die "not an IPv4 address: DESK_GW='${DESK_GW}'"
}
check_names

case "${1:-}" in
  net) do_net ;;
  default) do_default ;;
  lock) do_lock ;;
  status) do_status ;;
  uplinks) uplink_gate ;;
  boot-check) do_boot_check ;;
  restore) do_restore ;;
  ca) do_ca "${2:-}" "${3:-}" ;;
  ca-remove) do_ca_remove ;;
  *)
    echo "usage: $0 {net|default|lock|status|uplinks|boot-check|restore|ca <pem> [sha256]|ca-remove}" >&2
    exit 2 ;;
esac
