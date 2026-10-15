#!/bin/bash
# Policy routing for house WireGuard egress.
# It exists exactly while the tunnel (WG_IF, wg0 by default) exists. apply.sh and the wg-quick drop-in
# both call this script. The calls are idempotent.
set -euo pipefail

cmd="${1:-}"
dev="${2:-wg0}"
# up    the tunnel is up: send the house into it.
# park  the tunnel stopped but is still configured (the wg-quick stop):
#       remove the tunnel routes, keep the house on its own copper, and
#       blackhole all past it. This is the routing half of the kill switch.
#       Before, this was `down`, which removed the blackhole with all other
#       rules. Thus a stopped tunnel routed the house out the uplink, and
#       only the nft drop stopped it (seen 2026-09-23, first real tunnel).
# down  the config disables WireGuard (apply with WG_IF empty):
#       remove all rules. The house goes back to the plain uplink.
if [[ "${cmd}" != up && "${cmd}" != park && "${cmd}" != down ]]; then
  echo "usage: wg-routes.sh up|park|down [wg0]" >&2
  exit 2
fi

HOUSE_ENV="${HOUSE_ENV:-/etc/pi-fortress/house.env}"
NET_ENV="${NET_ENV:-/etc/pi-fortress/net.env}"
SEGMENTS_DIR="${SEGMENTS_DIR:-/etc/pi-fortress/segments.d}"

if [[ -z "${HOUSE_NET:-}" && -f "${HOUSE_ENV}" ]]; then
  # No line is not an error: the render default for the house is 10.78.0.0/24.
  # A grep that matches nothing fails under pipefail, and it stopped the
  # script. Thus the lookup can give an empty result.
  HOUSE_NET="$( (grep -E '^HOUSE_NET=' "${HOUSE_ENV}" || true) | tail -1 | cut -d= -f2- | tr -cd '0-9./')"
  HOUSE_NET="${HOUSE_NET:-10.78.0.0/24}"
fi
NET_ENV_LOCAL="${NET_ENV_LOCAL:-/etc/pi-fortress/net.env.local}"
if [[ -z "${AGENT_NET:-}" && -f "${NET_ENV}" ]]; then
  # shellcheck source=/dev/null
  source "${NET_ENV}"
  # apply built the fence from the overlay over the base. Thus the subnet
  # that these rules steer must come from the same merge.
  if [[ -f "${NET_ENV_LOCAL}" ]]; then
    # shellcheck source=/dev/null
    source "${NET_ENV_LOCAL}"
  fi
fi
# The mark that render puts on vpn_bypass_v4 traffic, and that the forward
# kill switch accepts on the uplink. Before, it was a literal 0x1 here. Thus
# a different WG_BYPASS_MARK marked the packets in nft, but they still went
# into the tunnel. apply gives the checked value (render
# CheckWGBypassMark). house.env is the fallback, 0x1 the default.
if [[ -z "${WG_BYPASS_MARK:-}" && -f "${HOUSE_ENV}" ]]; then
  WG_BYPASS_MARK="$( (grep -E '^WG_BYPASS_MARK=' "${HOUSE_ENV}" || true) | tail -1 | cut -d= -f2- | tr -cd '0-9a-fA-Fx')"
fi
WG_BYPASS_MARK="${WG_BYPASS_MARK:-0x1}"
if [[ ! "${WG_BYPASS_MARK}" =~ ^0x[0-9a-fA-F]{1,8}$ ]]; then
  echo "pi-fortress: wg-routes: WG_BYPASS_MARK='${WG_BYPASS_MARK}' is not a hex fwmark" >&2
  exit 1
fi
if [[ -z "${HOUSE_NET:-}" || -z "${AGENT_NET:-}" ]]; then
  echo "pi-fortress: wg-routes: HOUSE_NET and AGENT_NET are required" >&2
  exit 1
fi
# The NETs of the plain segments (segments.d), with a space between them.
# The house reaches one only by SSH_FROM. Without a main-table rule, that SYN
# went into the tunnel, as all other house traffic. apply gives the
# list, also when it is empty. If it is unset (a drop-in from before apply
# gave it), this script reads it from segments.d.
if [[ -z "${SEG_NETS+set}" ]]; then
  SEG_NETS=""
  for _f in "${SEGMENTS_DIR}"/*.env; do
    [[ -f "${_f}" ]] || continue
    SEG_NETS="${SEG_NETS} $( (grep -E '^NET=' "${_f}" || true) | tail -1 | cut -d= -f2- | tr -cd '0-9./')"
  done
fi
read -r -a seg_nets <<<"${SEG_NETS}"
for _n in "${seg_nets[@]}"; do
  if [[ ! "${_n}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    echo "pi-fortress: wg-routes: segment NET '${_n}' is not an IPv4 CIDR" >&2
    exit 1
  fi
done

# All rules at the priority, not only the first: the segment rules share 96,
# and a HOUSE_NET that changed leaves an old rule next to the new one.
# The loop has a limit, so an `ip` that never fails cannot spin it.
del_prio() {
  local _
  for _ in $(seq 1 32); do
    ip rule del priority "$1" 2>/dev/null || return 0
  done
}

seg_rules() {
  del_prio 96
  for _n in "${seg_nets[@]}"; do
    ip rule add from "${HOUSE_NET}" to "${_n}" lookup main priority 96
  done
}

if [[ "${cmd}" == park ]]; then
  # The blackhole first, and never deleted here: if 100 goes with no
  # 101 behind it, also for the moment between a del and an add, the house
  # goes out the uplink. An identical rule that is already there is EEXIST.
  ip rule add from "${HOUSE_NET}" blackhole priority 101 2>/dev/null || true
  del_prio 90
  del_prio 92
  del_prio 100
  ip route flush table 100 2>/dev/null || true
  ip route del 10.64.0.1/32 dev "${dev}" 2>/dev/null || true
  del_prio 94
  ip rule add from "${HOUSE_NET}" to "${HOUSE_NET}" lookup main priority 94
  del_prio 95
  ip rule add from "${HOUSE_NET}" to "${AGENT_NET}" lookup main priority 95
  seg_rules
  exit 0
fi

if [[ "${cmd}" == down ]]; then
  del_prio 90
  del_prio 92
  del_prio 94
  del_prio 95
  del_prio 96
  del_prio 100
  del_prio 101
  ip route flush table 100 2>/dev/null || true
  ip route del 10.64.0.1/32 dev "${dev}" 2>/dev/null || true
  exit 0
fi

if ! ip link show "${dev}" >/dev/null 2>&1; then
  echo "pi-fortress: wg-routes: ${dev} is not up" >&2
  exit 1
fi
wgaddr="$(ip -4 -o addr show dev "${dev}" | awk '{print $4}' | head -1)"
wgaddr="${wgaddr%/*}"
if [[ -z "${wgaddr}" ]]; then
  echo "pi-fortress: wg-routes: ${dev} has no IPv4 address" >&2
  exit 1
fi

# Priorities 90-101 are ours. A leftover wg-quick default table (51820)
# means that Table=off did not stay, and house/agent would share a tunnel.
if ip rule show | grep -Eq 'lookup 51820'; then
  echo "pi-fortress: leftover wg-quick routing (lookup 51820); Table = off did not stick" >&2
  exit 1
fi

ip route replace default dev "${dev}" table 100
ip route replace 10.64.0.1/32 dev "${dev}"
del_prio 90
ip rule add fwmark "${WG_BYPASS_MARK}" lookup main priority 90
del_prio 92
ip rule add from "${wgaddr}" lookup 100 priority 92
# The subnet of the house must never reach table 100. That table holds a
# default route and nothing else, so all that it receives goes out through
# the tunnel. A packet from one house client to another is masqueraded
# out to Mullvad, and does not stay on the copper. The replies of the Pi
# to the house go the same way. Their source is HOUSE_IP, and the
# `from HOUSE_NET` of priority 100 matches it as easily as a client.
# That last case stops the full segment - DNS answers, DHCP ACKs and
# ping replies all leave the house and never come back. Thus this rule is
# necessary for the house to work. It is not an improvement. Same shape as
# the agent hole below, one priority earlier so that the two read in order.
del_prio 94
ip rule add from "${HOUSE_NET}" to "${HOUSE_NET}" lookup main priority 94
del_prio 95
ip rule add from "${HOUSE_NET}" to "${AGENT_NET}" lookup main priority 95
# SSH_FROM into a plain segment, the same shape as the agent hole.
seg_rules
del_prio 100
ip rule add from "${HOUSE_NET}" lookup 100 priority 100
del_prio 101
ip rule add from "${HOUSE_NET}" blackhole priority 101
sysctl -w "net.ipv4.conf.${dev}.rp_filter=2" >/dev/null
