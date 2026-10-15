#!/bin/bash
set -euo pipefail

# One house device as a network namespace inside the house VM
# (docs/cloud_lab.md). Each device has its own NIC on the house bridge.
# Thus it gets its own lease from the gw pool, as a phone or a TV does.
# pf-house-ns@<name>.service runs this before dhclient, at each boot.
#
#   house-ns.sh up <name>   move the NIC with MAC from
#                           /etc/pf-lab/ns-<name>.env into netns <name>
#
# ns-<name>.env: MAC=<mac>; RESOLVER=<ip> to ignore the DHCP DNS option
# (a device with a hardcoded resolver); ACCEPT_RA=1 to accept IPv6 router
# advertisements as a phone does.

name="${2:?usage: house-ns.sh up <name>}"
[[ "$1" == up ]] || { echo "usage: house-ns.sh up <name>" >&2; exit 2; }
# shellcheck disable=SC1090
. "/etc/pf-lab/ns-${name}.env"
dev="${name}0"

ip netns list | grep -qw "${name}" || ip netns add "${name}"
install -d -m 0755 "/etc/netns/${name}"
touch "/etc/netns/${name}/resolv.conf"

if ! ip -n "${name}" link show "${dev}" >/dev/null 2>&1; then
  found=""
  for d in /sys/class/net/*; do
    if [[ "$(cat "${d}/address" 2>/dev/null)" == "${MAC,,}" ]]; then
      found="${d##*/}"
      break
    fi
  done
  [[ -n "${found}" ]] || { echo "house-ns: no NIC with MAC ${MAC}" >&2; exit 1; }
  ip link set dev "${found}" netns "${name}"
  ip -n "${name}" link set dev "${found}" name "${dev}"
fi

ip -n "${name}" link set lo up
ip netns exec "${name}" sysctl -qw "net.ipv6.conf.${dev}.accept_ra=${ACCEPT_RA:-0}"
ip -n "${name}" link set "${dev}" up
