#!/bin/bash
set -euo pipefail

# A house device in the local lab. Unlike all other VMs here, it has no
# address of its own: it asks the Pi for one. This is the only way that a
# lab reaches the DHCP half of dnsmasq: the range, the house.hosts
# reservation, the lease file, and all code that parses them.
#
#   /vagrant/vm/house/lab.sh bootstrap   packages, then a lease
#   /vagrant/vm/house/lab.sh lease       the lease alone, per boot
#
# A real house device is a phone, a TV or a printer, and runs none of
# this. The parts that are important to the Pi are the DHCP exchange and
# the resolver that the device gets. This script does both the usual way.

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT}/vm/pi/net.env"

say() { echo "house: $*"; }
die() { echo "house: $*" >&2; exit 1; }

# Find by MAC, not by name. The Vagrantfile pins the adapter, so that the
# Pi can reserve an address for it. That pin is the one identifier that
# is valid before an address exists.
house_if() {
  local d n
  for d in /sys/class/net/*; do
    n="$(basename "${d}")"
    [[ "${n}" == lo ]] && continue
    [[ "$(cat "${d}/address" 2>/dev/null)" == "${LAB_HOUSE_MAC}" ]] || continue
    printf '%s\n' "${n}"
    return
  done
}

do_lease() {
  local ifc
  ifc="$(house_if)"
  [[ -n "${ifc}" ]] || die "no interface with MAC ${LAB_HOUSE_MAC}; the house network did not come up"
  ip link set "${ifc}" up

  # The VirtualBox NAT adapter keeps its own connected route for the ssh
  # that Vagrant provisions over. All other traffic goes through the Pi,
  # as a device on the LAN of the access point sees.
  dhclient -r "${ifc}" >/dev/null 2>&1 || true
  chattr -i /etc/resolv.conf 2>/dev/null || true
  dhclient -1 -v "${ifc}" 2>&1 | tail -3 || die "no lease on ${ifc}"

  local addr
  addr="$(ip -4 -o addr show dev "${ifc}" | awk '{print $4; exit}')"
  [[ -n "${addr}" ]] || die "dhclient returned but ${ifc} has no address"

  while ip route del default >/dev/null 2>&1; do :; done
  ip route add default via "${LAB_HOUSE_IP}" dev "${ifc}"

  # dhclient gives the Pi as the resolver. Pin it, so that the lease of
  # the NAT adapter cannot overwrite it at the next renew.
  printf 'nameserver %s\n' "${LAB_HOUSE_IP}" >/etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true

  say "lease ${addr} on ${ifc}, default via ${LAB_HOUSE_IP}"
}

case "${1:-}" in
  bootstrap)
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v dhclient >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y --no-install-recommends isc-dhcp-client
    fi
    do_lease
    ;;
  lease)
    do_lease
    ;;
  *)
    echo "usage: $0 {bootstrap|lease}" >&2
    exit 2 ;;
esac
