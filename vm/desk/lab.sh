#!/bin/bash
set -euo pipefail

# The desk seat of the local lab. A real desktop uses setup.sh
# (docs/lab.md). This script runs the same script on a VirtualBox VM. The
# VM has one untagged adapter for each segment, not 802.1Q children of a
# trunk, and no NetworkManager. The topology one layer up is the topology
# that the Pi serves. Thus this script tests the plain segment, its NAT,
# its isolation and the lock of this host. It does not test tags, trunk
# naming and netplan. They stay with runbook B.
#
#   /vagrant/vm/desk/lab.sh bootstrap   packages, addresses, route, lock
#   /vagrant/vm/desk/lab.sh routes      route and resolver only, per boot

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT}/vm/pi/net.env"

export PF_LAB=1
export DESK_ADDR="${DESK_SEAT_IP}/${DESK_NET##*/}"
export DESK_GW="${DESK_IP}"
# setup.sh sets DESK_DNS, with DESK_GW as the default. The segment now has
# its own resolver on the Pi. A direct query to DNS_UPSTREAM gets a reject
# on the way out.

case "${1:-}" in
  bootstrap)
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v nft >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y --no-install-recommends nftables
    fi
    "${HERE}/setup.sh" net
    "${HERE}/setup.sh" default
    "${HERE}/setup.sh" lock
    ;;
  routes)
    "${HERE}/setup.sh" net
    "${HERE}/setup.sh" default
    ;;
  status)
    "${HERE}/setup.sh" status
    ;;
  *)
    echo "usage: $0 {bootstrap|routes|status}" >&2
    exit 2 ;;
esac
