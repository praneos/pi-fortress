#!/bin/bash
set -euo pipefail

# The network of the cloud lab gateway, before vm/pi/provision.sh runs. It
# acts as the Pi 5 after the VLAN cutover (docs/user_guide/home_network.md): WAN on
# the mgmt NIC, the agent segment on <trunk>.20, the desk on <trunk>.79
# and the house on its own NIC. It writes the same files that an operator
# writes manually on the real Pi. Env comes from lab.env.

nic_by_mac() {
  local d want="${1,,}"
  for d in /sys/class/net/*; do
    if [[ "$(cat "${d}/address" 2>/dev/null)" == "${want}" ]]; then
      echo "${d##*/}"
      return 0
    fi
  done
  echo "gw: no NIC with MAC $1" >&2
  ip -br link >&2
  return 1
}

WAN="$(nic_by_mac "${GW_MGMT_MAC}")"
TRUNK="$(nic_by_mac "${GW_TRUNK_MAC}")"
HOUSE="$(nic_by_mac "${GW_HOUSE_MAC}")"
AGENT_IF="${TRUNK}.${AGENT_VLAN}"
DESK_IF="${TRUNK}.${DESK_VLAN}"

export DEBIAN_FRONTEND=noninteractive

# NetworkManager owns the trunk and house NICs, as on the Pi. It must
# not DHCP on them first. mgmt stays with ifupdown. NM does not change it.
install -d -m 0755 /etc/NetworkManager/conf.d /etc/pi-fortress/segments.d
cat >/etc/NetworkManager/conf.d/80-pf-cloudlab.conf <<'EOF'
[main]
no-auto-default=*
EOF
apt-get update
apt-get install -y --no-install-recommends network-manager
systemctl enable --now NetworkManager

modprobe 8021q
echo 8021q >/etc/modules-load.d/pf-cloudlab.conf
ip link set "${TRUNK}" up

# Runbook B step 2: agent-net exists as a VLAN before the first apply.
# Thus apply gets INT_IF from it, and never puts an address on the trunk itself.
if ! nmcli -t -f NAME con show | grep -qx agent-net; then
  nmcli con add type vlan con-name agent-net ifname "${AGENT_IF}" dev "${TRUNK}" id "${AGENT_VLAN}" \
    ipv4.method manual ipv4.addresses 10.77.0.1/24 ipv4.never-default yes ipv6.method disabled \
    connection.autoconnect yes >/dev/null
fi
nmcli con up agent-net >/dev/null

cat >/etc/pi-fortress/net.env.local <<EOF
INT_IF=${AGENT_IF}
WAN_IF=${WAN}
EOF

cat >/etc/pi-fortress/house.env <<EOF
HOUSE_IF=${HOUSE}
HOUSE_NET=10.78.0.0/24
HOUSE_IP=10.78.0.1
HOUSE_DHCP_START=10.78.0.100
HOUSE_DHCP_END=10.78.0.199
HOUSE_ADMIN_IP=10.78.0.20
EOF

# The reservation of the house VM. The TUI can add more, so append only.
touch /etc/pi-fortress/house.hosts
grep -qi "^${HOUSE_MAC}," /etc/pi-fortress/house.hosts ||
  echo "${HOUSE_MAC},10.78.0.20,house" >>/etc/pi-fortress/house.hosts

cat >/etc/pi-fortress/segments.d/desk.env <<EOF
IF=${DESK_IF}
NET=10.79.0.0/30
IP=10.79.0.1
ADMIN=yes
SSH_TO=10.77.0.10-10.77.0.12
EOF

echo "gw: WAN=${WAN} agents=${AGENT_IF} desk=${DESK_IF} house=${HOUSE}"
