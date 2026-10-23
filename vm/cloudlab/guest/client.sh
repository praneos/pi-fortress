#!/bin/bash
set -euo pipefail

# Cloud lab client network (docs/cloud_lab.md). One role per VM:
#
#   client.sh house   DHCP from the gw on the house NIC, plus 10.78.0.250
#                     as a second, non-admin source address
#   client.sh desk    vm/desk/setup.sh net, default and lock on the trunk NIC
#   client.sh agent   static PF_AGENT_IP; vm/agent/provision.sh runs next
#   client.sh ca      the gw's CA for vm/agent/routes.sh
#
# Env: MGMT_MAC and LAB_MAC (from the Vagrantfile), PF_AGENT_IP for agents.
# Packages install first, while mgmt still reaches the internet. After
# that, mgmt never keeps the default route or DNS, and lab.sh cut sets its
# link down. Thus each packet that a client sends goes through the gw.

role="${1:?usage: client.sh house|desk|agent|ca}"

nic_by_mac() {
  local d want="${1,,}"
  for d in /sys/class/net/*; do
    if [[ "$(cat "${d}/address" 2>/dev/null)" == "${want}" ]]; then
      echo "${d##*/}"
      return 0
    fi
  done
  echo "client: no NIC with MAC $1" >&2
  ip -br link >&2
  return 1
}

wait_for() {
  local i
  for i in $(seq 1 60); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "client: gave up waiting for: $*" >&2
  return 1
}

MGMT="$(nic_by_mac "${MGMT_MAC}")"
LAB_IF="$(nic_by_mac "${LAB_MAC}")"
export DEBIAN_FRONTEND=noninteractive

if [[ "${role}" == ca ]]; then
  install -d -m 0755 /etc/pi-fortress
  wait_for curl -fsS --max-time 5 -o /etc/pi-fortress/egress-ca.pem http://10.77.0.1/ca.pem
  chmod 0644 /etc/pi-fortress/egress-ca.pem
  echo "client: CA from the gw in /etc/pi-fortress/egress-ca.pem"
  exit 0
fi

case "${role}" in
  house) pkgs=(curl dnsutils netcat-openbsd ca-certificates) ;;
  desk)
    pkgs=(network-manager nftables curl dnsutils netcat-openbsd python3 ca-certificates)
    install -d -m 0755 /etc/NetworkManager/conf.d
    printf '[main]\nno-auto-default=*\n' >/etc/NetworkManager/conf.d/80-pf-cloudlab.conf
    ;;
  agent) pkgs=(curl dnsutils iproute2 nftables ca-certificates netcat-openbsd) ;;
  *)
    echo "client: unknown role ${role}" >&2
    exit 2
    ;;
esac
# A second provision finds the mgmt default route gone: the first one
# dropped it. If the lab route did not come up, apt has no route at all.
# The mgmt net is a libvirt net, so its router is the .1 address.
if ! ip route show default | grep -q .; then
  mgmt_ip="$(ip -4 -o addr show dev "${MGMT}" | awk '{print $4}' | cut -d/ -f1)"
  ip route add default via "${mgmt_ip%.*}.1" dev "${MGMT}"
fi
apt-get update
apt-get install -y --no-install-recommends "${pkgs[@]}"

cat >/etc/pf-lab.env <<EOF
ROLE=${role}
LAB_IF=${LAB_IF}
MGMT_IF=${MGMT}
EOF

# A renewed mgmt lease must not bring back a default route or resolver.
install -d -m 0755 /etc/dhcp/dhclient-enter-hooks.d
cat >/etc/dhcp/dhclient-enter-hooks.d/pf-cloudlab <<EOF
if [ "\${interface}" = "${MGMT}" ]; then
  unset new_routers
  make_resolv_conf() { :; }
fi
EOF

drop_mgmt_default() {
  while ip route del default dev "${MGMT}" 2>/dev/null; do :; done
}

case "${role}" in
  house)
    drop_mgmt_default
    cat >/etc/network/interfaces.d/pf-house <<EOF
allow-hotplug ${LAB_IF}
iface ${LAB_IF} inet dhcp
    up ip addr add 10.78.0.250/24 dev ${LAB_IF} 2>/dev/null || true
EOF
    ifup "${LAB_IF}" || true
    wait_for ip -4 addr show dev "${LAB_IF}" to 10.78.0.20
    echo "client: house on ${LAB_IF}: $(ip -4 -br addr show dev "${LAB_IF}")"

    # Pool devices, one netns for each (guest/house-ns.sh): a phone with a
    # MAC that has no reservation on the gw, and an IoT box that ignores
    # the DHCP DNS option and uses a hardcoded 8.8.8.8.
    install -m 0755 /vagrant/vm/cloudlab/guest/house-ns.sh /usr/local/sbin/pf-house-ns
    install -d -m 0755 /etc/pf-lab
    printf 'MAC=%s\nACCEPT_RA=1\n' "${PHONE_MAC:?}" >/etc/pf-lab/ns-phone.env
    printf 'MAC=%s\nRESOLVER=8.8.8.8\n' "${IOT_MAC:?}" >/etc/pf-lab/ns-iot.env
    # dhclient runs under ip netns exec. There, /etc/resolv.conf is the
    # bind mount of the netns. Write through it, do not rename onto it.
    cat >/etc/dhcp/dhclient-enter-hooks.d/pf-house-ns <<'EOF'
case "${interface}" in
  phone0 | iot0)
    make_resolv_conf() {
      RESOLVER=""
      . "/etc/pf-lab/ns-${interface%0}.env"
      : >/etc/resolv.conf
      for ns in ${RESOLVER:-${new_domain_name_servers}}; do
        echo "nameserver ${ns}" >>/etc/resolv.conf
      done
    }
    ;;
esac
EOF
    cat >/etc/systemd/system/pf-house-ns@.service <<'EOF'
[Unit]
Description=cloud lab house device %i
After=network.target

[Service]
ExecStartPre=/usr/local/sbin/pf-house-ns up %i
ExecStart=/usr/sbin/ip netns exec %i /sbin/dhclient -4 -d -pf /run/dhclient-%i.pid -lf /var/lib/dhcp/dhclient-%i.leases %i0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    for dev in phone iot; do
      systemctl enable --now "pf-house-ns@${dev}.service"
      wait_for ip netns exec "${dev}" ip route show default via 10.78.0.1
      echo "client: house ${dev}: $(ip -n "${dev}" -4 -o addr show dev "${dev}0" | awk '{print $4}')"
    done
    ;;
  desk)
    systemctl enable --now NetworkManager
    drop_mgmt_default
    PARENT="${LAB_IF}" /vagrant/vm/desk/setup.sh net
    wait_for ping -c1 -W2 10.79.0.1
    PARENT="${LAB_IF}" /vagrant/vm/desk/setup.sh default
    PARENT="${LAB_IF}" /vagrant/vm/desk/setup.sh lock
    # NetworkManager can leave the resolv.conf of the mgmt lease in place.
    # The segment resolves through the Pi and rejects a lookup sent to all
    # other servers. Thus the seat asks the Pi, as in the desktop runbook.
    echo 'nameserver 10.79.0.1' >/etc/resolv.conf
    ;;
  agent)
    # routes.sh finds the interface by this address. The mgmt default
    # route stays until then: vm/agent/provision.sh still runs apt.
    cat >/etc/network/interfaces.d/pf-agent <<EOF
auto ${LAB_IF}
iface ${LAB_IF} inet static
    address ${PF_AGENT_IP:?}/24
EOF
    ifup "${LAB_IF}" || true
    wait_for ping -c1 -W2 10.77.0.1
    echo "client: agent ${PF_AGENT_IP} on ${LAB_IF}"
    ;;
esac
