#!/bin/bash
set -euo pipefail

# The Vagrant provisioner of a lab agent VM. It installs packages and
# writes /etc. Thus it runs only as root in a lab VM, where the agent
# scripts are at /vagrant/vm/agent. On a desktop, it stops here.
if [[ "${EUID}" -ne 0 || ! -d /vagrant/vm/agent ]]; then
  echo "pi-fortress: vm/agent/provision.sh refuses to run on ${HOSTNAME:-this host}: it runs only as root in a lab agent VM (/vagrant/vm/agent). It installs packages and writes /etc." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  curl dnsutils iproute2 nftables ca-certificates

install -d -m 0755 /etc/pi-fortress /usr/local/lib/pi-fortress
install -m 0755 /vagrant/vm/agent/routes.sh /usr/local/lib/pi-fortress/routes.sh
cp /vagrant/vm/pi/net.env /etc/pi-fortress/net.env

# shellcheck source=/dev/null
source /etc/pi-fortress/net.env
PF_AGENT_IP="${PF_AGENT_IP:-${AGENT_IP}}"

# Which NIC faces the Pi, and which NIC is management. Only the first
# provisioning can decide this by address. At that time the VirtualBox
# NAT adapter still has its address. Thus the other ethernet interfaces
# are the cable (first) and management (second, unbridged only). From the
# next boot, the link of that adapter is cut. A new run of this script
# would then read the dead NAT port as the cable. Thus the script keeps a
# recorded answer: agent.env is the one file that the box keeps across the cut.
NET_IF=""
MGMT_IF=""
CA_SHA256=""
if [[ -f /etc/pi-fortress/agent.env ]]; then
  NET_IF="$(sed -n 's/^NET_IF=//p' /etc/pi-fortress/agent.env)"
  MGMT_IF="$(sed -n 's/^MGMT_IF=//p' /etc/pi-fortress/agent.env)"
  CA_SHA256="$(sed -n 's/^CA_SHA256=//p' /etc/pi-fortress/agent.env | tail -1)"
fi
# The pin of the egress CA (routes.sh pick_ca). PF_CA_SHA256 sets it. If
# not, a re-provision keeps the recorded pin. A first provision records
# the sha256 of the ca.pem that it fetches at the end (PF_CA_TOFU).
if [[ -n "${PF_CA_SHA256:-}" ]]; then
  if [[ ! "${PF_CA_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "agent: PF_CA_SHA256='${PF_CA_SHA256}' is not a sha256" >&2
    exit 1
  fi
  CA_SHA256="${PF_CA_SHA256}"
fi
[[ -z "${CA_SHA256}" || "${CA_SHA256}" =~ ^[0-9a-f]{64}$ ]] || CA_SHA256=""
# A box provisioned before the management NIC existed has NET_IF but no
# MGMT_IF. Its NAT adapter was never cut in unbridged mode. Thus the
# address-based discovery below still reads it correctly.
_want_mgmt=0
if [[ "${PF_BRIDGED:-0}" != 1 && -n "${PF_MGMT_IP:-}" ]]; then
  _want_mgmt=1
fi
if [[ -z "${NET_IF}" || ! -e "/sys/class/net/${NET_IF}" ]] ||
   [[ "${_want_mgmt}" == 1 && ( -z "${MGMT_IF}" || ! -e "/sys/class/net/${MGMT_IF}" ) ]]; then
  NET_IF=""
  MGMT_IF=""
  for _d in /sys/class/net/*; do
    _n="${_d##*/}"
    [[ "${_n}" == lo || "${_n}" == docker* || "${_n}" == veth* ]] && continue
    [[ -e "${_d}/device" ]] || continue
    if ip -4 -o addr show dev "${_n}" to "${VBOX_NAT_NET}" 2>/dev/null | grep -q .; then
      continue
    fi
    if [[ -z "${NET_IF}" ]]; then
      NET_IF="${_n}"
      continue
    fi
    # The management NIC: the non-NAT NIC that is not the cable.
    # auto_config is false, so neither NIC has an address yet. Vagrant
    # configures networks over the ssh session that will later use this
    # same NIC. The NIC has no address until the stanza below enables
    # it. The script finds it by position, then records it in agent.env.
    if [[ "${PF_BRIDGED:-0}" != 1 && -n "${PF_MGMT_IP:-}" && -z "${MGMT_IF}" ]]; then
      MGMT_IF="${_n}"
    fi
    break
  done
fi
if [[ -z "${NET_IF}" && "${PF_BRIDGED:-0}" == 1 ]]; then
  echo "agent: no interface facing the Pi; is AGENT_BRIDGE the right device?" >&2
  ip -br addr || true
  exit 1
fi
if [[ "${PF_BRIDGED:-0}" == 1 ]]; then
  MGMT_IF=""
fi
if [[ -n "${MGMT_IF}" && ! -e "/sys/class/net/${MGMT_IF}" ]]; then
  MGMT_IF=""
fi
cat >/etc/pi-fortress/agent.env <<EOF
PF_AGENT_IP=${PF_AGENT_IP}
NET_IF=${NET_IF}
MGMT_IF=${MGMT_IF}
AGENT_SUDO=${PF_AGENT_SUDO:-0}
CA_SHA256=${CA_SHA256}
EOF
chmod 0644 /etc/pi-fortress/agent.env

# The host cuts the NAT adapter after this. Thus nothing must wait for a
# DHCP lease that it will never get.
if [[ "${PF_BRIDGED:-0}" == 1 ]]; then
  install -d -m 0755 /etc/network/interfaces.d
  cat >/etc/network/interfaces.d/pf-agent <<EOF
auto ${NET_IF}
iface ${NET_IF} inet static
  address ${PF_AGENT_IP}
  netmask 255.255.255.0
  gateway ${PI_IP}
EOF
fi
# In unbridged mode, this script writes both NICs. They must work after a
# boot that starts with the NAT adapter already cut. Vagrant would configure
# them over ssh, the ssh session uses the management NIC, and that NIC has
# no address until this file enables it. The script also applies the
# configuration live. Thus the first boot is configured before the trigger
# on the host looks for the management address.
if [[ "${PF_BRIDGED:-0}" != 1 && -n "${MGMT_IF}" && -n "${PF_MGMT_IP:-}" ]]; then
  # ifupdown needs a dotted mask. net.env has a prefix.
  _len="${LAB_MGMT_NET##*/}"
  _m=$(( (0xFFFFFFFF << (32 - _len)) & 0xFFFFFFFF ))
  _mask="$(( (_m >> 24) & 0xFF )).$(( (_m >> 16) & 0xFF )).$(( (_m >> 8) & 0xFF )).$(( _m & 0xFF ))"
  install -d -m 0755 /etc/network/interfaces.d
  cat >/etc/network/interfaces.d/pf-agent <<EOF
auto ${NET_IF}
iface ${NET_IF} inet static
  address ${PF_AGENT_IP}
  netmask 255.255.255.0
  gateway ${PI_IP}

auto ${MGMT_IF}
iface ${MGMT_IF} inet static
  address ${PF_MGMT_IP}
  netmask ${_mask}
EOF
  ip link set "${NET_IF}" up 2>/dev/null || true
  ip addr add "${PF_AGENT_IP}/${AGENT_NET##*/}" dev "${NET_IF}" 2>/dev/null || true
  ip link set "${MGMT_IF}" up 2>/dev/null || true
  ip addr add "${PF_MGMT_IP}/${LAB_MGMT_NET##*/}" dev "${MGMT_IF}" 2>/dev/null || true
fi

# The account for the work of the agent. `vagrant` is the account of the
# provisioner. It has passwordless sudo because Vagrant needs it. On a
# bento box, its password is the word "vagrant", and sshd accepts
# passwords. Thus each local user is one `su vagrant` from root. Root in
# the guest gives nothing on the network, because the Pi controls that.
# But root is where a hypervisor escape starts: an escape uses device
# nodes and module loads. Thus the work uses `agent`, with no sudo, and
# the password of vagrant is locked. Its key still logs in.
#
# AGENT_SUDO=1 at `make agent-up` (or a re-provision) gives agent
# passwordless sudo, for work that needs it: package installs, docker,
# the devops tasks for which a user rents a cloud VM. It is off by
# default. A re-provision without it removes it again.
if ! id -u agent >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash agent
fi
passwd -l agent >/dev/null
passwd -l vagrant >/dev/null
# bento ships root locked. debian/bookworm64 (the cloud lab box) ships it
# with the password "vagrant". That is the same `su` that the lock above closes.
passwd -l root >/dev/null
if [[ -s /home/vagrant/.ssh/authorized_keys ]]; then
  install -d -m 0700 -o agent -g agent /home/agent/.ssh
  install -m 0600 -o agent -g agent /home/vagrant/.ssh/authorized_keys /home/agent/.ssh/authorized_keys
fi
if [[ "${PF_AGENT_SUDO:-0}" == 1 ]]; then
  echo 'agent ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/pf-agent.tmp
  chmod 0440 /etc/sudoers.d/pf-agent.tmp
  visudo -cf /etc/sudoers.d/pf-agent.tmp >/dev/null
  mv /etc/sudoers.d/pf-agent.tmp /etc/sudoers.d/pf-agent
  echo "agent: the agent user has passwordless sudo (AGENT_SUDO=1); root in the guest is where a hypervisor escape starts" >&2
else
  rm -f /etc/sudoers.d/pf-agent /etc/sudoers.d/pf-agent.tmp
  gpasswd -d agent sudo >/dev/null 2>&1 || true
fi

# Set the clock before the script removes (below) the part that keeps it.
# An agent behind the Pi has no NTP: the forward chain accepts nothing
# from this segment, and the Pi serves no time. The timesync of Guest
# Additions was the only clock control of this VM. A clock that drifts
# across a host suspend fails all certificate checks. The gateway CA
# server puts a Date header on a port that the lockdown already allows.
# That header is as good as its cable: the same trust that the CA itself
# comes on. TLS needs only accuracy to the second.
cat >/usr/local/lib/pi-fortress/clock.sh <<'EOF'
#!/bin/bash
set -euo pipefail
# shellcheck source=/dev/null
source /etc/pi-fortress/net.env
# The Date header has no signature. So after the first sync of a boot, one
# poll cannot step the clock more than 24 hours. Then a device that answers
# for the Pi cannot move the clock outside the validity of the CA in one
# poll. A larger step needs two polls, 10 to 30 minutes apart, that give
# the same offset within 5 seconds. The Date header has a resolution of 1
# second on each of the two polls, and the request takes some time, so 5
# seconds is enough. A host suspend of more than a day gives such a pair,
# and the next poll of the timer takes it. A device that answers for the
# Pi must do so for two polls. The first run of a boot can take any step: a
# new VM or a box with a flat clock battery can start days or years off.
# The state files are in /run, so a reboot also recovers the clock.
synced=/run/pi-fortress-agent-clock.synced
# pending holds the offset and the time of a poll that was over max.
pending="${synced%.synced}.pending"
max=86400
tol=5
stamp="$(curl -fsSI --max-time 5 "http://${PI_IP}/ca.pem" | sed -n 's/^[Dd]ate: //p' | tr -d '\r')"
[[ -n "${stamp}" ]] || { echo "agent clock: no Date header from ${PI_IP}" >&2; exit 1; }
want="$(date -d "${stamp}" +%s)"
now="$(date +%s)"
off=$(( want - now ))
if [[ -e "${synced}" ]] && (( off > max || off < -max )); then
  poff="" pat=""
  [[ ! -s "${pending}" ]] || read -r poff pat <"${pending}" || true
  if [[ "${poff}" =~ ^-?[0-9]+$ && "${pat}" =~ ^[0-9]+$ ]] &&
    (( off - poff <= tol && poff - off <= tol && now - pat >= 600 && now - pat <= 1800 )); then
    : >"${pending}"
    date -s "@${want}" >/dev/null
    echo "agent clock: stepped ${off}s to the gateway's: two polls $(( now - pat ))s apart gave this offset"
    exit 0
  fi
  echo "${off} ${now}" >"${pending}"
  echo "agent clock: refused a step of ${off}s from ${PI_IP}: over ${max}s after the first sync of this boot; the next poll takes it if it gives the same offset" >&2
  exit 0
fi
[[ ! -s "${pending}" ]] || : >"${pending}"
if (( off > 2 || off < -2 )); then
  date -s "@${want}" >/dev/null
  echo "agent clock: stepped ${off}s to the gateway's"
fi
: >"${synced}"
EOF
chmod 0755 /usr/local/lib/pi-fortress/clock.sh
cat >/etc/systemd/system/pi-fortress-agent-clock.service <<'EOF'
[Unit]
Description=pi-fortress agent clock from the gateway's Date header
After=network-online.target pi-fortress-agent-routes.service

[Service]
Type=oneshot
ExecStart=/usr/local/lib/pi-fortress/clock.sh
EOF
cat >/etc/systemd/system/pi-fortress-agent-clock.timer <<'EOF'
[Unit]
Description=pi-fortress agent clock, at boot and every 15 minutes

[Timer]
OnBootSec=20s
OnUnitActiveSec=15min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl disable --now systemd-timesyncd.service >/dev/null 2>&1 || true

# Remove Guest Additions. The share is rsync, so nothing here uses them.
# The vboxguest module is the HGCM door: the largest part of host code
# that a guest can talk to. Vagrant needs them only for vboxsf.
for _u in /opt/VBoxGuestAdditions-*/uninstall.sh; do
  if [[ -x "${_u}" ]]; then
    "${_u}" >/dev/null 2>&1 || true
  fi
done
apt-get purge -y 'virtualbox-guest-*' >/dev/null 2>&1 || true
systemctl disable --now vboxadd.service vboxadd-service.service >/dev/null 2>&1 || true
# The removal of the additions is not sufficient. The Debian kernel has
# vboxguest, vboxsf and vboxvideo in-tree. It loads vboxguest by PCI id
# at each boot, with or without the additions. Use `install ... /bin/false`,
# not `blacklist`. A blacklist stops only the alias match, and root in the
# guest can quietly undo it with one modprobe. This makes the load fail.
# The script manually removes the copy that this boot already loaded.
cat >/etc/modprobe.d/pi-fortress-no-vbox.conf <<'EOF'
install vboxguest /bin/false
install vboxsf /bin/false
install vboxvideo /bin/false
EOF
# The uninstaller deletes the binaries but does not stop them.
# VBoxDRMClient keeps /dev/vboxguest open from a deleted file. The module
# cannot unload while it does.
for _p in VBoxService VBoxDRMClient VBoxClient; do
  pkill -x "${_p}" >/dev/null 2>&1 || true
done
sleep 1
for _m in vboxsf vboxvideo vboxguest; do
  rmmod "${_m}" >/dev/null 2>&1 || true
done

cat >/usr/local/sbin/pi-fortress-agent-routes <<'EOF'
#!/bin/bash
if [[ -f /vagrant/vm/agent/routes.sh ]]; then
  exec bash /vagrant/vm/agent/routes.sh "$@"
fi
exec bash /usr/local/lib/pi-fortress/routes.sh "$@"
EOF
chmod 755 /usr/local/sbin/pi-fortress-agent-routes

cat >/etc/sysctl.d/99-pi-fortress-agent.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
sysctl --system >/dev/null

install -d -m 0755 /etc/dhcp/dhclient-enter-hooks.d
cat >/etc/dhcp/dhclient-enter-hooks.d/pin-dns <<'EOF'
make_resolv_conf() { :; }
EOF
chmod 755 /etc/dhcp/dhclient-enter-hooks.d/pin-dns

if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
  systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
fi

cat >/etc/systemd/system/pi-fortress-agent-routes.service <<'EOF'
[Unit]
Description=Route agent egress via pi-fortress
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/pi-fortress-agent-routes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pi-fortress-agent-routes.service
systemctl enable pi-fortress-agent-clock.timer >/dev/null 2>&1 || true
# routes.sh writes /etc/nftables.conf. This unit loads it again at boot.
# Thus the egress lock exists before sshd, not only after routes has run.
systemctl enable nftables.service >/dev/null 2>&1 || true
PF_CA_TOFU=1 /usr/local/sbin/pi-fortress-agent-routes
