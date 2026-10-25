#!/bin/bash
# install.sh ROLE: put the appliance first boot, seal and lint into a
# provisioned lab VM. scripts/appliance.sh uploads this directory with
# EVALUATION_NOTICE.txt (and, for the fence, the release pf as ./pf) to
# /tmp/pf-appliance. Then it runs this script as root before seal-image.sh.
set -euo pipefail

ROLE="${1:-}"
case "${ROLE}" in fence | agent) ;; *) echo "usage: install.sh fence|agent" >&2; exit 2 ;; esac
[[ "${EUID}" -eq 0 ]] || { echo "install.sh: run as root" >&2; exit 1; }
# Only in a lab VM (the checkout is at /vagrant/vm): this writes /etc and
# enables a first-boot unit. On a desktop, it stops here.
[[ -d /vagrant/vm ]] || { echo "install.sh: refuses to run on ${HOSTNAME:-this host}: it runs only in a lab VM (/vagrant/vm), from scripts/appliance.sh" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
LIB=/usr/local/lib/pi-fortress/appliance

install -d -m 0755 "${LIB}" /usr/share/doc/pi-fortress /etc/pi-fortress /etc/issue.d /etc/profile.d
install -m 0755 "${here}/firstboot.sh" "${here}/seal-image.sh" "${here}/image-lint.sh" "${LIB}/"
install -m 0644 "${here}/hygiene.sh" "${here}/hygiene.list" "${LIB}/"
install -m 0644 "${here}/EVALUATION_NOTICE.txt" /usr/share/doc/pi-fortress/EVALUATION_NOTICE.txt
sed 's/\\/\\\\/g' "${here}/EVALUATION_NOTICE.txt" >/etc/issue.d/40-pi-fortress-evaluation.issue
install -m 0644 "${here}/EVALUATION_NOTICE.txt" /etc/motd
echo "${ROLE}" >/etc/pi-fortress/appliance.role
cat >/etc/profile.d/zz-pi-fortress-seat.sh <<'EOF'
[ -r /etc/pi-fortress/seat.txt ] && [ -z "${PF_SEAT_SHOWN:-}" ] && cat /etc/pi-fortress/seat.txt && export PF_SEAT_SHOWN=1
EOF
chmod 0644 /etc/profile.d/zz-pi-fortress-seat.sh

install -m 0644 "${here}/pi-fortress-firstboot.service" /etc/systemd/system/pi-fortress-firstboot.service
systemctl daemon-reload
systemctl enable pi-fortress-firstboot.service >/dev/null

if [[ "${ROLE}" == fence ]]; then
  # Last chance to read the checkout: seal-image.sh unmounts /vagrant.
  bash "${here}/tree.sh" "${SRC:-/vagrant}" /
  if [[ -f "${here}/pf" ]]; then
    install -m 0755 "${here}/pf" /usr/local/sbin/pf
    echo "install.sh: fence runs $(/usr/local/sbin/pf version 2>/dev/null || echo 'the release pf')"
  fi
  command -v VBoxControl >/dev/null || echo "install.sh: VBoxControl missing; only /boot/pi-fortress-canary can seed the canary" >&2
  exit 0
fi

# The seat: an unprivileged tester, logged in on tty1. This script locks
# its password. First boot sets the password and prints it on the console.
if ! id tester >/dev/null 2>&1; then
  useradd -m -s /bin/bash tester
fi
for g in sudo adm wheel vboxsf; do
  gpasswd -d tester "${g}" >/dev/null 2>&1 || true
done
usermod -L tester
install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
cat >/etc/systemd/system/getty@tty1.service.d/pi-fortress-autologin.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin tester --noclear %I $TERM
EOF
systemctl daemon-reload

# One cable. The export does not include the host-only management NIC of
# the lab (the clone drops nic3). Thus its stanza would name an interface
# that the appliance does not have, and `ifup -a` would fail at each boot.
# Remove the stanza, and record in agent.env that there is no such NIC.
env_file=/etc/pi-fortress/agent.env
mgmt_if="$(sed -n 's/^MGMT_IF=//p' "${env_file}" 2>/dev/null || true)"
if [[ -n "${mgmt_if}" ]]; then
  ifs=/etc/network/interfaces.d/pf-agent
  if [[ -f "${ifs}" ]]; then
    awk -v m="${mgmt_if}" '
      /^auto / { skip = ($2 == m) }
      /^iface / { skip = ($2 == m) }
      !skip' "${ifs}" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' >"${ifs}.new"
    mv "${ifs}.new" "${ifs}"
  fi
  sed -i 's/^MGMT_IF=.*/MGMT_IF=/' "${env_file}"
  echo "install.sh: agent keeps ${mgmt_if} out of the image; one cable to the fence"
fi
command -v VBoxControl >/dev/null || echo "install.sh: VBoxControl missing; only /boot/pi-fortress-claim can seed the claim" >&2
