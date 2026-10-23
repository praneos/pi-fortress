#!/bin/bash
# shellcheck shell=bash
# apply.sh and provision.sh source this file. It is not a program. It
# shares the globals and the set -euo of the script that sources it.
# The OS hardening that needs no network and no package install: the
# sysctl file and the unattended-upgrades config. provision.sh runs it on
# a fresh box. apply.sh runs it on each full apply. Thus a box that pf
# upgrade or a ship updates gets the same files as a fresh install of the
# same release. Each step is idempotent, and writes a file only when its
# content changes.
#
# The paths come from the caller, as HARDEN_SYSCTL_D, HARDEN_APT_D and
# HARDEN_WORK (a scratch directory). Thus
# the path rewrite of apply.sh in the appliance test also reaches them.
# The package installs stay in provision.sh. apply.sh only tells the
# operator when a package that a step needs is missing.

# harden_put SRC DST: install SRC at DST (0644) if DST is different.
# Returns 0 when it wrote DST, 1 when DST was already the same.
harden_put() {
  if cmp -s "$1" "$2"; then
    return 1
  fi
  install -d -m 0755 "${2%/*}"
  install -m 0644 "$1" "$2"
}

# Forwarding ships OFF. Before, it was 1 here, persisted and applied again
# at each boot. But the ruleset that makes forwarding safe was only
# conditional: an apply that failed before it installed /etc/nftables.conf
# left the stock Debian accept-policy file. provision then enabled
# and started that file -- an open router between the agent segment and the
# uplink, announced by one line on stderr. apply.sh enables forwarding at
# runtime after it loads our ruleset. The nftables.service drop-in that it
# installs does the same at boot. Thus the two can never be out of sync again.
harden_sysctl_write() {
  cat >"${HARDEN_WORK}/99-pi-fortress.conf" <<'EOF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.netfilter.nf_conntrack_acct=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.default.arp_announce=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=2
kernel.yama.ptrace_scope=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0
EOF
  harden_put "${HARDEN_WORK}/99-pi-fortress.conf" "${HARDEN_SYSCTL_D}/99-pi-fortress.conf" || true
}

# harden_sysctl_load sets the values of the file now, on a running box,
# except ip_forward. apply.sh enabled forwarding after it loaded the
# ruleset. The 0 in the file is for the next boot only. If this step
# set it now, the agent would lose its traffic until the next apply.
harden_sysctl_load() {
  grep -v '^net\.ipv4\.ip_forward=' "${HARDEN_SYSCTL_D}/99-pi-fortress.conf" >"${HARDEN_WORK}/99-pi-fortress.live" || true
  sysctl -e -p "${HARDEN_WORK}/99-pi-fortress.live" >/dev/null 2>&1 ||
    echo "pi-fortress: some values of ${HARDEN_SYSCTL_D}/99-pi-fortress.conf did not apply now; the file applies at the next boot" >&2
}

# Security updates from the distribution, with no automatic reboot.
# The package itself is installed by provision.sh. Without it, the files
# below do nothing, and this step says so.
harden_apt() {
  cat >"${HARDEN_WORK}/20auto-upgrades" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat >"${HARDEN_WORK}/52-pi-fortress-upgrades" <<'EOF'
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename},label=Debian-Security";
  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
  "origin=Raspberry Pi Foundation,codename=${distro_codename}";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  harden_put "${HARDEN_WORK}/20auto-upgrades" "${HARDEN_APT_D}/20auto-upgrades" || true
  harden_put "${HARDEN_WORK}/52-pi-fortress-upgrades" "${HARDEN_APT_D}/52-pi-fortress-upgrades" || true
  if command -v unattended-upgrade >/dev/null 2>&1; then
    systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  else
    echo "pi-fortress: unattended-upgrades is not installed, so the box gets no automatic security updates; run apt-get install unattended-upgrades (or vm/pi/provision.sh)" >&2
  fi
}
