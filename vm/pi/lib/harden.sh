#!/bin/bash
# shellcheck shell=bash
# apply.sh and provision.sh source this file. It is not a program. It
# shares the globals and the set -euo of the script that sources it.
# The OS hardening that needs no network and no package install: the
# sysctl file, the unattended-upgrades config and the key-only sshd
# drop-in. provision.sh runs it on a fresh box. apply.sh runs it on each
# full apply. Thus a box that pf upgrade or a ship updates gets the same
# files as a fresh install of the same release. Each step is idempotent,
# and writes a file only when its content changes.
#
# The paths come from the caller, as HARDEN_SYSCTL_D, HARDEN_APT_D,
# HARDEN_SSHD_D, HARDEN_HOME and HARDEN_WORK (a scratch directory). Thus
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

# harden_ssh_key_users prints each user under HARDEN_HOME whose
# authorized_keys sshd can use for a login: at least one key that
# ssh-keygen reads, not counting a key with a forced command, and a
# home, .ssh and file that sshd accepts (StrictModes): owned by the user
# or by root, and not writable by group or other. A key that sshd
# ignores is not a key here. To count it would lock the operator out.
harden_ssh_key_users() {
  local f dir home owner p st ok
  for f in "${HARDEN_HOME}"/*/.ssh/authorized_keys; do
    [[ -f "${f}" ]] || continue
    dir="${f%/*}"
    home="${dir%/*}"
    owner="$(stat -c %u -- "${home}" 2>/dev/null)" || continue
    ok=1
    for p in "${home}" "${dir}" "${f}"; do
      st="$(stat -c '%u %a' -- "${p}" 2>/dev/null)" || { ok=0; break; }
      if [[ "${st%% *}" != "${owner}" && "${st%% *}" != 0 ]] || (( 8#${st##* } & 8#022 )); then
        ok=0
        break
      fi
    done
    [[ "${ok}" == 1 ]] || continue
    grep -vE '^[[:space:]]*(#|$)' -- "${f}" 2>/dev/null | grep -v 'command=' >"${HARDEN_WORK}/keys" || true
    if [[ -s "${HARDEN_WORK}/keys" ]] && ssh-keygen -l -f "${HARDEN_WORK}/keys" >/dev/null 2>&1; then
      printf '%s\n' "${home##*/}"
    fi
  done
}

# Key-only SSH, but only after a key is installed: to enforce it on a
# box with no usable authorized_keys is a lockout, not a hardening. sshd
# -t checks the new file before the reload. If sshd refuses it, the old
# file comes back (or none), so sshd always stays as it was.
harden_ssh() {
  local conf="${HARDEN_SSHD_D}/99-pi-fortress.conf" users had=0 eff=""
  command -v sshd >/dev/null 2>&1 || return 0
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "pi-fortress: ssh-keygen is missing, so the login keys cannot be checked; sshd is left as is" >&2
    return 0
  fi
  users="$(harden_ssh_key_users | sort -u | tr '\n' ' ')"
  users="${users% }"
  if [[ -z "${users}" ]]; then
    if [[ ! -f "${conf}" ]]; then
      echo "pi-fortress: no usable login key in ${HARDEN_HOME}/*/.ssh/authorized_keys; sshd password login stays on. Add a key (ssh-copy-id) and apply again" >&2
    fi
    return 0
  fi
  printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' >"${HARDEN_WORK}/sshd.conf"
  if ! cmp -s "${HARDEN_WORK}/sshd.conf" "${conf}"; then
    if [[ -f "${conf}" ]]; then
      cp -p "${conf}" "${HARDEN_WORK}/sshd.prev"
      had=1
    fi
    install -d -m 0755 "${HARDEN_SSHD_D}"
    install -m 0644 "${HARDEN_WORK}/sshd.conf" "${conf}"
    if ! sshd -t >/dev/null 2>&1; then
      if [[ "${had}" == 1 ]]; then
        cp -p "${HARDEN_WORK}/sshd.prev" "${conf}"
      else
        rm -f "${conf}"
      fi
      echo "pi-fortress: sshd rejected the key-only drop-in; password auth left as is (sshd -t)" >&2
      return 0
    fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    echo "pi-fortress: sshd now takes keys only (login keys for: ${users})"
  fi
  # sshd uses the first value that it reads. A file that sorts before
  # ours in sshd_config.d (a cloud image ships one) can keep passwords on.
  # The output goes to a variable first: with pipefail, grep -q that stops
  # early can make sshd fail on a closed pipe, and hide the match.
  eff="$(sshd -T 2>/dev/null)" || eff=""
  if grep -qix 'passwordauthentication yes' <<<"${eff}"; then
    echo "pi-fortress: sshd still takes passwords: a line that sshd reads before ${conf} sets PasswordAuthentication yes (sudo sshd -T; ls ${HARDEN_SSHD_D})" >&2
  fi
}

# The hardware watchdog (HW_WATCHDOG in net.env). systemd (PID 1) feeds
# the watchdog device. If the kernel hangs, or RAM is so short that PID 1
# cannot run, the device resets the Pi. After the boot, pf alert posts the
# unclean restart. auto enables it only when the kernel has a watchdog
# device: a lab VM usually has none. The timeout is 30 s and 2 min at
# reboot, but never above the maximum of the device. The Pi 5 watchdog
# takes at most 15 s. With no maximum to read, both are 15 s. PID 1
# reads system.conf only at start, so a change re-executes it.
#
# The paths come from the caller, as HARDEN_SYSTEM_CONF_D and
# HARDEN_WATCHDOG_SYS (the watchdog class directory in sysfs).
harden_watchdog() {
  local conf="${HARDEN_SYSTEM_CONF_D}/pi-fortress-watchdog.conf" dev="${HARDEN_WATCHDOG_SYS}/watchdog0"
  local on=0 max="" rt=15 rb=15
  case "${HW_WATCHDOG:-auto}" in
    1) on=1 ;;
    auto) [[ -e "${dev}" ]] && on=1 ;;
  esac
  if [[ "${on}" == 0 ]]; then
    if [[ -f "${conf}" ]]; then
      rm -f "${conf}"
      systemctl daemon-reexec || echo "pi-fortress: systemctl daemon-reexec failed; the hardware watchdog stays on until the next boot" >&2
      echo "pi-fortress: the hardware watchdog is off (HW_WATCHDOG=${HW_WATCHDOG:-auto})"
    fi
    return 0
  fi
  if [[ ! -e "${dev}" ]]; then
    echo "pi-fortress: HW_WATCHDOG=1, but the kernel has no watchdog device; systemd logs the failure and continues" >&2
  fi
  max="$(cat "${dev}/max_timeout" 2>/dev/null || true)"
  if [[ "${max}" =~ ^[0-9]+$ && "${max}" -gt 0 ]]; then
    rt=$((max < 30 ? max : 30))
    rb=$((max < 120 ? max : 120))
  fi
  printf '%s\n' '# Written by pi-fortress apply.sh (HW_WATCHDOG in net.env); edits here are replaced on the next apply.' \
    '[Manager]' "RuntimeWatchdogSec=${rt}s" "RebootWatchdogSec=${rb}s" >"${HARDEN_WORK}/pi-fortress-watchdog.conf"
  if harden_put "${HARDEN_WORK}/pi-fortress-watchdog.conf" "${conf}"; then
    systemctl daemon-reexec || echo "pi-fortress: systemctl daemon-reexec failed; the hardware watchdog starts at the next boot" >&2
    echo "pi-fortress: the hardware watchdog is on: a hang of ${rt} s resets the Pi"
  fi
}
