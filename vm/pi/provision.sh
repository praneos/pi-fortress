#!/bin/bash
set -euo pipefail
# A file that > writes gets its mode from the umask.  sudo or the shell of
# the operator can give a looser umask than the umask of root.
umask 022

# SRC is the checkout that provisions this box. The lab mounts it at
# /vagrant. A real Pi passes SRC=/opt/pi-fortress, so it needs no symlink
# at /vagrant for these paths (docs/user_guide/pi_setup.md). This check
# runs before apt, so a wrong SRC costs nothing. apply.sh still resolves
# /vagrant itself.
SRC="${SRC:-/vagrant}"
if [[ ! -d "${SRC}/vm/pi" || ! -d "${SRC}/vm/policy" ]]; then
  echo "pi-fortress: SRC=${SRC} is not a pi-fortress checkout" >&2
  exit 1
fi

# Only as root on a Raspberry Pi, a lab VM (the checkout is at /vagrant)
# or with PF_ALLOW_ANY_HOST=1 (pf install on a fresh Debian or Ubuntu
# box): this installs packages and rewrites system configuration. On a
# desktop, that is damage. lib/guard.sh has the rule, the same as for
# apply.sh. The Vagrant provisioner runs a copy of this file from /tmp,
# so the guard comes from SRC.
# shellcheck source=lib/guard.sh
source "${SRC}/vm/pi/lib/guard.sh"
pf_guard_target provision.sh || exit 1

# check_signers FILE NAMESPACE refuses an ssh allowed_signers file unless
# each key line has namespaces="NAMESPACE" as its one namespaces option.
# ssh-keygen -Y verify lets a key on a line with no namespaces option sign
# in each namespace. The ship key (pi-fortress-release, allowed_signers)
# and the release key (pi-fortress-dist, release-signers) must each verify
# only in their own namespace. pf applies the same rule before each verify
# (internal/ship/signers.go).
check_signers() {
  local file="$1" ns="$2" n=0 keys=0 line _p opts _rest count val
  if [[ ! -f "${file}" ]]; then
    echo "pi-fortress: ${file}: no such file" >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    n=$((n + 1))
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    keys=$((keys + 1))
    read -r _p opts _rest <<<"${line}"
    count=0
    val=""
    while [[ "${opts}" =~ ^([A-Za-z-]+)(=\"([^\"]*)\")?(,|$) ]]; do
      if [[ "${BASH_REMATCH[1],,}" == namespaces ]]; then
        count=$((count + 1))
        val="${BASH_REMATCH[3]}"
      fi
      opts="${opts:${#BASH_REMATCH[0]}}"
    done
    if [[ "${count}" -eq 0 ]]; then
      echo "pi-fortress: ${file} line ${n} has no namespaces= option; add namespaces=\"${ns}\" after the principal" >&2
      return 1
    fi
    if [[ "${count}" -ne 1 || "${val}" != "${ns}" ]]; then
      echo "pi-fortress: ${file} line ${n} has namespaces=\"${val}\"; this file needs namespaces=\"${ns}\" only" >&2
      return 1
    fi
  done <"${file}"
  if [[ "${keys}" -eq 0 ]]; then
    echo "pi-fortress: ${file} holds no key line" >&2
    return 1
  fi
}

# check_rsync returns 0 when rsync --version is 3.2.7 or later. Else it
# says why on stderr and returns 1. The pfship key runs rrsync, which
# runs this rsync. 3.2.7 is the rsync of each supported OS (Debian 12 and
# 13, Raspberry Pi OS, Ubuntu 24.04) or older than it. The distributions
# put later fixes into the package and keep the version number, so apt
# updates (unattended-upgrades) must stay on.
check_rsync() {
  local out have
  out="$(rsync --version 2>/dev/null)" || out=""
  if [[ ! "${out}" =~ version[[:space:]]+v?([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    echo "pi-fortress: cannot read the rsync version (rsync --version)" >&2
    return 1
  fi
  have="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  if ((10#${BASH_REMATCH[1]} * 1000000 + 10#${BASH_REMATCH[2]} * 1000 + 10#${BASH_REMATCH[3]} < 3002007)); then
    echo "pi-fortress: rsync ${have} is older than 3.2.7, the oldest rsync that signed ship takes" >&2
    return 1
  fi
}

# A signer file to install is checked before apt, so a bad line costs
# nothing and the box keeps the file it has.
if [[ -n "${PF_ALLOWED_SIGNERS:-}" ]]; then
  check_signers "${PF_ALLOWED_SIGNERS}" pi-fortress-release || exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  nftables dnsmasq wireguard wireguard-tools curl tcpdump iproute2 ca-certificates dnsutils conntrack usb-modeswitch logrotate rsync python3 chrony
# chrony replaces systemd-timesyncd (the package conflicts with it, so apt
# removes it). apply writes an NTS-only chrony.conf. Reason: with plain NTP
# on an uplink that the owner does not control, that network can move the
# clock, and with it each certificate check on the box.

# agent-net, house-net, each segment and the VLAN trunk are all
# NetworkManager profiles (vm/pi/lib/netman.sh). A Pi OS Lite image does
# not always ship NetworkManager. Then apply refuses, and the box never
# gets an address. Not in the lab: there ifupdown owns eth0 and eth1 from
# the Vagrant private_network. The nmcli block of apply must stay skipped
# there. A second configurator on those interfaces can make the box
# unreachable during the provision.
if [[ "${PF_LAB:-}" != 1 ]]; then
  apt-get install -y --no-install-recommends network-manager
fi

install -d -m 0755 /etc/pi-fortress /usr/local/lib/pi-fortress
if [[ "${PF_LAB:-}" == 1 ]]; then
  touch /etc/pi-fortress/lab
fi
# The lists of the operator, seeded one time. With a tree at /vagrant or
# /opt/pi-fortress, apply, the TUI, pf fetch and pf backup all read and
# edit vm/policy of the tree (base.PolicyDir). These copies are the policy
# only of a box with no tree, where /etc/pi-fortress is the one source of
# truth. In both cases, a re-provision must not put the shipped defaults
# back over what the operator blocked, allowed or disabled.
# This step does not merge sources.json as a ship merges it
# (fetch.MergeSeed): a box with no tree gets no ship.
# Each list here is in PI_OWNED (Makefile): the operator owns it, and a
# ship keeps it. doh.*, shared_parents.domains, core.hosts and
# key_prefixes.rules are not: they ship, and each ship and each provision
# replace them.
# The operator lines of each are in its .local file (core.hosts.local,
# key_prefixes.rules.local, doh.ips.local, doh.domains.local). apply and
# pf compile add that file, and this step never writes it.
for _f in blacklist.ips blacklist.domains never_block.ips never_block.domains direct_ip.allow sources.json \
  allow.domains dns_types.allow git_push.allow ntp_pass.ips; do
  if [[ ! -e "/etc/pi-fortress/${_f}" ]]; then
    install -m 0644 "${SRC}/vm/policy/${_f}" "/etc/pi-fortress/${_f}"
  fi
done
cp "${SRC}"/vm/policy/doh.ips /etc/pi-fortress/doh.ips
cp "${SRC}"/vm/policy/doh.domains /etc/pi-fortress/doh.domains
cp "${SRC}"/vm/policy/shared_parents.domains /etc/pi-fortress/shared_parents.domains
install -m 0755 "${SRC}"/vm/pi/apply.sh /usr/local/lib/pi-fortress/apply.sh
install -d -m 0755 /usr/local/lib/pi-fortress/lib
install -m 0644 "${SRC}"/vm/pi/lib/*.sh /usr/local/lib/pi-fortress/lib/
install -m 0755 "${SRC}"/vm/pi/status.sh /usr/local/lib/pi-fortress/status.sh
install -m 0644 "${SRC}"/vm/pi/net.env /etc/pi-fortress/net.env
if [[ "${PF_LAB:-}" == 1 ]]; then
  # The desk seat as a plain segment. On the real Pi, an operator copies
  # segments.d/desk.env.example and edits it. The lab writes it, because
  # the one field that is different is the interface. Only the box knows
  # on which adapter the hypervisor put the segment. Undotted: a
  # VirtualBox internal network carries no 802.1Q tags, and render reads
  # an undotted IF= as a plain ethernet port.
  # shellcheck source=/dev/null
  source "${SRC}"/vm/pi/net.env
  # The house segment, in the same way: on a real Pi, the operator writes
  # house.env.example manually, for a USB adapter. Only this box knows
  # which adapter the hypervisor gave it. The admin address is a DHCP
  # reservation, not a static lease, so the lab also tests house.hosts.
  # The reservation flow of the TUI edits that file.
  house_if="$(ip -4 -o addr show to "${LAB_HOUSE_IP}/32" 2>/dev/null | awk '{sub(/@.*/, "", $2); print $2; exit}')"
  if [[ -z "${house_if}" ]]; then
    echo "pi-fortress: no interface holds ${LAB_HOUSE_IP}; the house segment is not installed" >&2
  else
    cat >/etc/pi-fortress/house.env <<EOF
HOUSE_IF=${house_if}
HOUSE_NET=${LAB_HOUSE_NET}
HOUSE_IP=${LAB_HOUSE_IP}
HOUSE_DHCP_START=${LAB_HOUSE_IP%.*}.100
HOUSE_DHCP_END=${LAB_HOUSE_IP%.*}.199
HOUSE_ADMIN_IP=${LAB_HOUSE_ADMIN_IP}
HOUSE_DNS_UPSTREAM=${LAB_HOUSE_DNS_UPSTREAM}
EOF
    chmod 0644 /etc/pi-fortress/house.env
    # Seeded one time. The reservations of the TUI are in this file. The
    # gw.sh of the cloud lab reserved its own house MAC (a libvirt MAC, not
    # LAB_HOUSE_MAC) before this runs. A re-provision must keep both.
    if [[ ! -s /etc/pi-fortress/house.hosts ]]; then
      printf '%s,%s,house\n' "${LAB_HOUSE_MAC}" "${LAB_HOUSE_ADMIN_IP}" >/etc/pi-fortress/house.hosts
    fi
    chmod 0644 /etc/pi-fortress/house.hosts
  fi
  desk_if="$(ip -4 -o addr show to "${DESK_IP}/32" 2>/dev/null | awk '{sub(/@.*/, "", $2); print $2; exit}')"
  if [[ -z "${desk_if}" ]]; then
    echo "pi-fortress: no interface holds ${DESK_IP}; the desk segment is not installed" >&2
  else
    install -d -m 0755 /etc/pi-fortress/segments.d
    cat >/etc/pi-fortress/segments.d/desk.env <<EOF
IF=${desk_if}
NET=${DESK_NET}
IP=${DESK_IP}
ADMIN=yes
SSH_TO=${AGENT_IP}-${AGENT_IP%.*}.$((${AGENT_IP##*.} + 2))
EOF
    chmod 0644 /etc/pi-fortress/segments.d/desk.env
  fi
fi
cp "${SRC}"/vm/policy/core.hosts /etc/pi-fortress/core.hosts
cp "${SRC}"/vm/policy/key_prefixes.rules /etc/pi-fortress/key_prefixes.rules
# observe.service can write only this directory under /var/lib/pi-fortress,
# and does not start without it. apply makes it too, but the restart
# below can come before the first apply.
install -d -m 0755 /var/lib/pi-fortress/observe
install -m 0644 "${SRC}"/vm/pi/observe.service /etc/systemd/system/pi-fortress-observe.service
install -m 0644 "${SRC}"/vm/pi/alert.service /etc/systemd/system/pi-fortress-alert.service
install -m 0644 "${SRC}"/vm/pi/www.service /etc/systemd/system/pi-fortress-www.service
# Log rotation. apply.sh installs it again from PI_LIB on each run. This is
# the copy that PI_LIB points to on a real Pi. It goes to
# /etc/pi-fortress/logrotate.conf, and our own timer runs it each hour. It
# is not in /etc/logrotate.d, where only the daily run of the system sees it.
install -m 0644 "${SRC}"/vm/pi/logrotate.conf /usr/local/lib/pi-fortress/logrotate.conf
install -m 0644 "${SRC}"/vm/pi/logrotate.conf /etc/pi-fortress/logrotate.conf
install -m 0644 "${SRC}"/vm/pi/logrotate.service /etc/systemd/system/pi-fortress-logrotate.service
install -m 0644 "${SRC}"/vm/pi/logrotate.timer /etc/systemd/system/pi-fortress-logrotate.timer
rm -f /etc/logrotate.d/pi-fortress
install -m 0644 "${SRC}"/vm/agent/setup.sh /usr/local/lib/pi-fortress/agent-setup.sh
# apply copies this seed to allow.<segment>.domains for a plain segment
# that has no such file yet (docs/paranoid_mode.md). apply looks in PI_LIB.
install -m 0644 "${SRC}"/vm/pi/allow.segment.domains.example /usr/local/lib/pi-fortress/allow.segment.domains.example

for _bin in "${SRC}/bin/pf" "${SRC}/vm/pi/pf"; do
  if [[ -x "${_bin}" ]]; then
    install -m 0755 "${_bin}" /usr/local/sbin/pf
    break
  fi
done
if [[ ! -x /usr/local/sbin/pf ]]; then
  echo "pi-fortress: pf missing (make split-bin)" >&2
  exit 1
fi
ln -sfn pf /usr/local/sbin/pi-fortress

# The sysctl file, the unattended-upgrades config and the key-only sshd
# drop-in: lib/harden.sh. apply.sh writes the same files on each apply, so
# an upgraded box keeps them in step with this release. Here, sysctl
# --system also sets ip_forward=0 now; the first apply enables it after it
# loads the ruleset.
HARDEN_SYSCTL_D=/etc/sysctl.d
HARDEN_APT_D=/etc/apt/apt.conf.d
HARDEN_SSHD_D=/etc/ssh/sshd_config.d
HARDEN_HOME=/home
HARDEN_WORK="$(mktemp -d)"
trap 'rm -rf "${HARDEN_WORK}"' EXIT
# shellcheck source=lib/harden.sh
source "${SRC}/vm/pi/lib/harden.sh"
harden_sysctl_write
sysctl -e --system >/dev/null

# Key-only SSH, but only after a usable key is installed (lib/harden.sh).
harden_ssh

# The memory cgroup and PSI on the kernel command line (lib/harden.sh).
# Not in the lab: a VM boots with no cmdline.txt.
if [[ "${PF_LAB:-}" != 1 ]]; then
  HARDEN_CMDLINE=/boot/firmware/cmdline.txt HARDEN_REBOOT_FLAG=/var/run/reboot-required harden_cmdline
fi

# Raspberry Pi OS ships avahi enabled. The gateway must not announce itself
# on the segments that it fences. Also, its own multicast loops back in on
# each segment, and the input chain drops and logs it: 18 lines each
# minute, shown in the TUI as pi_input events from the address of the Pi
# (Pi, 2026-09-21). The cost: <hostname>.local does not resolve after this.
# Each page here reaches the Pi by address.
systemctl disable --now avahi-daemon.socket avahi-daemon.service >/dev/null 2>&1 || true
systemctl disable --now bluetooth.service >/dev/null 2>&1 || true
systemctl disable --now hciuart.service >/dev/null 2>&1 || true
rfkill block bluetooth >/dev/null 2>&1 || true
if [[ -f /boot/firmware/config.txt ]] && ! grep -q '^dtoverlay=disable-bt' /boot/firmware/config.txt; then
  echo "dtoverlay=disable-bt" >>/boot/firmware/config.txt
fi

apt-get install -y --no-install-recommends unattended-upgrades
harden_apt

systemctl disable --now dnsmasq 2>/dev/null || true
systemctl mask dnsmasq 2>/dev/null || true
install -m 0644 "${SRC}"/vm/pi/70-pi-fortress-rtl8153.rules /etc/udev/rules.d/70-pi-fortress-rtl8153.rules
udevadm control --reload-rules >/dev/null 2>&1 || true
udevadm trigger --subsystem-match=usb --action=add >/dev/null 2>&1 || true
# Still soft, on purpose: a first boot with no cables in cannot settle
# the segments. An exit here leaves a half-installed box that cannot
# finish. The soft warning was dangerous because of ip_forward=1 above:
# before, a failed apply meant an open router. Now forwarding is off until
# an apply loads the ruleset, so a failed apply gives a Pi that routes
# nothing. The warning says that. It does not imply that the box is only untidy.
# pf install runs this from a scratch copy before it publishes a tree.
# Then pf ship applies the published tree. An apply here would read the
# stale install under /usr/local/lib and report a failure that is not real.
if [[ "${PF_SHIP_APPLIES:-}" == 1 ]]; then
  echo "pi-fortress: first apply left to pf ship, which applies the published tree next"
else
  /usr/local/sbin/pf apply ||
    echo "pi-fortress: the first apply left segments unsettled (above); the Pi forwards nothing until an apply succeeds -- run 'sudo pf apply' again once the cables are in" >&2
fi
systemctl daemon-reload
systemctl enable nftables
systemctl enable pi-fortress-observe
systemctl enable pi-fortress-alert
systemctl enable pi-fortress-www
systemctl disable --now pi-fortress-mitm.service >/dev/null 2>&1 || true
systemctl restart nftables
systemctl restart pi-fortress-observe
systemctl restart pi-fortress-alert
systemctl restart pi-fortress-www

# Signed ship (docs/signed_ship.md). pfship can write only the upload
# directory, through rrsync. Its home is outside /home, so the key-only
# check above never counts it. root owns its authorized_keys.
PF_INCOMING=/var/lib/pi-fortress/incoming
PF_SHIP_HOME=/var/lib/pi-fortress/pfship
PF_SHIP_PUBKEY="${PF_SHIP_PUBKEY:-/etc/pi-fortress/pfship.pub}"
# ship.service names both directories in ReadWritePaths, and does not
# start without them. A ship can come before the first apply.
install -d -m 0755 /var/lib/pi-fortress /var/log/pi-fortress
if ! id -u pfship >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir "${PF_SHIP_HOME}" --shell /bin/sh pfship
fi
# '*' is no password, not locked: without PAM, sshd refuses keys for '!'.
usermod -p '*' pfship
install -d -m 0755 -o root -g root "${PF_SHIP_HOME}" "${PF_SHIP_HOME}/.ssh"
install -d -m 0700 -o pfship -g pfship "${PF_INCOMING}"
# Only the rrsync of the rsync package (/usr/bin/rrsync), which check_rsync
# checks. An older copy in another place is not used.
RRSYNC=/usr/bin/rrsync
if [[ ! -x "${RRSYNC}" ]]; then
  echo "pi-fortress: rrsync not found at /usr/bin/rrsync (the rsync package ships it from 3.2.4); pfship gets no key and signed ship stays off" >&2
elif ! check_rsync; then
  # A key from an earlier provision must not stay on an rsync that is too
  # old. The file stays, empty, so sshd takes no key for pfship.
  if [[ -s "${PF_SHIP_HOME}/.ssh/authorized_keys" ]]; then
    install -m 0644 -o root -g root /dev/null "${PF_SHIP_HOME}/.ssh/authorized_keys"
  fi
  echo "pi-fortress: pfship gets no key and signed ship stays off. Update rsync (apt-get install rsync) and run provision.sh again" >&2
elif [[ ! -f "${PF_SHIP_PUBKEY}" ]]; then
  echo "pi-fortress: ${PF_SHIP_PUBKEY} missing; pfship gets no key (docs/signed_ship.md, setup)" >&2
else
  _ship_key="$(grep -m1 -E '^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh.com) ' "${PF_SHIP_PUBKEY}" | cut -d' ' -f1,2 || true)"
  if [[ -z "${_ship_key}" ]]; then
    echo "pi-fortress: ${PF_SHIP_PUBKEY} holds no ed25519 or ecdsa public key; pfship gets no key" >&2
  elif grep -qsF -- "${_ship_key#* }" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; then
    echo "pi-fortress: the pfship key is also a login key; make a separate one (docs/signed_ship.md). pfship gets no key" >&2
  else
    printf 'restrict,command="%s -wo %s" %s pfship\n' "${RRSYNC}" "${PF_INCOMING}" "${_ship_key}" >"${PF_SHIP_HOME}/.ssh/authorized_keys.tmp"
    install -m 0644 -o root -g root "${PF_SHIP_HOME}/.ssh/authorized_keys.tmp" "${PF_SHIP_HOME}/.ssh/authorized_keys"
    rm -f "${PF_SHIP_HOME}/.ssh/authorized_keys.tmp"
  fi
fi
if [[ -n "${PF_ALLOWED_SIGNERS:-}" ]]; then
  install -m 0644 -o root -g root "${PF_ALLOWED_SIGNERS}" /etc/pi-fortress/allowed_signers
fi
if [[ ! -f /etc/pi-fortress/allowed_signers ]]; then
  echo "pi-fortress: /etc/pi-fortress/allowed_signers missing; pf ship install refuses every bundle until it exists" >&2
elif ! check_signers /etc/pi-fortress/allowed_signers pi-fortress-release; then
  echo "pi-fortress: pf ship install refuses every bundle until /etc/pi-fortress/allowed_signers is correct (docs/signed_ship.md)" >&2
fi
# pf install writes release-signers. Here it is only checked.
if [[ -f /etc/pi-fortress/release-signers ]] && ! check_signers /etc/pi-fortress/release-signers pi-fortress-dist; then
  echo "pi-fortress: pf upgrade refuses every bundle until /etc/pi-fortress/release-signers is correct (docs/gateway_install.md)" >&2
fi
install -m 0644 "${SRC}"/vm/pi/ship.path /etc/systemd/system/pi-fortress-ship.path
install -m 0644 "${SRC}"/vm/pi/ship.service /etc/systemd/system/pi-fortress-ship.service
systemctl daemon-reload
systemctl enable --now pi-fortress-ship.path

# Passwordless sudo (docs/signed_ship.md): with it, a stolen login key is
# root. This removes a file only on request, only if each rule in it is
# "user ... NOPASSWD: ALL", and only for a user with a password to type. It
# puts the file back if visudo or sudo -l disagrees after. Never in apply.sh:
# there, a wrong guess would remove the sudo access of the operator again
# on each run.
if [[ "${PF_REMOVE_NOPASSWD:-0}" != "1" ]]; then
  for _f in /etc/sudoers.d/*; do
    if [[ -f "${_f}" ]] && grep -qsE '^[^#]*NOPASSWD:[[:space:]]*ALL' "${_f}"; then
      echo "pi-fortress: ${_f} grants passwordless sudo for ALL; left in place (PF_REMOVE_NOPASSWD=1 removes it, docs/signed_ship.md)" >&2
    fi
  done
else
  _bk=/var/backups/pi-fortress-sudoers
  install -d -m 0700 -o root -g root "${_bk}"
  for _f in /etc/sudoers.d/*; do
    [[ -f "${_f}" ]] || continue
    grep -qsE '^[^#]*NOPASSWD' "${_f}" || continue
    _rules="$(grep -vE '^[[:space:]]*(#|$)' "${_f}" || true)"
    if grep -qvE '^[[:space:]]*[a-z_][a-z0-9_-]*[[:space:]]+ALL[[:space:]]*=[[:space:]]*(\([^)]*\)[[:space:]]*)?NOPASSWD:[[:space:]]*ALL[[:space:]]*$' <<<"${_rules}"; then
      echo "pi-fortress: ${_f} has rules other than 'user ALL=(ALL) NOPASSWD: ALL' (a group, a command list, a continuation); left in place, edit it by hand" >&2
      continue
    fi
    _ok=1
    _users="$(awk '{print $1}' <<<"${_rules}" | sort -u)"
    for _u in ${_users}; do
      _st="$(passwd -S "${_u}" 2>/dev/null | awk '{print $2}' || true)"
      if [[ "${_st}" != "P" ]]; then
        echo "pi-fortress: ${_f}: ${_u} has no usable password (passwd -S status '${_st}'); set one with 'sudo passwd ${_u}' first. Left in place" >&2
        _ok=0
      fi
    done
    [[ "${_ok}" == "1" ]] || continue
    _saved="${_bk}/$(basename "${_f}").$(date +%Y%m%dT%H%M%S)"
    mv "${_f}" "${_saved}"
    _why=""
    if ! visudo -c >/dev/null 2>&1; then
      _why="visudo -c failed"
    else
      for _u in ${_users}; do
        if ! sudo -l -U "${_u}" 2>/dev/null | grep -qE '^[[:space:]]*\(ALL( : ALL)?\)[[:space:]]+ALL[[:space:]]*$'; then
          _why="${_u} would lose sudo entirely (not in group sudo?)"
        fi
      done
    fi
    if [[ -n "${_why}" ]]; then
      mv "${_saved}" "${_f}"
      echo "pi-fortress: ${_f}: ${_why}; restored" >&2
    else
      echo "pi-fortress: removed ${_f} (saved as ${_saved}); sudo now asks for a password" >&2
    fi
  done
  visudo -c >/dev/null
fi
