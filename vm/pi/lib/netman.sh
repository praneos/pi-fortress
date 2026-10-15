#!/bin/bash
# shellcheck shell=bash
# apply.sh sources this file. It is not a program. It shares the globals
# and the set -euo of apply.sh.
# NetworkManager and resolver plumbing: the DNS pin of the box and its
# check, trunk ports, VLAN children and segment profiles.

# The resolver of the Pi itself. NetworkManager owns the WAN profile and
# rewrites resolv.conf from it at each reconnect. Thus the pin must be in the
# profile, and reapply pushes it without a restart of the link. This also
# writes a resolv.conf that is a plain file, and keeps the original. Thus
# "off" puts back the old content and does not guess. A failure here
# is not a leak: the output chain drops port 53 off loopback when
# DoT is on. But the DNS of the box is then dead (apt, the feed fetch)
# while apply reports success. Thus dot_pin_check verifies the result at
# the end, and fails the apply if the pin did not land.
box_dns_pin() {
  local con
  if command -v nmcli >/dev/null 2>&1; then
    con="$(nmcli -g GENERAL.CONNECTION device show "${WAN_IF}" 2>/dev/null | head -1)"
    if [[ -n "${con}" && "${con}" != "--" ]]; then
      if [[ "$1" == on ]]; then
        nmcli con modify "${con}" ipv4.ignore-auto-dns yes ipv4.dns "${DOT_ADDR}" >/dev/null 2>&1 \
          || echo "pi-fortress: could not pin ${con} to ${DOT_ADDR}; the Pi's own lookups have no resolver (the output chain drops port 53 off loopback)" >&2
      else
        nmcli con modify "${con}" ipv4.ignore-auto-dns no ipv4.dns "" >/dev/null 2>&1 \
          || echo "pi-fortress: could not unpin ${con}; the Pi's own lookups point at ${DOT_ADDR} with no stub there" >&2
      fi
      nmcli device reapply "${WAN_IF}" >/dev/null 2>&1 \
        || echo "pi-fortress: reapply on ${WAN_IF} failed; the DNS change lands on the next reconnect" >&2
    fi
  fi
  [[ -L /etc/resolv.conf ]] && return 0
  # The nmcli branch above covers only a box that NetworkManager manages.
  # On other boxes -- the lab, a USB modem that ifupdown starts --
  # dhclient rewrites resolv.conf from the WAN lease at each renewal.
  # With DoT on, that is worse than a leak: the output chain drops the
  # plaintext query, so the box loses all DNS, with no message,
  # until the next apply. Seen on the lab 2026-09-16, where all threat
  # feeds became stale. The immutable bit is the one control that stops
  # dhclient, NetworkManager and resolvconf. It is best-effort:
  # some filesystems do not support chattr, and a box that cannot
  # set it is not in a worse condition than before.
  chattr -i /etc/resolv.conf >/dev/null 2>&1 || true
  if [[ "$1" == on ]]; then
    if [[ ! -f /etc/pi-fortress/resolv.conf.pre-dot && -f /etc/resolv.conf ]]; then
      cp /etc/resolv.conf /etc/pi-fortress/resolv.conf.pre-dot
    fi
    printf 'nameserver %s\noptions timeout:2 attempts:2\n' "${DOT_ADDR}" >"${WORKDIR}/resolv.conf"
    install -m 0644 "${WORKDIR}/resolv.conf" /etc/resolv.conf
    chattr +i /etc/resolv.conf >/dev/null 2>&1 || true
  elif [[ -f /etc/pi-fortress/resolv.conf.pre-dot ]]; then
    install -m 0644 /etc/pi-fortress/resolv.conf.pre-dot /etc/resolv.conf
    rm -f /etc/pi-fortress/resolv.conf.pre-dot
  fi
}

# stub_ready: does a process answer on the address of the stub?
# "systemctl restart" returns when the unit started, not when the stub
# bound its port. Thus a stub that stops on a bad argument or a port in
# use still exits 0. That was important: the pin above then points the
# box at ${DOT_ADDR}, and dot_pin_check finds exactly the nameserver that
# it wants. Thus apply reported success on a box with no DNS: apt and the
# next feed fetch cannot resolve. The /dev/tcp of bash, not ss: there is
# no binary to find on a box whose DNS is already down. A connect that
# completes proves that the stub accepts connections, not only that it
# is bound.
# Takes the address to probe, because there is now one stub per DoT
# provider: ${DOT_ADDR} for the box and the agents, ${HOUSE_DOT_ADDR} for a
# house that resolves through a different provider.
stub_ready() {
  local addr="$1" i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    (exec 3<>"/dev/tcp/${addr}/53") 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# dot_pin_check: with DoT requested, each nameserver that the box itself
# uses must be the stub, and the stub must be up. NetworkManager
# rewrites resolv.conf asynchronously after a reapply, so the check
# first waits a few seconds. It runs at the end of apply, not
# immediately after the pin, so that the rest of the box still converges.
# Only the exit status shows the failure.
dot_pin_check() {
  [[ -n "${DOT_IPS}" && "${RENDER}" -eq 0 ]] || return 0
  local i ns
  # A pinned resolv.conf over a dead stub looks correct here. Thus the
  # caller must give the state of the stub. This check cannot infer it.
  if [[ "${DOT_STUB_DOWN:-0}" -eq 1 ]]; then
    echo "pi-fortress: DoT is requested but nothing answers on ${DOT_ADDR}:53, so the Pi has no resolver of its own and the segments have none either; the output chain drops port 53 off loopback, so there is no second resolver to fall back to. Fix the stub (journalctl -u pi-fortress-dns-stub@main) and apply again." >&2
    return 1
  fi
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ns="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ' ')"
    [[ "${ns}" == "${DOT_ADDR} " ]] && return 0
    sleep 1
  done
  echo "pi-fortress: DoT is requested but /etc/resolv.conf names '${ns:-nothing}' instead of ${DOT_ADDR}; the segments are on the stub, the Pi's own lookups are not. Fix the ${WAN_IF} profile (nmcli con modify <con> ipv4.ignore-auto-dns yes ipv4.dns ${DOT_ADDR}; nmcli device reapply ${WAN_IF}) and apply again." >&2
  return 1
}

# A VLAN parent needs its own profile. If not, NetworkManager makes a
# "Wired connection" that DHCPs on the trunk port, and that profile can
# take the device from the children. The trunk carries only tags: no
# address, no route, no DNS.
# nm_holders IFNAME: each profile bound to an interface, active or not.
# Only active connections have a value in the DEVICE column. Thus this must
# find an idle autoconnect profile through connection.interface-name.
# If not, that profile DHCPs on the raw trunk at the next boot and takes
# the device from the VLAN children.
nm_holders() {
  local n
  {
    nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$1" '$2 == d {print $1}'
    while IFS= read -r n; do
      [[ -n "${n}" ]] || continue
      [[ "$(nmcli -g connection.interface-name con show "${n}" 2>/dev/null)" == "$1" ]] && printf '%s\n' "${n}"
    done < <(nmcli -t -f NAME con show 2>/dev/null)
  } | sort -u
}

# trunk_keep PARENT: succeeds when a VLAN parent is still the addressed
# interface of the agents, the uplink, the house or a segment. Thus it must
# not go through nm_trunk, which strips its address and deletes the
# profile that holds it -- the profile that carries the fence. HOUSE_IF as
# the parent is a supported layout: the house stays untagged on its port,
# and an SSID per VLAN goes tagged on it (render checkHouseCable limits those
# to house trust). Thus it is kept with no message. All other addressed
# parents get the notice to move them to a VLAN child.
trunk_keep() {
  local parent="$1" u
  [[ -n "${HOUSE_IF:-}" && "${parent}" == "${HOUSE_IF}" ]] && return 0
  for u in "${INT_IF:-}" "${WAN_IF:-}" ${SEG_IF[@]+"${SEG_IF[@]}"}; do
    [[ -n "${u}" && "${u}" == "${parent}" ]] || continue
    echo "pi-fortress: ${parent} is a VLAN parent and still addressed; not made a trunk port. Move it to a VLAN child (nmcli con delete, then nmcli con add type vlan) and apply again." >&2
    return 0
  done
  return 1
}

nm_trunk() {
  local parent="$1" other
  local con="trunk-${parent}"
  # A profile that netplan generates is under /run and comes back at the
  # next netplan apply or reboot. A delete would look successful but fail
  # later. Thus the YAML must change instead.
  while read -r other; do
    case "${other}" in
      netplan-*)
        echo "pi-fortress: ${other} is generated by netplan and holds ${parent}. Remove the ${parent} entry from /etc/netplan/*.yaml, run netplan apply, then apply again." >&2
        exit 1 ;;
    esac
  done < <(nm_holders "${parent}")
  while read -r other; do
    [[ -n "${other}" && "${other}" != "${con}" ]] || continue
    echo "pi-fortress: removing ${other}, which holds trunk port ${parent}" >&2
    nmcli con delete "${other}" >/dev/null 2>&1 || true
  done < <(nm_holders "${parent}")
  if nmcli -t -f NAME con show 2>/dev/null | grep -qx "${con}"; then
    nmcli con modify "${con}" connection.interface-name "${parent}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  else
    nmcli con add type ethernet ifname "${parent}" con-name "${con}" ipv4.method disabled ipv6.method disabled connection.autoconnect yes >/dev/null
  fi
  nmcli con up "${con}" >/dev/null 2>&1 || true
}

# nm_profile CON IFNAME ADDR/PREFIX. An interface with a dot is an 802.1Q
# child of all text before the last dot. A profile that already exists
# with the wrong type cannot be converted, so it is replaced.
nm_profile() {
  local con="$1" ifn="$2" addr="$3" parent id want have
  local -a add=() fix=()
  if [[ "${ifn}" == *.* ]]; then
    parent="${ifn%.*}"
    id="${ifn##*.}"
    if [[ ! "${id}" =~ ^[0-9]+$ ]]; then
      echo "pi-fortress: ${ifn} is not parent.vlan-id, no profile made" >&2
      return 1
    fi
    want=vlan
    add=(type vlan ifname "${ifn}" dev "${parent}" id "${id}")
    fix=(vlan.parent "${parent}" vlan.id "${id}")
  else
    want=802-3-ethernet
    add=(type ethernet ifname "${ifn}")
  fi
  if nmcli -t -f NAME con show 2>/dev/null | grep -qx "${con}"; then
    have="$(nmcli -t -f connection.type con show "${con}" 2>/dev/null | cut -d: -f2-)"
    if [[ "${have}" != "${want}" ]]; then
      nmcli con delete "${con}" >/dev/null 2>&1 || true
    fi
  fi
  if nmcli -t -f NAME con show 2>/dev/null | grep -qx "${con}"; then
    # Converge each key that the add branch sets, not only the address: a
    # profile that remains from an earlier layout can still be on DHCP, on
    # the wrong parent, or able to take the default route.
    nmcli con modify "${con}" connection.interface-name "${ifn}" "${fix[@]}" ipv4.method manual ipv4.addresses "${addr}" ipv4.never-default yes ipv6.method disabled connection.autoconnect yes >/dev/null
  else
    nmcli con add "${add[@]}" con-name "${con}" ipv4.method manual ipv4.addresses "${addr}" ipv4.never-default yes ipv6.method disabled connection.autoconnect yes >/dev/null
  fi
}

# ssh_local_addrs: the IPv4 address of the Pi under each inbound SSH
# session. When SSH_CONNECTION is set, it is the session that runs this
# apply. But sudo drops it from the environment by default, and the ship
# and timer paths never had one. Thus this also reads the sessions that
# sshd holds: if one of them is the admin session, a delete of the link
# under it cuts it.
ssh_local_addrs() {
  {
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      awk '{print $3}' <<<"${SSH_CONNECTION}"
    fi
    ss -Htnp state established 2>/dev/null | awk '/"sshd/ {print $3}'
  } | sed -E 's/^\[//; s/^::ffff://; s/\]?:[0-9]+$//' | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u || true
}

# seg_admin_link UUID IFNAME: prints the SSH session address that a profile
# carries, in its own address list or on its interface. It fails when
# the profile carries none.
seg_admin_link() {
  local uuid="$1" ifn="$2" a dev addrs
  addrs=",$(nmcli -g ipv4.addresses con show uuid "${uuid}" 2>/dev/null | tr -d ' '),"
  while IFS= read -r a; do
    [[ -n "${a}" ]] || continue
    if [[ "${addrs}" == *",${a}/"* ]]; then
      printf '%s\n' "${a}"
      return 0
    fi
    [[ -n "${ifn}" ]] || continue
    dev="$(ip -o -4 addr show 2>/dev/null | awk -v a="${a}" '{split($4, p, "/"); if (p[1] == a) {print $2; exit}}')"
    if [[ "${dev}" == "${ifn}" ]]; then
      printf '%s\n' "${a}"
      return 0
    fi
  done < <(ssh_local_addrs)
  return 1
}

# seg_prune: deletes the profile that nm_profile made for a segment that is
# no longer in segments.d, or whose IF moved. Thus the old interface does
# not keep the segment address after its firewall rules are gone. A
# moved profile is deleted, not rewritten, so that nothing of the old
# layout goes into the new profile. Only seg-<name> is ours, with a <name>
# that render accepts. All other connections belong to the operator.
# This uses the UUID of each profile, because NetworkManager allows two
# connections with one name.
#
# The lockout guard: if the SSH session of the admin arrives through a
# profile, that profile is kept, with a warning. SEG_KEPT names its segment,
# so that the caller does not rewrite it in place, which also moves it off
# the link. The owner reaches the Pi through the desk. For the same reason,
# the screens refuse an IF edit (internal/admin SegmentFixed).
SEG_KEPT=" "
seg_prune() {
  local line name uuid seg i want have addr why
  SEG_KEPT=" "
  while IFS= read -r line; do
    uuid="${line##*:}"
    name="${line%:*}"
    [[ "${name}" =~ ^seg-([a-z][a-z0-9_-]{0,15})$ ]] || continue
    seg="${BASH_REMATCH[1]}"
    want=""
    for i in "${!SEG_NAME[@]}"; do
      [[ "${SEG_NAME[${i}]}" == "${seg}" ]] && want="${SEG_IF[${i}]}"
    done
    have="$(nmcli -g connection.interface-name con show uuid "${uuid}" 2>/dev/null || true)"
    [[ -n "${want}" && "${have}" == "${want}" ]] && continue
    why="segment ${seg} is gone"
    [[ -n "${want}" ]] && why="segment ${seg} moved to IF=${want}"
    if addr="$(seg_admin_link "${uuid}" "${have}")"; then
      SEG_KEPT+="${seg} "
      echo "pi-fortress: WARNING kept NetworkManager profile ${name} on ${have:-no interface}: ${why}, but the SSH session on ${addr} arrives through it and deleting it would cut that session. Its firewall rules have already changed, so keep this session open until you have another way in, then remove it by hand: sudo nmcli con delete ${name} && sudo pf apply" >&2
      continue
    fi
    if nmcli con delete uuid "${uuid}" >/dev/null 2>&1; then
      echo "pi-fortress: pruned NetworkManager profile ${name} (${have:-no interface}): ${why}" >&2
      nm_park "${have}"
    else
      echo "pi-fortress: could not delete NetworkManager profile ${name} (${have:-no interface}); ${why}, so remove it by hand: sudo nmcli con delete uuid ${uuid}" >&2
    fi
  done < <(nmcli -t -f NAME,UUID con show 2>/dev/null)
}

# nm_claimed IFNAME: true if a pi-fortress role holds the interface: the
# agents, the uplink, the house, a segment, or a VLAN trunk.
nm_claimed() {
  local u
  for u in "${INT_IF:-}" "${WAN_IF:-}" "${HOUSE_IF:-}" ${SEG_IF[@]+"${SEG_IF[@]}"} ${VLAN_PARENTS:-}; do
    [[ -n "${u}" && "${u}" == "$1" ]] && return 0
  done
  return 1
}

# nm_park IFNAME: an untagged port that seg_prune emptied gets an inert
# profile, pf-parked-<if>: no address, no DHCP, no route. For a port with no
# profile, NetworkManager makes a "Wired connection". That profile DHCPs
# all that is connected, and can take the default route of the Pi.
# The profile is the one setting that survives a reboot and changes only
# that port. no-auto-default=* would change all ports on the box.
# A VLAN child needs no profile: its device goes with its profile. If a
# different role claims a port, that role makes the profile.
nm_park() {
  local ifn="$1" con="pf-parked-$1"
  [[ "${ifn}" =~ ^[A-Za-z][A-Za-z0-9_-]{0,14}$ ]] || return 0
  nm_claimed "${ifn}" && return 0
  nmcli -t -f NAME con show 2>/dev/null | grep -qxF "${con}" && return 0
  if nmcli con add type ethernet ifname "${ifn}" con-name "${con}" ipv4.method disabled ipv4.never-default yes ipv6.method disabled connection.autoconnect yes >/dev/null 2>&1; then
    echo "pi-fortress: parked ${ifn} with the inert profile ${con} (no address, no DHCP, no route), so NetworkManager does not DHCP whatever is plugged into it; apply removes it when a segment or the house uses ${ifn} again" >&2
  else
    echo "pi-fortress: WARNING could not park ${ifn}; NetworkManager may DHCP whatever is plugged into it and take the default route. Park it by hand: sudo nmcli con add type ethernet ifname ${ifn} con-name ${con} ipv4.method disabled ipv6.method disabled" >&2
  fi
}

# nm_unpark: deletes, by UUID, the pf-parked-<if> profile of each port that
# a role claims again, before the profile of that role is made. Thus the two
# do not compete for the device. Only a pf-parked-<if> bound to <if> is
# ours.
nm_unpark() {
  local line name uuid ifn
  while IFS= read -r line; do
    uuid="${line##*:}"
    name="${line%:*}"
    [[ "${name}" =~ ^pf-parked-([A-Za-z][A-Za-z0-9_-]{0,14})$ ]] || continue
    ifn="${BASH_REMATCH[1]}"
    [[ "$(nmcli -g connection.interface-name con show uuid "${uuid}" 2>/dev/null || true)" == "${ifn}" ]] || continue
    nm_claimed "${ifn}" || continue
    if nmcli con delete uuid "${uuid}" >/dev/null 2>&1; then
      echo "pi-fortress: unparked ${ifn}: removed ${name}, the port is in use again" >&2
    else
      echo "pi-fortress: could not remove ${name}, which parks ${ifn}; remove it by hand: sudo nmcli con delete uuid ${uuid}" >&2
    fi
  done < <(nmcli -t -f NAME,UUID con show 2>/dev/null)
}
