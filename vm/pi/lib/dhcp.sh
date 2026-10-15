#!/bin/bash
# shellcheck shell=bash
# apply.sh sources this file. It is not a program. It shares the globals
# and the set -euo of apply.sh.
# DHCP for plain segments (segments.d DHCP=on): one DHCP-only dnsmasq per
# segment, the same pattern as the house, as pi-fortress-dhcp@<name>.service.
#
# One instance per segment, not one dnsmasq for all ranges:
# - dnsmasq SO_BINDTODEVICEs its DHCP socket only when it serves exactly
#   one interface. Thus an instance never receives the broadcasts of a
#   different segment.
# - A bad conf or a crash stops the leases of one segment, not all.
# - Each instance has its own lease file and log. pf doctor and an
#   operator read these per segment.
# The house keeps its own unit (dns-house.service), so a shared instance
# would also be a second instance next to it. The cost is a few MiB of RAM
# per segment.
#
# The paths come from apply, as DHCP_ETC, DHCP_STATE, DHCP_LOGS
# and DHCP_UNITS. Thus the path rewrite of apply.sh in the appliance test
# also reaches them.

# seg_dhcp_conf NAME IF IP START END [HOSTS]: the dnsmasq conf of the
# instance. It is the house conf (apply.sh, dns-house.conf) with the segment
# names: bound to its one interface, port=0 so it never answers DNS (pf dns
# holds 53 on IP), the Pi as router and resolver, its own leases and log.
# It sends no other option: no domain, no search list, no WPAD. HOSTS is
# the SEG_DHCP_HOSTS of the segment: the reservations from dhcp.<name>.hosts
# that render checked. Each MAC,IP[,name] becomes a dhcp-host line. The
# house reads its house.hosts as a dhcp-hostsfile instead. The TUI edits that
# file and reloads it with a HUP. These change only through an apply. Thus
# they are in the conf that apply writes and that dnsmasq --test checks.
seg_dhcp_conf() {
  local name="$1" ifname="$2" ip="$3" start="$4" end="$5" hosts="${6:-}" h
  cat <<EOF
interface=${ifname}
except-interface=lo
bind-dynamic
port=0
dhcp-range=${start},${end},12h
dhcp-authoritative
dhcp-option=option:router,${ip}
dhcp-option=option:dns-server,${ip}
dhcp-leasefile=${DHCP_STATE}/dhcp-${name}.leases
log-dhcp
log-facility=${DHCP_LOGS}/dhcp-${name}.log
EOF
  for h in ${hosts}; do
    printf 'dhcp-host=%s\n' "${h}"
  done
}

# dhcp_account NAME: make the system account pf-dhcp-NAME if it is not
# there. Each dnsmasq instance runs as its own account, and its lease file
# and log are the only files that the account owns. Thus an instance
# cannot write the lease file or the log of a different instance, or send
# a signal to it. Segment names have 16 characters at most, so the name
# is in the 32-character limit of useradd. A removed segment keeps its
# account: the uid is not given to a different account while the old log
# of the segment is on the disk.
dhcp_account() {
  local user="pf-dhcp-$1"
  if ! id -u "${user}" >/dev/null 2>&1; then
    useradd --system --no-create-home --gid nogroup --home /nonexistent --shell /usr/sbin/nologin "${user}"
  fi
}

# seg_dhcp_names: each segment name that has an instance on this box, from
# its conf, its lease file or its enable link. Thus apply still finds a
# partly removed instance and completes the removal.
seg_dhcp_names() {
  local f n
  for f in "${DHCP_ETC}"/dhcp-*.conf "${DHCP_STATE}"/dhcp-*.leases \
    "${DHCP_UNITS}"/multi-user.target.wants/pi-fortress-dhcp@*.service; do
    [[ -e "${f}" || -L "${f}" ]] || continue
    n="${f##*/}"
    n="${n#dhcp-}"
    n="${n#pi-fortress-dhcp@}"
    n="${n%.conf}"
    n="${n%.leases}"
    n="${n%.service}"
    # Only names that render could write. All other names are not ours.
    if [[ "${n}" =~ ^[a-z][a-z0-9_-]{0,15}$ ]]; then
      printf '%s\n' "${n}"
    fi
  done | sort -u
}

# seg_dhcp_sync: an enabled, restarted instance for each segment with
# SEG_DHCP=on, and nothing for all other segments. If the DHCP of a segment
# is off, or its file was removed, this stops and disables the instance and
# deletes its conf and leases. Its log stays, as the house log does, until
# logrotate removes it. If no DHCP segment is left, the template unit is
# removed too. Returns 1 only when a conf fails dnsmasq --test, before it
# installs a file of that segment.
seg_dhcp_sync() {
  local i n want=" " changed=0 out
  for i in "${!SEG_NAME[@]}"; do
    [[ "${SEG_DHCP[${i}]:-off}" == on ]] && want+="${SEG_NAME[${i}]} "
  done
  while IFS= read -r n; do
    [[ -n "${n}" && "${want}" != *" ${n} "* ]] || continue
    systemctl disable --now "pi-fortress-dhcp@${n}.service" >/dev/null 2>&1 || true
    rm -f "${DHCP_ETC}/dhcp-${n}.conf" "${DHCP_STATE}/dhcp-${n}.leases" \
      "${DHCP_UNITS}/multi-user.target.wants/pi-fortress-dhcp@${n}.service"
    echo "pi-fortress: segment ${n} has no DHCP now; pi-fortress-dhcp@${n} stopped and its conf and leases removed" >&2
    changed=1
  done < <(seg_dhcp_names)
  if [[ "${want}" == " " ]]; then
    if [[ -f "${DHCP_UNITS}/pi-fortress-dhcp@.service" ]]; then
      rm -f "${DHCP_UNITS}/pi-fortress-dhcp@.service"
      changed=1
    fi
    if [[ "${changed}" -eq 1 ]]; then
      systemctl daemon-reload
    fi
    return 0
  fi
  if [[ ! -f "${PI_LIB}/dhcp@.service" ]]; then
    echo "pi-fortress: ${PI_LIB}/dhcp@.service missing" >&2
    return 1
  fi
  install -m 0644 "${PI_LIB}/dhcp@.service" "${DHCP_UNITS}/pi-fortress-dhcp@.service"
  systemctl daemon-reload
  for i in "${!SEG_NAME[@]}"; do
    [[ "${SEG_DHCP[${i}]:-off}" == on ]] || continue
    n="${SEG_NAME[${i}]}"
    seg_dhcp_conf "${n}" "${SEG_IF[${i}]}" "${SEG_IP[${i}]}" "${SEG_DHCP_START[${i}]}" "${SEG_DHCP_END[${i}]}" "${SEG_DHCP_HOSTS[${i}]:-}" >"${WORKDIR}/dhcp-${n}.conf"
    if ! out="$(dnsmasq --test --conf-file="${WORKDIR}/dhcp-${n}.conf" 2>&1)"; then
      echo "${out}" >&2
      echo "pi-fortress: dhcp-${n}.conf failed dnsmasq --test; segment ${n}'s running DHCP is unchanged" >&2
      return 1
    fi
    install -m 0644 "${WORKDIR}/dhcp-${n}.conf" "${DHCP_ETC}/dhcp-${n}.conf"
    # The same as the house: the daemon starts as its own account with no
    # CAP_CHOWN, so both files must be its own before it opens them.
    # The chown is also the upgrade from the shared dnsmasq account.
    dhcp_account "${n}"
    touch "${DHCP_STATE}/dhcp-${n}.leases" "${DHCP_LOGS}/dhcp-${n}.log"
    chown "pf-dhcp-${n}:root" "${DHCP_STATE}/dhcp-${n}.leases" "${DHCP_LOGS}/dhcp-${n}.log"
    chmod 0640 "${DHCP_STATE}/dhcp-${n}.leases" "${DHCP_LOGS}/dhcp-${n}.log"
    systemctl enable "pi-fortress-dhcp@${n}.service" >/dev/null 2>&1 || true
    # Not fatal: the ruleset and the other segments are already applied.
    # settled() reports an instance that is not active (exit 3).
    systemctl restart "pi-fortress-dhcp@${n}.service" ||
      echo "pi-fortress: pi-fortress-dhcp@${n} failed to start; segment ${n} has no DHCP until it does (journalctl -u pi-fortress-dhcp@${n})" >&2
  done
}
