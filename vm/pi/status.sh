#!/bin/bash
# No pipefail: the report pipes long nft listings into head. With pipefail,
# the SIGPIPE that this gives nft would end the script before the
# house and fence sections.
set -eu
umask 027

echo "== addresses =="
ip -br addr
echo
echo "== routes =="
ip route
echo
# Lines of a manual list (ssh_allow.ips, direct_ip.allow) that pf compile skipped
# in the last apply. The output of that apply shows the lines themselves.
_cw="$(tr -cd '0-9' </var/lib/pi-fortress/compile-warnings 2>/dev/null || true)"
if [[ -n "${_cw}" && "${_cw}" != 0 ]]; then
  echo "WARN: the last apply skipped ${_cw} hand-kept list line(s) (pf apply --local, read the \"compile: warning:\" lines)"
  echo
fi
echo "== sysctl =="
sysctl net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6 2>/dev/null || true
echo
echo "== resources =="
# Disk: the logs, the journal and the fake-IP journal are all on the root of
# the SD card. A full card stops all writers at the same time. Thus this warns
# at 1 GiB free -- the same floor that journald keeps (SystemKeepFree, apply).
for _mnt in / /var/log; do
  _free_kb="$(df -Pk "${_mnt}" 2>/dev/null | awk 'NR==2 {print $4}')"
  [[ -n "${_free_kb}" ]] || continue
  if (( _free_kb < 1048576 )); then
    echo "WARN: ${_mnt} has $(( _free_kb / 1024 )) MiB free, under 1 GiB (du -sh /var/log/pi-fortress; journalctl --disk-usage)"
  else
    echo "${_mnt}: $(( _free_kb / 1048576 )) GiB free"
  fi
done
journalctl --disk-usage 2>/dev/null || true
# The connection table. The budget of each segment is a part of it (apply.sh).
echo "conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') of $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
free -m | awk 'NR==2 {print "memory: " $7 " MiB available of " $2}'
echo
echo "== nft set size =="
nft list set inet fortress blacklist_v4 2>/dev/null | wc -l
echo "(first 20 lines)"
nft list set inet fortress blacklist_v4 2>/dev/null | head -20
echo
echo "== dns pin / quic / v6 =="
nft list set inet fortress dns_bypass_v4 2>/dev/null | head -20
nft list chain inet fortress filter_prerouting 2>/dev/null | grep -E 'dport (22|53|853|443)|ipv6' || true
nft list chain inet fortress forward 2>/dev/null | grep -E 'policy|dport (22|53|853|443)|ipv6|counter drop' || true
echo "doh domain rules: $(wc -l < /etc/pi-fortress/doh-domains.conf 2>/dev/null || echo 0)"
echo
echo "== resolver gate =="
# The drop counter is the instrument: zero after a normal session, one
# for each connection that a client made to an address it never resolved.
nft list chain inet fortress resolver_gate 2>/dev/null | grep -E 'counter' || echo "NO GATE: the ruleset has no resolver_gate chain"
echo "resolved (agent): $(nft list set inet fortress resolved_v4 2>/dev/null | grep -cE 'expires') addresses live"
if nft list set inet fortress resolved_house_v4 >/dev/null 2>&1; then
  echo "resolved (house): $(nft list set inet fortress resolved_house_v4 2>/dev/null | grep -cE 'expires') addresses live"
fi
echo "direct_ip.allow: $(nft list set inet fortress direct_ip_v4 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){3}(/[0-9]+)?' | wc -l) prefixes"
if nft list set inet fortress house_direct_ip_v4 >/dev/null 2>&1; then
  echo "house_direct_ip.allow: $(nft list set inet fortress house_direct_ip_v4 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){3}(/[0-9]+)?' | wc -l) prefixes"
fi
if nft list set inet fortress ssh_allow_v4 >/dev/null 2>&1; then
  echo "ssh_allow.ips: $(nft list set inet fortress ssh_allow_v4 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){3}(/[0-9]+)?' | wc -l) prefixes"
else
  echo "ssh_allow.ips: (no set)"
fi
# The set exists only when a plain segment has NTP=pass.
if nft list set inet fortress ntp_pass_v4 >/dev/null 2>&1; then
  echo "ntp_pass.ips: $(nft list set inet fortress ntp_pass_v4 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){3}(/[0-9]+)?' | wc -l) prefixes"
fi
if [[ -f /etc/pi-fortress/git_push.allow ]]; then
  echo "git_push.allow: $(grep -vcE '^[[:space:]]*(#|$)' /etc/pi-fortress/git_push.allow || true) repos"
else
  echo "git_push.allow: (no file, every push refused)"
fi
# The mode that the next apply will use (docs/paranoid_mode.md). The
# order of apply: net.env, then the operator overlay over it, then
# paranoid.env over both. A read of the base alone reported "off" on a box
# that its overlay armed. pf dns gives the forward-name count, in
# the "== pf dns ==" section below (paranoid=N for each segment). Now that
# dnsmasq does no DNS, there is no separate conf here to count.
paranoid_src=(/etc/pi-fortress/net.env /etc/pi-fortress/net.env.local)
if [[ -f /etc/pi-fortress/paranoid.env ]]; then
  paranoid_src=(/etc/pi-fortress/paranoid.env)
fi
paranoid="$(grep -hE '^PARANOID=' "${paranoid_src[@]}" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\"' " || true)"
if [[ "${paranoid}" == 1 ]]; then
  echo "paranoid=on"
else
  echo "paranoid=off"
fi
# The PARANOID=on|off of each plain segment (segments.d). The agent line
# above does not show it. Detail for each segment under "plain segments".
_segpar=""
for _f in /etc/pi-fortress/segments.d/*.env; do
  [[ -f "${_f}" ]] || continue
  _n="${_f##*/}"
  _p="$(grep -E '^PARANOID=' "${_f}" | tail -1 | cut -d= -f2- | tr -cd '[:lower:]')"
  _segpar="${_segpar} ${_n%.env}=${_p:-off}"
done
if [[ -n "${_segpar}" ]]; then
  echo "paranoid (plain segments):${_segpar}"
fi
echo
# pf dns serves each segment, so there is no dnsmasq conf to read here:
# what it serves comes from its own segment list.
echo "== pf dns =="
systemctl is-active pi-fortress-dns-agent-go || true
# One line for each segment, from the -check of the daemon: the interface,
# address, upstream and nft set that it would serve. A house segment that
# fed resolved_v4 instead of resolved_house_v4 shows here and
# nowhere else in this report.
if [[ -x /usr/local/sbin/pf && -f /etc/pi-fortress/dns.json ]]; then
  /usr/local/sbin/pf dns -config /etc/pi-fortress/dns.json -check 2>&1 || true
else
  echo "NO SEGMENT LIST: /etc/pi-fortress/dns.json is missing; pf dns has nothing to serve"
fi
# The DNS mode of the agent, as apply last wrote it: dns.json has
# fakeip_net on the agent segment only under AGENT_DNS=fakeip. Mapped
# names are the distinct addresses in the journal. The pool never frees
# an address. It only gives it to a new name. Thus each address in the
# journal is exactly one live mapping, for any number of refresh lines.
fakeip_net="$(grep -oE '"fakeip_net": *"[^"]*"' /etc/pi-fortress/dns.json 2>/dev/null | head -1 | cut -d'"' -f4 || true)"
if [[ -n "${fakeip_net}" ]]; then
  fakeip_journal=/var/lib/pi-fortress/dns/fakeip.journal
  echo "agent dns: fakeip ${fakeip_net}, $(awk 'NF == 3 {print $2}' "${fakeip_journal}" 2>/dev/null | sort -u | wc -l) names mapped (${fakeip_journal})"
else
  echo "agent dns: forward"
fi
echo "blocked domain rules: $(wc -l < /etc/pi-fortress/blocked-domains.conf 2>/dev/null || echo 0)"
echo "filters: AAAA and HTTPS dropped unconditionally"
echo
echo "== upstream DNS =="
# One config and one unit instance for each stub (apply.sh stub_config):
# main always, house when HOUSE_DOT_* names a provider of its own.
stubs=(/etc/pi-fortress/dns-stub-*.json)
if [[ -f "${stubs[0]}" ]]; then
  for f in "${stubs[@]}"; do
    inst="${f##*/dns-stub-}"
    inst="${inst%.json}"
    echo "dns-stub@${inst}: $(systemctl is-active "pi-fortress-dns-stub@${inst}" 2>/dev/null || true) $(/usr/local/sbin/pf dns -config "${f}" -check 2>/dev/null | sed -n 's/.*upstream=\(dot:[^ ]*\).*/\1/p' | tr '\n' ' ')"
  done
  # The pins, not the intent: a ruleset that lost them forwards in
  # clear, and nothing else in this report would show it.
  nft list chain inet fortress output 2>/dev/null | grep -E 'pf-dns|dport 53' || echo "NO OUTPUT PINS: the stub is up but plaintext 53 is not blocked"
  echo "resolv.conf: $(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
else
  upstream="$(/usr/local/sbin/pf dns -config /etc/pi-fortress/dns.json -check 2>/dev/null | sed -n 's/.*upstream=\([^ ]*\).*/\1/p' | sort -u | tr '\n' ' ' || true)"
  echo "plaintext to ${upstream}(no DoT stub; set DOT_AUTH_NAME and DOT_IPS in net.env)"
fi
echo
echo "== local canaries =="
# The lists that apply compiles from (base.PolicyDir): the tree of the lab
# or of a pf install box, else /etc/pi-fortress.
P=/etc/pi-fortress
for _t in /vagrant /opt/pi-fortress; do
  if [[ -f "${_t}/vm/pi/net.env" && -d "${_t}/vm/policy" ]]; then
    P="${_t}/vm/policy"
    break
  fi
done
P="${PI_FORTRESS_POLICY:-${P}}"
echo "--- ${P}/blacklist.ips ---"
cat "${P}/blacklist.ips"
echo "--- ${P}/blacklist.domains ---"
cat "${P}/blacklist.domains"
if [[ -f "${P}/generated/fetch.report" ]]; then
  echo
  echo "== feed fetch =="
  cat "${P}/generated/fetch.report"
fi
if [[ -f "${P}/generated/sample.domain" ]]; then
  echo "sample.domain=$(tr -d '[:space:]' < "${P}/generated/sample.domain")"
fi
echo
echo "== observe =="
if [[ -x /usr/local/sbin/pf ]]; then
  /usr/local/sbin/pf observe once
else
  echo "(observer not installed)"
fi
echo
echo "== last strip =="
if [[ -x /usr/local/sbin/pf ]]; then
  /usr/local/sbin/pf alert show
else
  echo "(alerter not installed)"
fi
echo
echo "== house segment =="
if [[ -f /etc/pi-fortress/house.env ]]; then
  # Read, not sourced: apply.sh validates this file; status only displays it.
  house_val() { grep -E "^$1=" /etc/pi-fortress/house.env | tail -1 | cut -d= -f2- | tr -cd 'A-Za-z0-9._/-'; }
  HOUSE_IF="$(house_val HOUSE_IF)"
  HOUSE_IP="$(house_val HOUSE_IP)"
  # house.env may leave HOUSE_IP unset; apply then gives the interface
  # render.DefaultHouseIP, so show that instead of an empty field.
  echo "HOUSE_IF=${HOUSE_IF:-?} HOUSE_IP=${HOUSE_IP:-10.78.0.1} admin=$(house_val HOUSE_ADMIN_IP)"
  # dnsmasq is bind-dynamic: it stays "active" with no interface to serve.
  # Thus a missing USB adapter stayed hidden behind a green status for a
  # full lease. Report the interface first, and qualify the unit by it.
  if [[ -n "${HOUSE_IF}" && -e "/sys/class/net/${HOUSE_IF}" ]]; then
    ip -br addr show "${HOUSE_IF}"
    house_state="$(systemctl is-active pi-fortress-dns-house 2>/dev/null || true)"
  else
    echo "HOUSE_IF=${HOUSE_IF:-?} MISSING: no such interface; the USB adapter is not enumerated (lsusb), the house segment has no gateway"
    house_state="$(systemctl is-active pi-fortress-dns-house 2>/dev/null || true) but serving nothing (no ${HOUSE_IF:-interface})"
  fi
  # Two roles, two lines. An active dns-house means DHCP and nothing
  # else (port=0). This split stops the mistake to read it as "the house
  # has DNS".
  echo "dns-house (DHCP only): ${house_state}"
  echo "house DNS: pf dns, $(systemctl is-active pi-fortress-dns-agent-go 2>/dev/null || true) -- see the pf dns section for the house segment"
  echo "HOUSE_BLOCK_DIRECT_IP=$(house_val HOUSE_BLOCK_DIRECT_IP | grep . || echo on) HOUSE_BLOCK_HTTP=$(house_val HOUSE_BLOCK_HTTP | grep . || echo off) HOUSE_BLOCK_VPN=$(house_val HOUSE_BLOCK_VPN | grep . || echo on) HOUSE_PRIVATE_DNS=$(house_val HOUSE_PRIVATE_DNS | grep . || echo off)"
  echo "HOUSE_EGRESS=$(house_val HOUSE_EGRESS | grep . || echo strict) HOUSE_ALLOW_WIFI_CALLING=$(house_val HOUSE_ALLOW_WIFI_CALLING | grep . || echo off) HOUSE_ALLOW_CALL_UDP=$(house_val HOUSE_ALLOW_CALL_UDP | grep . || echo off) HOUSE_ALLOW_WHATSAPP=$(house_val HOUSE_ALLOW_WHATSAPP | grep . || echo on) HOUSE_ALLOW_PORTS=$(house_val HOUSE_ALLOW_PORTS | grep . || echo none)"
  if [[ "$(house_val HOUSE_PRIVATE_DNS)" == on ]]; then
    echo "HOUSE_PRIVATE_DNS=on: secure DNS (tcp 853/443) allowed to $(nft list set inet fortress house_private_dns_v4 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){3}(/[0-9]+)?' | wc -l) pinned addresses for the endpoints in house_private_dns.domains"
  fi
  echo "leases: $(grep -c . /var/lib/pi-fortress/house.leases 2>/dev/null || echo 0)"
  nft list chain inet fortress forward 2>/dev/null | grep -E "oifname \"${HOUSE_IF:-none}\"|iifname \"${HOUSE_IF:-none}\"" | head -6 || true
  WG_IF="$(house_val WG_IF)"
  if [[ -n "${WG_IF}" ]]; then
    echo "== wireguard =="
    if command -v wg >/dev/null 2>&1 && ip link show "${WG_IF}" >/dev/null 2>&1; then
      _ep="$(wg show "${WG_IF}" endpoints 2>/dev/null | awk '{print $2}' | head -1)"
      _hs="$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)"
      _xfer="$(wg show "${WG_IF}" transfer 2>/dev/null | awk '{print $2, $3}' | head -1)"
      _ago=""
      if [[ -n "${_hs}" && "${_hs}" != "0" ]]; then
        _ago="$(( $(date +%s) - _hs ))s ago"
      else
        _ago="never"
      fi
      echo "${WG_IF}: endpoint ${_ep:-?} handshake ${_ago} transfer ${_xfer:-?}"
    else
      echo "${WG_IF}: down"
    fi
    ip rule show 2>/dev/null | grep -E 'fwmark|blackhole|lookup 100' || true
    ip route show table 100 2>/dev/null || true
    echo "vpn_bypass_v4: $(nft list set inet fortress vpn_bypass_v4 2>/dev/null | grep -cE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+') elements"
  fi
else
  echo "(no /etc/pi-fortress/house.env)"
fi
echo
echo "== plain segments =="
# Read, not sourced: apply.sh validates these files; status only displays
# them. grep -F in all locations, because a VLAN interface name has a dot.
# As in pf render, spaces before the key and around = are permitted, and
# the last line of a key wins.
seg_val() { grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" | tail -1 | cut -d= -f2- | tr -cd 'A-Za-z0-9./_-'; }
if compgen -G "/etc/pi-fortress/segments.d/*.env" >/dev/null 2>&1; then
  for _f in /etc/pi-fortress/segments.d/*.env; do
    _name="${_f##*/}"
    _name="${_name%.env}"
    _if="$(seg_val "${_f}" IF)"
    _par="$(seg_val "${_f}" PARANOID)"
    echo "${_name}: IF=${_if:-?} IP=$(seg_val "${_f}" IP) NET=$(seg_val "${_f}" NET) admin=$(seg_val "${_f}" ADMIN) ssh_to=$(seg_val "${_f}" SSH_TO) block_direct_ip=$(seg_val "${_f}" BLOCK_DIRECT_IP) egress=$(seg_val "${_f}" EGRESS) ssh_from=$(seg_val "${_f}" SSH_FROM) paranoid=${_par:-off} ntp=$(_ntp="$(seg_val "${_f}" NTP)"; echo "${_ntp:-redirect}")"
    # When armed, the segment reaches only its own allowlist. pf dns gives the
    # name count (paranoid=N on the line of this segment in the pf dns section).
    if [[ "${_par}" == on ]]; then
      _allow="/etc/pi-fortress/allow.${_name}.domains"
      if [[ -r "${_allow}" ]]; then
        echo "  allowlist: ${_allow}, $(grep -vcE '^[[:space:]]*(#|$)' "${_allow}" || true) line(s)"
      else
        echo "  PARANOID=on but ${_allow} is missing or unreadable; the next apply refuses (sudo pf doctor)"
      fi
    fi
    # The connection budget of the segment. An empty field means the SEG_ value of net.env.
    if grep -qE '^[[:space:]]*(CONN_PER_IP|NEW_PER_IP|CONN_TOTAL|NEW_TOTAL)[[:space:]]*=' "${_f}"; then
      echo "  own budget: conn_per_ip=$(seg_val "${_f}" CONN_PER_IP) new_per_ip=$(seg_val "${_f}" NEW_PER_IP) conn_total=$(seg_val "${_f}" CONN_TOTAL) new_total=$(seg_val "${_f}" NEW_TOTAL)"
    fi
    if [[ -n "${_if}" && -e "/sys/class/net/${_if}" ]]; then
      ip -br addr show "${_if}"
    else
      echo "  MISSING: no such interface; this segment has no gateway"
    fi
    nft list chain inet fortress forward 2>/dev/null | grep -F -e "iifname \"${_if:-none}\"" -e "oifname \"${_if:-none}\"" | head -8 || true
    nft list chain inet fortress postrouting 2>/dev/null | grep -F "$(seg_val "${_f}" NET)" || true
  done
else
  echo "(no /etc/pi-fortress/segments.d)"
fi
echo
echo "== fence =="
echo "mode=$(tr -d '[:space:]' < /etc/pi-fortress/fence 2>/dev/null || echo '(unset)')"
systemctl is-active pi-fortress-engine 2>/dev/null || true
systemctl is-active pi-fortress-broker 2>/dev/null || true
systemctl is-active pi-fortress-mitm 2>/dev/null || true
ss -ltnH 'sport = :8080' 2>/dev/null || true
echo
echo "== enroll www =="
systemctl is-active pi-fortress-www || true
ls -l /var/lib/pi-fortress/www 2>/dev/null || echo "(www dir missing)"
echo
echo "== management =="
echo "sudo pf tui over ssh or at the seat; no listener. apply lock: $(if [[ -e /run/pi-fortress/apply.lock ]] && ! flock -n /run/pi-fortress/apply.lock true 2>/dev/null; then echo held; else echo free; fi)"
