#!/bin/bash
# shellcheck shell=bash
# apply.sh sources this file. It is not a program. It shares the globals
# and the set -euo of apply.sh.
# The feed download unit, pi-fortress-feeds.service: pf fetch as the
# account pf-feeds, with no capability. feeds_prepare makes the account,
# installs the unit and the drop-in that keeps it on the uplink, and makes
# the input directory. Then apply runs pf feeds run (root), which starts
# the unit and imports its lists through a strict check.
#
# The paths come from apply, as FEEDS_UNITS (the systemd unit directory)
# and FEEDS_IN (the input directory). Thus the path rewrite of apply.sh in
# the apply test also reaches them.

# Off a gateway, the source stops here, before this file defines a
# function (lib/guard.sh). The return also stops a set -e caller.
_pf_lib="${BASH_SOURCE[0]%/*}"
[[ "${_pf_lib}" != "${BASH_SOURCE[0]}" ]] || _pf_lib=.
# shellcheck source=guard.sh
source "${_pf_lib}/guard.sh" && pf_guard_target lib/feeds.sh || return 1 2>/dev/null || exit 1

# feeds_uplink prints the device of the IPv4 default route with the lowest
# metric, as pf render finds WAN_IF when net.env leaves it empty. The
# download runs before render, so apply asks here. No default route
# prints nothing.
feeds_uplink() {
  ip -4 route show default 2>/dev/null | awk '
    {
      dev = ""; metric = 0
      for (i = 1; i < NF; i++) {
        if ($i == "dev") dev = $(i + 1)
        if ($i == "metric") metric = $(i + 1) + 0
      }
      if (dev != "" && (best == "" || metric < low)) { best = dev; low = metric }
    }
    END { print best }'
}

# feeds_resolvers prints the nameservers of FEEDS_RESOLV (default
# /etc/resolv.conf) that are not loopback, on one line. The unit denies
# the private ranges. A box whose resolver is the router of the uplink
# (from DHCP) needs that one address open, or no name of a feed
# resolves. Loopback is open in the unit already. Only a plain IPv4 or
# IPv6 address counts: a zone (fe80::1%eth0) or other text does not.
feeds_resolvers() {
  local f="${FEEDS_RESOLV:-/etc/resolv.conf}" kw="" addr="" out=()
  [[ -r "${f}" ]] || return 0
  # The || keeps a last line that has no newline.
  while read -r kw addr _ || [[ -n "${kw}" ]]; do
    [[ "${kw}" == nameserver ]] || continue
    if [[ "${addr}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      [[ "${addr}" != 127.* ]] || continue
    elif [[ "${addr}" =~ ^[0-9A-Fa-f:]{2,39}$ && "${addr}" == *:* ]]; then
      [[ "${addr}" != ::1 ]] || continue
    else
      continue
    fi
    out+=("${addr}")
  done <"${f}"
  if ((${#out[@]})); then
    printf '%s\n' "${out[*]}"
  fi
}

# feeds_prepare SRC WAN_IF: SRC is the feeds.service of the tree. The
# unit may use only lo and the uplink: the traffic of the Pi itself does
# not go through the house tunnel. The drop-in also opens the resolvers of
# resolv.conf that are not loopback (feeds_resolvers), by address only.
# Each step does nothing when it is already done. A daemon-reload runs
# only when a unit file changed.
feeds_prepare() {
  local src="$1" wan="$2"
  local unit="${FEEDS_UNITS}/pi-fortress-feeds.service"
  local drop="${FEEDS_UNITS}/pi-fortress-feeds.service.d/uplink.conf"
  local want dns changed=0
  if [[ ! -f "${src}" ]]; then
    echo "pi-fortress: ${src} is missing, so no feed is downloaded" >&2
    return 1
  fi
  if [[ -z "${wan}" ]]; then
    echo "pi-fortress: no uplink for the feed download (WAN_IF is empty and there is no IPv4 default route), so no feed is downloaded" >&2
    return 1
  fi
  # The name goes into a unit file. Apply checked it already; this
  # refuses all that is not an interface name.
  if [[ ! "${wan}" =~ ^[A-Za-z0-9_.@-]{1,15}$ ]]; then
    echo "pi-fortress: '${wan}' is not an interface name; the feed download unit is not changed" >&2
    return 1
  fi
  getent group pf-feeds >/dev/null || groupadd --system pf-feeds
  if ! id -u pf-feeds >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-feeds --home /nonexistent --shell /usr/sbin/nologin pf-feeds
  fi
  install -d -m 0755 "${FEEDS_IN}"
  if ! cmp -s "${src}" "${unit}"; then
    install -m 0644 "${src}" "${unit}"
    changed=1
  fi
  want="$(printf '[Service]\nRestrictNetworkInterfaces=lo %s' "${wan}")"
  dns="$(feeds_resolvers)"
  [[ -z "${dns}" ]] || want+=$'\n'"IPAddressAllow=${dns}"
  if [[ "$(cat "${drop}" 2>/dev/null || true)" != "${want}" ]]; then
    install -d -m 0755 "${drop%/*}"
    printf '%s\n' "${want}" >"${drop}"
    chmod 0644 "${drop}"
    changed=1
  fi
  if [[ "${changed}" -eq 1 ]]; then
    systemctl daemon-reload
  fi
}
