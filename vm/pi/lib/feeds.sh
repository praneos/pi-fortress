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

# feeds_prepare SRC WAN_IF [WG_IF]: SRC is the feeds.service of the tree.
# The unit may use only lo, the uplink and the WireGuard interface. Each
# step does nothing when it is already done. A daemon-reload runs only
# when a unit file changed.
feeds_prepare() {
  local src="$1" wan="$2" wg="${3:-}"
  local unit="${FEEDS_UNITS}/pi-fortress-feeds.service"
  local drop="${FEEDS_UNITS}/pi-fortress-feeds.service.d/uplink.conf"
  local want _i changed=0
  if [[ ! -f "${src}" ]]; then
    echo "pi-fortress: ${src} is missing, so no feed is downloaded" >&2
    return 1
  fi
  # The names go into a unit file. Apply checked them already; this
  # refuses all that is not an interface name.
  for _i in "${wan}" ${wg:+"${wg}"}; do
    if [[ ! "${_i}" =~ ^[A-Za-z0-9_.@-]{1,15}$ ]]; then
      echo "pi-fortress: '${_i}' is not an interface name; the feed download unit is not changed" >&2
      return 1
    fi
  done
  getent group pf-feeds >/dev/null || groupadd --system pf-feeds
  if ! id -u pf-feeds >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-feeds --home /nonexistent --shell /usr/sbin/nologin pf-feeds
  fi
  install -d -m 0755 "${FEEDS_IN}"
  if ! cmp -s "${src}" "${unit}"; then
    install -m 0644 "${src}" "${unit}"
    changed=1
  fi
  want="$(printf '[Service]\nRestrictNetworkInterfaces=lo %s%s' "${wan}" "${wg:+ ${wg}}")"
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
