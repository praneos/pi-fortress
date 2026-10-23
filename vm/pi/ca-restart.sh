#!/bin/bash
# ca-restart.sh: restart the long-running pf daemons that verify TLS after
# the system CA bundle changes.
#
# A Go process reads the system CA roots one time, when it starts. Thus
# after an apt run that changes /etc/ssl/certs/ca-certificates.crt (an
# update of ca-certificates, or update-ca-certificates from a different
# package), these daemons keep the old roots until they restart:
#   pf-broker   TLS to the origins
#   pf dns      DoT to the upstream (the agent resolver and each stub)
#   pf alert    the webhook
# The apt hook /etc/apt/apt.conf.d/60pi-fortress-ca (DPkg::Post-Invoke)
# runs this script after each dpkg run. It restarts only the units that
# run, and only when the hash of the bundle is different from the hash of
# the last run. The first run with no recorded hash only records it: there
# is no evidence of a change.
#
# A sealed credential store is locked again at each broker start, and then
# each credential is refused until a person runs pf unlock. Nobody asked
# for this restart, and nobody is there to unlock. Thus with a sealed store
# the script does not restart the broker. It writes the time to a root-only
# marker instead. pf doctor warns while the marker is there, and each
# broker start removes it (ExecStartPost in pf-broker.service).
#
#   (no argument)  compare, restart on a change, record the new hash
#   --seed         record the hash only if none is recorded (apply.sh)
#
# It writes nothing to the terminal, and it always exits 0: it must never
# fail an apt run. A restart goes to the journal (tag pi-fortress-ca).
set -uo pipefail

BUNDLE="${PF_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
STATE="${PF_CA_STATE:-/var/lib/pi-fortress/ca-bundle.sha256}"
PENDING="${PF_CA_PENDING:-/var/lib/pi-fortress/ca-restart-pending}"
SECRETS="${PF_SECRETS:-/etc/pi-fortress/broker/secrets.env}"
SYSTEMCTL="${PF_SYSTEMCTL:-systemctl}"
LOGGER="${PF_LOGGER:-logger}"
BROKER=pi-fortress-broker.service
UNITS=(
  pi-fortress-dns-agent-go.service
  'pi-fortress-dns-stub@*.service'
  pi-fortress-alert.service
)

# No state directory: this box has no pi-fortress install to restart.
[[ -d "${STATE%/*}" && -r "${BUNDLE}" ]] || exit 0
new="$(sha256sum <"${BUNDLE}" 2>/dev/null)" || exit 0
new="${new%% *}"
[[ -n "${new}" ]] || exit 0
old="$(cat "${STATE}" 2>/dev/null || true)"

# A root-only file goes in through a rename, so a reader never sees half
# of it.
put() {
  local tmp="$1.tmp"
  if (umask 077 && printf '%s\n' "$2" >"${tmp}") 2>/dev/null; then
    mv -f "${tmp}" "$1" 2>/dev/null || rm -f "${tmp}" 2>/dev/null
  fi
  return 0
}

# The broker reads the store as sealed when a line is the sealed header
# (internal/secrets: isSealedHeader). No store is not sealed. A store that
# cannot be read counts as sealed: a skipped restart costs a warning, but a
# wrong restart locks the fence.
sealed() {
  [[ -e "${SECRETS}" ]] || return 1
  grep -qE '^[[:space:]]*#pf-sealed ' "${SECRETS}" 2>/dev/null
  [[ $? -ne 1 ]]
}

if [[ "${1:-}" == --seed ]]; then
  [[ -n "${old}" ]] || put "${STATE}" "${new}"
  exit 0
fi
[[ "${new}" != "${old}" ]] || exit 0
if [[ -z "${old}" ]]; then
  put "${STATE}" "${new}"
  exit 0
fi
# try-restart starts no unit that is stopped. --no-block does not keep apt
# waiting for the broker to come up. One unit per call, so that a unit
# that is not installed does not stop the restart of the others.
if sealed; then
  put "${PENDING}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  note="the store is sealed, so ${BROKER} keeps the old roots until it restarts (pf doctor rung ca)"
else
  UNITS=("${BROKER}" "${UNITS[@]}")
  note=""
fi
for _u in "${UNITS[@]}"; do
  "${SYSTEMCTL}" try-restart --no-block "${_u}" >/dev/null 2>&1 || true
done
"${LOGGER}" -t pi-fortress-ca "system CA bundle changed; restarted the running units of: ${UNITS[*]}${note:+; ${note}}" >/dev/null 2>&1 || true
put "${STATE}" "${new}"
exit 0
