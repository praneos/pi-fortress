#!/bin/bash
# seal-image ROLE [ROOT]: remove each per-instance or secret item that
# hygiene.list names. Thus no two downloads of the appliance share a key.
# firstboot.sh regenerates what the VM needs on the machine of the tester.
#
# ROOT defaults to /, which is the only real use: run as root inside the
# VM, as the last step before poweroff, then image-lint.sh. Any other ROOT
# applies only the list, and does not touch the running system.
# lint_test.sh uses that.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=hygiene.sh
source "${here}/hygiene.sh"

ROLE="${1:-}"
hygiene_role_ok "${ROLE}"
ROOT="${2:-/}"
ROOT="${ROOT%/}"
LIST="${PF_HYGIENE_LIST:-${here}/hygiene.list}"
LIVE=0
[[ -z "${ROOT}" ]] && LIVE=1

die() {
  echo "seal-image: $*" >&2
  exit 1
}

have_role="$(cat "${ROOT}/etc/pi-fortress/appliance.role" 2>/dev/null || true)"
[[ "${have_role}" == "${ROLE}" ]] || die "appliance.role is '${have_role}', not ${ROLE}; run install.sh ${ROLE} first"
rows="$(hygiene_rows "${ROLE}" "${LIST}")"

if [[ "${LIVE}" -eq 1 ]]; then
  [[ "${EUID}" -eq 0 ]] || die "run as root"
  # /vagrant can be the checkout of the builder, mounted read-write from
  # the host. The script unmounts it before the list deletes under it. If
  # any mount below it stays, nothing occurs at all.
  #
  # Unmount until the point is clear, not one time. vagrant stacks a second
  # vboxsf mount on the same directory. Thus the first umount succeeds and
  # leaves a different mount below. `umount || umount -l` cannot see that:
  # the lazy arm ran only when the plain one failed, and it does not fail.
  # The check below then refused the full seal. This is why no appliance
  # was ever exported.
  for _ in 1 2 3 4 5; do
    mountpoint -q /vagrant 2>/dev/null || break
    umount /vagrant 2>/dev/null || umount -l /vagrant || break
  done
  while read -r _dev mnt _rest; do
    case "${mnt}" in /vagrant | /vagrant/*) die "${mnt} is still mounted; refusing to delete under it" ;; esac
  done </proc/mounts
  # Stop all that could write state back after the removal.
  systemctl stop 'pi-fortress-*.timer' 'pi-fortress-*.path' 2>/dev/null || true
  systemctl stop 'pi-fortress-*.service' 2>/dev/null || true
  systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service \
    apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true
fi

while read -r check pattern; do
  case "${check}" in
    absent)
      while IFS= read -r p; do
        [[ -n "${p}" ]] && rm -rf -- "${p}"
      done < <(hygiene_matches "${ROOT}" "${pattern}")
      ;;
    empty)
      while IFS= read -r p; do
        [[ -n "${p}" ]] && : >"${p}"
      done < <(hygiene_matches "${ROOT}" "${pattern}")
      ;;
    locked)
      shadow="${ROOT}/etc/shadow"
      [[ -f "${shadow}" ]] || continue
      # usermod -L does the same edit. sed works on a ROOT that is not /.
      sed -i -E "s/^(${pattern}):([^!*:][^:]*)?:/\1:!\2:/" "${shadow}"
      ;;
  esac
done <<<"${rows}"

if [[ "${LIVE}" -eq 1 ]]; then
  if [[ "${ROLE}" == agent ]]; then
    update-ca-certificates --fresh >/dev/null 2>&1 || true
  fi
  apt-get clean
  journalctl --rotate >/dev/null 2>&1 || true
  journalctl --vacuum-time=1s >/dev/null 2>&1 || true
  find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete
  find /var/log -type f ! -path '/var/log/journal/*' -exec truncate -s 0 {} +
  systemctl enable pi-fortress-firstboot.service >/dev/null
  sync
fi
echo "seal-image: ${ROLE}: sealed${ROOT:+ under ${ROOT}}"
