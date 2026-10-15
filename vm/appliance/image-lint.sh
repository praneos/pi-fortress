#!/bin/bash
# image-lint ROLE [ROOT]: fail if a path that hygiene.list names is still
# in the filesystem under ROOT (default /). Runs inside the VM after
# seal-image.sh and before poweroff. A failure stops the export.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=hygiene.sh
source "${here}/hygiene.sh"

ROLE="${1:-}"
hygiene_role_ok "${ROLE}"
ROOT="${2:-/}"
ROOT="${ROOT%/}"
LIST="${PF_HYGIENE_LIST:-${here}/hygiene.list}"

rows="$(hygiene_rows "${ROLE}" "${LIST}")"
bad=0
flag() {
  echo "image-lint: ${ROLE}: $1" >&2
  bad=1
}

while read -r check pattern; do
  case "${check}" in
    absent)
      while IFS= read -r p; do
        [[ -n "${p}" ]] && flag "present ${p#"${ROOT}"}"
      done < <(hygiene_matches "${ROOT}" "${pattern}")
      ;;
    empty)
      while IFS= read -r p; do
        [[ -n "${p}" && -s "${p}" ]] && flag "not empty ${p#"${ROOT}"}"
      done < <(hygiene_matches "${ROOT}" "${pattern}")
      ;;
    locked)
      shadow="${ROOT}/etc/shadow"
      [[ -f "${shadow}" ]] || continue
      hash="$(awk -F: -v u="${pattern}" '$1 == u { print $2 "."; exit }' "${shadow}")"
      [[ -z "${hash}" ]] && continue
      hash="${hash%.}"
      case "${hash}" in
        '!'* | '*'*) ;;
        '') flag "no password on ${pattern}" ;;
        *) flag "password login open for ${pattern}" ;;
      esac
      ;;
  esac
done <<<"${rows}"

if [[ "${bad}" -ne 0 ]]; then
  echo "image-lint: ${ROLE}: FAILED; do not export this image" >&2
  exit 1
fi
echo "image-lint: ${ROLE}: clean"
