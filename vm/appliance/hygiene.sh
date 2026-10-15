# seal-image.sh and image-lint.sh source this file. It is the one reader
# for hygiene.list. Thus the removed paths and the checked paths cannot drift.

# hygiene_rows ROLE LIST: print "CHECK PATTERN" for every row that
# applies to ROLE. Fails on a row that it does not understand.
hygiene_rows() {
  local want=$1 list=$2 role check pattern extra
  [[ -r "${list}" ]] || { echo "hygiene: ${list} not readable" >&2; return 1; }
  while read -r role check pattern extra || [[ -n "${role}" ]]; do
    [[ -z "${role}" || "${role}" == \#* ]] && continue
    if [[ -z "${pattern}" || -n "${extra}" ]]; then
      echo "hygiene: bad row: ${role} ${check} ${pattern} ${extra}" >&2
      return 1
    fi
    case "${role}" in both | fence | agent) ;; *) echo "hygiene: bad role ${role}" >&2; return 1 ;; esac
    case "${check}" in absent | empty | locked) ;; *) echo "hygiene: bad check ${check}" >&2; return 1 ;; esac
    [[ "${role}" == both || "${role}" == "${want}" ]] || continue
    printf '%s %s\n' "${check}" "${pattern}"
  done <"${list}"
}

# hygiene_matches ROOT PATTERN: every existing path (links included)
# under ROOT that PATTERN names, one per line, dotfiles included.
hygiene_matches() {
  local root=$1 pattern=$2 p
  (
    shopt -s nullglob dotglob
    # shellcheck disable=SC2086
    for p in ${root}${pattern}; do
      [[ -e "${p}" || -L "${p}" ]] && printf '%s\n' "${p}"
    done
  )
}

hygiene_role_ok() {
  case "${1:-}" in fence | agent) return 0 ;; esac
  echo "usage: $(basename "$0") fence|agent [ROOT]" >&2
  return 1
}
