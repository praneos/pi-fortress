#!/bin/bash
set -euo pipefail
# A file that > writes gets its mode from the umask. Sudo or the shell
# of the operator can give a looser umask than the umask of root.
umask 022

# --render-nft prints the ruleset that apply would load. Then it exits
# before it changes the box. With PF_NET_ENV, PF_HOUSE_ENV, PF_INT_IF, PF_WAN_IF,
# PF_ELEMENTS, PF_DOH_ELEMENTS, PF_DIRECT_ELEMENTS and PF_SSH_ELEMENTS it
# needs no root and no Pi. It needs only a pf build (make pf, or PF_BIN).
# vm/pi/apply_test.sh uses it to prove that the no-house output never drifts.
#
# A real run holds an exclusive flock on /run/pi-fortress/apply.lock for
# all of its life. pf apply takes the same lock and execs this script. The
# descriptor stays open. The script finds that inherited descriptor and
# locks through it. It does not contend with its own parent.
RENDER=0
LOCAL_ONLY=0
REFRESH=0
apply_usage() {
  cat <<'EOF'
usage: pf apply [--local | --refresh | --render-nft]

  (no flag)     fetch feeds, compile policy, load nft + dnsmasq, restart the fence
  --local       compile and reload nft + dnsmasq only; no feed fetch
  --refresh     --local plus the feed download; the unattended timer path
  --render-nft  print the ruleset that would be loaded and exit, changing nothing
EOF
}
# Before, this loop had no default branch. Thus apply ignored each word
# that it did not recognise. RENDER and LOCAL_ONLY stayed at 0, so
# `pf apply -h` was a full fetch, install and fence restart. (The pf usage
# tells the operator to type that command.) A flag with a typo did the
# same. A request for help is not consent to reconfigure the box.
# Also, the modes are mutually exclusive: --local --render-nft asked for
# two different answers. It silently got the branch that came first.
_mode=""
for _arg in "$@"; do
  case "${_arg}" in
    -h | --help | help)
      apply_usage
      exit 0
      ;;
    --local | --refresh | --render-nft)
      if [[ -n "${_mode}" && "${_mode}" != "${_arg}" ]]; then
        echo "pi-fortress: apply: ${_mode} and ${_arg} are different modes; pick one" >&2
        exit 2
      fi
      _mode="${_arg}"
      ;;
    *)
      echo "pi-fortress: apply: unknown argument '${_arg}'; pf apply -h lists what it takes" >&2
      exit 2
      ;;
  esac
done
case "${_mode}" in
  --local) LOCAL_ONLY=1 ;;
  --refresh)
    LOCAL_ONLY=1
    REFRESH=1
    ;;
  --render-nft) RENDER=1 ;;
esac

# Run only as root on a box that is a gateway: a Raspberry Pi, a lab VM,
# the appliance, or a box that pf install made a gateway. lib/guard.sh has
# the rule. All other boxes are a desktop where someone ran this by
# mistake. The code below rewrites its firewall, network profiles and
# services. --render-nft changes nothing and needs neither this check nor
# root. The Vagrant provisioner runs a copy of this file from /tmp. Thus
# the guard is looked for in the same lib directories as the libs below.
LOCK_DIR=/run/pi-fortress
LOCK_FILE="${LOCK_DIR}/apply.lock"
if [[ "${RENDER}" -eq 0 ]]; then
  _guard=""
  for _d in "$(dirname "$(readlink -f "$0")")/lib" "${PF_PI_LIB:-/nonexistent}/lib" /vagrant/vm/pi/lib /usr/local/lib/pi-fortress/lib; do
    if [[ -f "${_d}/guard.sh" ]]; then
      _guard="${_d}/guard.sh"
      break
    fi
  done
  if [[ -z "${_guard}" ]]; then
    echo "pi-fortress: lib/guard.sh not found next to apply.sh, under PF_PI_LIB, /vagrant/vm/pi or /usr/local/lib/pi-fortress; nothing was changed" >&2
    exit 1
  fi
  # shellcheck source=lib/guard.sh
  source "${_guard}"
  pf_guard_target apply.sh || exit 1
  if [[ "${EUID}" -ne 0 ]]; then
    echo "pi-fortress: apply must run as root" >&2
    exit 1
  fi
  install -d -m 0750 "${LOCK_DIR}"
  if [[ -L "${LOCK_FILE}" || ( -e "${LOCK_FILE}" && ! -f "${LOCK_FILE}" ) ]]; then
    echo "pi-fortress: ${LOCK_FILE} is not a regular file" >&2
    exit 1
  fi
  lock_fd=""
  for _fd in /proc/self/fd/*; do
    if [[ -e "${LOCK_FILE}" && "${_fd}" -ef "${LOCK_FILE}" ]]; then
      lock_fd="${_fd##*/}"
      break
    fi
  done
  if [[ -z "${lock_fd}" ]]; then
    exec 9>>"${LOCK_FILE}"
    lock_fd=9
  fi
  if ! flock -n "${lock_fd}"; then
    echo "pi-fortress: another apply is running" >&2
    exit 75
  fi
  chmod 0640 "${LOCK_FILE}"
fi

# The checkout from which apply reads its policy, units and pf: the lab
# /vagrant (a link to /opt/pi-fortress on a hand-set Pi). If not, the tree
# that contains this script. A pf install box runs /opt/pi-fortress/vm/pi/apply.sh.
# A ship never refreshes the copy under /usr/local/lib.
TREE=""
_self="$(cd "$(dirname "$(readlink -f "$0")")/../.." 2>/dev/null && pwd || true)"
for _t in /vagrant "${_self}"; do
  if [[ -n "${_t}" && -f "${_t}/vm/pi/net.env" && -d "${_t}/vm/policy" ]]; then
    TREE="${_t}"
    break
  fi
done

NET_ENV_SRC=""
if [[ -n "${PF_NET_ENV:-}" ]]; then
  # shellcheck source=/dev/null
  source "${PF_NET_ENV}"
  NET_ENV_SRC="${PF_NET_ENV}"
  POLICY=/etc/pi-fortress
  PI_LIB="${PF_PI_LIB:-/usr/local/lib/pi-fortress}"
elif [[ -n "${TREE}" ]]; then
  # shellcheck source=/dev/null
  source "${TREE}/vm/pi/net.env"
  NET_ENV_SRC="${TREE}/vm/pi/net.env"
  POLICY="${TREE}/vm/policy"
  PI_LIB="${TREE}/vm/pi"
elif [[ -f /etc/pi-fortress/net.env ]]; then
  # shellcheck source=/dev/null
  source /etc/pi-fortress/net.env
  NET_ENV_SRC=/etc/pi-fortress/net.env
  POLICY=/etc/pi-fortress
  PI_LIB=/usr/local/lib/pi-fortress
else
  echo "pi-fortress: net.env not found" >&2
  exit 1
fi
# PF_POLICY points apply at another policy tree (the TUI's -policy).
POLICY="${PF_POLICY:-${POLICY}}"

# With a checkout, the lists come from the checkout. pf tui edits the
# checkout, and provision seeds /etc/pi-fortress only once. So a copy in
# /etc/pi-fortress that differs from the checkout copy is usually only an
# old seed. Name a list only when its copy in /etc/pi-fortress is newer
# than the checkout copy: a hand edit there that has no effect. Below,
# this apply copies the lists in the case pattern into /etc/pi-fortress
# (doh.*, git_push.allow, allow.domains, dns_types.allow). For these, the
# line says that apply replaces the edit. Keep the two sets the same. One
# line, at most 5 names per part. PF_TEST_ETC is the apply_test stand-in
# for /etc/pi-fortress.
_etc="${PF_TEST_ETC:-/etc/pi-fortress}"
if [[ -n "${TREE}" && "${POLICY}" -ef "${TREE}/vm/policy" && ! "${POLICY}" -ef "${_etc}" ]]; then
  _keep=()
  _repl=()
  for _f in "${POLICY}"/*.domains "${POLICY}"/*.ips "${POLICY}"/*.allow; do
    _n="${_f##*/}"
    if [[ -f "${_f}" && -f "${_etc}/${_n}" && "${_etc}/${_n}" -nt "${_f}" ]] && ! cmp -s "${_f}" "${_etc}/${_n}"; then
      case "${_n}" in
        allow.domains | dns_types.allow | doh.ips | doh.domains | git_push.allow) _repl+=("${_n}") ;;
        *) _keep+=("${_n}") ;;
      esac
    fi
  done
  # Prints the first 5 names of its arguments, and the count of the rest.
  _names() {
    local more=""
    if [[ "$#" -gt 5 ]]; then
      more=" (+$(($# - 5)) more)"
    fi
    printf '%s' "${*:1:5}${more}"
  }
  _msg=""
  if [[ "${#_keep[@]}" -gt 0 ]]; then
    _msg="; edits there have no effect: $(_names "${_keep[@]}")"
  fi
  if [[ "${#_repl[@]}" -gt 0 ]]; then
    _msg+="; this apply replaces edits there: $(_names "${_repl[@]}")"
  fi
  if [[ -n "${_msg}" ]]; then
    echo "pi-fortress: lists come from ${POLICY}, not ${_etc}${_msg}" >&2
  fi
fi

# net.env comes from git, and a ship copies it over /etc. Thus the next
# ship reverts a value that the operator sets at the seat. The overlay is
# not in the tree. Nothing copies over it. So operator settings go here.
NET_ENV_LOCAL="${PF_NET_ENV_LOCAL:-/etc/pi-fortress/net.env.local}"
if [[ -f "${NET_ENV_LOCAL}" ]]; then
  # shellcheck source=/dev/null
  source "${NET_ENV_LOCAL}"
fi

# Paranoid mode (docs/paranoid_mode.md): a PARANOID= line in net.env, or
# its own file. Apply sources that file only if it exists. A render gets
# the value from the environment, so apply_test.sh can render both modes
# without a file on the box. A value other than 0 or 1 is a typo in the
# armed state. Apply refuses it and does not guess.
if [[ "${RENDER}" -eq 1 ]]; then
  PARANOID="${PF_PARANOID:-${PARANOID:-0}}"
elif [[ -f /etc/pi-fortress/paranoid.env ]]; then
  # shellcheck source=/dev/null
  source /etc/pi-fortress/paranoid.env
fi
PARANOID="${PARANOID:-0}"
if [[ "${PARANOID}" != "0" && "${PARANOID}" != "1" ]]; then
  echo "pi-fortress: PARANOID='${PARANOID}' is not 0 or 1 (${NET_ENV_LOCAL}, net.env or /etc/pi-fortress/paranoid.env)" >&2
  exit 1
fi
# When armed, the agent segment can reach only the forward set. Thus a
# missing or unreadable half of the set is not an empty list: it is the
# fence about to open. Apply checks this before it changes the box.
if [[ "${RENDER}" -eq 0 && "${PARANOID}" == "1" ]]; then
  for _f in "${POLICY}/allow.domains" "${POLICY}/core.hosts"; do
    if [[ ! -r "${_f}" ]]; then
      echo "pi-fortress: PARANOID=1 but ${_f} is missing or unreadable; nothing was changed" >&2
      exit 1
    fi
  done
fi

# GO_DNS selected dnsmasq or pf dns while both could serve. Now dnsmasq
# does no DNS on any segment, so the key selects nothing. A key that
# selects nothing is worse than no key. An operator who sets GO_DNS=0 to
# revert gets a box that silently ignores the operator. Apply sources
# both files above, so a leftover in either file is visible here. Tell
# which file has it.
if [[ -n "${GO_DNS+x}" ]]; then
  _holds=""
  for _f in "${NET_ENV_SRC}" "${NET_ENV_LOCAL}"; do
    [[ -f "${_f}" ]] && grep -qE '^[[:space:]]*GO_DNS[[:space:]]*=' "${_f}" && _holds="${_holds:+${_holds} and }${_f}"
  done
  echo "pi-fortress: GO_DNS is retired -- pf dns serves every segment and dnsmasq keeps DHCP. Remove the line from ${_holds:-the environment}; nothing was changed." >&2
  exit 1
fi
# The query log has one row for each transaction, with the client. Thus
# observe can read it and does not have to match a reply to a query by
# name. GO_DNS_FORMAT selected this format over the two dnsmasq lines
# while dnsmasq could still write them. Now it selects nothing, so apply
# refuses a leftover the same way as GO_DNS.
if [[ -n "${GO_DNS_FORMAT+x}" ]]; then
  _holds=""
  for _f in "${NET_ENV_SRC}" "${NET_ENV_LOCAL}"; do
    [[ -f "${_f}" ]] && grep -qE '^[[:space:]]*GO_DNS_FORMAT[[:space:]]*=' "${_f}" && _holds="${_holds:+${_holds} and }${_f}"
  done
  echo "pi-fortress: GO_DNS_FORMAT is retired -- the query log is one row per transaction. Remove the line from ${_holds:-the environment}; nothing was changed." >&2
  exit 1
fi
FEED_REFRESH="${FEED_REFRESH:-1}"
if [[ "${FEED_REFRESH}" != "0" && "${FEED_REFRESH}" != "1" ]]; then
  echo "pi-fortress: FEED_REFRESH='${FEED_REFRESH}' is not 0 or 1 (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
EYEBALL="${EYEBALL:-audit}"
if [[ "${EYEBALL}" != off && "${EYEBALL}" != audit && "${EYEBALL}" != refuse ]]; then
  echo "pi-fortress: EYEBALL='${EYEBALL}' is not off, audit or refuse (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
JOURNAL_PERSIST="${JOURNAL_PERSIST:-0}"
if [[ "${JOURNAL_PERSIST}" != 0 && "${JOURNAL_PERSIST}" != 1 ]]; then
  echo "pi-fortress: JOURNAL_PERSIST='${JOURNAL_PERSIST}' is not 0 or 1 (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
HW_WATCHDOG="${HW_WATCHDOG:-auto}"
if [[ "${HW_WATCHDOG}" != auto && "${HW_WATCHDOG}" != 0 && "${HW_WATCHDOG}" != 1 ]]; then
  echo "pi-fortress: HW_WATCHDOG='${HW_WATCHDOG}' is not auto, 0 or 1 (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
# The hourly budget of each slot (net.env, docs/fence.md 5.2d). Apply
# checks it here because nothing else does. A typo goes to the broker as
# a flag, the unit does not start, and the fence is down until someone
# reads the journal. 0 sets a threshold off. Both stops ship with 0.
SLOT_WARN_REQUESTS="${SLOT_WARN_REQUESTS:-3000}"
SLOT_STOP_REQUESTS="${SLOT_STOP_REQUESTS:-0}"
SLOT_WARN_UPLOAD_MB="${SLOT_WARN_UPLOAD_MB:-500}"
SLOT_STOP_UPLOAD_MB="${SLOT_STOP_UPLOAD_MB:-0}"
for _k in SLOT_WARN_REQUESTS SLOT_STOP_REQUESTS SLOT_WARN_UPLOAD_MB SLOT_STOP_UPLOAD_MB; do
  if [[ ! "${!_k}" =~ ^[0-9]+$ ]]; then
    echo "pi-fortress: ${_k}='${!_k}' is not a whole number, 0 for off (net.env or ${NET_ENV_LOCAL})" >&2
    exit 1
  fi
done
# A stop below its own warn quarantines the slot before the alert that
# gives the operator a chance to examine the slot.
if [[ "${SLOT_STOP_REQUESTS}" != "0" && "${SLOT_WARN_REQUESTS}" != "0" && "${SLOT_STOP_REQUESTS}" -lt "${SLOT_WARN_REQUESTS}" ]]; then
  echo "pi-fortress: SLOT_STOP_REQUESTS=${SLOT_STOP_REQUESTS} is below SLOT_WARN_REQUESTS=${SLOT_WARN_REQUESTS}; the slot would be quarantined before the warning (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
if [[ "${SLOT_STOP_UPLOAD_MB}" != "0" && "${SLOT_WARN_UPLOAD_MB}" != "0" && "${SLOT_STOP_UPLOAD_MB}" -lt "${SLOT_WARN_UPLOAD_MB}" ]]; then
  echo "pi-fortress: SLOT_STOP_UPLOAD_MB=${SLOT_STOP_UPLOAD_MB} is below SLOT_WARN_UPLOAD_MB=${SLOT_WARN_UPLOAD_MB}; the slot would be quarantined before the warning (net.env or ${NET_ENV_LOCAL})" >&2
  exit 1
fi
# The NetworkManager helpers are in a sourced file next to this one. pf
# apply execs from /vagrant/vm/pi or /usr/local/lib/pi-fortress. The
# Vagrant provisioner first uploads this file to /tmp. apply_test.sh runs
# it from the tree. So apply tries each location to find the lib directory.
LIB_DIR=""
for _d in "$(dirname "$(readlink -f "$0")")/lib" "${PF_PI_LIB:-/nonexistent}/lib" /vagrant/vm/pi/lib "${PI_LIB}/lib"; do
  if [[ -f "${_d}/netman.sh" ]]; then
    LIB_DIR="${_d}"
    break
  fi
done
if [[ -z "${LIB_DIR}" ]]; then
  echo "pi-fortress: lib/ not found next to apply.sh, under PF_PI_LIB, /vagrant/vm/pi or ${PI_LIB}" >&2
  exit 1
fi
# Each lib stops a caller that is not root on a gateway (lib/guard.sh).
# --render-nft uses none of their functions and runs with no root, so it
# does not source them.
if [[ "${RENDER}" -eq 0 ]]; then
  # shellcheck source=lib/netman.sh
  source "${LIB_DIR}/netman.sh"
  # shellcheck source=lib/dhcp.sh
  source "${LIB_DIR}/dhcp.sh"
  # shellcheck source=lib/harden.sh
  source "${LIB_DIR}/harden.sh"
fi
# The location where seg_dhcp_sync (lib/dhcp.sh) keeps the dnsmasq conf,
# leases, log and unit of each segment. They are here, not in the lib, so
# that this file names all that apply writes.
DHCP_ETC=/etc/pi-fortress
DHCP_STATE=/var/lib/pi-fortress
DHCP_LOGS=/var/log/pi-fortress
DHCP_UNITS=/etc/systemd/system
# The same for the OS files of lib/harden.sh.
HARDEN_SYSCTL_D=/etc/sysctl.d
HARDEN_APT_D=/etc/apt/apt.conf.d
HARDEN_SSHD_D=/etc/ssh/sshd_config.d
HARDEN_HOME=/home
HARDEN_SYSTEM_CONF_D=/etc/systemd/system.conf.d
HARDEN_WATCHDOG_SYS=/sys/class/watchdog

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
HARDEN_WORK="${WORKDIR}"

# Each segment that the closing line claims must have its address. If
# not, the line is false and the operator looks in the wrong place.
unmet_segments() {
  local _i
  addr_missing "${INT_IF}" "${PI_IP}" && echo "${PI_IP} is not on INT_IF=${INT_IF}"
  if [[ -n "${HOUSE_IF}" ]]; then
    addr_missing "${HOUSE_IF}" "${HOUSE_IP}" && echo "${HOUSE_IP} is not on HOUSE_IF=${HOUSE_IF}"
    systemctl is-active --quiet pi-fortress-dns-house.service ||
      echo "pi-fortress-dns-house is not active, so the house has no DHCP or DNS"
  fi
  for _i in "${!SEG_NAME[@]}"; do
    addr_missing "${SEG_IF[${_i}]}" "${SEG_IP[${_i}]}" &&
      echo "${SEG_IP[${_i}]} is not on ${SEG_NAME[${_i}]}=${SEG_IF[${_i}]}"
    if [[ "${SEG_DHCP[${_i}]:-off}" == on ]]; then
      systemctl is-active --quiet "pi-fortress-dhcp@${SEG_NAME[${_i}]}.service" ||
        echo "pi-fortress-dhcp@${SEG_NAME[${_i}]} is not active, so segment ${SEG_NAME[${_i}]} has no DHCP"
    fi
  done
  return 0
}

addr_missing() {
  ! ip -o -4 addr show dev "$1" 2>/dev/null | grep -qw "$2"
}

# Call this immediately before each closing line. It reports what is not
# true and leaves a non-zero status. The box keeps all that did apply.
# The callers exit 3 for it, not 1: "applied, but a segment is missing"
# is not a failed apply, and pi-fortress-fetch.service counts 3 as done.
# With 1, a house adapter that never enumerated made the refresh timer
# retry twenty times and then stop (2026-09-22). But each retry had
# applied the feeds. All other non-zero values are still a real failure.
settled() {
  local _unmet
  _unmet="$(unmet_segments)"
  [[ -z "${_unmet}" ]] && return 0
  echo "pi-fortress: applied, but the box is not in the state above:" >&2
  echo "${_unmet}" | sed 's/^/  /' >&2
  echo "  check the cable and 'ip -br addr'; 'pf apply' again once it is in" >&2
  return 1
}

if [[ "${RENDER}" -eq 1 ]]; then
  # No root and no Pi: the element lists come inline. pf is the build of
  # the tree (make pf), PF_BIN, or the pf that is on PATH.
  printf '%s' "${PF_ELEMENTS:-}" >"${WORKDIR}/elements.nft"
  printf '%s' "${PF_DOH_ELEMENTS:-}" >"${WORKDIR}/doh.nft"
  printf '%s' "${PF_DIRECT_ELEMENTS:-}" >"${WORKDIR}/direct.nft"
  printf '%s' "${PF_HOUSE_DIRECT_ELEMENTS:-}" >"${WORKDIR}/house-direct.nft"
  printf '%s' "${PF_HOUSE_PRIVATE_DNS_ELEMENTS:-}" >"${WORKDIR}/house-private-dns.nft"
  printf '%s' "${PF_HOUSE_WHATSAPP_ELEMENTS:-}" >"${WORKDIR}/house-whatsapp.nft"
  printf '%s' "${PF_SSH_ELEMENTS:-}" >"${WORKDIR}/ssh.nft"
  printf '%s' "${PF_NTP_PASS_ELEMENTS:-}" >"${WORKDIR}/ntp-pass.nft"
  PF="${PF_BIN:-}"
  if [[ -z "${PF}" ]]; then
    for _src in "$(dirname "$(readlink -f "$0")")/../../bin/pf" "${TREE:-/nonexistent}/bin/pf" "${TREE:-/nonexistent}/vm/pi/pf" "${PI_LIB}/pf" "$(command -v pf || true)"; do
      if [[ -n "${_src}" && -x "${_src}" ]]; then
        PF="${_src}"
        break
      fi
    done
  fi
  if [[ -z "${PF}" ]]; then
    echo "pi-fortress: pf not found for --render-nft (make pf, or set PF_BIN)" >&2
    exit 1
  fi
else
  PF_SRC=""
  for _src in "${TREE:-/nonexistent}/bin/pf" "${TREE:-/nonexistent}/vm/pi/pf" "${PI_LIB}/pf"; do
    if [[ -f "${_src}" && -x "${_src}" ]]; then
      PF_SRC="${_src}"
      break
    fi
  done
  if [[ -n "${PF_SRC}" ]]; then
    install -m 0755 "${PF_SRC}" /usr/local/sbin/pf
  fi
  if [[ ! -x /usr/local/sbin/pf ]]; then
    echo "pi-fortress: pf missing (make split-bin)" >&2
    exit 1
  fi
  PF=/usr/local/sbin/pf
  ln -sfn pf /usr/local/sbin/pi-fortress
  rm -f /usr/local/sbin/pf-{engine,broker,console,www,alert,enroll,compile,observe,fetch}
  rm -f /usr/local/sbin/pi-fortress-{apply,status,observe,alert,enroll,www,console}

  if [[ "${LOCAL_ONLY}" -eq 0 || "${REFRESH}" -eq 1 ]]; then
    if ! "${PF}" fetch --policy "${POLICY}" --out "${POLICY}/generated"; then
      echo "pi-fortress: feed fetch failed; compiling from the last generated lists" >&2
      if [[ ! -s "${POLICY}/generated/blacklist.domains" ]]; then
        echo "pi-fortress: ${POLICY}/generated/blacklist.domains missing or empty; nothing to fall back on" >&2
        exit 1
      fi
    fi
  fi

  "${PF}" compile \
    --policy "${POLICY}" \
    --out-nft "${WORKDIR}/elements.nft" \
    --out-dns "${WORKDIR}/blocked.domains" \
    --out-doh-nft "${WORKDIR}/doh.nft" \
    --out-doh-dns "${WORKDIR}/doh.domains" \
    --out-house-dns "${WORKDIR}/house.domains" \
    --out-house-vpn-dns "${WORKDIR}/house-vpn.domains" \
    --out-house-doh-dns "${WORKDIR}/house-doh.domains" \
    --out-house-private-dns-nft "${WORKDIR}/house-private-dns.nft" \
    --out-direct-nft "${WORKDIR}/direct.nft" \
    --out-house-direct-nft "${WORKDIR}/house-direct.nft" \
    --out-house-whatsapp-nft "${WORKDIR}/house-whatsapp.nft" \
    --out-ssh-nft "${WORKDIR}/ssh.nft" \
    --out-ntp-pass-nft "${WORKDIR}/ntp-pass.nft" \
    --out-domain-map "${WORKDIR}/blocked-domains.map" \
    --out-ip-map "${WORKDIR}/blocked-ips.map" |
    tee "${WORKDIR}/compile.out"
  # tee, not a redirect: the summary and each "compile: warning:" line
  # (a skipped line in a hand-kept list, e.g. a hostname in
  # ssh_allow.ips) stay in the apply output. The code below counts the
  # copy for the closing line and status.sh. pipefail keeps the compile exit.

  # pf-fortress: every daemon, for the files they share (logs, state).
  # pf-fence: engine and broker only; it gates the broker socket.
  getent group pf-fortress >/dev/null || groupadd --system pf-fortress
  getent group pf-fence >/dev/null || groupadd --system pf-fence
  if ! id -u pf-broker >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-fortress --home /nonexistent --shell /usr/sbin/nologin pf-broker
  fi
  if ! id -u pf-engine >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-fortress --home /nonexistent --shell /usr/sbin/nologin pf-engine
  fi
  if ! id -u pf-sidecar >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-fortress --home /nonexistent --shell /usr/sbin/nologin pf-sidecar
  fi
  # pf-dns: the agent resolver and the DoT stub. It is here, not next to
  # the agent unit below, because render checks for it and the
  # DoT stub starts long before that point.
  if ! id -u pf-dns >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-fortress --home /nonexistent --shell /usr/sbin/nologin pf-dns
  fi
  # pf-fakeip: the broker only. It is the group of the fake-IP journal
  # (below, where apply sets up the resolver files). pf dns writes the
  # journal and the broker reads it. Not pf-fortress, because all daemons
  # are in it. Not pf-fence, because the engine is in it. The journal has
  # each name that the agent resolved, and the broker is its only reader.
  getent group pf-fakeip >/dev/null || groupadd --system pf-fakeip
  usermod -aG pf-fakeip pf-broker
  usermod -aG pf-fence pf-broker
  usermod -aG pf-fence pf-engine
  # pf-observe: pf observe run. It reads the logs of the other daemons
  # through pf-fortress, and owns only its state and its two logs.
  if ! id -u pf-observe >/dev/null 2>&1; then
    useradd --system --no-create-home --gid pf-fortress --home /nonexistent --shell /usr/sbin/nologin pf-observe
  fi
  # pf-leases: observe only. It is the group of the DHCP lease files
  # (house.leases here, dhcp-<name>.leases in lib/dhcp.sh), for the client
  # names. Not pf-fortress: the leases have the MAC and the name of each
  # client, and the other daemons do not read them.
  getent group pf-leases >/dev/null || groupadd --system pf-leases
  usermod -aG pf-leases pf-observe
  # pf-sidecar (the group): the alert sidecar only, through
  # SupplementaryGroups in alert.service. It is the group of alert.url, the
  # webhook URL, whose path is its bearer token. No account is a member.
  # Thus monitor, which also runs as pf-sidecar, does not read it.
  getent group pf-sidecar >/dev/null || groupadd --system pf-sidecar
  chown root:pf-fence "${LOCK_DIR}"
  chmod 0750 "${LOCK_DIR}"
  install -d -m 0755 /etc/tmpfiles.d
  echo "d ${LOCK_DIR} 0750 root pf-fence -" >/etc/tmpfiles.d/pi-fortress.conf
fi

# Apply seeds the paranoid allowlist of a plain segment (docs/paranoid_mode.md)
# from the shipped file the first time that it sees the segment, and never
# again. After the file exists, it is the file of the operator, who edits
# it by hand. The seed has the Anthropic names, so with PARANOID=on on a
# desk, Claude Code works without a first edit. This runs before render,
# because render refuses a paranoid segment whose file is missing or empty.
seed_segment_allow() {
  local dir="$1" seed="$2" f name dst
  [[ -d "${dir}" && -f "${seed}" ]] || return 0
  for f in "${dir}"/*.env; do
    [[ -f "${f}" ]] || continue
    name="${f##*/}"
    name="${name%.env}"
    [[ "${name}" =~ ^[a-z][a-z0-9_-]{0,15}$ ]] || continue
    dst="$(dirname "${dir}")/allow.${name}.domains"
    if [[ ! -e "${dst}" && ! -L "${dst}" ]]; then
      install -m 0644 "${seed}" "${dst}"
    fi
  done
}
if [[ "${RENDER}" -eq 0 ]]; then
  seed_segment_allow "${PF_SEGMENTS_DIR:-/etc/pi-fortress/segments.d}" "${PI_LIB}/allow.segment.domains.example"
fi

# pf render reads house.env, segments.d and the DoT keys. It refuses all
# that would not isolate. It writes the ruleset and apply.env: the
# derived names (INT_IF, HOUSE_*, SEG_*, DNS_FORWARD, VLAN_PARENTS) that
# the rest of this script uses. Each refusal occurs while the old
# ruleset is still loaded.
export AGENT_NET PI_IP DNS_UPSTREAM NET_ENV_SRC PARANOID
# net.env can name the interfaces directly. An empty value keeps detection.
export INT_IF="${INT_IF:-}" WAN_IF="${WAN_IF:-}"
export AGENT_IP="${AGENT_IP:-}" DOT_AUTH_NAME="${DOT_AUTH_NAME:-}" DOT_IPS="${DOT_IPS:-}"
export UNTRUSTED_UPLINK="${UNTRUSTED_UPLINK:-}"
# How pf dns answers the agent (forward or fakeip), and the pool. render
# validates both, sets their defaults, and gives them back in apply.env.
# Thus the rest of this script reads the checked pair, not the net.env text.
export AGENT_DNS="${AGENT_DNS:-}" FAKEIP_NET="${FAKEIP_NET:-}"
# The connection budgets for each device and each segment (net.env, the
# render connlimit.go). Apply exports them empty when unset: render reads
# "" as its default. Thus a net.env older than these keys still renders the
# limits. Render refuses a bad value while the old ruleset is still loaded.
export AGENT_CONN_PER_IP="${AGENT_CONN_PER_IP:-}" AGENT_NEW_PER_IP="${AGENT_NEW_PER_IP:-}" AGENT_CONN_TOTAL="${AGENT_CONN_TOTAL:-}"
export HOUSE_CONN_PER_IP="${HOUSE_CONN_PER_IP:-}" HOUSE_NEW_PER_IP="${HOUSE_NEW_PER_IP:-}" HOUSE_CONN_TOTAL="${HOUSE_CONN_TOTAL:-}"
export HOUSE_NEW_TOTAL="${HOUSE_NEW_TOTAL:-}"
export SEG_CONN_PER_IP="${SEG_CONN_PER_IP:-}" SEG_NEW_PER_IP="${SEG_NEW_PER_IP:-}" SEG_CONN_TOTAL="${SEG_CONN_TOTAL:-}"
export SEG_NEW_TOTAL="${SEG_NEW_TOTAL:-}"
render_args=(
  --house-env "${PF_HOUSE_ENV:-/etc/pi-fortress/house.env}"
  --segments-dir "${PF_SEGMENTS_DIR:-/etc/pi-fortress/segments.d}"
  --elements "${WORKDIR}/elements.nft"
  --doh-elements "${WORKDIR}/doh.nft"
  --direct-elements "${WORKDIR}/direct.nft"
  --house-direct-elements "${WORKDIR}/house-direct.nft"
  --house-private-dns-elements "${WORKDIR}/house-private-dns.nft"
  --house-whatsapp-elements "${WORKDIR}/house-whatsapp.nft"
  --ssh-elements "${WORKDIR}/ssh.nft"
  --ntp-pass-elements "${WORKDIR}/ntp-pass.nft"
  --out-nft "${WORKDIR}/nftables.conf"
  --out-env "${WORKDIR}/apply.env"
)
if [[ "${PARANOID}" == "1" ]]; then
  render_args+=(--paranoid)
fi
if [[ "${RENDER}" -eq 1 ]]; then
  render_args+=(--int-if "${PF_INT_IF:-eth0}" --wan-if "${PF_WAN_IF:-wlan0}")
else
  # The DoT pre-flight check is `pf dns -check` below. It runs with the
  # exact argument vector of the stub, before apply installs anything.
  render_args+=(--live)
  if [[ -n "${PF_INT_IF:-}" ]]; then
    render_args+=(--int-if "${PF_INT_IF}")
  fi
  if [[ -n "${PF_WAN_IF:-}" ]]; then
    render_args+=(--wan-if "${PF_WAN_IF}")
  fi
fi
"${PF}" render "${render_args[@]}"
# shellcheck source=/dev/null
source "${WORKDIR}/apply.env"

if [[ "${RENDER}" -eq 1 ]]; then
  # On this path, apply.env goes away with WORKDIR. So a test that must
  # read the derived variables names a location that it can keep.
  [[ -n "${PF_ENV_OUT:-}" ]] && cp "${WORKDIR}/apply.env" "${PF_ENV_OUT}"
  cat "${WORKDIR}/nftables.conf"
  exit 0
fi

# A JSON string for a path that we already control: these are interface
# names, addresses and paths that render validated. Thus the only
# character that could need an escape is a backslash. None of them can
# contain one. Refuse, and do not emit a file that will not parse.
json_str() {
  case "$1" in
    *\\*|*\"*)
      echo "pi-fortress: ${2}='${1}' contains a quote or backslash; pf dns config cannot carry it" >&2
      exit 1
      ;;
  esac
  printf '"%s"' "$1"
}
json_list() {
  local out="" p
  for p in "$@"; do
    [[ -n "${p}" ]] || continue
    out+="${out:+, }$(json_str "${p}" sinkhole)"
  done
  printf '[%s]' "${out}"
}
# The pf dns config of one DoT stub: a single segment on lo. It forwards
# over DoT only, with no sinkhole, no query log and no nft set. The
# lookups of the box itself must not get the agent blocklist. They must
# not go in the log that pf observe reads as client traffic. Nothing that
# resolves here opens a gate. The unit runs the -config file that -check reads.
stub_config() {
  local s_ip s_name s_ips s_if=""
  if [[ "$1" == house ]]; then
    s_ip="${HOUSE_DOT_ADDR}" s_name="${HOUSE_DOT_AUTH_NAME}" s_ips="${HOUSE_DOT_IPS}"
    # A WireGuard house reaches its provider through the tunnel. The stub
    # dials are bound to the tunnel. Thus a stopped tunnel leaves the house
    # without DNS. The stub does not resolve over the uplink.
    s_if="${WG_IF:-}"
  else
    s_ip="${DOT_ADDR}" s_name="${DOT_AUTH_NAME}" s_ips="${DOT_IPS}"
  fi
  printf '{\n  "listen": 53,\n  "nft_table": "inet fortress",\n  "segments": [\n'
  printf '    {"name": %s, "iface": "lo", "ip": %s, "upstream": "", "dot_name": %s, "dot_ips": [%s], "dot_iface": %s, "sinkhole": [], "nft_set": "", "log": ""}\n' \
    "$(json_str "stub-$1" "stub name")" "$(json_str "${s_ip}" "stub address")" \
    "$(json_str "${s_name}" DOT_AUTH_NAME)" "$(json_str "${s_ips}" DOT_IPS)" \
    "$(json_str "${s_if}" WG_IF)"
  printf '  ]\n}\n'
}
STUB_WANT=()
if [[ -n "${DOT_IPS}" ]]; then
  # One instance for each provider. "main" answers the box and the agents.
  # "house" exists only when HOUSE_DOT_IPS names a different provider.
  STUB_WANT=(main)
  [[ -n "${HOUSE_DOT_IPS:-}" ]] && STUB_WANT+=(house)
fi

# Each address on which this box answers (agent-net, house-net, each
# segment, the VLAN trunk, ignore-carrier) is a NetworkManager profile
# (lib/netman.sh). Without nmcli, apply skips all of the block below.
# Before, apply then ran 600 more lines on a box with no addresses, and
# then settled() blamed the cable. It is not always an error: the appliance
# image and the VirtualBox lab have no NetworkManager and never needed
# it, because ifupdown and the sealed image add the addresses first.
# So the question is not whether nmcli is here. It is whether something
# addressed the interfaces. If nothing did, refuse now, while the ruleset
# has no change, and not at the end with the wrong cause.
if ! command -v nmcli >/dev/null 2>&1; then
  _noaddr=""
  addr_missing "${INT_IF}" "${PI_IP}" && _noaddr+=" ${PI_IP} on INT_IF=${INT_IF}"
  if [[ -n "${HOUSE_IF}" ]]; then
    addr_missing "${HOUSE_IF}" "${HOUSE_IP}" && _noaddr+=" ${HOUSE_IP} on HOUSE_IF=${HOUSE_IF}"
  fi
  for _i in "${!SEG_NAME[@]}"; do
    addr_missing "${SEG_IF[${_i}]}" "${SEG_IP[${_i}]}" &&
      _noaddr+=" ${SEG_IP[${_i}]} on ${SEG_NAME[${_i}]}=${SEG_IF[${_i}]}"
  done
  if [[ -n "${_noaddr}" ]]; then
    echo "pi-fortress: NetworkManager (nmcli) is not installed and these addresses are not on their interfaces:${_noaddr}. nmcli is what puts them there, so nothing later in this run would; the ruleset was not touched. Install it (apt-get install -y network-manager) or rerun vm/pi/provision.sh, then apply again." >&2
    exit 1
  fi
fi

# Apply checks the DoT stubs before the ruleset, not after it. With
# DOT_IPS set, the ruleset drops plaintext 53 off lo. After the ruleset
# loads, the box resolves through the stub or not at all. A stub that does
# not start, found after that point, made apply exit 1 on a box with no
# DNS. A pf dns flag change did this on 2026-09-18 (the stub still
# passed flags that -config had replaced).
for inst in "${STUB_WANT[@]+"${STUB_WANT[@]}"}"; do
  stub_config "${inst}" >"${WORKDIR}/dns-stub-${inst}.json"
  if ! _out="$("${PF}" dns -config "${WORKDIR}/dns-stub-${inst}.json" -check 2>&1)"; then
    echo "${_out}" >&2
    echo "pi-fortress: pf dns refuses the ${inst} DoT stub configuration; the ruleset was not touched" >&2
    exit 1
  fi
done

# A load replaces the full table, so resolved_v4 and its sibling set for
# each segment come back empty. The agent VM asks the Pi for each lookup
# and sees no difference. A client with its own cache (systemd-resolved
# on the desk, a phone) answers from that cache and does not ask again.
# Thus the gate drops its connections until the cached TTL expires.
# Seen from the desk 2026-09-22. pf nftsets carries the elements across the
# load with the remaining time of each timeout, and never more. WORKDIR is
# root-only (mktemp -d above), and its trap removes the file.
#
# Both halves are advisory. If a capture or a re-add fails, apply logs one
# line and continues with an empty set. The box did that before this code
# existed. A warm cache is never a reason to leave the fence
# half-loaded.
RESOLVED_CARRY="${WORKDIR}/resolved-sets.carry"
# -t: the probe needs only to know that the table exists. Without it, nft
# also prints each element of each set, blacklist_v4 included.
if nft -t list table inet fortress >/dev/null 2>&1; then
  "${PF}" nftsets save --table "inet fortress" --file "${RESOLVED_CARRY}" ||
    echo "pi-fortress: could not read the resolved-address sets; they come back empty and a client that answers from its own DNS cache waits out that cache before the gate lets it through again" >&2
fi

nft -c -f "${WORKDIR}/nftables.conf"
install -m 0644 "${WORKDIR}/nftables.conf" /etc/nftables.conf
nft -f /etc/nftables.conf

"${PF}" nftsets restore --table "inet fortress" --file "${RESOLVED_CARRY}" ||
  echo "pi-fortress: could not put the resolved addresses back; the sets are empty and a client that answers from its own DNS cache waits out that cache before the gate lets it through again" >&2
rm -f "${RESOLVED_CARRY}"

# An established flow goes through the conntrack accept and does not meet
# the egress policy again. Thus a flow that the house or a plain segment
# opened under the old policy keeps the old permission until it closes.
# render gives a fingerprint of the egress policy of each segment
# (HOUSE_EGRESS_FP, SEG_EGRESS_FP; render/egressfp.go). Apply keeps the
# last values in EGRESS_STATE. When a value changes, or a segment is gone
# from the policy, apply ends the open flows of that segment after the
# new ruleset is loaded. Then each new flow meets the new policy. The
# agent needs nothing: its raw chain checks each packet.
#
# A flow to or from an address of this box stays. Thus the SSH session of
# the operator to the Pi, DNS and DHCP continue. A flow between the agent,
# the house and the segments also stays: the isolation decides it, not
# the egress policy (egress_cut). With no state file (a
# lost file, or the first apply) each segment counts as changed. A
# missing conntrack gives a warning, never a failed apply: the new policy
# is loaded already.
EGRESS_STATE=/var/lib/pi-fortress/egress.state

# One line for each segment with an egress policy: key, fingerprint, subnet.
egress_state() {
  local i
  if [[ -n "${HOUSE_EGRESS_FP:-}" ]]; then
    printf 'house %s %s\n' "${HOUSE_EGRESS_FP}" "${HOUSE_NET}"
  fi
  for i in "${!SEG_NAME[@]}"; do
    printf 'seg:%s %s %s\n' "${SEG_NAME[${i}]}" "${SEG_EGRESS_FP[${i}]}" "${SEG_NET[${i}]}"
  done
}

# egress_cut NAME NET SELF INNER ends each tracked flow whose original
# source or destination is in NET, except a flow to or from an address in
# SELF, and a flow between two subnets in INNER (both space separated).
# It deletes by the address pair of the original direction. All flows of
# such a pair are flows of the segment.
#
# INNER is the agent subnet and the subnets of the new policy. A flow
# between two of them does not go through an egress chain: the
# isolation of forward decides it, and isolate_ct examines each of its
# established packets with the holes of the new ruleset. Thus an admin
# SSH session through a hole (HOUSE_SSH_TO, SSH_TO, SSH_FROM) continues
# while its hole stays, and stops at its next packet when the hole is
# gone. A subnet that is gone from the policy is not in INNER, so its
# flows to the agent end here.
egress_cut() {
  local name="$1" net="$2" self="$3" inner="$4" pairs s d rc n=0 bad=0
  pairs="$({
    conntrack -L -s "${net}" 2>/dev/null || [[ $? -eq 1 ]] || bad=1
    conntrack -L -d "${net}" 2>/dev/null || [[ $? -eq 1 ]] || bad=1
    [[ "${bad}" -eq 0 ]] || echo "list-failed"
  } | awk -v self=" ${self} " -v inner="${inner}" '
    function num(a,   p) {
      if (split(a, p, ".") != 4) return -1
      return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4]
    }
    function in_inner(a,   i, c, b, x) {
      x = num(a)
      if (x < 0) return 0
      for (i = 1; i <= ni; i++) {
        if (split(nets[i], c, "/") != 2) c[2] = 32
        b = 2 ^ (32 - c[2])
        if (int(x / b) == int(num(c[1]) / b)) return 1
      }
      return 0
    }
    BEGIN { ni = split(inner, nets, " ") }
    $1 == "list-failed" { print; next }
    {
      s = d = ""
      for (i = 1; i <= NF; i++) {
        if (s == "" && $i ~ /^src=/) s = substr($i, 5)
        else if (d == "" && $i ~ /^dst=/) d = substr($i, 5)
      }
      if (s == "" || d == "" || index(self, " " s " ") || index(self, " " d " ")) next
      if (in_inner(s) && in_inner(d)) next
      print s, d
    }' | sort -u)"
  while read -r s d; do
    [[ -n "${s}" ]] || continue
    if [[ "${s}" == list-failed ]]; then
      bad=1
      continue
    fi
    rc=0
    conntrack -D -s "${s}" -d "${d}" >/dev/null 2>&1 || rc=$?
    # Exit 1 is no entry: the flow closed after the list.
    if [[ "${rc}" -eq 0 ]]; then
      n=$((n + 1))
    elif [[ "${rc}" -ne 1 ]]; then
      bad=1
    fi
  done <<<"${pairs}"
  echo "pi-fortress: the egress policy of ${name} changed; ended the open flows of ${n} address pair(s) in ${net}"
  if [[ "${bad}" -ne 0 ]]; then
    echo "pi-fortress: WARN conntrack failed for ${name}; some open flows of ${net} keep the old egress policy until they close (sudo conntrack -L -s ${net})" >&2
  fi
}

# egress_cuts STATE NEW compares NEW (the egress_state lines of this apply)
# with STATE, ends the flows of each changed segment and of each segment
# that is gone from NEW, then keeps NEW in STATE.
egress_cuts() {
  local state="$1" new="$2" key fp net old self inner c
  local -a cut=()
  if [[ -s "${state}" ]]; then
    while read -r key fp net; do
      old="$(awk -v k="${key}" '$1 == k { print $2; exit }' "${state}")"
      if [[ -n "${old}" && "${old}" != "${fp}" ]]; then
        cut+=("${key#seg:} ${net}")
      fi
    done <"${new}"
    # A removed segment (or house) keeps its subnet in STATE only.
    while read -r key fp net; do
      [[ -n "${net}" ]] || continue
      if ! awk -v k="${key}" '$1 == k { f = 1 } END { exit !f }' "${new}"; then
        cut+=("${key#seg:} ${net}")
      fi
    done <"${state}"
  else
    # No record: the last policy is not known, so each segment counts as
    # changed. Apply cannot tell a lost file from a new box. On a new box
    # this ends nothing: forwarding stays off until the ruleset is loaded
    # (below), so no segment has a forwarded flow yet.
    while read -r key fp net; do
      cut+=("${key#seg:} ${net}")
    done <"${new}"
  fi
  if [[ "${#cut[@]}" -gt 0 ]]; then
    if command -v conntrack >/dev/null 2>&1; then
      self="$(ip -4 -o addr show 2>/dev/null | awk '{ sub(/\/.*/, "", $4); printf "%s ", $4 }')"
      self+=" ${PI_IP:-} ${HOUSE_IP:-} ${SEG_IP[*]:-}"
      inner="${AGENT_NET:-} $(awk '{ printf "%s ", $3 }' "${new}")"
      for c in "${cut[@]}"; do
        # shellcheck disable=SC2086 # c is "name net", two words by design
        egress_cut ${c} "${self}" "${inner}"
      done
    else
      for c in "${cut[@]}"; do
        echo "pi-fortress: WARN conntrack is not installed; the open flows of ${c%% *} keep the old egress policy until they close (apt-get install -y conntrack)" >&2
      done
    fi
  fi
  install -d -m 0755 "$(dirname "${state}")"
  install -m 0600 "${new}" "${state}"
}

egress_state >"${WORKDIR}/egress.state"
egress_cuts "${EGRESS_STATE}" "${WORKDIR}/egress.state" ||
  echo "pi-fortress: WARN could not record the egress policy in ${EGRESS_STATE}; the next apply compares with an older record" >&2

# Forwarding depends on the ruleset. It is not a peer of the ruleset. So
# apply enables it here and nowhere else: only after this line is there a
# fence to forward through. /etc/sysctl.d ships ip_forward=0 (lib/harden.sh).
# Thus each path that does not get to this line (a render refusal, a failed
# nft load, a box that did not complete provisioning) leaves a Pi that
# routes nothing. It does not leave a Pi that routes everything.
sysctl -w net.ipv4.ip_forward=1 >/dev/null ||
  echo "pi-fortress: could not enable net.ipv4.ip_forward; the ruleset is loaded but nothing is routed" >&2

# The same coupling across a reboot, where no apply runs: nftables.service
# replays /etc/nftables.conf. Forwarding follows only if OUR table loaded
# with it. A box that still has the stock Debian accept-policy conf loads
# it, finds no inet fortress, and stays closed. ExecStopPost is the other
# half: `systemctl stop nftables` flushes the ruleset. If ip_forward stays
# at 1 after that, it is the same open router by a different route.
install -d -m 0755 /etc/systemd/system/nftables.service.d
cat >"${WORKDIR}/10-pi-fortress-forward.conf" <<'EOF'
[Service]
ExecStartPost=-/bin/sh -c 'nft list table inet fortress >/dev/null 2>&1 && sysctl -w net.ipv4.ip_forward=1 >/dev/null'
ExecStopPost=-/bin/sh -c 'sysctl -w net.ipv4.ip_forward=0 >/dev/null'
EOF
_forward_changed=0
cmp -s "${WORKDIR}/10-pi-fortress-forward.conf" /etc/systemd/system/nftables.service.d/10-pi-fortress-forward.conf ||
  _forward_changed=1
install -m 0644 "${WORKDIR}/10-pi-fortress-forward.conf" /etc/systemd/system/nftables.service.d/10-pi-fortress-forward.conf
if [[ "${_forward_changed}" -eq 1 ]]; then
  systemctl daemon-reload
fi
# enable, not only install: before, only provision.sh did this. Thus a
# box updated through ship/upgrade had the ruleset live only, while
# ip_forward=1 persisted: an open router at the next boot. Guarded like
# the other enables in this file, and never --now: a restart of
# nftables here flushes the ruleset that apply loaded above.
systemctl enable nftables.service >/dev/null 2>&1 ||
  echo "pi-fortress: systemctl enable nftables failed; the ruleset is live now but will not be reloaded at boot (forwarding stays off, so the box fails closed)" >&2

install -d -m 0755 /etc/pi-fortress
if [[ "${NET_ENV_SRC}" != /etc/pi-fortress/net.env ]]; then
  install -m 0644 "${NET_ENV_SRC}" /etc/pi-fortress/net.env
fi
BLOCKED_CHANGED=0
cmp -s "${WORKDIR}/blocked.domains" /etc/pi-fortress/blocked-domains.conf || BLOCKED_CHANGED=1
install -m 0644 "${WORKDIR}/blocked.domains" /etc/pi-fortress/blocked-domains.conf
install -m 0644 "${WORKDIR}/doh.domains" /etc/pi-fortress/doh-domains.conf
install -m 0644 "${WORKDIR}/house.domains" /etc/pi-fortress/house-domains.conf
install -m 0644 "${WORKDIR}/house-vpn.domains" /etc/pi-fortress/house-vpn-domains.conf
# The ranges to which an ECH flow can go under the house SNI check. They
# ship and are not operator state, because they are the published list of the provider.
install -m 0644 "${POLICY}/house_ech.ips" /etc/pi-fortress/house-ech.ips
# The Meta ranges, where a non-TLS flow (the WhatsApp chat protocol) can
# go when HOUSE_ALLOW_WHATSAPP is on. They ship for the same reason.
install -m 0644 "${POLICY}/house_whatsapp.ips" /etc/pi-fortress/house-whatsapp.ips
install -m 0644 "${WORKDIR}/house-doh.domains" /etc/pi-fortress/house-doh-domains.conf
# install_atomic MODE SRC DST copies SRC to DST with one rename. The copy
# goes to DST.new in the same directory, and is on the disk before the
# rename. Thus a process that reads DST at any time gets the old file or
# the full new file. It never gets no file or a part of a file. A copy
# that fails leaves DST as it was.
install_atomic() {
  local tmp="${3}.new"
  if ! install -m "${1}" "${2}" "${tmp}" || ! sync "${tmp}"; then
    rm -f "${tmp}"
    return 1
  fi
  mv -f "${tmp}" "${3}"
}
# The table of eyeball networks that pf fetch built, and the exemptions
# of the operator. The broker loads both again when they change, so
# neither is a fence input and neither restarts the fence. The broker can
# read them during the copy, so the copy is atomic. No table leaves the
# installed copy. Its age stops its use in the broker. No eyeball.allow in
# the policy directory means no exemptions.
if [[ -s "${POLICY}/generated/eyeball.table" ]]; then
  cmp -s "${POLICY}/generated/eyeball.table" /etc/pi-fortress/eyeball.table ||
    install_atomic 0644 "${POLICY}/generated/eyeball.table" /etc/pi-fortress/eyeball.table
fi
if [[ -f "${POLICY}/eyeball.allow" ]]; then
  if [[ ! "${POLICY}/eyeball.allow" -ef /etc/pi-fortress/eyeball.allow ]]; then
    install_atomic 0644 "${POLICY}/eyeball.allow" /etc/pi-fortress/eyeball.allow
  fi
else
  rm -f /etc/pi-fortress/eyeball.allow
fi
# name/prefix → feed, read by pf observe to label blocked events.
install -m 0644 "${WORKDIR}/blocked-domains.map" /etc/pi-fortress/blocked-domains.map
install -m 0644 "${WORKDIR}/blocked-ips.map" /etc/pi-fortress/blocked-ips.map
# Without /vagrant, POLICY is /etc/pi-fortress. An install or cp of a
# file onto itself fails, and set -e then stops apply.
if [[ -f "${POLICY}/doh.ips" && ! "${POLICY}/doh.ips" -ef /etc/pi-fortress/doh.ips ]]; then
  install -m 0644 "${POLICY}/doh.ips" /etc/pi-fortress/doh.ips
fi
if [[ -f "${POLICY}/doh.domains" && ! "${POLICY}/doh.domains" -ef /etc/pi-fortress/doh.domains ]]; then
  install -m 0644 "${POLICY}/doh.domains" /etc/pi-fortress/doh.domains
fi

install -d -m 0755 /var/log/pi-fortress /var/lib/pi-fortress
# Make the www directory before the first daemon starts. Each daemon unit
# except www lists it in InaccessiblePaths with "-". systemd skips such a
# path when it is missing at the start. Then a daemon that starts in the
# first apply could read the claim codes until its next restart. apply
# --local skips it: it runs in fetch.service, which cannot see the
# directory, and only after a full apply made it.
[[ "${LOCAL_ONLY}" -eq 1 ]] || install -d -m 0755 /var/lib/pi-fortress/www
# The number of hand-kept list lines that pf compile skipped in this run.
# status.sh shows it. The closing line repeats it so that it is not lost above.
COMPILE_WARNINGS="$(grep -c '^compile: warning:' "${WORKDIR}/compile.out" 2>/dev/null || true)"
COMPILE_WARNINGS="${COMPILE_WARNINGS:-0}"
printf '%s\n' "${COMPILE_WARNINGS}" >/var/lib/pi-fortress/compile-warnings 2>/dev/null || true
# The logs under it grow until something rotates them. Nothing else does.
# The conf goes to /etc/pi-fortress, not /etc/logrotate.d: the daily
# logrotate.timer of the system reads only the latter, and the DNS query
# logs need hourly rotation. pi-fortress-logrotate.timer runs this file instead.
if [[ -f "${PI_LIB}/logrotate.conf" ]]; then
  install -m 0644 "${PI_LIB}/logrotate.conf" /etc/pi-fortress/logrotate.conf
  # An install from before the timer put the conf where the daily run
  # reads it. Two runs on the same paths with two state files rotate
  # two times as often as each run intends.
  rm -f /etc/logrotate.d/pi-fortress
fi
if [[ -f "${PI_LIB}/logrotate.service" && -f "${PI_LIB}/logrotate.timer" ]]; then
  install -m 0644 "${PI_LIB}/logrotate.service" /etc/systemd/system/pi-fortress-logrotate.service
  install -m 0644 "${PI_LIB}/logrotate.timer" /etc/systemd/system/pi-fortress-logrotate.timer
  systemctl daemon-reload
  systemctl enable --now pi-fortress-logrotate.timer >/dev/null 2>&1 \
    || echo "pi-fortress: pi-fortress-logrotate.timer did not start; the DNS query logs rotate only on the next pf apply (journalctl -u pi-fortress-logrotate.timer)" >&2
fi
# At power-on, the house adapter acts as its own driver CD. The rule starts
# the switch at each plug-in. The unit runs it at boot, where one eject
# failure was seen (usb-nic-switch.sh). Apply installs it here, not only
# provision.sh, so a ship delivers it to a box provisioned before it.
if [[ -f "${PI_LIB}/usb-nic-switch.sh" && -f "${PI_LIB}/usb-nic-switch.service" && -f "${PI_LIB}/70-pi-fortress-rtl8153.rules" ]]; then
  install -d -m 0755 /usr/local/lib/pi-fortress /etc/systemd/system /etc/udev/rules.d
  # The installed layout (appliance, /etc/pi-fortress net.env) has
  # PI_LIB at the target already.
  [[ "${PI_LIB}/usb-nic-switch.sh" -ef /usr/local/lib/pi-fortress/usb-nic-switch.sh ]] ||
    install -m 0755 "${PI_LIB}/usb-nic-switch.sh" /usr/local/lib/pi-fortress/usb-nic-switch.sh
  install -m 0644 "${PI_LIB}/usb-nic-switch.service" /etc/systemd/system/pi-fortress-usb-nic-switch.service
  install -m 0644 "${PI_LIB}/70-pi-fortress-rtl8153.rules" /etc/udev/rules.d/70-pi-fortress-rtl8153.rules
  systemctl daemon-reload
  systemctl enable pi-fortress-usb-nic-switch.service >/dev/null 2>&1 \
    || echo "pi-fortress: pi-fortress-usb-nic-switch.service is not enabled; a house adapter plugged in at power-on may stay in driver-CD mode" >&2
  udevadm control --reload-rules >/dev/null 2>&1 || true
fi
# The dead-man timer for an unconfirmed pf ship install (docs/signed_ship.md,
# "Confirm or revert"). Apply installs it here and
# not only provision.sh. Thus a ship delivers the timer itself to a box
# provisioned before this existed. That box most needs a dead-man on its
# next upgrade.
if [[ -f "${PI_LIB}/ship-deadman.service" && -f "${PI_LIB}/ship-deadman.timer" ]]; then
  install -m 0644 "${PI_LIB}/ship-deadman.service" /etc/systemd/system/pi-fortress-ship-deadman.service
  install -m 0644 "${PI_LIB}/ship-deadman.timer" /etc/systemd/system/pi-fortress-ship-deadman.timer
  systemctl daemon-reload
  systemctl enable --now pi-fortress-ship-deadman.timer >/dev/null 2>&1 \
    || echo "pi-fortress: pi-fortress-ship-deadman.timer did not start; an unconfirmed upgrade will not revert itself (journalctl -u pi-fortress-ship-deadman.timer)" >&2
fi
# A Go daemon reads the system CA roots one time, at start. The apt hook
# runs ca-restart.sh after each dpkg run, and the script restarts the
# daemons that verify TLS when the system CA bundle changed. Apply installs
# it here, not only provision.sh, so a ship delivers it to a box
# provisioned before it. --seed records the hash of the bundle now, so the
# first change after this install is seen.
if [[ -f "${PI_LIB}/ca-restart.sh" && -f "${PI_LIB}/60pi-fortress-ca" && -d /etc/apt/apt.conf.d ]]; then
  install -d -m 0755 /usr/local/lib/pi-fortress
  [[ "${PI_LIB}/ca-restart.sh" -ef /usr/local/lib/pi-fortress/ca-restart.sh ]] ||
    install -m 0755 "${PI_LIB}/ca-restart.sh" /usr/local/lib/pi-fortress/ca-restart.sh
  install -m 0644 "${PI_LIB}/60pi-fortress-ca" /etc/apt/apt.conf.d/60pi-fortress-ca
  /usr/local/lib/pi-fortress/ca-restart.sh --seed || true
fi
# The budget goes in PF_BROKER_FLAGS, not in ${VAR} in the unit ExecStart.
# A net.env from before these keys existed expands to a bare
# "-slot-warn-requests=". The flag parser refuses it, and systemd then
# has a fence that does not start. Here the shell defaults above have
# already set the values.
BROKER_BUDGET="-slot-warn-requests=${SLOT_WARN_REQUESTS} -slot-stop-requests=${SLOT_STOP_REQUESTS}"
BROKER_BUDGET="${BROKER_BUDGET} -slot-warn-upload-mb=${SLOT_WARN_UPLOAD_MB} -slot-stop-upload-mb=${SLOT_STOP_UPLOAD_MB}"
BROKER_BUDGET="${BROKER_BUDGET} -eyeball=${EYEBALL}"
# A segment with INSPECT=on gets the fence of the agent network. The
# ruleset sends its 443 to the engine port on the segment address. The
# engine listens there, and the broker serves its subnet. Both files are
# fence inputs below, so a switch of INSPECT restarts the fence.
# The engine and the broker share one connection cap of 256, sized for the
# agents. A desk browser can hold a hundred or more, so with a desk the cap
# goes to 512, the same in both daemons.
ENGINE_INSPECT=""
INSPECT_DESC=""
for _i in "${!SEG_NAME[@]}"; do
  [[ "${SEG_INSPECT[${_i}]:-off}" == on ]] || continue
  ENGINE_INSPECT="${ENGINE_INSPECT} -inspect-listen ${SEG_IP[${_i}]}:8080"
  INSPECT_DESC="${INSPECT_DESC}, ${SEG_NAME[${_i}]} on ${SEG_IP[${_i}]}:8080"
  BROKER_BUDGET="${BROKER_BUDGET} -fence-net ${SEG_NET[${_i}]}"
done
if [[ -n "${ENGINE_INSPECT}" ]]; then
  ENGINE_INSPECT="${ENGINE_INSPECT} -max-conns 512"
  BROKER_BUDGET="${BROKER_BUDGET} -max-conns 512"
fi
if [[ -f /etc/pi-fortress/lab ]]; then
  echo "PF_BROKER_FLAGS=\"-lab-echo ${BROKER_BUDGET}\"" >/etc/pi-fortress/broker.env
else
  echo "PF_BROKER_FLAGS=\"${BROKER_BUDGET}\"" >/etc/pi-fortress/broker.env
fi
chmod 0644 /etc/pi-fortress/broker.env
if [[ -f /etc/pi-fortress/lab ]]; then
  echo "PF_ENGINE_FLAGS=\"-lab-echo${ENGINE_INSPECT}\"" >/etc/pi-fortress/engine.env
else
  echo "PF_ENGINE_FLAGS=\"${ENGINE_INSPECT# }\"" >/etc/pi-fortress/engine.env
fi
chmod 0644 /etc/pi-fortress/engine.env

# The daemons get the mode from a file that the units read, not from
# their own read of net.env: only apply decides it. Apply always writes
# both names, so a disarm is an apply, the same as an arm.
if [[ "${PARANOID}" == "1" ]]; then
  cat >"${WORKDIR}/paranoid.flags" <<'EOF'
PF_PARANOID_BROKER_FLAGS=-paranoid
PF_PARANOID_ENGINE_FLAGS="-paranoid -allow /etc/pi-fortress/allow.domains -core-hosts /etc/pi-fortress/core.hosts"
EOF
else
  printf 'PF_PARANOID_BROKER_FLAGS=\nPF_PARANOID_ENGINE_FLAGS=\n' >"${WORKDIR}/paranoid.flags"
fi
install -m 0644 "${WORKDIR}/paranoid.flags" /etc/pi-fortress/paranoid.flags
# Fake-IP (AGENT_DNS=fakeip), the broker half: map a pool address back
# to its name through the journal that pf dns writes, and resolve that
# name itself. It has the same one-file-for-each-mode shape as
# paranoid.flags. Apply always writes it, so a switch back to forward is
# an apply, the same as a switch to fakeip. It is also a FENCE_INPUTS
# entry, so each switch restarts the broker.
#
# -resolver is DNS_FORWARD, the upstream of pf dns for the agent, in the
# host:port form. With DoT off, that is DNS_UPSTREAM: the one resolver that
# the output chain opens to the pf-broker uid. resolv.conf has the value
# from the uplink DHCP, usually a LAN router that the broker reserved drop
# refuses. With DoT on, DNS_FORWARD is the local stub, 127.0.0.1. lo passes
# it, and it is the one path on which the DNS of the box is encrypted.
FAKEIP_JOURNAL_DIR=/var/lib/pi-fortress/dns
FAKEIP_JOURNAL="${FAKEIP_JOURNAL_DIR}/fakeip.journal"
BROKER_RESOLVER="${DNS_FORWARD/\#/:}"
[[ "${BROKER_RESOLVER}" == *:* ]] || BROKER_RESOLVER="${BROKER_RESOLVER}:53"
if [[ "${AGENT_DNS}" == fakeip ]]; then
  printf 'PF_FAKEIP_BROKER_FLAGS="-fakeip-net %s -fakeip-journal %s -resolver %s"\n' \
    "${FAKEIP_NET}" "${FAKEIP_JOURNAL}" "${BROKER_RESOLVER}" >"${WORKDIR}/fakeip.flags"
else
  printf 'PF_FAKEIP_BROKER_FLAGS=\n' >"${WORKDIR}/fakeip.flags"
fi
install -m 0644 "${WORKDIR}/fakeip.flags" /etc/pi-fortress/fakeip.flags
# git_push.allow (docs/git_push.md). pf compile above already refused a
# malformed one. The broker reads it one time at start, so a change
# restarts the fence, the same as a changed PARANOID. No file in the policy
# dir means no pushes. So apply also removes the installed copy, which
# otherwise continues to allow pushes.
if [[ -f "${POLICY}/git_push.allow" ]]; then
  if [[ ! "${POLICY}/git_push.allow" -ef /etc/pi-fortress/git_push.allow ]]; then
    install -m 0644 "${POLICY}/git_push.allow" /etc/pi-fortress/git_push.allow
  fi
elif [[ -e /etc/pi-fortress/git_push.allow ]]; then
  rm -f /etc/pi-fortress/git_push.allow
fi

# The remaining inputs of the fence. Before, apply copied these three 100
# lines below, after the point where --local returns. So an operator who
# revoked a permission and reloaded saw "local policy reloaded" while
# the fence still had the permission. Apply now installs them here, with
# all other files that the daemons read, so no branch can report
# success without them.
# Without /vagrant, POLICY is /etc/pi-fortress, and a copy of a file onto
# itself fails. set -e then stops apply.
for _f in allow.domains dns_types.allow; do
  if [[ -f "${POLICY}/${_f}" && ! "${POLICY}/${_f}" -ef "/etc/pi-fortress/${_f}" ]]; then
    install -m 0644 "${POLICY}/${_f}" "/etc/pi-fortress/${_f}"
  fi
done
# core.hosts and key_prefixes.rules ship, and each upgrade replaces them.
# core.hosts.local and key_prefixes.rules.local are the files of the
# operator, and apply keeps them. The daemons read one file, so the
# installed file is the shipped one with the local one below a marker.
# Apply reads the shipped part up to that marker. Thus on a box whose
# policy dir IS /etc/pi-fortress, the rewrite replaces the old local part
# in place. It does not add a copy on each apply. A local file with only
# comments adds nothing, and apply omits it. Thus the installed copy
# stays the same as the shipped one, byte for byte. pf compile above
# already refused a bad line in each local file.
install_with_local() {
  local name=$1 mark="# ---- $1.local (pf apply appends it here; edit that file, not this) ----"
  [[ -f "${POLICY}/${name}" ]] || return 0
  awk -v m="${mark}" '$0 == m { exit } { print }' "${POLICY}/${name}" >"${WORKDIR}/${name}"
  if [[ -f "${POLICY}/${name}.local" ]] && grep -qv '^[[:space:]]*\(#.*\)\{0,1\}$' "${POLICY}/${name}.local"; then
    { printf '%s\n' "${mark}"; awk '{ print }' "${POLICY}/${name}.local"; } >>"${WORKDIR}/${name}"
  fi
  if ! cmp -s "${WORKDIR}/${name}" "/etc/pi-fortress/${name}"; then
    install -m 0644 "${WORKDIR}/${name}" "/etc/pi-fortress/${name}"
  fi
}
install_with_local core.hosts
install_with_local key_prefixes.rules
# pf dns refuses a dns_types.allow that it is told about and cannot read.
# So a box whose policy dir is older than the seed gets an empty one: no
# overrides, which is also what the seed says. This is better than a
# resolver that does not start.
if [[ ! -e /etc/pi-fortress/dns_types.allow ]]; then
  install -m 0644 /dev/null /etc/pi-fortress/dns_types.allow
fi
if [[ ! -s /etc/pi-fortress/key_prefixes.rules ]]; then
  echo "pi-fortress: key_prefixes.rules missing or empty; the broker refuses to start without it" >&2
  exit 1
fi

# Whether the fence must restart. The broker and the engine read each
# file below one time at start. Thus a change to one of them is live in
# nft and dnsmasq when apply installs it, but the daemons do not have it
# until they restart. The old code asked that question with three
# separate "did this one change" flags, one for each file that somebody
# remembered. Thus apply never saw a change to any other input. Worse,
# on a box whose policy dir IS /etc/pi-fortress, the same-file guard
# above skips the comparison. That set the git_push.allow flag to 0
# forever, and an in-place edit to the push allowlist never got to the
# broker. Now apply asks the question one time, of the installed files,
# against a snapshot of what the daemons last read. Thus it cannot miss
# an input, and it does not care how the change
# arrived.
FENCE_STATE=/etc/pi-fortress/fence.state
FENCE_INPUTS=(
  /etc/pi-fortress/paranoid.flags
  # The fake-IP mode, pool and resolver, in the form that the broker gets.
  # net.env below already has AGENT_DNS and FAKEIP_NET. But this is the
  # rendered pair with defaults, plus DNS_FORWARD. Thus a changed default
  # or a DoT switch that changes the resolver also restarts the broker.
  # pf dns needs no entry: apply restarts it on each run.
  /etc/pi-fortress/fakeip.flags
  /etc/pi-fortress/git_push.allow
  /etc/pi-fortress/core.hosts
  /etc/pi-fortress/allow.domains
  /etc/pi-fortress/key_prefixes.rules
  # The three EnvironmentFiles that the two units read. They are inputs,
  # the same as the policy files: the lab marker decides -lab-echo, and
  # net.env with its overlay decides the listen address of the engine and
  # the agent subnet of the broker. A daemon reads them one time at start.
  # Thus a change that does not restart the fence leaves the fence on the
  # old values, while the ruleset that apply loaded is on the new values.
  /etc/pi-fortress/broker.env
  /etc/pi-fortress/engine.env
  /etc/pi-fortress/net.env
  "${NET_ENV_LOCAL}"
)
install -d -m 0755 "${FENCE_STATE}"
# blocked-domains.conf is also a fence input, and by far the largest on a
# box with real feeds. Apply compiles this one and does not copy it.
# Thus BLOCKED_CHANGED above already compared the new compile with the
# installed copy. It joins the answer here, without a second copy of a
# megabyte of names under /etc.
# FENCE_INPUT_CHANGED keeps the answer for the other inputs apart. A feed
# refresh changes only the list, and the refresh path below uses this
# difference.
FENCE_CHANGED="${BLOCKED_CHANGED}"
FENCE_INPUT_CHANGED=0
for _i in "${FENCE_INPUTS[@]}"; do
  if [[ -f "${_i}" ]]; then
    cmp -s "${_i}" "${FENCE_STATE}/${_i##*/}" || FENCE_INPUT_CHANGED=1
  elif [[ -e "${FENCE_STATE}/${_i##*/}" ]]; then
    # A file that the policy removed is a change, the same as an edited
    # file: the daemons still enforce its old content.
    FENCE_INPUT_CHANGED=1
  fi
done
if [[ "${FENCE_INPUT_CHANGED}" -eq 1 ]]; then
  FENCE_CHANGED=1
fi
# Record this only after the daemons run again on these inputs. A
# restart that failed, or a restart that an unattended refresh skipped on
# purpose, must leave the change visible to the next apply. A snapshot
# taken when apply read the inputs would mark the fence as up to date
# while the daemons still had the old policy.
fence_state_record() {
  local _s
  for _s in "${FENCE_INPUTS[@]}"; do
    if [[ -f "${_s}" ]]; then
      install -m 0644 "${_s}" "${FENCE_STATE}/${_s##*/}"
    else
      rm -f "${FENCE_STATE}/${_s##*/}"
    fi
  done
}

# The logs are group-readable only. pf observe (pf-observe) reads them
# through the group pf-fortress.
# The query log was dnsmasq.log while dnsmasq wrote it. Now pf dns writes
# it and it has rows, so its name tells what it holds. The rename must
# also move the offset sidecar: pf observe holds a byte count into the
# file. With a new name and no offset next to it, observe reads all of the
# history again and counts each name in it two times. Rename keeps the
# inode, so the count stays true. An offset with no log to point into
# is stale by definition, and apply removes it.
_dns_log_moves=(
  "/var/log/pi-fortress/dnsmasq.log:/var/log/pi-fortress/dns.jsonl:/var/lib/pi-fortress/dnsmasq.offset:/var/lib/pi-fortress/dns.offset"
  "/var/log/pi-fortress/dnsmasq-house.log:/var/log/pi-fortress/dns-house.jsonl:/var/lib/pi-fortress/dnsmasq-house.offset:/var/lib/pi-fortress/dns-house.offset"
)
_dns_log_due=""
for _pair in "${_dns_log_moves[@]}"; do
  [[ -e "${_pair%%:*}" ]] && _dns_log_due=1
done
if [[ -n "${_dns_log_due}" ]]; then
  # The observe of the old version is still running, and it still knows
  # the old names. If it stays up, it writes its offset back under the old
  # name immediately after the migration, and leaves a sidecar that
  # nothing owns. It starts again below with all the other services.
  systemctl stop pi-fortress-observe.service >/dev/null 2>&1 || true
  for _pair in "${_dns_log_moves[@]}"; do
    IFS=: read -r _old _new _oldoff _newoff <<<"${_pair}"
    if [[ -f "${_old}" && ! -f "${_new}" ]]; then
      mv "${_old}" "${_new}"
      [[ -f "${_oldoff}" ]] && mv "${_oldoff}" "${_newoff}"
    fi
    rm -f "${_old}" "${_oldoff}"
  done
fi

for _log in /var/log/pi-fortress/dns.jsonl /var/log/pi-fortress/dns-house.jsonl /var/log/pi-fortress/dnsmasq-house-dhcp.log; do
  touch "${_log}"
  chmod 0640 "${_log}"
done


# The stub starts before the resolvers that forward to it. The lookups of
# the box itself also go to the stub, not to the segment resolver: pf dns
# has the sinkholes and the AAAA drop, and apt and the feed fetches should
# not get them. Also, a resolver that points at itself is a loop.
# The Debian stubby package ships its own stubby.service on 127.0.0.1:53.
# We no longer install that package, but an image or an operator can.
# pi-fortress owns that port in both states. With DoT on, the two would
# race for it at boot. With DoT off, it is a resolver that nobody asked
# for, on the port that box_dns_pin cares about.
systemctl disable --now stubby.service >/dev/null 2>&1 || true
systemctl mask stubby.service >/dev/null 2>&1 || true

if [[ -n "${DOT_IPS}" ]]; then
  if [[ ! -f "${PI_LIB}/dns-stub@.service" ]]; then
    echo "pi-fortress: ${PI_LIB}/dns-stub@.service missing" >&2
    exit 1
  fi
  install -m 0644 "${PI_LIB}/dns-stub@.service" /etc/systemd/system/pi-fortress-dns-stub@.service

  # Both instances run as pf-dns off lo, so the single uid pin of the
  # output chain already covers the union of their addresses. Apply wrote
  # and checked the configs before the ruleset loaded.
  stub_want=("${STUB_WANT[@]}")
  for inst in "${stub_want[@]}"; do
    install -m 0644 "${WORKDIR}/dns-stub-${inst}.json" "/etc/pi-fortress/dns-stub-${inst}.json"
    # Before the stub had -config, the unit read its settings only from
    # this env file. The unit now reads the JSON file, so remove the old file.
    rm -f "/etc/pi-fortress/dns-stub-${inst}.env"
  done
  systemctl daemon-reload

  # If a house no longer has its own provider, an old instance stays. It
  # would continue to answer 127.0.0.2 with the old upstream. Nothing
  # forwards there now, but it is a resolver that we did not intend to
  # run. So stop it before the others start.
  if [[ -z "${HOUSE_DOT_IPS:-}" ]]; then
    systemctl disable --now pi-fortress-dns-stub@house.service >/dev/null 2>&1 || true
    rm -f /etc/pi-fortress/dns-stub-house.json /etc/pi-fortress/dns-stub-house.env
  fi

  DOT_STUB_DOWN=0
  for inst in "${stub_want[@]}"; do
    systemctl enable "pi-fortress-dns-stub@${inst}.service" >/dev/null 2>&1 || true
    # If this fails, Restart=always continues to try. Apply still moves
    # dnsmasq to the stub below. Thus the box converges when the stub
    # starts. It does not continue to forward to a port that the output
    # chain now drops until someone runs apply again.
    systemctl restart "pi-fortress-dns-stub@${inst}.service" \
      || echo "pi-fortress: pi-fortress-dns-stub@${inst} failed to start; no DNS through it until it does (journalctl -u pi-fortress-dns-stub@${inst})" >&2
  done

  # The exit code of the restart tells only that the unit started. The pin
  # below then makes ${DOT_ADDR} the only resolver of the box: the ruleset
  # is already loaded, so it drops port 53 off loopback. No second
  # resolver is available as a fallback. A resolv.conf that names a dead
  # stub is exactly what dot_pin_check wants to see. So, before, apply
  # ended with "applied" on a box that could not resolve anything,
  # including the feed fetch of the next run. Now wait for the port, and
  # give the answer to dot_pin_check so that the apply fails at the end.
  # The pin stays in both cases: an unpin cannot give DNS back to the box
  # while the output chain drops 53 off lo. The pin is what
  # lets Restart=always heal the box when the stub starts.
  if ! stub_ready "${DOT_ADDR}"; then
    DOT_STUB_DOWN=1
    echo "pi-fortress: nothing answers on ${DOT_ADDR}:53 after the pi-fortress-dns-stub@main restart; the Pi and every segment are without DNS until it comes up (journalctl -u pi-fortress-dns-stub@main)" >&2
  fi
  # If the house stub does not answer, the box still has its own DNS. Thus
  # it does not gate the stubby retirement below. It is still an outage
  # for all house clients, so it is still an error.
  if [[ -n "${HOUSE_DOT_IPS:-}" ]] && ! stub_ready "${HOUSE_DOT_ADDR}"; then
    echo "pi-fortress: nothing answers on ${HOUSE_DOT_ADDR}:53 after the pi-fortress-dns-stub@house restart; the house segment is without DNS until it comes up (journalctl -u pi-fortress-dns-stub@house)" >&2
  fi
  box_dns_pin on
  # Retire the stubby that an older release installed, but only after its
  # replacement answers. The box resolves through the service that holds
  # ${DOT_ADDR}, and
  # the feed fetch of the next run also resolves through it. So a stop of
  # the old stub before the new one binds would remove DNS from a box
  # whose ruleset already drops all other routes to a resolver.
  if [[ "${DOT_STUB_DOWN}" == "0" ]]; then
    systemctl disable --now pi-fortress-stubby.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/pi-fortress-stubby.service /etc/pi-fortress/stubby.yml
    # Also the single-instance stub that the previous release installed.
    # It holds the same ${DOT_ADDR} that the "main" instance now wants.
    systemctl disable --now pi-fortress-dns-stub.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/pi-fortress-dns-stub.service /etc/pi-fortress/dns-stub.env
    systemctl daemon-reload
  fi
elif [[ -f /etc/systemd/system/pi-fortress-dns-stub@.service || -f /etc/systemd/system/pi-fortress-dns-stub.service || -f /etc/systemd/system/pi-fortress-stubby.service ]]; then
  # DOT_IPS was cleared. Stop the stub before apply tells dnsmasq to
  # forward to ${DNS_UPSTREAM} again, and give the box its old resolver
  # back. The Debian unit stays masked.
  systemctl disable --now pi-fortress-dns-stub@main.service >/dev/null 2>&1 || true
  systemctl disable --now pi-fortress-dns-stub@house.service >/dev/null 2>&1 || true
  systemctl disable --now pi-fortress-dns-stub.service >/dev/null 2>&1 || true
  systemctl disable --now pi-fortress-stubby.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/pi-fortress-dns-stub@.service /etc/pi-fortress/dns-stub-main.env /etc/pi-fortress/dns-stub-house.env
  rm -f /etc/pi-fortress/dns-stub-main.json /etc/pi-fortress/dns-stub-house.json
  rm -f /etc/systemd/system/pi-fortress-dns-stub.service /etc/pi-fortress/dns-stub.env
  rm -f /etc/systemd/system/pi-fortress-stubby.service /etc/pi-fortress/stubby.yml
  systemctl daemon-reload
  box_dns_pin off
fi

# The agent resolver is pf dns. There is no conf file to write, validate
# or install: one set of values goes to both -check and the environment
# of the unit. Thus a green check is a statement about the process that
# will run. DNS_FORWARD is in the dnsmasq server= form (a bare address,
# or address#port), and pf dns takes host:port.
DNS_RESOLVER_UPSTREAM="${DNS_FORWARD/\#/:}"
[[ "${DNS_RESOLVER_UPSTREAM}" == *:* ]] || DNS_RESOLVER_UPSTREAM="${DNS_RESOLVER_UPSTREAM}:53"
# The echo fixtures are address= lines with real addresses. The dnsmasq
# arm puts them in dns-agent.conf. pf dns reads address= files and
# answers the names in them. Thus they go in as one more file, not as a
# separate flag.
{
  echo "address=/pf-open-echo.test/${ECHO_OPEN_IP:-192.0.2.3}"
  if [[ -f /etc/pi-fortress/lab ]]; then
    echo "address=/pf-core-echo.test/${ECHO_CORE_IP:-192.0.2.2}"
  fi
} >"${WORKDIR}/dns-agent-go.hosts"
install -m 0644 "${WORKDIR}/dns-agent-go.hosts" /etc/pi-fortress/dns-agent-go.hosts
DNS_RESOLVER_LOG=/var/log/pi-fortress/dns.jsonl
# Paranoid is the posture of the agent segment only. The house has no
# forward set and never had paranoid lines in its conf. The resolver
# decides with corepolicy.Forward, the same oracle that the engine and
# the broker use. Thus the names that it resolves and the names that the
# fence connects to cannot drift apart.
DNS_RESOLVER_PARANOID=""
if [[ "${PARANOID}" == "1" ]]; then
  DNS_RESOLVER_PARANOID=', "paranoid": true, "allow": "/etc/pi-fortress/allow.domains", "core_hosts": "/etc/pi-fortress/core.hosts"'
  # The same lab marker that decides -lab-echo for the engine and the
  # broker, so the fixture is open in the same places for all three.
  if [[ -f /etc/pi-fortress/lab ]]; then
    DNS_RESOLVER_PARANOID="${DNS_RESOLVER_PARANOID}, \"lab_echo\": true"
  fi
fi
# AGENT_DNS=fakeip: the agent segment answers A from FAKEIP_NET and
# journals each name for the broker (internal/fakeip). It forwards none.
# The keys go on the agent segment only, and only in that mode. Thus a
# forward-mode dns.json is byte for byte the same as before.
#
# The journal directory lets the broker, and only the broker, read the
# journal. pf dns runs User=pf-dns Group=pf-fortress. The broker runs
# Group=pf-fence. All daemons are in pf-fortress, pf-fence includes the
# engine, and the journal has each name that the agent resolved. So
# neither group fits. pf-fakeip has only the broker (created with the
# users above). The directory is pf-dns:pf-fakeip 2750: setgid. Thus
# the journal that pf dns creates in it, and the temp file that a
# compaction renames over it, get pf-fakeip. pf dns does not need to be
# a member or have CAP_CHOWN. fakeip.OpenPool sets 0640 on both. Not
# StateDirectory=, because it would chown the directory to the User and
# Group of the unit on each start, and so give it back to pf-fortress.
# ProtectSystem=strict makes /var/lib read-only for pf dns, so its unit
# names this directory in ReadWritePaths. The broker only reads it, and
# strict already allows that. Apply makes it before -check, which checks
# that it exists and is writable. Apply keeps it when the mode goes back
# to forward. Thus an agent that still has a pool answer from before a
# round trip maps the same.
DNS_RESOLVER_FAKEIP=""
if [[ "${AGENT_DNS}" == fakeip ]]; then
  install -d -o pf-dns -g pf-fakeip -m 2750 "${FAKEIP_JOURNAL_DIR}"
  if [[ -e "${FAKEIP_JOURNAL}" ]]; then
    chown pf-dns:pf-fakeip "${FAKEIP_JOURNAL}"
    chmod 0640 "${FAKEIP_JOURNAL}"
  fi
  DNS_RESOLVER_FAKEIP=", \"fakeip_net\": $(json_str "${FAKEIP_NET}" FAKEIP_NET), \"fakeip_journal\": $(json_str "${FAKEIP_JOURNAL}" fakeip_journal)"
fi
DNS_RESOLVER_HOUSE_LOG=/var/log/pi-fortress/dns-house.jsonl
# One segment for each interface that the box serves. The agent is always
# here. The house is also here when HOUSE_IF is set. That removes dnsmasq
# from DNS and leaves it with DHCP. Each segment has its own upstream, sinkhole list, set
# and log. The house must never feed resolved_v4. If it did, the agent
# gate would pass an address that only the house asked about.
{
  printf '{\n  "listen": 53,\n  "nft_table": "inet fortress",\n  "segments": [\n'
  # address_only (addronly.go in internal/dnsd) applies to the agent and
  # to each plain segment. Neither needs an answer other than an address,
  # and a TXT answer or a CNAME target is a channel back in. A plain
  # segment extends it with DNS_TYPES. The house and the loopback stubs
  # forward all types.
  printf '    {"iface": %s, "ip": %s, "upstream": %s, "sinkhole": %s, "nft_set": "resolved_v4", "log": %s, "key_rules": "/etc/pi-fortress/key_prefixes.rules", "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow"%s%s}' \
    "$(json_str "${INT_IF}" INT_IF)" "$(json_str "${PI_IP}" PI_IP)" \
    "$(json_str "${DNS_RESOLVER_UPSTREAM}" DNS_FORWARD)" \
    "$(json_list /etc/pi-fortress/blocked-domains.conf /etc/pi-fortress/doh-domains.conf /etc/pi-fortress/dns-agent-go.hosts)" \
    "$(json_str "${DNS_RESOLVER_LOG}" log)" "${DNS_RESOLVER_PARANOID}" "${DNS_RESOLVER_FAKEIP}"
  if [[ -n "${HOUSE_IF}" ]]; then
    DNS_RESOLVER_HOUSE_UPSTREAM="${HOUSE_DNS_FORWARD/\#/:}"
    # HOUSE_PRIVATE_DNS=on serves the DoH sinkhole without the names in
    # house_private_dns.domains of the operator. Thus a phone can resolve
    # the DoT/DoH hostname of its own provider. To match, the ruleset opens
    # tcp 443/853 to house_private_dns.ips. When off, the house sinkholes
    # all DoH names, the same as the agents.
    DNS_RESOLVER_HOUSE_DOH=/etc/pi-fortress/doh-domains.conf
    if [[ "${HOUSE_PRIVATE_DNS:-}" == on ]]; then
      DNS_RESOLVER_HOUSE_DOH=/etc/pi-fortress/house-doh-domains.conf
    fi
    # HOUSE_BLOCK_VPN (on unless off) adds the VPN/proxy feed. Thus a
    # VPN app cannot reach its provider to sign in or fetch servers. The
    # ruleset drops the tunnels themselves.
    DNS_RESOLVER_HOUSE_VPN=/etc/pi-fortress/house-vpn-domains.conf
    [[ "${HOUSE_BLOCK_VPN:-}" == off ]] && DNS_RESOLVER_HOUSE_VPN=""
    # The SNI check (render houseSNI): the ruleset holds the pending 443
    # flows of the house in this queue. pf dns asks the house segment
    # about the name that each flow sends.
    DNS_RESOLVER_HOUSE_SNI=""
    if [[ -n "${HOUSE_SNI_QUEUE:-}" ]]; then
      [[ "${HOUSE_SNI_QUEUE}" =~ ^[0-9]+$ ]] || { echo "pi-fortress: HOUSE_SNI_QUEUE='${HOUSE_SNI_QUEUE}' is not a number" >&2; exit 1; }
      DNS_RESOLVER_HOUSE_SNI=", \"sni_queue\": ${HOUSE_SNI_QUEUE}, \"sni_ech_ips\": \"/etc/pi-fortress/house-ech.ips\""
      [[ "${HOUSE_ALLOW_WHATSAPP:-}" == off ]] || DNS_RESOLVER_HOUSE_SNI="${DNS_RESOLVER_HOUSE_SNI}, \"sni_opaque_ips\": \"/etc/pi-fortress/house-whatsapp.ips\""
    fi
    [[ "${DNS_RESOLVER_HOUSE_UPSTREAM}" == *:* ]] || DNS_RESOLVER_HOUSE_UPSTREAM="${DNS_RESOLVER_HOUSE_UPSTREAM}:53"
    printf ',\n    {"name": "house", "iface": %s, "ip": %s, "upstream": %s, "sinkhole": %s, "nft_set": "resolved_house_v4", "log": %s%s}' \
      "$(json_str "${HOUSE_IF}" HOUSE_IF)" "$(json_str "${HOUSE_IP}" HOUSE_IP)" \
      "$(json_str "${DNS_RESOLVER_HOUSE_UPSTREAM}" HOUSE_DNS_FORWARD)" \
      "$(json_list /etc/pi-fortress/blocked-domains.conf "${DNS_RESOLVER_HOUSE_DOH}" /etc/pi-fortress/house-domains.conf "${DNS_RESOLVER_HOUSE_VPN}")" \
      "$(json_str "${DNS_RESOLVER_HOUSE_LOG}" log)" "${DNS_RESOLVER_HOUSE_SNI}"
  fi
  # A plain segment from segments.d also resolves through this box, with
  # the agent lists and the agent upstream. Before, it resolved through
  # the resolver that it configured itself: no feeds, no sinkhole, no
  # resolver gate and no observe rows. Thus the desk seat (it runs the
  # agent VMs and its own CLI agents) was the one tier whose DNS
  # nobody could see. Its own set and its own log, for the same reason as
  # the house: a name that resolves on one segment must not open an
  # address on another.
  # The agent's PARANOID never reaches a plain segment. The PARANOID=on of
  # a segment (segments.d) arms it on its own allow.<name>.domains, the
  # path that render checked and gave back in SEG_ALLOW, with no
  # core_hosts: allow.domains and core.hosts belong to the agent.
  # Each plain segment gets the DNS guards of the agent, because a desk can
  # be a machine to which an agent escaped: refuse key-shaped names, answer
  # address-only with the agent dns_types.allow, plus its own DNS_TYPES.
  for _i in "${!SEG_NAME[@]}"; do
    _sname="${SEG_NAME[${_i}]}"
    _sparanoid=""
    if [[ "${SEG_PARANOID[${_i}]:-off}" == on ]]; then
      _sparanoid=", \"paranoid\": true, \"allow\": $(json_str "${SEG_ALLOW[${_i}]}" "segment allowlist")"
    fi
    printf ',\n    {"name": %s, "iface": %s, "ip": %s, "upstream": %s, "sinkhole": %s, "nft_set": "resolved_%s_v4", "log": %s, "key_rules": "/etc/pi-fortress/key_prefixes.rules", "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow", "dns_types": %s%s}' \
      "$(json_str "${_sname}" "segment name")" \
      "$(json_str "${SEG_IF[${_i}]}" "segment IF")" \
      "$(json_str "${SEG_IP[${_i}]}" "segment IP")" \
      "$(json_str "${DNS_RESOLVER_UPSTREAM}" DNS_FORWARD)" \
      "$(json_list /etc/pi-fortress/blocked-domains.conf /etc/pi-fortress/doh-domains.conf /etc/pi-fortress/dns-agent-go.hosts)" \
      "${_sname//-/_}" \
      "$(json_str "/var/log/pi-fortress/dns-${_sname}.jsonl" log)" \
      "$(json_str "${SEG_DNS_TYPES[${_i}]:-}" "segment DNS_TYPES")" \
      "${_sparanoid}"
  done
  printf '\n  ]\n}\n'
} >"${WORKDIR}/dns.json"
# Keep the property that dnsmasq --test gave: refuse here a configuration
# that will not start, while the running resolver has no change.
if ! _out="$("${PF}" dns -config "${WORKDIR}/dns.json" -check 2>&1)"; then
  echo "${_out}" >&2
  echo "pi-fortress: pf dns -check failed; the running resolver is unchanged" >&2
  exit 1
fi
install -m 0644 "${WORKDIR}/dns.json" /etc/pi-fortress/dns.json
# Only after the check passed, so a refusal leaves the box as it was.
# paranoid-dns.conf is the dnsmasq form of the setting, and pf dns reads
# the forward set itself. Thus the file is stale for each PARANOID
# value. dns-agent-go.env was the unit interface with one variable for
# each flag. The segment list replaces it. Apply removes both here, so
# they do not stay as stale files: a box upgraded from the dnsmasq
# resolver still has them.
rm -f /etc/pi-fortress/dns-agent.conf /etc/pi-fortress/paranoid-dns.conf /etc/pi-fortress/dns-agent-go.env

sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
for _v6 in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
  echo 1 >"${_v6}" 2>/dev/null || true
done
# ARP answers only for an address on the interface that gets the request.
# Thus a stranger on the uplink cannot learn 10.77.0.1 or the house address
# from wlan0. Apply also writes it here, not only provision.sh, so a box
# provisioned before this line keeps it across a reboot (docs/user_guide/public_wifi.md).
cat >"${WORKDIR}/98-pi-fortress-arp.conf" <<'EOF'
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.default.arp_announce=2
EOF
install -D -m 0644 "${WORKDIR}/98-pi-fortress-arp.conf" /etc/sysctl.d/98-pi-fortress-arp.conf
sysctl -p /etc/sysctl.d/98-pi-fortress-arp.conf >/dev/null 2>&1 || true

# The connection table. It is
# one table for all segments and for the flows of the Pi itself -- the
# broker origin dials, the DoT upstream, SSH into the Pi. Thus when it is
# full, new flows fail everywhere at the same time. The ruleset gives each
# device and each segment a budget (render/connlimit.go). These settings
# set the size of the table that contains the budgets.
#
#   nf_conntrack_max 131072: the kernel default on a 4 GB Pi is about
#   65536, and the segment totals alone (agent 4096, house 32768, 4096 a
#   plain segment) would use most of that. An entry uses about 300
#   bytes with accounting on, so the full table at 131072 is about
#   40 MiB of the 4 GB, and only when it is really full.
#   tcp_timeout_established 86400: the default is five days. Thus a house
#   device that disappeared during a flow held its entry for most of a week.
#   Push channels send keepalives every few minutes, so a day with no
#   traffic is never a live flow.
#   tcp_timeout_time_wait 30: each closed TCP flow that the Pi forwards or
#   terminates holds its entry this long, and nothing counts it as live.
#   Thus the per-segment new-flow totals (render/connlimit.go
#   agentNewTotal, HOUSE_NEW_TOTAL, SEG_NEW_TOTAL) are the limit:
#   rate x this. At the kernel value of 120 s, the 1000/s of the house alone
#   was 125000 entries, the full table. At 30 s it is 35000 (27 %), the
#   agent 9600 (7 %) and each plain segment 9600 (7 %).
#   Shorter is safe here: the entry holds only the Pi state and NAT
#   mapping for a flow that both ends already closed. Each end keeps its
#   own TIME_WAIT (Linux 60 s) against old duplicates. A segment that arrives
#   after the entry expired finds no flow. From the WAN, it is no longer
#   de-NATed and goes to the input of the Pi, which drops it or
#   answers with a reset. From a device, it is a new flow that the far end
#   does not know, and the far end resets it. In both cases the connection
#   was complete, and the LAST_ACK timer of the peer ends it. A new SYN on
#   the same tuple is a new flow, which conntrack allows from TIME_WAIT also.
#
# The hash table (nf_conntrack_buckets) keeps the kernel size: it
# is only a lookup cost, and some kernels refuse a write to it.
#
# nf_conntrack is a module, and its sysctls exist only after it is
# loaded. At boot, systemd-sysctl runs before nftables.service loads the
# ruleset that would load it. Thus without modules-load.d, each boot skips
# the file below, and the box runs the kernel defaults until
# the next apply. systemd-modules-load runs before systemd-sysctl.
printf '%s\n' 'net.netfilter.nf_conntrack_max=131072' 'net.netfilter.nf_conntrack_tcp_timeout_established=86400' \
  'net.netfilter.nf_conntrack_tcp_timeout_time_wait=30' \
  >"${WORKDIR}/97-pi-fortress-conntrack.conf"
install -D -m 0644 "${WORKDIR}/97-pi-fortress-conntrack.conf" /etc/sysctl.d/97-pi-fortress-conntrack.conf
install -d -m 0755 /etc/modules-load.d
echo nf_conntrack >/etc/modules-load.d/pi-fortress-conntrack.conf
modprobe nf_conntrack >/dev/null 2>&1 || true
sysctl -p /etc/sysctl.d/97-pi-fortress-conntrack.conf >/dev/null 2>&1 ||
  echo "pi-fortress: the conntrack sysctls did not apply; the table keeps the kernel's size (sysctl -p /etc/sysctl.d/97-pi-fortress-conntrack.conf)" >&2

# The journal. The Debian default is 10% of the filesystem, with a maximum
# of 4 GiB. Each nft drop line, the stderr of each daemon and each unit restart
# goes into it. A hostile device can cause each of these again and again,
# at a high rate. 200 MiB is
# weeks of a quiet box, and still a limit on a noisy box. SystemKeepFree
# makes journald release space before the card is nearly full, whatever
# filled it. The runtime cap limits the copy in RAM (/run) before
# /var/log is mounted. The rate limit is written at its default, so that
# the drop-in shows all limits of the journal in one place: for a
# unit that logs more than 10000 lines in 30 s, journald suppresses the rest,
# with a count, until the interval ends.
# JOURNAL_PERSIST=1 adds Storage=persistent. Raspberry Pi OS sets
# Storage=volatile in /usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf.
# journald reads the drop-ins of all directories in the order of their
# file names, and pi-fortress.conf comes after 40-*, so this line wins.
# With 0, the drop-in has no Storage= line and the OS default stays.
install -d -m 0755 /etc/systemd/journald.conf.d
{
  printf '%s\n' '[Journal]' 'SystemMaxUse=200M' 'SystemKeepFree=1G' 'RuntimeMaxUse=64M' \
    'RateLimitIntervalSec=30s' 'RateLimitBurst=10000'
  if [[ "${JOURNAL_PERSIST}" == 1 ]]; then
    printf '%s\n' 'Storage=persistent'
  fi
} >"${WORKDIR}/journald-pi-fortress.conf"
if ! cmp -s "${WORKDIR}/journald-pi-fortress.conf" /etc/systemd/journald.conf.d/pi-fortress.conf; then
  install -m 0644 "${WORKDIR}/journald-pi-fortress.conf" /etc/systemd/journald.conf.d/pi-fortress.conf
  # A restart, not a reload: journald reads its limits at start. Only
  # when the file changed, so that an apply does not restart the journal for
  # no reason. Services keep their stdout across it (the fd store).
  systemctl restart systemd-journald.service >/dev/null 2>&1 ||
    echo "pi-fortress: systemd-journald did not restart; the journal cap applies from the next boot" >&2
  # The boot moves the RAM journal to the disk (systemd-journal-flush).
  # A change on a running box must do that step itself.
  if [[ "${JOURNAL_PERSIST}" == 1 ]]; then
    journalctl --flush >/dev/null 2>&1 || true
  fi
fi

# Time. systemd-timesyncd asked a Debian pool over plain NTP. Thus the
# operator of the uplink -- a hotel, a cafe, any user on the Wi-Fi -- could
# answer for the pool and move the clock. A clock that moves far enough fails
# each certificate check on the box: DoT upstream, the broker origin
# dials, NTS itself. chrony with NTS authenticates the servers over TLS
# (NTS-KE, TCP 4460) and each NTP packet after it (UDP 123). Three
# operators, so the other two outvote one falseticker. No plain source, not
# even as a fallback: an attacker who blocks 4460 would then talk to that
# fallback. apply writes the full file: the Debian
# chrony.conf reads NTP servers from DHCP (sourcedir /run/chrony-dhcp).
# That lets the uplink select the clock again.
#
# NTS-KE is also TLS. These stop a wrong clock from breaking TLS at boot:
# nocerttimecheck lets the first clock update ignore the validity dates of
# the certificate (chrony still checks the signature and the name). The RTC
# of the Pi 5 keeps the time across a reboot (and across a power cut with a
# battery on its BAT header). At boot, systemd advances the clock to the
# mtime of /var/lib/systemd/timesync/clock. The drop-in below touches that
# file when chrony stops, because timesyncd no longer does. The output
# chain policy is accept, and no rule drops 4460 or 123 for the _chrony
# user. Thus the firewall needs nothing (render TestPiOwnTimeSyncIsNotDropped).
#
# chrony is also the NTP server of the house and of each plain segment.
# The ruleset sends each NTP packet of these networks to the gateway
# (render ntpRedirect). NTP to a server of the device could carry data, so
# it never leaves. allow names only these networks: never the agent
# network, which has no NTP (vm/agent/setup.sh), and never the uplink.
# Input drops NTP on those interfaces too. The gateway serves plain NTP,
# not NTS: it has no NTS server key. It has no local directive, so it
# never serves a clock that it did not sync: an unsynced chrony answers
# with the leap bits of an unsynchronised server, and clients ignore it.
#
# ratelimit: a client address gets an answer for one request each 2 s on
# average (interval 1), with bursts of 8. iburst sends 4 to 8 requests
# 2 s apart, and a client then asks each 64 s or slower. A flood gets no
# answer above that, except the leak of chrony (1 in 4 by default), which
# tells a real client that the server is still there. chrony keeps this
# state in its client log, which has a fixed size (clientloglimit, 512 KiB
# by default). Thus the memory of chronyd does not grow with the number
# of clients. The command port stays off (cmdport 0). chronyc uses the
# Unix socket. bindcmdaddress keeps it on localhost if the port is ever
# on.
# chrony_conf writes chrony.conf on stdout: NTS sources, and an allow line
# for HOUSE_NET (when HOUSE_IF is set) and for each SEG_NET.
chrony_conf() {
  local n
  printf '%s\n' \
    '# Written by pi-fortress apply.sh; edits here are replaced on the next apply.' \
    'server time.cloudflare.com iburst nts' \
    'server nts.netnod.se iburst nts' \
    'server ptbtime1.ptb.de iburst nts' \
    'authselectmode require' \
    'nocerttimecheck 1' \
    'ntsdumpdir /var/lib/chrony' \
    'driftfile /var/lib/chrony/chrony.drift' \
    'makestep 1 3' \
    'rtcsync' \
    'maxupdateskew 100.0' \
    'cmdport 0' \
    'bindcmdaddress 127.0.0.1' \
    'logdir /var/log/chrony'
  if [[ -n "${HOUSE_IF:-}" && -n "${HOUSE_NET:-}" ]]; then
    printf 'allow %s\n' "${HOUSE_NET}"
  fi
  for n in "${SEG_NET[@]}"; do
    [[ -n "${n}" ]] && printf 'allow %s\n' "${n}"
  done
  printf '%s\n' 'ratelimit interval 1 burst 8'
}
if command -v chronyd >/dev/null 2>&1; then
  chrony_conf >"${WORKDIR}/chrony.conf"
  printf '%s\n' '[Service]' 'ExecStopPost=-/usr/bin/touch /var/lib/systemd/timesync/clock' >"${WORKDIR}/chrony-dropin.conf"
  install -d -m 0755 /etc/chrony /etc/systemd/system/chrony.service.d /var/lib/systemd/timesync
  _chrony_changed=0
  if ! cmp -s "${WORKDIR}/chrony.conf" /etc/chrony/chrony.conf; then
    install -m 0644 "${WORKDIR}/chrony.conf" /etc/chrony/chrony.conf
    _chrony_changed=1
  fi
  if ! cmp -s "${WORKDIR}/chrony-dropin.conf" /etc/systemd/system/chrony.service.d/pi-fortress.conf; then
    install -m 0644 "${WORKDIR}/chrony-dropin.conf" /etc/systemd/system/chrony.service.d/pi-fortress.conf
    systemctl daemon-reload
    _chrony_changed=1
  fi
  systemctl disable --now systemd-timesyncd.service >/dev/null 2>&1 || true
  systemctl enable chrony.service >/dev/null 2>&1 || true
  if [[ "${_chrony_changed}" == 1 ]]; then
    systemctl restart chrony.service ||
      echo "pi-fortress: chrony did not restart; the clock is not being kept (journalctl -u chrony)" >&2
  else
    systemctl start chrony.service >/dev/null 2>&1 || true
  fi
  touch /var/lib/systemd/timesync/clock 2>/dev/null || true
else
  echo "pi-fortress: chrony is not installed, so the clock is still set over plain NTP by systemd-timesyncd; run vm/pi/provision.sh (or apt-get install chrony) and apply again" >&2
fi

# sshd is the path back in when something else is wrong. Thus it is the last
# process that the kernel OOM killer may select. OpenSSH already writes -1000
# to its own oom_score_adj on Linux builds. But that is a compile-time
# option of a package that we do not build. The pf daemons get scores
# on purpose (their units), from 800 down to -500. Thus the order must be correct
# whatever the package did. -900, not -1000: sshd gives its start value
# to each session. Thus a login shell -- and all that the operator runs
# in it -- inherits this. At -900, the kernel can still kill a session
# when it holds most of the RAM itself. With -1000, the kernel could not
# kill a runaway command in an SSH session. No restart here: a
# restart of sshd from an apply that can itself run over SSH is
# too much risk for a value that the sshd -1000 already covers. It takes
# effect at the next boot or sshd restart.
if [[ -f /lib/systemd/system/ssh.service || -f /usr/lib/systemd/system/ssh.service ]]; then
  install -d -m 0755 /etc/systemd/system/ssh.service.d
  printf '%s\n' '[Service]' 'OOMScoreAdjust=-900' >"${WORKDIR}/ssh-pi-fortress.conf"
  if ! cmp -s "${WORKDIR}/ssh-pi-fortress.conf" /etc/systemd/system/ssh.service.d/pi-fortress.conf; then
    install -m 0644 "${WORKDIR}/ssh-pi-fortress.conf" /etc/systemd/system/ssh.service.d/pi-fortress.conf
    systemctl daemon-reload
  fi
fi

# A disconnected cable must not remove the segment address or stop its DNS.
# NetworkManager keeps the address on the interface without carrier,
# as on the LAN port of a router. dnsmasq binds dynamically (above), and
# restarts if it exits while the address is briefly absent.


if command -v nmcli >/dev/null 2>&1; then
  install -d -m 0755 /etc/NetworkManager/conf.d
  {
    echo "[device-pi-fortress-agent]"
    echo "match-device=interface-name:${INT_IF}"
    echo "ignore-carrier=yes"
    if [[ -n "${HOUSE_IF}" ]]; then
      echo
      echo "[device-pi-fortress-house]"
      echo "match-device=interface-name:${HOUSE_IF}"
      echo "ignore-carrier=yes"
    fi
    for _i in "${!SEG_NAME[@]}"; do
      echo
      echo "[device-pi-fortress-${SEG_NAME[${_i}]}]"
      echo "match-device=interface-name:${SEG_IF[${_i}]}"
      echo "ignore-carrier=yes"
    done
    for _p in ${VLAN_PARENTS}; do
      echo
      echo "[device-pi-fortress-trunk-${_p}]"
      echo "match-device=interface-name:${_p}"
      echo "ignore-carrier=yes"
    done
    if [[ -n "${WG_IF}" ]]; then
      echo
      echo "[keyfile]"
      echo "unmanaged-devices=interface-name:${WG_IF}"
    fi
  } >/etc/NetworkManager/conf.d/90-pi-fortress.conf
  nmcli general reload conf >/dev/null 2>&1 || true
  # If seg_prune parked a port (lib/netman.sh) and a role claims it again,
  # the port loses its inert profile before the profile of that role is made.
  nm_unpark
  for _p in ${VLAN_PARENTS}; do
    # A trunk port carries only tags, so nm_trunk strips its address and
    # deletes the profile that holds it. While that port is still the
    # addressed interface of a segment, that profile carries the fence.
    # trunk_keep (lib/netman.sh) does not change it, and tells the operator,
    # unless it is the house that carries its SSID VLANs.
    trunk_keep "${_p}" && continue
    nm_trunk "${_p}"
  done
  # A segment removed from segments.d, or moved to a different IF, loses its
  # old profile here (lib/netman.sh), unless the SSH session of the admin
  # arrives through it.
  seg_prune
  for _i in "${!SEG_NAME[@]}"; do
    [[ "${SEG_KEPT}" == *" ${SEG_NAME[${_i}]} "* ]] && continue
    _con="seg-${SEG_NAME[${_i}]}"
    if nm_profile "${_con}" "${SEG_IF[${_i}]}" "${SEG_IP[${_i}]}/${SEG_NET[${_i}]##*/}"; then
      if ! _seg_up_err="$(nmcli con up "${_con}" 2>&1 >/dev/null)"; then
        echo "pi-fortress: ${_con} not up on ${SEG_IF[${_i}]}: $(echo "${_seg_up_err}" | tr '\n' ' ')(is the interface present? check ip -br link)" >&2
      fi
    fi
  done
  # The same as house-net below: INT_IF moves when a cable or an
  # adapter changes, and a profile pinned to the old name never starts.
  nm_profile agent-net "${INT_IF}" "${PI_IP}/${AGENT_NET##*/}"
  if ! agent_up_err="$(nmcli con up agent-net 2>&1 >/dev/null)"; then
    echo "pi-fortress: agent-net not up on ${INT_IF}: $(echo "${agent_up_err}" | tr '\n' ' ')(is the cable in and the interface named ${INT_IF}? check ip -br link)" >&2
  fi
else
  # The gate above already proved that the addresses are on. Thus this is the
  # appliance or the lab, and the skip is correct. Tell the operator all the
  # same: before, this was silent, and the skipped items are still important.
  # Nothing owns these interfaces across a reboot and there is no
  # ignore-carrier. Thus a disconnected cable removes the segment address and stops its DNS.
  echo "pi-fortress: no nmcli; the interfaces keep the addresses they already have and get no NetworkManager profiles or ignore-carrier" >&2
fi

# The stock dnsmasq unit binds all interfaces with no sandbox, so it is
# masked, whatever else occurs here. dnsmasq still runs the house
# DHCP unit, which apply installs from its own file below.
rm -rf /etc/systemd/system/dnsmasq.service.d
systemctl disable --now dnsmasq.service >/dev/null 2>&1 || true
systemctl mask dnsmasq.service >/dev/null 2>&1 || true
if [[ ! -f "${PI_LIB}/dns-agent-go.service" ]]; then
  echo "pi-fortress: ${PI_LIB}/dns-agent-go.service missing" >&2
  exit 1
fi
# systemd drops the privilege that this daemon does not drop itself. Thus
# the daemon owns the log that it appends to. apply creates the account with
# the other system users, well before the DoT stub needs it.
chown pf-dns:pf-fortress /var/log/pi-fortress/dns.jsonl
chmod 0640 /var/log/pi-fortress/dns.jsonl
# The house log also: with the house on pf dns, it is the same daemon,
# with the same account. It appends to a file that dnsmasq owned before.
if [[ -n "${HOUSE_IF}" ]]; then
  touch /var/log/pi-fortress/dns-house.jsonl
  chown pf-dns:pf-fortress /var/log/pi-fortress/dns-house.jsonl
  chmod 0640 /var/log/pi-fortress/dns-house.jsonl
fi
# One per plain segment, same owner: the same daemon appends to it.
for _i in "${!SEG_NAME[@]}"; do
  _slog="/var/log/pi-fortress/dns-${SEG_NAME[${_i}]}.jsonl"
  touch "${_slog}"
  chown pf-dns:pf-fortress "${_slog}"
  chmod 0640 "${_slog}"
done
install -m 0644 "${PI_LIB}/dns-agent-go.service" /etc/systemd/system/pi-fortress-dns-agent-go.service
# A box that upgrades from the dnsmasq resolver still has that unit, and it
# wants the same address and port that pf dns will take. apply does not
# generate it now, so this is the one-time removal.
systemctl disable --now pi-fortress-dns-agent.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/pi-fortress-dns-agent.service
# The same is true of the house dnsmasq on that upgrade: it still
# holds 53 on HOUSE_IP. apply stops it here and starts it again DHCP-only below,
# after its port=0 conf is written. The gap stops DHCP renewals
# for a moment, and a 12h lease absorbs that. pf dns binds the house
# address when it appears -- the rebind timer covers an interface that is
# not up yet. That is also the first-apply case.
if [[ -n "${HOUSE_IF}" ]]; then
  systemctl stop pi-fortress-dns-house.service >/dev/null 2>&1 || true
fi
systemctl daemon-reload
systemctl enable pi-fortress-dns-agent-go.service >/dev/null 2>&1 || true
# An element of a resolved set does not name the DNS name that gave it.
# Thus, when the DNS policy of the operator changes (an operator block
# list, an allowlist, PARANOID, a key rule), apply cannot remove only the
# addresses of the names that the new policy blocks. pf nftsets policy
# flushes each set whose policy fingerprint changed since the last apply
# (RESOLVED_POLICY_STATE), and keeps the other sets. It runs while pf dns
# is stopped: the old pf dns adds no more addresses after the flush, and
# the new pf dns adds only addresses under the new policy. A client that
# answers from its own DNS cache waits out that cache, the same as after a
# reboot. With no state file (the first apply), each set counts as changed.
# The feeds are not in the fingerprint. Thus the nightly feed refresh does
# not flush, and a name that a feed adds keeps the addresses that it
# already has in a set until they expire (2h).
RESOLVED_POLICY_STATE=/var/lib/pi-fortress/resolved-policy.state
systemctl stop pi-fortress-dns-agent-go.service >/dev/null 2>&1 || true
"${PF}" nftsets policy --table "inet fortress" --config /etc/pi-fortress/dns.json --policy "${POLICY}" --state "${RESOLVED_POLICY_STATE}" ||
  echo "pi-fortress: could not compare the DNS policy of the resolved-address sets; a name that this apply blocks can keep its addresses in the set until they expire (2h)" >&2
systemctl restart pi-fortress-dns-agent-go.service

# House WireGuard egress. Nested on HOUSE_IF so that
# the no-house render cannot change. Empty WG_IF disables the unit in
# the same apply, and the house goes back to WAN_IF.
wg_dropin="/etc/systemd/system/wg-quick@${WG_IF:-wg0}.service.d/pi-fortress.conf"
if [[ -n "${HOUSE_IF}" && -n "${WG_IF}" ]]; then
  if [[ ! -x "${PI_LIB}/wg-conf.sh" || ! -x "${PI_LIB}/wg-routes.sh" ]]; then
    echo "pi-fortress: ${PI_LIB}/wg-conf.sh or wg-routes.sh missing" >&2
    exit 1
  fi
  if [[ ! -f /etc/pi-fortress/mullvad.conf ]]; then
    echo "pi-fortress: WG_IF=${WG_IF} is set but /etc/pi-fortress/mullvad.conf is missing. Drop the Mullvad Linux config there (root 0600) and apply again." >&2
    exit 1
  fi
  # A tunnel this apply no longer names (WG_IF renamed) is stopped and
  # its drop-in removed, or two wg-quick units fight over table 100.
  for _d in /etc/systemd/system/wg-quick@*.service.d/pi-fortress.conf; do
    [[ -f "${_d}" ]] || continue
    _old="${_d#/etc/systemd/system/wg-quick@}"
    _old="${_old%.service.d/pi-fortress.conf}"
    [[ "${_old}" == "${WG_IF}" ]] && continue
    systemctl disable --now "wg-quick@${_old}" >/dev/null 2>&1 || true
    rm -f "${_d}" "/etc/wireguard/${_old}.conf"
    rmdir "/etc/systemd/system/wg-quick@${_old}.service.d" 2>/dev/null || true
  done
  install -d -m 0755 /usr/local/lib/pi-fortress /etc/wireguard "/etc/systemd/system/wg-quick@${WG_IF}.service.d"
  install -m 0755 "${PI_LIB}/wg-conf.sh" /usr/local/lib/pi-fortress/wg-conf.sh
  install -m 0755 "${PI_LIB}/wg-routes.sh" /usr/local/lib/pi-fortress/wg-routes.sh
  # wg-quick@X reads /etc/wireguard/X.conf, so the file has the name of
  # WG_IF. A fixed wg0.conf left each other WG_IF with no config.
  if ! /usr/local/lib/pi-fortress/wg-conf.sh /etc/pi-fortress/mullvad.conf >"${WORKDIR}/wg.conf"; then
    exit 1
  fi
  if ! grep -Eiq '^\s*Table\s*=\s*off' "${WORKDIR}/wg.conf"; then
    echo "pi-fortress: rewritten ${WG_IF}.conf lost Table = off" >&2
    exit 1
  fi
  install -m 0600 "${WORKDIR}/wg.conf" "/etc/wireguard/${WG_IF}.conf"
  cat >"${WORKDIR}/wg-quick.dropin" <<EOF
[Unit]
After=nftables.service network-online.target
Wants=network-online.target
[Service]
Restart=on-failure
RestartSec=5
# The subnets apply computed, defaults included. house.env need not carry
# HOUSE_NET, and wg-routes.sh reading it there found nothing and failed
# every start (2026-09-23, the first real tunnel).
# SEG_NETS: the plain segments SSH_FROM may reach from the house.
Environment=HOUSE_NET=${HOUSE_NET} AGENT_NET=${AGENT_NET} WG_BYPASS_MARK=${WG_BYPASS_MARK} "SEG_NETS=${SEG_NET[*]:-}"
ExecStartPost=/usr/local/lib/pi-fortress/wg-routes.sh up ${WG_IF}
# park, not down: a stopped tunnel keeps the house blackholed beyond
# its own subnet (wg-routes.sh). Only apply with WG_IF empty runs down.
ExecStopPost=-/usr/local/lib/pi-fortress/wg-routes.sh park ${WG_IF}
EOF
  install -m 0644 "${WORKDIR}/wg-quick.dropin" "${wg_dropin}"
  systemctl daemon-reload
  systemctl enable --now "wg-quick@${WG_IF}" \
    || echo "pi-fortress: wg-quick@${WG_IF} failed to start; house stays blackholed until it does (journalctl -u wg-quick@${WG_IF})" >&2
  HOUSE_NET="${HOUSE_NET}" AGENT_NET="${AGENT_NET}" WG_BYPASS_MARK="${WG_BYPASS_MARK}" SEG_NETS="${SEG_NET[*]:-}" /usr/local/lib/pi-fortress/wg-routes.sh up "${WG_IF}" \
    || echo "pi-fortress: wg-routes.sh up failed; house has nft kill switch only until ${WG_IF} is up" >&2
  if [[ -f "${PI_LIB}/wg-alert.service" && -f "${PI_LIB}/wg-alert.timer" ]]; then
    sed "s/wg0/${WG_IF}/g" "${PI_LIB}/wg-alert.service" >"${WORKDIR}/wg-alert.service"
    install -m 0644 "${WORKDIR}/wg-alert.service" /etc/systemd/system/pi-fortress-wg-alert.service
    install -m 0644 "${PI_LIB}/wg-alert.timer" /etc/systemd/system/pi-fortress-wg-alert.timer
    # The one path that wg-alert.service can write. The unit does not
    # start without it. The check runs as root, so root owns it.
    touch /var/lib/pi-fortress/wg.last
    chown root:root /var/lib/pi-fortress/wg.last
    chmod 0644 /var/lib/pi-fortress/wg.last
    systemctl daemon-reload
    systemctl enable --now pi-fortress-wg-alert.timer >/dev/null 2>&1 || true
  fi
elif [[ -f "${wg_dropin}" ]]; then
  systemctl disable --now pi-fortress-wg-alert.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/pi-fortress-wg-alert.timer /etc/systemd/system/pi-fortress-wg-alert.service
  systemctl disable --now "wg-quick@${WG_IF:-wg0}" >/dev/null 2>&1 || true
  if [[ -x /usr/local/lib/pi-fortress/wg-routes.sh ]]; then
    HOUSE_NET="${HOUSE_NET:-10.78.0.0/24}" AGENT_NET="${AGENT_NET}" /usr/local/lib/pi-fortress/wg-routes.sh down "${WG_IF:-wg0}" || true
  fi
  rm -f "${wg_dropin}"
  rmdir "/etc/systemd/system/wg-quick@${WG_IF:-wg0}.service.d" 2>/dev/null || true
  systemctl daemon-reload
fi

# House segment: its own dnsmasq (DHCP + DNS on HOUSE_IF, feeds shared)
# and a NetworkManager profile, so that the USB interface gets HOUSE_IP when
# it appears. No HOUSE_IF: apply stops the unit and changes nothing else.
if [[ -n "${HOUSE_IF}" ]]; then
  if command -v nmcli >/dev/null 2>&1; then
    # A replaced adapter or an edited house.env changes HOUSE_IF. The
    # profile was pinned to the old name, and would never start. If a dot
    # is added to or removed from HOUSE_IF, the profile type also changes.
    nm_profile house-net "${HOUSE_IF}" "${HOUSE_IP}/${HOUSE_NET##*/}"
    if ! house_up_err="$(nmcli con up house-net 2>&1 >/dev/null)"; then
      echo "pi-fortress: house-net not up on ${HOUSE_IF}: $(echo "${house_up_err}" | tr '\n' ' ')(is the adapter plugged in and named ${HOUSE_IF}? check ip -br link)" >&2
    fi
  fi
  touch /etc/pi-fortress/house.hosts
  chmod 0644 /etc/pi-fortress/house.hosts
  # dnsmasq no longer starts as root. Thus it cannot open these two files
  # as root and give them to itself when it drops privilege: systemd starts
  # it as pf-dhcp-house, and the files must already be its own. Not
  # nogroup -- the group of the daemon owns nothing on this box. The lease
  # file has the group pf-leases, so that observe (pf-observe) can read
  # the client names. dnsmasq writes the file in place, so the group stays.
  # The log has the group root. The
  # chown is also the upgrade: a box installed before this unit dropped its
  # privilege has a root:root lease file, and an older box has files of
  # the shared dnsmasq account. dnsmasq would fail to open the lease file
  # for write, and stop again and again in a restart loop. Each DHCP
  # instance has its own account (dhcp_account, lib/dhcp.sh).
  dhcp_account house
  touch /var/lib/pi-fortress/house.leases
  chown pf-dhcp-house:pf-leases /var/lib/pi-fortress/house.leases
  chmod 0640 /var/lib/pi-fortress/house.leases
  # The DHCP log. Before, dnsmasq did the fchown of this file itself at each
  # start, from root. CAP_CHOWN and CAP_DAC_OVERRIDE were on the unit
  # for that. Now apply does it one time.
  touch /var/log/pi-fortress/dnsmasq-house-dhcp.log
  chown pf-dhcp-house:root /var/log/pi-fortress/dnsmasq-house-dhcp.log
  chmod 0640 /var/log/pi-fortress/dnsmasq-house-dhcp.log
  # pf dns serves the house, so dnsmasq keeps only DHCP -- its permanent
  # role, by decision: DHCP has no per-segment posture to express, but renew,
  # rebind and relay edge cases are a real risk. port=0 makes it
  # DHCP-only. It must not hold 53 on an address that pf dns binds.
  #
  # dhcp-option:dns-server still gives HOUSE_IP: the address did not
  # change. Only the daemon that answers on it changed.
  # dhcp-option:ntp-server gives HOUSE_IP too: chrony answers there, and
  # the ruleset sends all other NTP of the house there.
  #
  # The DHCP log is a separate file. pf dns owns dns-house.jsonl and
  # rotates it (internal/dnsd sweepLogs). A dnsmasq with an fd to
  # the same inode would continue to write to the rotated file, and
  # observe tails that log by byte offset.
  #
  # no-ping: dnsmasq does not send an ICMP echo to an address before it
  # offers that address. The check needs a raw ICMP socket, and thus
  # CAP_NET_RAW. Without the check, the unit does not have that
  # capability. Most clients probe a new address with ARP and decline it
  # (DHCPDECLINE) if a different device answers. dnsmasq then offers a
  # different address. Keep the static addresses of the house out of
  # the DHCP range, or reserve them in house.hosts.
  cat >"${WORKDIR}/dns-house.conf" <<EOF
interface=${HOUSE_IF}
except-interface=lo
bind-dynamic
port=0
dhcp-range=${HOUSE_DHCP_START},${HOUSE_DHCP_END},12h
dhcp-authoritative
no-ping
dhcp-option=option:router,${HOUSE_IP}
dhcp-option=option:dns-server,${HOUSE_IP}
dhcp-option=option:ntp-server,${HOUSE_IP}
dhcp-hostsfile=/etc/pi-fortress/house.hosts
dhcp-leasefile=/var/lib/pi-fortress/house.leases
log-dhcp
log-facility=/var/log/pi-fortress/dnsmasq-house-dhcp.log
EOF
  if ! _out="$(dnsmasq --test --conf-file="${WORKDIR}/dns-house.conf" 2>&1)"; then
    echo "${_out}" >&2
    echo "pi-fortress: dns-house.conf failed dnsmasq --test; the running house resolver is unchanged" >&2
    exit 1
  fi
  install -m 0644 "${WORKDIR}/dns-house.conf" /etc/pi-fortress/dns-house.conf
  install -m 0644 "${PI_LIB}/dns-house.service" /etc/systemd/system/pi-fortress-dns-house.service
  systemctl daemon-reload
  systemctl enable pi-fortress-dns-house.service >/dev/null 2>&1 || true
  systemctl restart pi-fortress-dns-house.service
elif [[ -f /etc/systemd/system/pi-fortress-dns-house.service ]]; then
  systemctl disable --now pi-fortress-dns-house.service >/dev/null 2>&1 || true
fi

# Plain segments with DHCP=on: the DHCP-only dnsmasq of the house, one
# instance per segment (lib/dhcp.sh). The profile of each segment is up at
# this point, so each instance finds its interface. A segment with DHCP now
# off, or a removed segment, loses its instance, conf and leases here.
seg_dhcp_sync || exit 1

SEG_DESC=""
for _i in "${!SEG_NAME[@]}"; do
  SEG_DESC="${SEG_DESC} ${SEG_NAME[${_i}]}=${SEG_IF[${_i}]}"
  if [[ "${SEG_PARANOID[${_i}]:-off}" == on ]]; then
    SEG_DESC="${SEG_DESC}(paranoid)"
  fi
  if [[ "${SEG_INSPECT[${_i}]:-off}" == on ]]; then
    SEG_DESC="${SEG_DESC}(inspect)"
  fi
done

if [[ "${LOCAL_ONLY}" -eq 1 ]]; then
  # The engine and the broker read blocked-domains.conf one time at start,
  # and refuse a listed name at the SNI/Host. That check stops a client
  # that does not use the resolver. If a list edit got only to dnsmasq,
  # that check would stay on the old list. Thus a changed file restarts
  # both. Open agent connections drop. The operator changed policy, and
  # that is the expected cost. The same applies to a changed PARANOID,
  # and to each other file in FENCE_INPUTS: the ruleset and the resolver
  # have the new policy, but the daemons still hold the old policy.
  _fence_note=""
  if [[ "${REFRESH}" -eq 1 && "${BLOCKED_CHANGED}" -eq 1 && "${FENCE_INPUT_CHANGED}" -eq 0 ]]; then
    # The unattended path, when only the list changed. Above, "the
    # operator changed policy" makes it acceptable to drop open
    # connections. On a timer at 04:00, that is not true: nobody asked for
    # this, and nobody is there to see it. The sinkhole and the nft sets
    # are live in both cases. Thus the new list applies to all that
    # resolves. Only the SNI/Host check in the fence is still on the old
    # copy, and the Feeds screen shows that until an operator applies.
    # When a refresh also finds a change to another fence input, the
    # operator changed policy. The ruleset that this run loaded already
    # has that change. Thus the refresh restarts the fence and records
    # the state in the next branch, the same as --local does.
    echo "pi-fortress: feed refresh changed blocked-domains.conf; the fence keeps the old name list until the next pf apply" >&2
    _fence_note=" name list changed, fence not restarted (unattended refresh)"
  elif [[ "${FENCE_CHANGED}" -eq 1 ]] && systemctl is-active --quiet pi-fortress-engine.service; then
    if ! systemctl restart pi-fortress-broker.service || ! systemctl restart pi-fortress-engine.service; then
      echo "pi-fortress: a fence input changed but the fence did not restart; the name, allow and secret checks are on the old policy until it does (journalctl -u pi-fortress-engine -u pi-fortress-broker)" >&2
      exit 1
    fi
    fence_state_record
    _fence_note=" fence restarted (policy inputs changed)"
  elif [[ "${FENCE_CHANGED}" -eq 0 ]]; then
    # The daemons already use these inputs, so a new snapshot only
    # records a fact that was already true. It seeds fence.state on
    # the first apply after an upgrade, when there is no reason to restart,
    # and the next edit must still be seen.
    fence_state_record
  fi
  dot_pin_check
  _settled=0
  settled || _settled=3
  echo "pi-fortress: local policy reloaded INT_IF=${INT_IF} WAN_IF=${WAN_IF}${HOUSE_IF:+ HOUSE_IF=${HOUSE_IF}}${WG_IF:+ WG_IF=${WG_IF}}${SEG_DESC:+ segments:${SEG_DESC}} PARANOID=${PARANOID}${_fence_note}"
  exit "${_settled}"
fi

# observe keeps its ledger and its checkpoints in their own directory.
# It is the one path under /var/lib/pi-fortress that observe.service can
# write, and it must exist before the unit starts. An install from before
# this kept them at the top. A file there is from an observe of that
# version, so it is newer than a copy in the directory, and it replaces
# that copy. Move them with the old observe stopped: if it stays up, it
# writes them back under the old names.
OBSERVE_STATE=/var/lib/pi-fortress/observe
install -d -m 0755 "${OBSERVE_STATE}"
_obs_old=()
for _f in /var/lib/pi-fortress/observe.json /var/lib/pi-fortress/journal.cursor \
  /var/lib/pi-fortress/strip.offset /var/lib/pi-fortress/dns.offset /var/lib/pi-fortress/dns-*.offset; do
  if [[ -f "${_f}" && ! -L "${_f}" ]]; then
    _obs_old+=("${_f}")
  fi
done
if [[ "${#_obs_old[@]}" -gt 0 ]]; then
  systemctl stop pi-fortress-observe.service >/dev/null 2>&1 || true
  mv -f "${_obs_old[@]}" "${OBSERVE_STATE}/"
  rm -f /var/lib/pi-fortress/observe.json.lock
fi
# observe runs as pf-observe:pf-fortress (observe.service). It owns its
# state directory. It replaces each state file with a rename, so a file
# that root wrote there (an observe from before, or a sudo pf observe
# once) does not stop it. The flock file is the one file that it opens
# for write in place. An observe from before made it root:root 0640.
# chown -h: apply changes the entry in the directory, and never follows
# a symlink there to a different file.
# An observe from before runs as root with no CAP_DAC_OVERRIDE. When its
# logs belong to pf-observe, it cannot write them, and it fails on its
# last write when it stops. Thus stop it before the owners change. The
# restart below starts the new unit.
if [[ -f /etc/systemd/system/pi-fortress-observe.service ]] &&
  ! grep -qx 'User=pf-observe' /etc/systemd/system/pi-fortress-observe.service; then
  systemctl stop pi-fortress-observe.service >/dev/null 2>&1 || true
fi
chown pf-observe:pf-fortress "${OBSERVE_STATE}"
if [[ -f "${OBSERVE_STATE}/observe.json.lock" && ! -L "${OBSERVE_STATE}/observe.json.lock" ]]; then
  chown -h pf-observe:pf-fortress "${OBSERVE_STATE}/observe.json.lock"
fi
# observe appends to observe.jsonl and notice.jsonl. It cannot make a
# file in /var/log/pi-fortress, so apply makes both, owned by
# pf-observe, 0640 for the group. pf alert (pf-sidecar, in the group)
# reads notice.jsonl. apply makes it here, not its first writer: that can
# be a sudo pf observe once from an operator, which makes it root:root.
# The webhook then never gets the rows in it. logrotate.conf makes new
# files with the same owner and mode.
for _f in /var/log/pi-fortress/observe.jsonl /var/log/pi-fortress/notice.jsonl; do
  [[ -f "${_f}" ]] || : >"${_f}"
  chown pf-observe:pf-fortress "${_f}"
  chmod 0640 "${_f}"
done
if [[ -f "${PI_LIB}/observe.service" ]]; then
  install -m 0644 "${PI_LIB}/observe.service" /etc/systemd/system/pi-fortress-observe.service
fi
if [[ -f /etc/systemd/system/pi-fortress-observe.service ]]; then
  systemctl daemon-reload
  systemctl enable pi-fortress-observe.service >/dev/null 2>&1 || true
  systemctl restart pi-fortress-observe.service || true
fi
if [[ -f "${PI_LIB}/monitor.service" ]]; then
  install -m 0644 "${PI_LIB}/monitor.service" /etc/systemd/system/pi-fortress-monitor.service
  systemctl daemon-reload
  systemctl enable pi-fortress-monitor.service >/dev/null 2>&1 || true
  systemctl restart pi-fortress-monitor.service || true
fi

# The feed refresh. Nothing else in the tree downloads a blocklist again.
# Without this, the threat intel is the last manual fetch of an operator,
# and nothing shows its age.
if [[ -f "${PI_LIB}/fetch.service" && -f "${PI_LIB}/fetch.timer" ]]; then
  install -m 0644 "${PI_LIB}/fetch.service" /etc/systemd/system/pi-fortress-fetch.service
  install -m 0644 "${PI_LIB}/fetch.timer" /etc/systemd/system/pi-fortress-fetch.timer
  systemctl daemon-reload
  if [[ "${FEED_REFRESH:-1}" == "1" ]]; then
    systemctl enable --now pi-fortress-fetch.timer >/dev/null 2>&1 \
      || echo "pi-fortress: pi-fortress-fetch.timer did not start; feeds refresh only on pf apply (journalctl -u pi-fortress-fetch.timer)" >&2
  else
    systemctl disable --now pi-fortress-fetch.timer >/dev/null 2>&1 || true
  fi
fi

# alert runs as pf-sidecar. Root keeps ownership of the state directories.
# The sidecar owns exactly the files that it rewrites. alert.service can
# write these three and its StateDirectory (/var/lib/pi-fortress/alert),
# and no other path.
for _f in /var/lib/pi-fortress/alert.offset /var/lib/pi-fortress/alert.last /var/lib/pi-fortress/alert-notice.offset; do
  touch "${_f}"
  chown pf-sidecar:pf-fortress "${_f}"
  chmod 0644 "${_f}"
done

# The daily update check (pf alert updates) also runs as pf-sidecar. Its
# state file is the one path that update-check.service can write, and the
# unit does not start without it.
if [[ -f "${PI_LIB}/update-check.service" && -f "${PI_LIB}/update-check.timer" ]]; then
  install -m 0644 "${PI_LIB}/update-check.service" /etc/systemd/system/pi-fortress-update-check.service
  install -m 0644 "${PI_LIB}/update-check.timer" /etc/systemd/system/pi-fortress-update-check.timer
  touch /var/lib/pi-fortress/updates.last
  chown pf-sidecar:pf-fortress /var/lib/pi-fortress/updates.last
  chmod 0644 /var/lib/pi-fortress/updates.last
  systemctl daemon-reload
  systemctl enable --now pi-fortress-update-check.timer >/dev/null 2>&1 \
    || echo "pi-fortress: pi-fortress-update-check.timer did not start; no post tells a reboot or update that waits (journalctl -u pi-fortress-update-check.timer)" >&2
fi

install -d -m 0755 /usr/local/lib/pi-fortress
rm -f /usr/local/lib/pi-fortress/{alert,doh,core_policy,secrets_store,substitute,enroll,compile_policy,observe,fetch_blocklists,console,dump_streams}.py
# alert.url is a webhook URL whose path is its bearer token. Its readers
# are root (pf alert wg, the ship alert, the operator) and the alert
# sidecar, through the pf-sidecar group. Thus 0640 root:pf-sidecar, also
# for the copy in the policy tree: pf alert reads /vagrant/vm/policy
# first, and on a hand-set Pi /vagrant is a link to /opt/pi-fortress. A
# copy that the operator made by hand, or that a restore wrote (0600),
# gets the same mode here.
if [[ -f "${POLICY}/alert.url" && ! "${POLICY}/alert.url" -ef /etc/pi-fortress/alert.url ]]; then
  install -m 0640 -o root -g pf-sidecar "${POLICY}/alert.url" /etc/pi-fortress/alert.url
fi
for _f in "${POLICY}/alert.url" /etc/pi-fortress/alert.url; do
  if [[ -f "${_f}" && ! -L "${_f}" ]]; then
    if ! { chown root:pf-sidecar "${_f}" && chmod 0640 "${_f}"; }; then
      echo "pi-fortress: WARNING could not make ${_f} 0640 root:pf-sidecar; pf alert may not read it" >&2
    fi
  fi
done
if [[ -f "${PI_LIB}/alert.service" ]]; then
  install -m 0644 "${PI_LIB}/alert.service" /etc/systemd/system/pi-fortress-alert.service
  systemctl daemon-reload
  systemctl enable pi-fortress-alert.service >/dev/null 2>&1 || true
  systemctl restart pi-fortress-alert.service || true
fi

# broker_store_plain DIR NAME...: each NAME in DIR must be absent or a
# regular file with one link. If not, this prints its path and fails. The
# touch, chown, chmod and pf enroll of root below all use these names, in a
# directory that the broker can write.
broker_store_plain() {
  local dir="$1" p
  shift
  for p in "$@"; do
    p="${dir}/${p}"
    if [[ -L "${p}" ]] || { [[ -e "${p}" ]] && { [[ ! -f "${p}" ]] || [[ "$(stat -c %h -- "${p}")" != 1 ]]; }; }; then
      echo "${p}"
      return 1
    fi
  done
}

# The broker owns its own directory, so a harvest rewrite is tmp+rename
# there, never truncate-in-place. secrets.env and the quarantine sidecar
# move in on the first apply after the split. The old lock is only a
# lock, and apply drops it. Each pf enroll call below uses the same path
# through PI_FORTRESS_SECRETS.
#
# apply stops the broker first: with no pf-broker process alive, nothing
# can replace a checked name with a link before root acts on it. The fence
# restart below starts it again.
BROKER_DIR=/etc/pi-fortress/broker
SECRETS="${BROKER_DIR}/secrets.env"
systemctl stop pi-fortress-broker.service >/dev/null 2>&1 || true
if pgrep -u pf-broker >/dev/null; then
  echo "pi-fortress: a pf-broker process outlived stopping the broker; ${BROKER_DIR} left alone and the broker stays down" >&2
  exit 1
fi
install -d -m 0750 -o pf-broker -g pf-fortress "${BROKER_DIR}"
if ! _bad="$(broker_store_plain "${BROKER_DIR}" secrets.env secrets.env.lock secrets.disabled secrets.expires)"; then
  echo "pi-fortress: ${_bad} is not a plain file. Only the broker writes that directory, so treat it as compromised; the broker stays down" >&2
  exit 1
fi
for _f in secrets.env secrets.disabled; do
  if [[ -e "/etc/pi-fortress/${_f}" && ! -e "${BROKER_DIR}/${_f}" ]]; then
    mv "/etc/pi-fortress/${_f}" "${BROKER_DIR}/${_f}"
  fi
done
rm -f /etc/pi-fortress/secrets.env.lock
export PI_FORTRESS_SECRETS="${SECRETS}"
if [[ ! -f "${SECRETS}" ]]; then
  if [[ -f "${POLICY}/secrets.env.example" ]]; then
    install -m 0600 "${POLICY}/secrets.env.example" "${SECRETS}"
  else
    : >"${SECRETS}"
    chmod 600 "${SECRETS}"
  fi
fi
"${PF}" enroll migrate
chmod 600 "${SECRETS}"
# Quarantine sidecar: root writes it through the TUI, the broker reads it.
touch "${BROKER_DIR}/secrets.disabled"
chown pf-broker:pf-fortress "${BROKER_DIR}/secrets.disabled"
chmod 0640 "${BROKER_DIR}/secrets.disabled"
# Expiry sidecar: pf enroll mint/renew write it, the broker reads it. Same
# shape as the quarantine sidecar above (docs/fence.md §5.2e).
touch "${BROKER_DIR}/secrets.expires"
chown pf-broker:pf-fortress "${BROKER_DIR}/secrets.expires"
chmod 0640 "${BROKER_DIR}/secrets.expires"
"${PF}" enroll purge --older-than 7d
rm -f /usr/local/sbin/pi-fortress-mitmdump /usr/local/sbin/pi-fortress-mitm-run
systemctl disable --now pi-fortress-mitm.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/pi-fortress-mitm.service
rm -rf /etc/systemd/system/pi-fortress-mitm.service.d

chown pf-broker:pf-fortress "${SECRETS}"
chmod 600 "${SECRETS}"
touch "${SECRETS}.lock"
chown pf-broker:pf-fortress "${SECRETS}.lock"
chmod 600 "${SECRETS}.lock"
install -d -m 0755 /var/log/pi-fortress
for _log in strip.jsonl unknown.jsonl use.jsonl; do
  touch "/var/log/pi-fortress/${_log}"
  chown pf-broker:pf-fortress "/var/log/pi-fortress/${_log}" 2>/dev/null || true
  chmod 0640 "/var/log/pi-fortress/${_log}"
done

if [[ -f "${PI_LIB}/pf-broker.service" ]]; then
  install -m 0644 "${PI_LIB}/pf-broker.service" /etc/systemd/system/pi-fortress-broker.service
fi
if [[ -f "${PI_LIB}/pf-engine.service" ]]; then
  install -m 0644 "${PI_LIB}/pf-engine.service" /etc/systemd/system/pi-fortress-engine.service
fi
systemctl daemon-reload

# Only the engine has the CA key: 0700 directory, 0600 key. Only the
# cert half is world-readable, and apply copies it for www below.
ENGINE_DIR=/var/lib/pi-fortress/engine
ENGINE_CA="${ENGINE_DIR}/ca.pem"
ENGINE_CERT="${ENGINE_DIR}/ca-cert.pem"
# The trust set: the engine root and, during a rotation (pf engine ca),
# the next or the old root and the link between them. Agents get this
# set. Without a rotation it is the same bytes as ca-cert.pem.
ENGINE_TRUST="${ENGINE_DIR}/ca-trust.pem"
install -d -m 0700 -o pf-engine -g pf-fortress "${ENGINE_DIR}"
if [[ ! -f "${ENGINE_CA}" && -f /var/lib/pi-fortress/mitm/mitmproxy-ca.pem ]]; then
  install -m 0600 -o pf-engine -g pf-fortress /var/lib/pi-fortress/mitm/mitmproxy-ca.pem "${ENGINE_CA}"
fi
"${PF}" engine -init-ca -ca "${ENGINE_CA}" -ca-cert "${ENGINE_CERT}" -ca-trust "${ENGINE_TRUST}"
chown pf-engine:pf-fortress "${ENGINE_CA}" 2>/dev/null || true
chmod 0600 "${ENGINE_CA}"
if [[ -f "${ENGINE_CERT}" ]]; then
  chown pf-engine:pf-fortress "${ENGINE_CERT}" 2>/dev/null || true
  chmod 0644 "${ENGINE_CERT}"
fi
ca_src=""
if [[ -f "${ENGINE_TRUST}" ]]; then
  ca_src="${ENGINE_TRUST}"
elif [[ -f "${ENGINE_CERT}" ]]; then
  ca_src="${ENGINE_CERT}"
elif [[ -f /var/lib/pi-fortress/mitm/mitmproxy-ca-cert.pem ]]; then
  ca_src=/var/lib/pi-fortress/mitm/mitmproxy-ca-cert.pem
fi
if [[ -n "${ca_src}" ]]; then
  install -d -m 0755 "${POLICY}/generated"
  install -m 0644 "${ca_src}" "${POLICY}/generated/egress-ca.pem"
  echo "pi-fortress: exported CA to ${POLICY}/generated/egress-ca.pem"
  if [[ -f "${POLICY}/generated/mitm-ca.pem" ]]; then
    install -m 0644 "${ca_src}" "${POLICY}/generated/mitm-ca.pem"
  fi
else
  echo "pi-fortress: CA cert missing after init-ca" >&2
  exit 1
fi

if [[ ! -f "${ENGINE_CA}" ]]; then
  echo "pi-fortress: engine CA missing after init-ca" >&2
  exit 1
fi
echo split >/etc/pi-fortress/fence
systemctl disable --now pi-fortress-mitm.service >/dev/null 2>&1 || true
systemctl enable pi-fortress-broker.service >/dev/null 2>&1 || true
systemctl enable pi-fortress-engine.service >/dev/null 2>&1 || true
if ! systemctl restart pi-fortress-broker.service || ! systemctl restart pi-fortress-engine.service; then
  echo "pi-fortress: fence=split start failed" >&2
  exit 1
fi
# The daemons have just read all fence inputs. Thus this is the state that
# the next --local compares with.
fence_state_record
echo "pi-fortress: fence=split (engine+broker on ${PI_IP}:8080${INSPECT_DESC})"

WWW=/var/lib/pi-fortress/www
install -d -m 0755 "${WWW}"
# Claim codes: only the TUI (root) writes claims/. www (DynamicUser in
# group pf-fortress) reads it, and cannot create, change or remove a claim.
# install -d also sets the mode of a claims/ that an earlier apply made
# 2770. To spend a code, www makes a marker in claims-redeemed/, which also
# holds the enrollment ledger. Root and www append to the ledger.
install -d -m 2750 -o root -g pf-fortress "${WWW}/claims"
install -d -m 2770 -o root -g pf-fortress "${WWW}/claims-redeemed"
# The ledger was in claims/ before. Move it once, and never move a link.
for _l in ledger.jsonl ledger.jsonl.1; do
  if [[ -f "${WWW}/claims/${_l}" && ! -L "${WWW}/claims/${_l}" && ! -e "${WWW}/claims-redeemed/${_l}" ]]; then
    mv "${WWW}/claims/${_l}" "${WWW}/claims-redeemed/${_l}"
  fi
done
# apply makes the ledger through a descriptor, never by name: www can write
# claims-redeemed/, so the name can point to a different file. The same
# call removes old claims and their markers: www cannot remove a claim.
"${PF}" www -init-ledger -dir "${WWW}"
if [[ -n "${ca_src}" ]]; then
  install -m 0644 "${ca_src}" "${WWW}/ca.pem"
  install -m 0644 "${ca_src}" /etc/pi-fortress/egress-ca.pem
  if [[ -f /etc/pi-fortress/mitm-ca.pem ]]; then
    install -m 0644 "${ca_src}" /etc/pi-fortress/mitm-ca.pem
  fi
fi
setup_src=""
for candidate in "${TREE:-/nonexistent}/vm/agent/setup.sh" "${PI_LIB}/agent-setup.sh"; do
  if [[ -f "${candidate}" ]]; then
    setup_src="${candidate}"
    break
  fi
done
if [[ -n "${setup_src}" ]]; then
  install -m 0644 "${setup_src}" "${WWW}/setup.sh"
fi
if [[ -f "${PI_LIB}/www.service" ]]; then
  install -m 0644 "${PI_LIB}/www.service" /etc/systemd/system/pi-fortress-www.service
  # Enroll serves only the agent segment: no loopback. Thus a
  # compromised enroll process cannot reach a local admin socket.
  install -d -m 0755 /etc/systemd/system/pi-fortress-www.service.d
  printf '[Service]\nIPAddressDeny=any\nIPAddressAllow=%s\n' "${AGENT_NET}" >/etc/systemd/system/pi-fortress-www.service.d/net.conf
  systemctl daemon-reload
  systemctl enable pi-fortress-www.service >/dev/null 2>&1 || true
  systemctl restart pi-fortress-www.service || true
fi

# The HTTP console and the kiosk are gone; management is `sudo pf tui`.
systemctl disable --now pi-fortress-console pi-fortress-console-kiosk 2>/dev/null || true
rm -f /etc/systemd/system/pi-fortress-console.service /etc/systemd/system/pi-fortress-console-kiosk.service
rm -rf /usr/local/lib/pi-fortress/console
systemctl daemon-reload

# The OS hardening of provision.sh (lib/harden.sh): the sysctl file, the
# unattended-upgrades config and the key-only sshd drop-in. pf upgrade and
# a ship run this apply, not provision.sh. Thus a box from an older
# release gets the files of this release here, as a fresh install does.
# Also, a box that had no login key at install time turns password login
# off at the first apply after the operator adds a key. Only on a full
# apply: a --local or --refresh run changes policy, not the OS.
harden_sysctl_write
harden_sysctl_load
harden_apt
harden_ssh
harden_watchdog

# pf apply gets to this script through syscall.Exec, which replaces the
# Go process. internal/admin records that an apply was requested, and can
# record nothing after that, because no part of it is left to run.
# Thus this script writes the outcome here: it is the only part that survives
# to know it. The format is the internal/audit Entry, marshalled by hand -- one
# JSON object per line, the same file that the verb table appends to. Thus
# a reader gets the request and the result from one log, in order.
#
# Each value below is a literal or is already validated: the
# interface names and PARANOID come from net.env through the same checks
# that build the ruleset. The actor is refused, not escaped
# (see audit_actor). No value here can contain a quote or a backslash. Thus
# printf can write the line, and this script does not need a JSON writer,
# which it does not have.
AUDIT_LOG="${PF_AUDIT_LOG:-/var/log/pi-fortress/audit.jsonl}"

# audit_actor mirrors audit.Actor and audit.plainName in Go. The user who
# ran sudo sets SUDO_USER, so it is input. If it is not a short
# run of printable non-space ASCII, this drops it and uses the uid. The uid
# is the one identity that this script can really observe. That check
# also keeps a quote or a backslash out of the JSON.
audit_actor() {
  local who="${SUDO_USER:-}"
  if [[ -n "${who}" && "${#who}" -le 64 && "${who}" != *[\\\"]* && "${who}" != *[[:space:][:cntrl:]]* ]]; then
    printf 'sudo:%s' "${who}"
    return
  fi
  printf 'uid:%s' "$(id -u)"
}

# audit_apply records what this run did. It is best-effort, as the
# callers of audit.Append are: a box that was just reconfigured must not
# show as failed because its log is full or read-only. Thus each write
# here can fail with no message.
audit_apply() {
  local ok="true" err="" mode="full"
  # Each test here is an if, not a `[[ ... ]] && x` one-liner.
  # With `set -e`, such a line exits the full script when its
  # test is false. On a full apply -- REFRESH=0 -- the write of the audit
  # record would then cause the apply to fail.
  if [[ "$1" -ne 0 ]]; then
    ok="false"
    err=',"err":"not settled"'
  fi
  if [[ "${REFRESH}" -eq 1 ]]; then
    mode="refresh"
  elif [[ "${LOCAL_ONLY}" -eq 1 ]]; then
    mode="local"
  fi
  install -d -m 0755 "${AUDIT_LOG%/*}" 2>/dev/null || return 0
  # SECONDS is the run time of the shell, so the millisecond field is
  # whole seconds, scaled. It is the same quantity as Entry.MS, and
  # no reader needs more resolution than "did that take minutes".
  printf '{"ev":"applied","t":"%s","verb":"apply","role":"admin","actor":"%s","args":{"mode":"%s","int_if":"%s","wan_if":"%s","house_if":"%s","paranoid":"%s"},"ok":%s%s,"ms":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(audit_actor)" "${mode}" \
    "${INT_IF}" "${WAN_IF}" "${HOUSE_IF:-}" "${PARANOID}" \
    "${ok}" "${err}" "$((SECONDS * 1000))" >>"${AUDIT_LOG}" 2>/dev/null || return 0
  chmod 0600 "${AUDIT_LOG}" 2>/dev/null || true
}

dot_pin_check
_settled=0
settled || _settled=3
echo "pi-fortress: applied INT_IF=${INT_IF} WAN_IF=${WAN_IF}${HOUSE_IF:+ HOUSE_IF=${HOUSE_IF} HOUSE_IP=${HOUSE_IP}}${HOUSE_IF:+${HOUSE_PRIVATE_DNS:+ HOUSE_PRIVATE_DNS=${HOUSE_PRIVATE_DNS}}}${WG_IF:+ WG_IF=${WG_IF}}${SEG_DESC:+ segments:${SEG_DESC}} PARANOID=${PARANOID}"
if [[ "${COMPILE_WARNINGS}" != 0 ]]; then
  echo "pi-fortress: pf compile skipped ${COMPILE_WARNINGS} line(s) of a hand-kept list; see the \"compile: warning:\" lines above" >&2
fi
audit_apply "${_settled}"

# The required-unit list for pf doctor --post-upgrade
# (docs/signed_ship.md): only the units that this run enabled
# unconditionally. Thus the post-upgrade doctor never hardcodes a unit
# that is optional on some boxes (the house resolver, WireGuard), and
# never fails a box that never had it.
install -d -m 0755 /var/lib/pi-fortress
printf '%s\n' \
  nftables.service \
  pi-fortress-dns-agent-go.service \
  pi-fortress-broker.service \
  pi-fortress-engine.service \
  >/var/lib/pi-fortress/units.required 2>/dev/null || true
exit "${_settled}"
