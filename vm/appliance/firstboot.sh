#!/bin/bash
# Appliance first boot, one time for each imported VM, from
# pi-fortress-firstboot.service. Makes again what seal-image.sh removed,
# then enrols: the fence mints the canary and gives a claim code, and the
# agent redeems it. If an input is missing, the script prints instructions
# and exits without firstboot.done. The next boot then tries again.
#
# Inputs come as VirtualBox guest properties under /pi-fortress.
# pi-fortress-import.sh on the host of the tester sets and relays them:
#   /pi-fortress/canary    host -> fence  the live canary value
#   /pi-fortress/claim     fence -> host -> agent  one-time claim code
#   /pi-fortress/enrolled  fence -> host  set once the agent has claimed
# The script reads /boot/pi-fortress-canary and /boot/pi-fortress-claim
# first, for an image built for a different hypervisor.
set -euo pipefail

DONE=/var/lib/pi-fortress/firstboot.done
SLOT_FILE=/var/lib/pi-fortress/appliance.slot
NOTICE=/usr/share/doc/pi-fortress/EVALUATION_NOTICE.txt
SEAT=/etc/pi-fortress/seat.txt
ISSUE=/etc/issue.d/50-pi-fortress-seat.issue
WAIT_S="${PF_FIRSTBOOT_WAIT:-1800}"
ROLE="$(cat /etc/pi-fortress/appliance.role 2>/dev/null || true)"

say() {
  printf 'pi-fortress: %s\n' "$*"
  printf 'pi-fortress: %s\n' "$*" >/dev/console 2>/dev/null || true
}

prop() {
  command -v VBoxControl >/dev/null 2>&1 || return 1
  VBoxControl --nologo guestproperty "$@" 2>/dev/null
}
prop_get() { prop get "/pi-fortress/$1" | sed -n 's/^Value: //p' || true; }
prop_set() { prop set "/pi-fortress/$1" "$2" >/dev/null || true; }
prop_del() { prop set "/pi-fortress/$1" >/dev/null || true; }

# seat LINE...: the notice and LINEs on the console, before login
# (/etc/issue.d) and at login (profile.d reads seat.txt).
seat() {
  install -d -m 0755 /etc/issue.d /etc/pi-fortress
  { printf '%s\n' "$@"; echo; cat "${NOTICE}" 2>/dev/null || true; } >"${SEAT}"
  chmod 0644 "${SEAT}"
  sed 's/\\/\\\\/g' "${SEAT}" >"${ISSUE}"
  agetty --reload 2>/dev/null || true
  printf '\n' >/dev/console 2>/dev/null || true
  cat "${SEAT}" >/dev/console 2>/dev/null || true
  cat "${SEAT}"
}

# take NAME: a seed from /boot/pi-fortress-NAME or the guest property. The
# read also removes the seed. Prints nothing when neither has a seed.
take() {
  local f="/boot/pi-fortress-$1" v=""
  if [[ -s "${f}" ]]; then
    v="$(head -n 1 "${f}" | tr -d '[:space:]')"
    shred -u "${f}" 2>/dev/null || rm -f "${f}"
  else
    v="$(prop_get "$1" | tr -d '[:space:]')"
    [[ -n "${v}" ]] && prop_del "$1"
  fi
  printf '%s' "${v}"
}

regenerate() {
  [[ -s /etc/machine-id ]] || systemd-machine-id-setup >/dev/null
  ssh-keygen -A >/dev/null
  systemctl restart ssh.service 2>/dev/null || true
}

fence() {
  regenerate
  # Lab mode enables the echo origins. The appliance has none. pf apply is
  # the provisioning path: it mints the engine CA, and makes again the
  # empty store, the claims directory and the exported cert.
  rm -f /etc/pi-fortress/lab
  if ! /usr/local/sbin/pf apply; then
    say "pf apply reported a problem (journalctl -u pi-fortress-firstboot)"
  fi
  if [[ ! -s /var/lib/pi-fortress/engine/ca.pem ]] || ! systemctl is-active -q pi-fortress-broker.service; then
    say "the fence did not come up; first boot not done. Check the NAT adapter and reboot to retry."
    exit 1
  fi
  export PI_FORTRESS_SECRETS=/etc/pi-fortress/broker/secrets.env

  local slot="" ph="" out waited=0 value
  if [[ -s "${SLOT_FILE}" ]]; then
    slot="$(sed -n 's/^slot=//p' "${SLOT_FILE}")"
    ph="$(sed -n 's/^CANARY=//p' "${SLOT_FILE}")"
  fi
  if [[ -z "${slot}" ]]; then
    while :; do
      value="$(take canary)"
      [[ -n "${value}" ]] && break
      if (( waited % 60 == 0 )); then
        seat "NO CANARY YET: this fence has nothing to guard." \
          "On the host: pi-fortress-import.sh sets it, or by hand, while this VM runs:" \
          "  VBoxManage guestproperty set pi-fortress-fence /pi-fortress/canary \"\$(cat canary.txt)\"" \
          "Waiting $(( (WAIT_S - waited) / 60 )) more minutes, then reboot to retry."
      fi
      if (( waited >= WAIT_S )); then
        say "no canary after ${WAIT_S}s; first boot not done"
        exit 0
      fi
      sleep 5
      waited=$((waited + 5))
    done
    out="$(printf '%s\n' "${value}" | /usr/local/sbin/pf enroll mint --kind CANARY --expires none --stdin)"
    unset value
    rm -f /etc/pi-fortress/agent-env-*.sh
    slot="$(sed -n 's/^slot=//p' <<<"${out}")"
    ph="$(sed -n 's/^CANARY=//p' <<<"${out}")"
    [[ -n "${slot}" && -n "${ph}" ]] || { say "pf enroll mint printed no slot; first boot not done"; exit 1; }
    printf 'slot=%s\nCANARY=%s\n' "${slot}" "${ph}" >"${SLOT_FILE}"
    chmod 0600 "${SLOT_FILE}"
    chown pf-broker:pf-fortress "${PI_FORTRESS_SECRETS}"
    chmod 0600 "${PI_FORTRESS_SECRETS}"
    systemctl restart pi-fortress-broker.service
  fi

  # A claim lives five minutes (internal/www ClaimTTL). An agent VM can take
  # longer to boot. Thus the script sends a new claim until the agent uses one.
  local ledger=/var/lib/pi-fortress/www/claims/ledger.jsonl code i
  waited=0
  while :; do
    code="$(/usr/local/sbin/pf claim -slot "${slot}" | sed -n 's/^code=//p')"
    [[ -n "${code}" ]] || { say "pf claim issued no code; first boot not done"; exit 1; }
    prop_set claim "${code}"
    seat "pi-fortress fence: canary enrolled." \
      "  slot         ${slot}" \
      "  placeholder  CANARY=${ph}" \
      "Waiting for the agent VM to claim it (code ${code}, relayed by pi-fortress-import.sh)."
    for i in $(seq 1 58); do
      sleep 5
      if grep -F "\"code\":\"${code}\"" "${ledger}" 2>/dev/null | grep -q '"ev":"redeemed"'; then
        break 2
      fi
    done
    waited=$((waited + 290))
    if (( waited >= WAIT_S )); then
      prop_del claim
      say "no agent claimed within ${WAIT_S}s; first boot not done, reboot to retry"
      exit 0
    fi
  done
  prop_del claim
  prop_set enrolled "${slot}"
  touch "${DONE}"
  seat "pi-fortress fence: ready. The agent VM holds the placeholder." \
    "  slot         ${slot}" \
    "  placeholder  CANARY=${ph}" \
    "This console has no login; the seat is the agent VM."
}

agent() {
  regenerate
  # shellcheck source=/dev/null
  source /etc/pi-fortress/net.env
  systemctl restart pi-fortress-agent-routes.service || true

  local home=/home/tester code="" last="" waited=0 ph pw
  while :; do
    code="$(take claim)"
    if [[ "${code}" =~ ^[A-Za-z0-9]{4,64}$ && "${code}" != "${last}" ]]; then
      last="${code}"
      if curl -fsS --max-time 20 -o /run/pf-claim.sh "http://${PI_IP}/claim/${code}"; then
        break
      fi
      say "claim code ${code} was refused; waiting for a fresh one"
    fi
    if (( waited % 60 == 0 )); then
      seat "NO PLACEHOLDER YET: waiting for a claim code from the fence." \
        "Start the fence VM first; pi-fortress-import.sh relays the code."
    fi
    if (( waited >= WAIT_S )); then
      say "no claim code after ${WAIT_S}s; first boot not done, reboot to retry"
      exit 0
    fi
    sleep 5
    waited=$((waited + 5))
  done

  # The claim script runs setup.sh through sudo for the CA and network.
  # Then it writes the placeholder into $HOME. It runs as root with the tester HOME.
  HOME="${home}" sh /run/pf-claim.sh
  rm -f /run/pf-claim.sh
  local f
  for f in .pi-fortress .claude .git-credentials; do
    [[ -e "${home}/${f}" ]] && chown -R tester:tester "${home}/${f}"
  done
  ph="$(sed -n "s/^export CANARY='\(.*\)'\$/\1/p" "${home}/.pi-fortress/env.sh")"
  # Run as the tester, not root. ~/.profile is the file of the tester. If
  # root appends to it, root follows a symlink in that location to any
  # file on the box.
  # shellcheck disable=SC2016
  runuser -u tester -- sh -c 'grep -qs "pi-fortress/env.sh" "$1" || printf "%s\n" "[ -r \"\$HOME/.pi-fortress/env.sh\" ] && . \"\$HOME/.pi-fortress/env.sh\"" >>"$1"' sh "${home}/.profile" ||
    say "could not add env.sh to ${home}/.profile; the placeholder is still in ${home}/.pi-fortress/env.sh"

  pw="$(set +o pipefail; head -c 2048 /dev/urandom | LC_ALL=C tr -dc 'a-km-z2-9' | head -c 16)"
  [[ "${#pw}" -eq 16 ]] || { say "could not generate a password; first boot not done"; exit 1; }
  printf 'tester:%s\n' "${pw}" | chpasswd
  touch "${DONE}"
  seat "pi-fortress agent: your seat." \
    "  login        tester (logged in on tty1; password ${pw} for other consoles)" \
    "  placeholder  CANARY=${ph:-see ~/.pi-fortress/env.sh}" \
    "  fence        ${PI_IP}  (http://${PI_IP}/ca.pem)" \
    "Objective and scope: docs/challenge_rules.md. Report: SECURITY.md."
}

case "${ROLE}" in
  fence) fence ;;
  agent) agent ;;
  *)
    say "appliance.role is '${ROLE}'; nothing to do"
    exit 1
    ;;
esac
