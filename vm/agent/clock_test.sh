#!/bin/bash
# clock_test.sh: tests clock.sh, which sets the agent clock from the Date
# header of the Pi. setup.sh and provision.sh each install a copy. The test
# takes each copy from its heredoc and runs it with a fake curl and a fake
# date. Nothing on this host changes.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT
fail() { echo "agent clock_test: $*" >&2; exit 1; }

real_date="$(command -v date)"
mkdir -p "${t}/bin"
# curl -fsSI ... URL: prints the headers of the Pi. FAKE_DATE is the Date
# header. When FAKE_DATE is empty, there is no Date header.
cat >"${t}/bin/curl" <<'EOF'
#!/bin/bash
printf 'HTTP/1.1 200 OK\r\n'
[[ -z "${FAKE_DATE:-}" ]] || printf 'Date: %s\r\n' "${FAKE_DATE}"
printf 'Content-Type: application/x-pem-file\r\n\r\n'
EOF
# date +%s prints FAKE_NOW. date -s @N writes N to FAKE_SET. date -d uses
# the real date.
cat >"${t}/bin/date" <<EOF
#!/bin/bash
case "\$1" in
  +%s) echo "\${FAKE_NOW}" ;;
  -s) echo "\${2#@}" >"\${FAKE_SET}" ;;
  *) exec "${real_date}" "\$@" ;;
esac
EOF
chmod +x "${t}/bin/curl" "${t}/bin/date"

# body FILE: prints the lines of the clock.sh heredoc in FILE.
body() {
  awk '/cat >\/usr\/local\/lib\/pi-fortress\/clock.sh <</ { on = 1; next } on && /^EOF$/ { exit } on' "$1"
}

# setup.sh writes clock.sh from a heredoc that expands PI_IP. provision.sh
# writes it as is, and clock.sh reads PI_IP from net.env.
printf 'PI_IP=10.77.0.1\n' >"${t}/net.env"
b="$(body "${here}/setup.sh")"
PI_IP=10.77.0.1 bash -c 'eval "cat <<EOF
$1
EOF"' _ "${b}" >"${t}/clock-setup.sh"
body "${here}/provision.sh" | sed "s|/etc/pi-fortress/net.env|${t}/net.env|" >"${t}/clock-provision.sh"

now=1800000000
stamp() { "${real_date}" -u -d "@$1" '+%a, %d %b %Y %H:%M:%S GMT'; }

for copy in setup provision; do
  script="${t}/clock-${copy}.sh"
  grep -q '/run/pi-fortress-agent-clock.synced' "${script}" || fail "${copy}: clock.sh has no first-sync state file"
  sed -i "s|/run/pi-fortress-agent-clock.synced|${t}/${copy}.synced|" "${script}"
  state="${t}/${copy}.synced"

  # run OFFSET: runs clock.sh with the Pi OFFSET seconds from the agent.
  # Sets out, status and set (the time that date -s got, or "").
  run() {
    rm -f "${t}/set"
    local d=""
    [[ "$1" == none ]] || d="$(stamp $((now + $1)))"
    out="$(PATH="${t}/bin:${PATH}" FAKE_NOW="${now}" FAKE_DATE="${d}" FAKE_SET="${t}/set" bash "${script}" 2>&1)" && status=0 || status=$?
    set=""
    [[ ! -e "${t}/set" ]] || set="$(cat "${t}/set")"
  }

  # No Date header: no step, and the next run is still the first.
  run none
  [[ "${status}" -ne 0 && -z "${set}" && ! -e "${state}" ]] || fail "${copy}: no Date header: status ${status}, set '${set}': ${out}"

  # The first run after a boot takes any step: a new VM image or a flat
  # clock battery can be years off.
  run $((3 * 365 * 86400))
  [[ "${status}" -eq 0 && "${set}" == $((now + 3 * 365 * 86400)) ]] || fail "${copy}: first run did not take a step of three years: ${out}"
  [[ -e "${state}" ]] || fail "${copy}: first run wrote no state file"

  # After that, a step over 24 hours is refused, with one line and no change.
  for off in $((86400 + 1)) $((-86400 - 1)) $((30 * 86400)); do
    run "${off}"
    [[ "${status}" -eq 0 && -z "${set}" ]] || fail "${copy}: took a step of ${off}s after the first sync: ${out}"
    [[ "$(printf '%s\n' "${out}" | wc -l)" -eq 1 && "${out}" == *"refused"* ]] || fail "${copy}: a refused step of ${off}s did not log one line: ${out}"
  done

  # Steps inside 24 hours and over 2 seconds still go through.
  for off in 3600 -3600 86400 3; do
    run "${off}"
    [[ "${status}" -eq 0 && "${set}" == $((now + off)) ]] || fail "${copy}: did not step ${off}s: ${out}"
  done

  # 2 seconds or less: no step.
  run 2
  [[ "${status}" -eq 0 && -z "${set}" ]] || fail "${copy}: stepped for 2s: ${out}"

  # A step over 24 hours goes through when a second poll about 15 minutes
  # later gives the same offset, within 5 seconds. A host suspend of more
  # than a day gives that. One poll alone changes nothing.
  big=$((2 * 86400))
  base="${now}"
  run "${big}"
  [[ -z "${set}" && "${out}" == *"refused"* ]] || fail "${copy}: one poll took a step of ${big}s: ${out}"
  now=$((base + 900))
  run $((big + 3))
  [[ "${status}" -eq 0 && "${set}" == $((now + big + 3)) ]] || fail "${copy}: two polls 900s apart with the same offset did not step: ${out}"
  [[ "$(printf '%s\n' "${out}" | wc -l)" -eq 1 ]] || fail "${copy}: a confirmed step did not log one line: ${out}"

  # Each of these second polls changes nothing: a different offset, a poll
  # too soon, a poll too late, and a poll after a normal poll between.
  # first-offset second-offset gap between-offset
  for c in "${big} $((big + 60)) 900 -" "${big} ${big} 60 -" "${big} ${big} 7200 -" "${big} ${big} 900 0"; do
    read -r o1 o2 gap mid <<<"${c}"
    now="${base}"
    run "${o1}"
    [[ "${mid}" == - ]] || run "${mid}"
    now=$((base + gap))
    run "${o2}"
    [[ "${status}" -eq 0 && -z "${set}" && "${out}" == *"refused"* ]] || fail "${copy}: took a step on polls '${c}': ${out}"
    # The second poll above is now the first of a new pair.
    now=$((base + gap + 900))
    run "${o2}"
    [[ "${set}" == $((now + o2)) ]] || fail "${copy}: a new pair after '${c}' did not step: ${out}"
  done
  now="${base}"

  # A first run that needs no step still starts the limit.
  rm -f "${state}"
  run 0
  [[ -e "${state}" ]] || fail "${copy}: a first run in sync wrote no state file"
  run $((2 * 86400))
  [[ -z "${set}" ]] || fail "${copy}: took a step of two days after a first run in sync: ${out}"
done
echo "agent clock_test: ok"
