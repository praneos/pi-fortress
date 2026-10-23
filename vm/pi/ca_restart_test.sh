#!/bin/bash
# ca_restart_test.sh: ca-restart.sh against a fake CA bundle and state
# directory, with systemctl and logger stubbed. It checks that the script
# restarts only on a change, records a baseline without a restart, keeps
# the hash root-only, and always exits 0 with no output.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT
fail() { echo "ca_restart_test: $*" >&2; exit 1; }

cat >"${t}/systemctl" <<'EOF'
#!/bin/bash
echo "$*" >>"${T}/systemctl.log"
# A unit that is not installed: try-restart fails for it.
[[ "$*" != *alert* ]]
EOF
cat >"${t}/logger" <<'EOF'
#!/bin/bash
echo "$*" >>"${T}/logger.log"
EOF
chmod +x "${t}/systemctl" "${t}/logger"
mkdir -p "${t}/state"
echo "root A" >"${t}/bundle.crt"

run() {
  rm -f "${t}/systemctl.log" "${t}/logger.log"
  T="${t}" PF_CA_BUNDLE="${t}/bundle.crt" PF_CA_STATE="${t}/state/ca-bundle.sha256" \
    PF_CA_PENDING="${t}/state/ca-restart-pending" PF_SECRETS="${t}/secrets.env" \
    PF_SYSTEMCTL="${t}/systemctl" PF_LOGGER="${t}/logger" bash "${here}/ca-restart.sh" "$@"
}
printf 'GITHUB_TOKEN=x\n' >"${t}/secrets.env"

# --seed records a baseline and restarts nothing.
out="$(run --seed)" || fail "seed: exit $?"
[[ -z "${out}" ]] || fail "seed: wrote to the terminal: ${out}"
[[ ! -e "${t}/systemctl.log" ]] || fail "seed: restarted a unit"
[[ "$(cat "${t}/state/ca-bundle.sha256")" == "$(sha256sum <"${t}/bundle.crt" | cut -d' ' -f1)" ]] ||
  fail "seed: the recorded hash is not the hash of the bundle"
[[ "$(stat -c %a "${t}/state/ca-bundle.sha256")" == 600 ]] || fail "seed: the hash file is not 0600"

# A second --seed keeps the recorded hash, also after a change.
echo "root B" >"${t}/bundle.crt"
run --seed
[[ "$(cat "${t}/state/ca-bundle.sha256")" != "$(sha256sum <"${t}/bundle.crt" | cut -d' ' -f1)" ]] ||
  fail "seed: replaced a recorded hash, so the change that the hook must see is lost"

# The hook after a change restarts each unit and records the new hash.
out="$(run)" || fail "change: exit $?"
[[ -z "${out}" ]] || fail "change: wrote to the terminal: ${out}"
for u in pi-fortress-broker.service pi-fortress-dns-agent-go.service 'pi-fortress-dns-stub@*.service' pi-fortress-alert.service; do
  grep -qxF "try-restart --no-block ${u}" "${t}/systemctl.log" || fail "change: ${u} not restarted: $(cat "${t}/systemctl.log")"
done
[[ -s "${t}/logger.log" ]] || fail "change: the restart is not in the journal"
[[ "$(cat "${t}/state/ca-bundle.sha256")" == "$(sha256sum <"${t}/bundle.crt" | cut -d' ' -f1)" ]] ||
  fail "change: the new hash is not recorded"

[[ ! -e "${t}/state/ca-restart-pending" ]] || fail "change: a plain store left a pending marker"

# A sealed store: pf dns and pf alert restart, the broker does not, and a
# root-only marker holds the time for pf doctor.
printf '#pf-sealed v1 scrypt 32768 8 1 salt canary\nGITHUB_TOKEN=#pf1.x\n' >"${t}/secrets.env"
echo "root C" >"${t}/bundle.crt"
out="$(run)" || fail "sealed: exit $?"
[[ -z "${out}" ]] || fail "sealed: wrote to the terminal: ${out}"
grep -q 'pi-fortress-broker' "${t}/systemctl.log" && fail "sealed: restarted the broker, which locks the store"
for u in pi-fortress-dns-agent-go.service 'pi-fortress-dns-stub@*.service' pi-fortress-alert.service; do
  grep -qxF "try-restart --no-block ${u}" "${t}/systemctl.log" || fail "sealed: ${u} not restarted: $(cat "${t}/systemctl.log")"
done
grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' "${t}/state/ca-restart-pending" || fail "sealed: no time in the pending marker"
[[ "$(stat -c %a "${t}/state/ca-restart-pending")" == 600 ]] || fail "sealed: the pending marker is not 0600"
grep -q 'sealed' "${t}/logger.log" || fail "sealed: the journal does not say why the broker kept the old roots"
rm -f "${t}/state/ca-restart-pending"

# A store that cannot be read counts as sealed.
if [[ "$(id -u)" -ne 0 ]]; then
  chmod 000 "${t}/secrets.env"
  echo "root D" >"${t}/bundle.crt"
  run
  grep -q 'pi-fortress-broker' "${t}/systemctl.log" && fail "unreadable store: restarted the broker"
  [[ -e "${t}/state/ca-restart-pending" ]] || fail "unreadable store: no pending marker"
  chmod 600 "${t}/secrets.env"
fi

# No change: no restart.
run
[[ ! -e "${t}/systemctl.log" ]] || fail "same bundle: restarted a unit"

# No recorded hash: record it, restart nothing.
rm -f "${t}/state/ca-bundle.sha256"
run
[[ ! -e "${t}/systemctl.log" ]] || fail "no baseline: restarted a unit"
[[ -s "${t}/state/ca-bundle.sha256" ]] || fail "no baseline: hash not recorded"

# No bundle, or no state directory: exit 0 and do nothing.
T="${t}" PF_CA_BUNDLE="${t}/missing.crt" PF_CA_STATE="${t}/state/ca-bundle.sha256" \
  PF_SYSTEMCTL="${t}/systemctl" bash "${here}/ca-restart.sh" || fail "no bundle: exit $?"
T="${t}" PF_CA_BUNDLE="${t}/bundle.crt" PF_CA_STATE="${t}/nodir/ca-bundle.sha256" \
  PF_SYSTEMCTL="${t}/systemctl" bash "${here}/ca-restart.sh" || fail "no state dir: exit $?"
[[ ! -e "${t}/nodir" ]] || fail "no state dir: made one"

# The apt hook guards the call and can never fail the apt run.
hook="${here}/60pi-fortress-ca"
grep -q '^DPkg::Post-Invoke { "if \[ -x /usr/local/lib/pi-fortress/ca-restart.sh \]; then .* || true; fi"; };$' "${hook}" ||
  fail "60pi-fortress-ca: the Post-Invoke command is not guarded with -x and || true"
cmd="$(sed -n 's/^DPkg::Post-Invoke { "\(.*\)"; };$/\1/p' "${hook}")"
sh -c "${cmd}" || fail "60pi-fortress-ca: the command fails on a box with no script"

apply="${here}/apply.sh"
grep -qF 'install -m 0644 "${PI_LIB}/60pi-fortress-ca" /etc/apt/apt.conf.d/60pi-fortress-ca' "${apply}" ||
  fail "apply.sh does not install the apt hook"
grep -qF '/usr/local/lib/pi-fortress/ca-restart.sh --seed || true' "${apply}" ||
  fail "apply.sh does not seed the CA bundle hash"
grep -qxF 'ExecStartPost=-+/bin/rm -f /var/lib/pi-fortress/ca-restart-pending' "${here}/pf-broker.service" ||
  fail "pf-broker.service does not remove the pending marker at start"

echo "ca_restart_test: ok"
