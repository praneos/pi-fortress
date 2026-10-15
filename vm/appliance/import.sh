#!/usr/bin/env bash
# pi-fortress-import.sh: import the appliance OVA pair into VirtualBox,
# give the fence its canary, relay the claim code of the agent, start both.
# It ships next to the OVAs in the release directory (docs/release.md).
#
#   pi-fortress-import.sh CANARY_FILE [DIR]
#
# CANARY_FILE has the live canary value on its first line. The value goes
# to the fence as a guest property. The fence deletes it when it reads it.
# PF_VM_TYPE=headless starts the VMs without windows.
set -euo pipefail

FENCE=pi-fortress-fence
AGENT=pi-fortress-agent
die() {
  echo "pi-fortress-import: $*" >&2
  exit 1
}

canary="${1:-}"
dir="${2:-$(cd "$(dirname "$0")" && pwd)}"
[[ -n "${canary}" && -r "${canary}" ]] || die "usage: $0 CANARY_FILE [DIR]"
command -v VBoxManage >/dev/null || die "VBoxManage not found; install VirtualBox"

shopt -s nullglob
fence_ova=("${dir}"/pi-fortress-fence-*.ova)
agent_ova=("${dir}"/pi-fortress-agent-*.ova)
[[ "${#fence_ova[@]}" -eq 1 && "${#agent_ova[@]}" -eq 1 ]] ||
  die "need exactly one pi-fortress-fence-*.ova and one pi-fortress-agent-*.ova in ${dir}"
for vm in "${FENCE}" "${AGENT}"; do
  if VBoxManage showvminfo "${vm}" >/dev/null 2>&1; then
    die "${vm} already exists; remove it first: VBoxManage unregistervm ${vm} --delete"
  fi
done

value="$(head -n 1 "${canary}" | tr -d '[:space:]')"
[[ -n "${value}" ]] || die "${canary} is empty"

if [[ -r "${dir}/EVALUATION_NOTICE.txt" ]]; then
  cat "${dir}/EVALUATION_NOTICE.txt"
fi
read -r -p "Type accept to accept the evaluation notice: " answer
[[ "${answer}" == accept ]] || die "not accepted"

VBoxManage import "${fence_ova[0]}" --vsys 0 --vmname "${FENCE}" --eula accept
VBoxManage import "${agent_ova[0]}" --vsys 0 --vmname "${AGENT}" --eula accept
VBoxManage guestproperty set "${FENCE}" /pi-fortress/canary "${value}"
unset value

type="${PF_VM_TYPE:-gui}"
VBoxManage startvm "${FENCE}" --type "${type}"
VBoxManage startvm "${AGENT}" --type "${type}"

get() { VBoxManage guestproperty get "$1" "$2" 2>/dev/null | sed -n 's/^Value: //p'; }

echo "pi-fortress-import: waiting for the fence to enrol the canary and the agent to claim it (up to an hour)"
last=""
deadline=$((SECONDS + 3600))
while ((SECONDS < deadline)); do
  if [[ -n "$(get "${FENCE}" /pi-fortress/enrolled)" ]]; then
    VBoxManage guestproperty delete "${FENCE}" /pi-fortress/canary >/dev/null 2>&1 || true
    VBoxManage guestproperty delete "${AGENT}" /pi-fortress/claim >/dev/null 2>&1 || true
    echo "pi-fortress-import: enrolled. The agent VM console shows the tester login and the placeholder."
    exit 0
  fi
  code="$(get "${FENCE}" /pi-fortress/claim)"
  if [[ -n "${code}" && "${code}" != "${last}" ]]; then
    VBoxManage guestproperty set "${AGENT}" /pi-fortress/claim "${code}"
    last="${code}"
    echo "pi-fortress-import: relayed a claim code to ${AGENT}"
  fi
  sleep 3
done
die "no enrolment within an hour; read the fence VM console"
