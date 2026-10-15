#!/usr/bin/env bash
# One-shot cloud lab host setup: KVM, libvirt, vagrant and its libvirt
# plugin, then the lab itself. Run one time on a new Ubuntu host, with
# sudo, from the repository root. Manual: docs/cloud_lab.md.
#
# Plain `sudo bootstrap.sh` only sets up the host and prints the manual
# next steps (old behaviour, kept for a user who wants to run each step
# manually). `sudo bootstrap.sh --up` does all steps. It execs the rest of
# the work again as the invoking user, with the new libvirt/kvm groups
# already active (sg, so no log-out/log-in is necessary). It starts the
# lab, enrols one agent through the real claim flow, and runs a fast e2e
# group as a smoke check. Both forms are idempotent: run again at any time.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"

die() {
  echo "bootstrap: $*" >&2
  exit 1
}

# --continue-as-user is internal. bootstrap.sh execs itself again with this
# argument, as the invoking user and with the lab groups active, after the
# host half (which needs root) is done. Not for interactive use.
if [[ "${1:-}" == "--continue-as-user" ]]; then
  [[ "$(id -u)" -ne 0 ]] || die "--continue-as-user must not run as root"
  cd "${ROOT}"
  echo "bootstrap: bringing the lab up (vm/cloudlab/lab.sh up)"
  "${HERE}/lab.sh" up
  echo "bootstrap: enrolling one agent"
  already="$("${HERE}/lab.sh" ssh agent 'test -s "$HOME/.claude/.credentials.json" && echo yes || echo no' 2>/dev/null || echo no)"
  if [[ "$(printf '%s' "${already}" | tr -d '[:space:]')" == yes ]]; then
    echo "bootstrap: agent already holds credentials (from a previous run or the pre-seeded path); skipping the claim"
  else
    echo "bootstrap: enrolling the agent through the real claim flow (docs/fence.md 5.6, vm/itest/enroll_test.go)"
    oat="sk-ant-oat01-$(printf 'B%.0s' $(seq 1 64))"
    ort="sk-ant-ort01-$(printf 'C%.0s' $(seq 1 64))"
    fell_back=0
    if mint_out="$("${HERE}/lab.sh" ssh pi "printf '%s\n%s\n' '${oat}' '${ort}' | sudo pf enroll mint --kind CLAUDE --stdin" 2>&1)"; then
      slot="$(printf '%s\n' "${mint_out}" | sed -n 's/^slot=//p' | head -1)"
      if [[ -n "${slot}" ]]; then
        if claim_out="$("${HERE}/lab.sh" ssh pi "sudo pf claim -slot ${slot}" 2>&1)"; then
          command="$(printf '%s\n' "${claim_out}" | sed -n 's/^command=//p' | head -1)"
          if [[ -n "${command}" ]]; then
            if "${HERE}/lab.sh" ssh agent "${command}"; then
              echo "bootstrap: agent enrolled via slot ${slot} (real claim flow)"
            else
              echo "bootstrap: the claim command failed on the agent" >&2
              fell_back=1
            fi
          else
            echo "bootstrap: pf claim printed no command:" >&2
            echo "${claim_out}" >&2
            fell_back=1
          fi
        else
          echo "bootstrap: pf claim failed:" >&2
          echo "${claim_out}" >&2
          fell_back=1
        fi
      else
        echo "bootstrap: pf enroll mint printed no slot:" >&2
        echo "${mint_out}" >&2
        fell_back=1
      fi
    else
      echo "bootstrap: pf enroll mint failed:" >&2
      echo "${mint_out}" >&2
      fell_back=1
    fi
    if [[ "${fell_back}" -eq 1 ]]; then
      echo "bootstrap: real claim flow did not complete; falling back to whatever pre-seeded credentials vm/agent/provision.sh already left on the agent" >&2
    fi
  fi

  echo "bootstrap: smoke check"
  "${HERE}/lab.sh" status
  "${HERE}/lab.sh" test -run 'TestLab/policy' ||
    die "smoke e2e group (policy) failed; the lab came up but is not healthy"
  echo "bootstrap: done. The lab is up, one agent is enrolled, and the policy group passed."
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "run with sudo: sudo vm/cloudlab/bootstrap.sh [--up]"

# A normal user operates the lab. The vagrant plugins, the box cache and
# the ssh config are all in the home of that user, not of root.
USER_NAME="${SUDO_USER:-}"
[[ -n "${USER_NAME}" && "${USER_NAME}" != root ]] ||
  die "run it as your own user through sudo, not as root: sudo vm/cloudlab/bootstrap.sh"
USER_HOME="$(getent passwd "${USER_NAME}" | cut -d: -f6)"
[[ -d "${USER_HOME}" ]] || die "no home directory for ${USER_NAME}"

[[ -e /dev/kvm ]] ||
  die "no /dev/kvm: this machine cannot run KVM guests. Use a bare-metal instance, or a cloud type with nested virtualization on (docs/cloud_lab.md, Host)"

export DEBIAN_FRONTEND=noninteractive

# Packages, Go at the version of go.mod (GOTOOLCHAIN=local rejects the older
# golang-go of the distro), vagrant, the libvirt plugin and the groups.
echo "bootstrap: packages"
"${ROOT}/scripts/lab_deps.sh" libvirt

echo "bootstrap: lab networks"
"${HERE}/lab.sh" host

if [[ "${1:-}" == "--up" ]]; then
  echo "bootstrap: host done. Continuing as ${USER_NAME} with the libvirt and kvm groups active (sg, no re-login needed)."
  # sg reads /etc/group at exec time. Thus the group that usermod added
  # applies immediately in the new process that sg starts. Two nested sg
  # calls activate both libvirt (vagrant, virsh) and kvm (/dev/kvm).
  exec sudo -u "${USER_NAME}" -H sg libvirt -c "sg kvm -c '\"${HERE}/bootstrap.sh\" --continue-as-user'"
fi

cat <<EOF

bootstrap: done. ${USER_NAME} was added to the libvirt and kvm groups, which
a running shell does not pick up. Start the lab from a new login:

  cd ${ROOT}
  vm/cloudlab/lab.sh up
  vm/cloudlab/lab.sh status
  vm/cloudlab/lab.sh test

If a command says it cannot reach libvirt, log out and back in first.

Or run this script again as: sudo vm/cloudlab/bootstrap.sh --up
which does all of the above in one command, with no re-login needed.
EOF
