#!/bin/bash
# shellcheck shell=bash
# apply.sh, provision.sh and each other lib in this directory source this
# file first. It is not a program.
#
# pf_guard_target NAME stops a script that changes the system when it is
# not root on a gateway. The scripts and libs here add users, install
# packages, write /etc, load nft rulesets and start services. On a
# desktop, that is damage. NAME is the script or lib name for the
# message. The function returns 0 to continue. It returns 1 after one
# line on stderr, and the caller then stops before it changes anything.
#
# The rule:
# - PF_TEST_HARNESS=1: continue. Only the test harness sets it
#   (vm/pi/apply_test.sh, vm/appliance/apply_test.sh). The harness puts
#   stubs for systemctl, apt-get, nft and the other system tools first on
#   PATH, and the paths in a temporary directory.
# - All other cases: the user must be root (EUID 0), and the box must
#   show that it is a gateway. One of these is sufficient:
#     a Raspberry Pi model in /proc/device-tree/model (a real Pi);
#     /vagrant/vm/pi (a lab VM, which has the checkout there);
#     /etc/pi-fortress/appliance.role (the appliance, vm/appliance/install.sh);
#     /etc/pi-fortress/gateway.role (a box that pf install made a gateway);
#     PF_ALLOW_ANY_HOST=1 (pf install sets it when it runs provision.sh on
#     a fresh Debian or Ubuntu box; an operator can set it by hand).
#
# PF_TEST_HARNESS=guard is for the tests of this function. Then the
# function reads PF_TEST_GUARD_EUID in place of EUID, and finds
# /proc/device-tree/model, /vagrant and /etc/pi-fortress under
# PF_TEST_GUARD_ROOT. With no harness value, it reads none of these.
#
# The function uses only bash built-ins. Thus a PATH with stub tools
# cannot change its answer.
pf_guard_target() {
  local name="${1:-this script}" euid="${EUID}" root="" model="" why=""
  case "${PF_TEST_HARNESS:-}" in
    1) return 0 ;;
    guard)
      euid="${PF_TEST_GUARD_EUID:-${EUID}}"
      root="${PF_TEST_GUARD_ROOT:-}"
      ;;
  esac
  { IFS= read -r -d '' model <"${root}/proc/device-tree/model"; } 2>/dev/null || true
  if [[ "${euid}" != 0 ]]; then
    why="the user is not root (EUID ${euid})"
  fi
  if [[ "${PF_ALLOW_ANY_HOST:-}" != 1 && "${model}" != *"Raspberry Pi"* && ! -d "${root}/vagrant/vm/pi" &&
    ! -f "${root}/etc/pi-fortress/appliance.role" && ! -f "${root}/etc/pi-fortress/gateway.role" ]]; then
    why="${why:+${why}; }the box is not a gateway (${model:-no Raspberry Pi model}; no /vagrant lab checkout; no appliance or gateway role in /etc/pi-fortress)"
  fi
  [[ -n "${why}" ]] || return 0
  echo "pi-fortress: ${name} refuses to run on ${HOSTNAME:-this host}: ${why}. It changes the firewall, the network, users and system services. Run it as root on a gateway (PF_ALLOW_ANY_HOST=1 runs it as root on another box). To test it, run make apply-test." >&2
  return 1
}
