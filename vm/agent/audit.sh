#!/bin/bash
# Host side, for `make agent-audit`. Read the VirtualBox settings of an
# agent VM. Fail on a host-guest channel or an emulated device that the
# Vagrantfile disables. Fail on a shared folder. Fail on a NIC that is not
# the cable or the NAT adapter. The settings are only as good as the last
# `vagrant up`. This script shows if they are still good.
set -euo pipefail
vm="${1:-pi-fortress-agent}"
info="$(VBoxManage showvminfo "${vm}" --machinereadable)" || { echo "agent-audit: no VM ${vm}" >&2; exit 2; }
bad=0
want() {
  local key="$1" val="$2" got
  got="$(sed -n "s/^${key}=\"\\{0,1\\}\\([^\"]*\\)\"\\{0,1\\}\$/\\1/p" <<<"${info}" | head -1)"
  if [[ "${got}" != "${val}" ]]; then
    echo "agent-audit: ${vm}: ${key} is '${got:-unset}', want '${val}'" >&2
    bad=1
  fi
}
# Some keys are absent while the device is off.
refuse() {
  if grep -q "^$1=\"$2\"\$" <<<"${info}"; then
    echo "agent-audit: ${vm}: $1 is '$2'" >&2
    bad=1
  fi
}
want clipboard disabled
want draganddrop disabled
want audio none
want usb off
refuse usbohci on
refuse usbehci on
refuse usbxhci on
want vrde off
want nested-hw-virt off
want uart1 off
want lpt1 off
if grep -q '^SharedFolderName' <<<"${info}"; then
  echo "agent-audit: ${vm}: has a VirtualBox shared folder: $(grep '^SharedFolderPath' <<<"${info}" | head -1)" >&2
  bad=1
fi
while IFS= read -r nic; do
  case "${nic#*=}" in
    '"nat"'|'"bridged"'|'"intnet"'|'"hostonly"'|'"none"') ;;
    *) echo "agent-audit: ${vm}: unexpected ${nic}" >&2; bad=1 ;;
  esac
done < <(grep -E '^nic[0-9]+=' <<<"${info}")
if grep -q '^nic[0-9]*="bridged"' <<<"${info}" && grep -q '^nic[0-9]*="hostonly"' <<<"${info}"; then
  echo "agent-audit: ${vm}: bridged and still has a host-only NIC" >&2
  bad=1
fi
if [[ "${bad}" == 0 ]]; then
  echo "agent-audit: ${vm}: ok"
fi
exit "${bad}"
