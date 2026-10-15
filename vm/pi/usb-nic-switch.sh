#!/bin/bash
# usb-nic-switch.sh: change each USB NIC that enumerated as its own
# driver CD into a NIC. This applies if it was connected before or after boot.
#
# The house RTL8153 powers up as mass storage (0bda:8151) and becomes a
# NIC (0bda:8153) only after a SCSI eject. At hot-plug, one eject was
# sufficient. On 2026-09-22, a cold boot left it at 8151 for twelve hours.
# The eject from the udev rule did nothing. A manual `usb_modeswitch -K`
# later also did nothing, and answered "status 0" to each message.
# A replug fixed it. Thus this script does not stop at the eject: it escalates
# to a port reset and then a logical unplug (authorized 0 then 1). These
# re-enumerate the device as a replug does, and the script ejects again after
# each. The script logs each step, so the next failure shows which rung held.
#
# pi-fortress-usb-nic-switch.service runs it at boot, and from the udev
# rule at each plug. Exits 0: a stuck adapter is reported, not fatal.
# `pf doctor` names it after that.
set -uo pipefail

SYS="${PF_USB_SYS:-/sys/bus/usb/devices}"
MODESWITCH="${PF_USB_MODESWITCH:-/usr/sbin/usb_modeswitch}"
USBRESET="${PF_USB_RESET:-/usr/bin/usbreset}"
WAIT_S="${PF_USB_WAIT_S:-8}"
# Keep in step with driverCD in internal/doctor/doctor.go.
IDS="${PF_USB_IDS:-0bda:8151 0bda:1a2b 2357:0601}"

say() { echo "usb-nic-switch: $*"; }

id_of() {
  local v p
  v="$(cat "$1/idVendor" 2>/dev/null)" || return 1
  p="$(cat "$1/idProduct" 2>/dev/null)" || return 1
  echo "${v}:${p}"
}

stuck() {
  local id want
  id="$(id_of "$1")" || return 1
  for want in ${IDS}; do
    [[ "${id}" == "${want}" ]] && return 0
  done
  return 1
}

# Poll the port path, not the device number: a switched adapter appears
# again at the same path (4-1) with a new product id.
settled() {
  local dev=$1 i
  for ((i = 0; i < WAIT_S * 2; i++)); do
    stuck "${dev}" || return 0
    sleep 0.5
  done
  return 1
}

eject() {
  local id
  id="$(id_of "$1")" || return 0
  "${MODESWITCH}" -v "${id%%:*}" -p "${id##*:}" -K >/dev/null 2>&1 || true
}

recover() {
  local dev=$1 name id
  name="${dev##*/}"
  id="$(id_of "${dev}")"
  say "${name} ${id} is in driver-CD mode"

  eject "${dev}"
  settled "${dev}" && { say "${name}: switched after eject, now $(id_of "${dev}" || echo gone)"; return 0; }

  say "${name}: still ${id} after eject; resetting the port"
  "${USBRESET}" "$(printf '%03d/%03d' "$(cat "${dev}/busnum")" "$(cat "${dev}/devnum")")" >/dev/null 2>&1 || true
  sleep 1
  eject "${dev}"
  settled "${dev}" && { say "${name}: switched after port reset, now $(id_of "${dev}" || echo gone)"; return 0; }

  say "${name}: still ${id} after port reset; unplugging it logically"
  echo 0 >"${dev}/authorized" 2>/dev/null || true
  sleep 1
  echo 1 >"${dev}/authorized" 2>/dev/null || true
  sleep 1
  eject "${dev}"
  settled "${dev}" && { say "${name}: switched after re-authorize, now $(id_of "${dev}" || echo gone)"; return 0; }

  say "${name}: still ${id}; unplug the adapter and plug it back in"
  return 1
}

found=0 left=0
for dev in "${SYS}"/*; do
  [[ -f "${dev}/idVendor" ]] || continue
  stuck "${dev}" || continue
  found=$((found + 1))
  recover "${dev}" || left=$((left + 1))
done
[[ "${found}" -eq 0 ]] && say "no adapter in driver-CD mode"
[[ "${left}" -eq 0 ]] || say "${left} adapter(s) still in driver-CD mode"
exit 0
