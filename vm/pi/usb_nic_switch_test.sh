#!/bin/bash
# usb_nic_switch_test.sh: usb-nic-switch.sh against a fake sysfs, with
# usb_modeswitch and usbreset stubbed. One case per rung of the ladder:
# nothing stuck, the eject works, only the logical unplug works, nothing
# works.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT
fail() { echo "usb_nic_switch_test: $*" >&2; exit 1; }

# The stub eject switches the device only when the case allows it:
#   eject   always
#   unplug  only once authorized was written 0 then 1 (it starts "init")
#   never   not at all
cat >"${t}/modeswitch" <<'EOF'
#!/bin/bash
echo "$*" >>"${T}/modeswitch.log"
case "$(cat "${T}/case")" in
  eject) echo 8153 >"${DEV}/idProduct" ;;
  unplug) [[ "$(cat "${DEV}/authorized")" == 1 ]] && echo 8153 >"${DEV}/idProduct" ;;
esac
exit 0
EOF
cat >"${t}/usbreset" <<'EOF'
#!/bin/bash
echo "$*" >>"${T}/usbreset.log"
EOF
chmod +x "${t}/modeswitch" "${t}/usbreset"

run() {
  local c=$1
  rm -rf "${t}/sys" "${t}"/*.log
  mkdir -p "${t}/sys/4-1" "${t}/sys/usb4"
  printf '1d6b\n' >"${t}/sys/usb4/idVendor"
  printf '0003\n' >"${t}/sys/usb4/idProduct"
  printf '0bda\n' >"${t}/sys/4-1/idVendor"
  if [[ "${c}" == none ]]; then
    printf '8153\n' >"${t}/sys/4-1/idProduct"
  else
    printf '8151\n' >"${t}/sys/4-1/idProduct"
  fi
  printf '4\n' >"${t}/sys/4-1/busnum"
  printf '2\n' >"${t}/sys/4-1/devnum"
  printf 'init\n' >"${t}/sys/4-1/authorized"
  echo "${c}" >"${t}/case"
  T="${t}" DEV="${t}/sys/4-1" PF_USB_SYS="${t}/sys" PF_USB_MODESWITCH="${t}/modeswitch" \
    PF_USB_RESET="${t}/usbreset" PF_USB_WAIT_S=1 bash "${here}/usb-nic-switch.sh"
}

out="$(run none)"
grep -q 'no adapter in driver-CD mode' <<<"${out}" || fail "none: ${out}"
[[ ! -e "${t}/modeswitch.log" ]] || fail "none: ejected a NIC"

out="$(run eject)"
grep -q '4-1: switched after eject, now 0bda:8153' <<<"${out}" || fail "eject: ${out}"
grep -qx -- '-v 0bda -p 8151 -K' "${t}/modeswitch.log" || fail "eject: wrong arguments: $(cat "${t}/modeswitch.log")"
[[ ! -e "${t}/usbreset.log" ]] || fail "eject: reset a port that had already switched"

out="$(run unplug)"
grep -q 'still 0bda:8151 after eject; resetting the port' <<<"${out}" || fail "unplug: ${out}"
grep -qx '004/002' "${t}/usbreset.log" || fail "unplug: usbreset got $(cat "${t}/usbreset.log")"
grep -q '4-1: switched after re-authorize, now 0bda:8153' <<<"${out}" || fail "unplug: ${out}"
[[ "$(wc -l <"${t}/modeswitch.log")" -eq 3 ]] || fail "unplug: want an eject after each rung"

out="$(run never)"
grep -q '4-1: still 0bda:8151; unplug the adapter and plug it back in' <<<"${out}" || fail "never: ${out}"
grep -q '1 adapter(s) still in driver-CD mode' <<<"${out}" || fail "never: ${out}"

# The ids the script matches are the ids the doctor names.
# shellcheck disable=SC2013,SC2016
for id in $(sed -n 's/^IDS="\${PF_USB_IDS:-\(.*\)}"$/\1/p' "${here}/usb-nic-switch.sh"); do
  grep -q "\"${id}\":" "${here}/../../internal/doctor/doctor.go" || fail "${id} is switched but internal/doctor does not name it"
  grep -q "\"${id%%:*}\", ATTRS{idProduct}==\"${id##*:}\"" "${here}/70-pi-fortress-rtl8153.rules" || fail "${id} has no udev rule"
done

echo "usb_nic_switch_test: ok"
