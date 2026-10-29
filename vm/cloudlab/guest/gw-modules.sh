#!/bin/bash
set -euo pipefail

# The kernel modules that the lab tests load on the gateway at run time.
# Lab only. The gateway locks module loads 10 minutes after boot
# (MODULE_LOCK, pi-fortress-modlock.timer), and then the kernel refuses
# each load until the next boot. Thus the lab loads these now and at each
# boot. vm/pi/apply.sh loads the modules that pf itself can need. These are
# for the tests only, so they stay out of vm/pi.
#   dummy      the stand-in uplink of the uplink-watch group (nmcli type
#              dummy). numdummies=0: the load makes no dummy0 link.
#   af_packet  tcpdump of the ntp group. Most kernels have it built in.
# vm/cloudlab/Vagrantfile runs this file at each up, and lab.sh sync runs
# it before apply. Not the VirtualBox lab: its fence VM is also the source
# of the appliance image, and a lab file must not ship in that image.

MODS=(dummy af_packet)
install -d -m 0755 /etc/modules-load.d /etc/modprobe.d
echo 'options dummy numdummies=0' >/etc/modprobe.d/pf-lab-dummy.conf
printf '%s\n' '# Lab only (vm/cloudlab/guest/gw-modules.sh): modules of the lab tests.' "${MODS[@]}" \
  >/etc/modules-load.d/pf-lab-tests.conf
if [[ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)" == 1 ]]; then
  missing=""
  for m in "${MODS[@]}"; do
    [[ -d "/sys/module/${m}" ]] || grep -qs "/${m}\.ko" "/lib/modules/$(uname -r)/modules.builtin" || missing+=" ${m}"
  done
  if [[ -n "${missing}" ]]; then
    echo "gw-modules: kernel module loads are locked and these are not loaded:${missing}. Reboot gw to load them (the tests that need them fail until then)." >&2
  fi
  exit 0
fi
modprobe -a "${MODS[@]}"
