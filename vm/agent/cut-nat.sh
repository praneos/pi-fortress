#!/bin/bash
# Cut the VirtualBox NAT adapter of the agent VM after ssh answers on the
# approved path. The approved path is the bridged address over the bridge
# through the Pi, or the host-only management address in the default lab.
# Before that proof, Vagrant uses the NAT adapter to reach a new box. Thus
# if the first proof fails, the script enables the adapter again. The lab
# then stays reachable. After one proof, a failure never enables it again.
# Root in the VM controls if sshd answers, and the cut exists to contain root.
#
# This is a file with a shebang, not a Vagrant inline trigger. Vagrant runs
# inline trigger strings without a shell: Shellwords.split goes directly
# into an exec. Thus an inline if/then/fi never ran its branches. Only the
# first line ran, and the cut occurred always. Vagrant execs a path
# trigger as a script, with its shell.
set -u
vb="$1" ip="$2" name="$3" mode="${4:-lab}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# The marker names the mode of the proof ("lab", or the bridge device).
# Reason: the two modes leave different addresses in the guest. An agent
# proved over the bridge has no management address. An `up` without
# AGENT_BRIDGE would then ssh to an address that the agent never got. The
# Vagrantfile treats a marker for a different mode as not provisioned.
# Then the NAT cable comes back and the proof runs again.
marker="${root}/.vagrant/pf-${name}-provisioned"
was_proved=0
if [[ -f "${marker}" && "$(cat "${marker}")" == "${mode}" ]]; then
  was_proved=1
fi

VBoxManage controlvm "${vb}" setlinkstate1 off >/dev/null 2>&1 || true
# Retry, do not probe one time. A box made again at the same address has
# a new MAC. The host neighbour entry for the old MAC stays in STALE. It
# loses the first seconds of traffic until the host resolves it again. A
# single 5s probe failed at each destroy+up in the lab.
proved=0
for _ in 1 2 3 4 5 6; do
  if timeout 5 bash -c "cat </dev/null >/dev/tcp/${ip}/22" 2>/dev/null; then
    proved=1
    break
  fi
  sleep 1
done
# host_guard: the host side of the agent NIC. The guest lock (routes.sh)
# already drops new connections out of the management NIC. But root in the
# VM can flush that lock. Also, the host answers on that NIC for each
# address that it owns. With the host-only network, the agent can then
# reach the listeners of the laptop without the gateway. The fence then
# never sees it. The guard is an nft table on the host. It lets the host
# sessions into the VM (vagrant ssh), and lets their replies come back. It
# drops each connection that the VM opens to the host. In bridged mode, the
# host has no address on the agent VLAN device. Thus the same guard applies
# there, and only there. A bridge onto a device that has a host address is
# the host LAN. The script does not change it.
#
# The guard needs root on the host. With passwordless sudo, the script
# installs it here at each up, provision, and reload. (A table does not
# stay after a host reboot.) Without passwordless sudo, the script prints
# the exact command and changes nothing else. Thus a lab without sudo
# operates as before.
host_guard() {
  local ifc="$1" tbl="pf_lab_guard_${name//[^a-zA-Z0-9]/_}" rules
  [[ -n "${ifc}" && -e "/sys/class/net/${ifc}" ]] || return 0
  if [[ "${mode}" != lab ]] && ip -4 -o addr show dev "${ifc}" 2>/dev/null | grep -q .; then
    echo "${name}: ${ifc} carries a host address, so it is the host's own network; no host guard" >&2
    return 0
  fi
  rules="table inet ${tbl}
delete table inet ${tbl}
table inet ${tbl} {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname \"${ifc}\" ct state established,related accept
    iifname \"${ifc}\" counter drop
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname \"${ifc}\" ct state established,related accept
    iifname \"${ifc}\" counter drop
  }
}"
  if command -v nft >/dev/null 2>&1 && sudo -n true 2>/dev/null && printf '%s\n' "${rules}" | sudo -n nft -f - 2>/dev/null; then
    echo "${name}: host guard ${tbl} on ${ifc}: the VM cannot open connections to the host"
  else
    echo "${name}: no host guard on ${ifc} (needs root on the host). Root in the VM could reach this host's own listeners over it. To close it:" >&2
    printf '  sudo nft -f - <<'"'"'EOF'"'"'\n%s\nEOF\n' "${rules}" >&2
  fi
}

if [[ "${proved}" == 1 ]]; then
  if [[ "${mode}" == lab ]]; then
    host_guard "$(VBoxManage showvminfo "${vb}" --machinereadable 2>/dev/null | sed -n 's/^hostonlyadapter[0-9]*="\(.*\)"$/\1/p' | head -1)"
  else
    host_guard "${mode}"
  fi
  mkdir -p "${root}/.vagrant"
  printf '%s\n' "${mode}" >"${marker}"
  echo "${name}: ssh reaches ${ip}:22 on the sanctioned path (${mode}); the NAT adapter stays off"
elif [[ "${was_proved}" == 1 ]]; then
  echo "${name}: no ssh to ${ip}:22 on the sanctioned path, which answered before; the NAT adapter stays off." >&2
  echo "${name}: to give the box its NAT adapter back on purpose: rm ${marker} && vagrant reload ${name}" >&2
  exit 1
else
  rm -f "${marker}"
  VBoxManage controlvm "${vb}" setlinkstate1 on >/dev/null 2>&1 || true
  echo "${name}: no ssh to ${ip}:22 on the sanctioned path, so the NAT adapter stays available" >&2
fi
