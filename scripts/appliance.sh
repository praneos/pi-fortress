#!/usr/bin/env bash
# appliance.sh [DIR]: export the provisioned lab VMs as an OVA pair
#   DIR/pi-fortress-fence-<version>.ova
#   DIR/pi-fortress-agent-<version>.ova
# plus pi-fortress-import.sh and EVALUATION_NOTICE.txt. docs/release.md.
#
# VBoxManage export, not vagrant package: testers import an OVA with
# VirtualBox alone, no Vagrant, and the OVA carries the notice as its EULA.
#
# Each lab VM is snapshotted, provisioned again from this tree, sealed and
# linted inside, powered off, and cloned. The clone is exported and deleted.
# Then the snapshot is restored, so the lab keeps its keys and enrolments.
# DIR defaults to dist/<version>/. release.sh runs this with APPLIANCE=1
# before SHA256SUMS, so the sums cover the images.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
SNAP=pf-appliance-pre
die() { echo "appliance: $*" >&2; exit 1; }

ver=${VERSION:-$("$ROOT/scripts/release.sh" version)}
dir=${1:-$ROOT/dist/$ver}
command -v VBoxManage >/dev/null || die "VBoxManage not found"
command -v vagrant >/dev/null || die "vagrant not found"
[ -z "${AGENT_BRIDGE:-}" ] || die "unset AGENT_BRIDGE: the appliance agent sits on the internal network"
# The vboxdrv of VirtualBox takes VT-x for itself. A VM start under it,
# while KVM has guests that run, does not fail loudly: it removes the CPU
# from under them. They go to "paused (unknown)" and refuse to resume
# with "Resetting the Virtual Machine is required". That is a triple fault,
# one virsh reset and resume away from a working state, but each process
# that talked to them is gone. The cloudlab is libvirt and this export is
# VirtualBox, so the two cannot be up at once.
if command -v virsh >/dev/null; then
	kvm=$(virsh -c qemu:///system list --name --state-running 2>/dev/null | grep -c . || true)
	[ "${kvm:-0}" -eq 0 ] ||
		die "$kvm KVM guest(s) are running; VirtualBox would wedge them. Halt them first: vm/cloudlab/lab.sh down"
fi
[ -f "$ROOT/EVALUATION_NOTICE.txt" ] || die "EVALUATION_NOTICE.txt missing"
if [ "${PF_APPLIANCE_IN_RELEASE:-}" != 1 ] && [ -e "$dir/SHA256SUMS" ]; then
	die "$dir is a finished release; its SHA256SUMS would not cover the images. Use make release APPLIANCE=1"
fi
# shellcheck source=/dev/null
. "$ROOT/vm/pi/net.env"
mkdir -p "$dir"

stage=$(mktemp -d)
vb="" clone=""
cleanup() {
	local rc=$?
	rm -rf "$stage"
	if [ -n "$clone" ] && VBoxManage showvminfo "$clone" >/dev/null 2>&1; then
		VBoxManage unregistervm "$clone" --delete >/dev/null 2>&1 || true
	fi
	if [ -n "$vb" ]; then
		VBoxManage controlvm "$vb" poweroff >/dev/null 2>&1 || true
		sleep 3
		VBoxManage snapshot "$vb" restore "$SNAP" >/dev/null 2>&1 || true
		VBoxManage snapshot "$vb" delete "$SNAP" >/dev/null 2>&1 || true
		echo "appliance: $vb restored to its pre-export snapshot" >&2
	fi
	exit "$rc"
}
trap cleanup EXIT

cp "$ROOT"/vm/appliance/* "$stage/"
cp "$ROOT/EVALUATION_NOTICE.txt" "$stage/"
if [ -f "$dir/pf-linux-amd64" ]; then
	cp "$dir/pf-linux-amd64" "$stage/pf"
else
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$stage/pf" ./cmd/pf)
fi

state() { VBoxManage showvminfo "$1" --machinereadable | sed -n 's/^VMState="\(.*\)"$/\1/p'; }

# export_vm ROLE VAGRANT_NAME VBOX_NAME PROVISIONERS
export_vm() {
	local role=$1 name=$2 box=$3 prov=$4 out i sf rule
	out="$dir/pi-fortress-$role-$ver.ova"
	[ ! -e "$out" ] || die "$out exists"
	VBoxManage showvminfo "$box" >/dev/null 2>&1 || die "no VM $box; run make up (and make agent-up) first"
	VBoxManage showvminfo "$box-appliance" >/dev/null 2>&1 && die "$box-appliance exists from an earlier run; unregistervm --delete it"
	(cd "$ROOT" && vagrant up "$name" --no-provision)
	vb=$box
	# Not --live: it saves RAM in passes while the guest runs, and it stops
	# with VERR_SSM_TOO_MANY_PASSES when the guest dirties pages faster. The
	# fence does that (tailers, dnsmasq, the blocklist compile). The VM is
	# powered off below in any case, so a brief pause here costs nothing.
	VBoxManage snapshot "$box" take "$SNAP"

	(cd "$ROOT" && vagrant provision "$name" --provision-with "$prov")
	(cd "$ROOT" && vagrant ssh "$name" -c "rm -rf /tmp/pf-appliance")
	(cd "$ROOT" && vagrant upload "$stage" /tmp/pf-appliance "$name")
	(cd "$ROOT" && vagrant ssh "$name" -c "sudo bash -c 'bash /tmp/pf-appliance/install.sh $role && /usr/local/lib/pi-fortress/appliance/seal-image.sh $role && /usr/local/lib/pi-fortress/appliance/image-lint.sh $role'") ||
		die "$role: install, seal or image-lint failed; nothing exported"

	VBoxManage controlvm "$box" acpipowerbutton
	for i in $(seq 1 90); do
		[ "$(state "$box")" = poweroff ] && break
		sleep 2
	done
	[ "$(state "$box")" = poweroff ] || die "$box did not power off"

	clone=$box-appliance
	VBoxManage clonevm "$box" --name "$clone" --mode machine --register
	VBoxManage showvminfo "$clone" --machinereadable |
		sed -n 's/^SharedFolderNameMachineMapping[0-9]*="\(.*\)"$/\1/p' |
		while read -r sf; do VBoxManage sharedfolder remove "$clone" --name "$sf"; done
	VBoxManage showvminfo "$clone" --machinereadable |
		sed -n 's/^Forwarding([0-9]*)="\([^,]*\),.*$/\1/p' |
		while read -r rule; do VBoxManage modifyvm "$clone" --natpf1 delete "$rule"; done
	VBoxManage modifyvm "$clone" --nic2 intnet --intnet2 "$INTNET_NAME"
	# The agent keeps one NIC, the cable to the fence. Its NAT adapter
	# goes, and so does the host-only management NIC of the lab (nic3). If
	# it stayed, the host of the tester would have a path into the agent VM
	# that the fence never sees. The first export (2026-09-22) shipped it.
	[ "$role" = fence ] || VBoxManage modifyvm "$clone" --nic1 none --nic3 none

	VBoxManage export "$clone" --output "$out" --options manifest,nomacs \
		--vsys 0 --vmname "pi-fortress-$role" --product "pi-fortress $role (evaluation only)" \
		--version "$ver" --eulafile "$ROOT/EVALUATION_NOTICE.txt"
	VBoxManage unregistervm "$clone" --delete
	clone=""

	VBoxManage snapshot "$box" restore "$SNAP"
	VBoxManage snapshot "$box" delete "$SNAP"
	vb=""
	echo "appliance: $out"
}

# The agent first: its provisioning reaches the fence, which stays up.
export_vm agent agent pi-fortress-agent bootstrap,routes
export_vm fence pi pi-fortress bootstrap,apply

install -m 0755 "$ROOT/vm/appliance/import.sh" "$dir/pi-fortress-import.sh"
install -m 0644 "$ROOT/EVALUATION_NOTICE.txt" "$dir/"
echo "appliance: both lab VMs are back at their snapshots, saved; vagrant up resumes them"
