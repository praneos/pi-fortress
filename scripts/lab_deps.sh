#!/usr/bin/env bash
# Host dependencies for the local lab, on Debian or Ubuntu (apt).
#
#   scripts/lab_deps.sh --check                 what is there and what is missing, no root
#   sudo scripts/lab_deps.sh [libvirt]          KVM lab, vm/cloudlab (docs/cloud_lab.md); the default
#   sudo scripts/lab_deps.sh virtualbox         VirtualBox lab, the root Vagrantfile (docs/lab.md)
#   sudo scripts/lab_deps.sh both
#
# Installs packages only. Lab networks and VMs stay with vm/cloudlab/lab.sh
# and vm/bin/up.sh. Idempotent: run it again at any time.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

COMMON_PKGS=(make git rsync curl ca-certificates gpg lsb-release openssh-client
  shellcheck nftables iptables iproute2 bind9-dnsutils openssl tar)
# libvirt-daemon-driver-interface is only a Recommends of libvirt-daemon-system
# on Ubuntu 26.04. The network validation of vagrant-libvirt calls
# virConnectListAllInterfaces, and dies without it. On Ubuntu 24.04 the driver
# is part of libvirt-daemon and the package does not exist, so
# install_libvirt adds it only when apt has it.
IFACE_PKG=libvirt-daemon-driver-interface
LIBVIRT_PKGS=(qemu-system-x86 qemu-utils libvirt-daemon-system
  libvirt-clients libvirt-dev
  dnsmasq-base ebtables ruby-dev build-essential pkg-config libxml2-dev libxslt1-dev zlib1g-dev)
VIRTUALBOX_PKGS=(virtualbox)
# The apt signing key of HashiCorp comes from the host that it vouches for,
# so its fingerprint is checked before apt trusts it. HashiCorp rotates it
# (this one dates from 2026-09). On a mismatch, confirm the new fingerprint
# with HashiCorp out of band. Then run again with HASHICORP_KEY_FPR set to it.
HASHICORP_KEY_FPR="${HASHICORP_KEY_FPR:-D55C0D1AC78A8D8126CB631CFC9CA96ACA026560}"

die() {
  echo "lab_deps: $*" >&2
  exit 1
}
say() { echo "lab_deps: $*"; }

go_want() {
  local v
  v="$(sed -n 's/^toolchain go//p' "${ROOT}/go.mod")"
  [[ -n "${v}" ]] || v="$(sed -n 's/^go //p' "${ROOT}/go.mod")"
  [[ -n "${v}" ]] || die "no go or toolchain line in go.mod"
  echo "${v}"
}

go_have() {
  local bin
  bin="$(command -v go || true)"
  [[ -n "${bin}" ]] || bin=/usr/local/go/bin/go
  [[ -x "${bin}" ]] || return 0
  GOTOOLCHAIN=local "${bin}" env GOVERSION 2>/dev/null | sed 's/^go//'
}

# GOTOOLCHAIN=local in the Makefile: the host go must be at least the go.mod version.
go_ok() {
  local have want
  have="$(go_have)"
  want="$(go_want)"
  [[ -n "${have}" ]] && [[ "$(printf '%s\n%s\n' "${want}" "${have}" | sort -V | head -1)" == "${want}" ]]
}

check() {
  local mode="$1" missing=0 c
  row() {
    if [[ "$2" == ok ]]; then
      printf '  %-28s ok    %s\n' "$1" "$3"
    else
      printf '  %-28s MISS  %s\n' "$1" "$3"
      missing=$((missing + 1))
    fi
  }
  has() { command -v "$1" >/dev/null 2>&1 && echo ok || echo miss; }

  echo "common"
  if go_ok; then row "go >= $(go_want)" ok "$(go_have)"; else row "go >= $(go_want)" miss "have: $(go_have || true)"; fi
  for c in make git rsync curl ssh shellcheck nft iptables ip dig openssl; do row "${c}" "$(has "${c}")" ""; done
  row vagrant "$(has vagrant)" "$(vagrant --version 2>/dev/null || true)"

  if [[ "${mode}" == libvirt || "${mode}" == both ]]; then
    echo "libvirt (vm/cloudlab)"
    [[ -e /dev/kvm ]] && row /dev/kvm ok "" || row /dev/kvm miss "no hardware virtualisation, or nested virt off"
    for c in virsh qemu-img qemu-system-x86_64; do row "${c}" "$(has "${c}")" ""; done
    if [[ "$(vagrant plugin list 2>/dev/null)" == *vagrant-libvirt* ]]; then row vagrant-libvirt ok ""; else row vagrant-libvirt miss ""; fi
    [[ " $(id -nG) " == *" libvirt "* ]] && row "group libvirt" ok "" || row "group libvirt" miss "or not picked up yet: log in again"
    [[ " $(id -nG) " == *" kvm "* ]] && row "group kvm" ok "" || row "group kvm" miss "or not picked up yet: log in again"
  fi

  if [[ "${mode}" == virtualbox || "${mode}" == both ]]; then
    echo "virtualbox (root Vagrantfile)"
    row VBoxManage "$(has VBoxManage)" "$(VBoxManage --version 2>/dev/null || true)"
    if vboxdrv_loaded; then row "vboxdrv module" ok ""; else row "vboxdrv module" miss "Secure Boot may need the module signed (MOK)"; fi
    [[ " $(id -nG) " == *" vboxusers "* ]] && row "group vboxusers" ok "" || row "group vboxusers" miss "or not picked up yet: log in again"
    if kvm_holds_vtx; then row "kvm enable_virt_at_load=0" miss "KVM holds VT-x at load; VirtualBox VMs will not start"; else row "kvm enable_virt_at_load=0" ok ""; fi
  fi

  echo
  [[ ${missing} -eq 0 ]] && say "nothing missing for ${mode}" || say "${missing} missing; run: sudo $0 ${mode}"
}

# Since kernel 6.12, KVM enables VT-x when its module loads, and VirtualBox
# then fails with VERR_VMX_IN_VMX_ROOT_MODE. enable_virt_at_load=0 delays
# that until the first KVM guest. So both hypervisors can be on one host
# (but not run at the same time).
# Capture, then match: under pipefail, `cmd | grep -q` fails whenever grep
# exits first and cmd dies of SIGPIPE.
vboxdrv_loaded() { [[ "$(lsmod 2>/dev/null)" =~ (^|$'\n')vboxdrv[[:space:]] ]]; }

kvm_holds_vtx() {
  local p=/sys/module/kvm/parameters/enable_virt_at_load
  [[ -r "${p}" ]] && [[ "$(cat "${p}")" == Y ]]
}

install_go() {
  local want arch url tmp sum
  want="$(go_want)"
  if go_ok; then
    say "go $(go_have) already satisfies ${want}"
  else
    arch="$(dpkg --print-architecture)"
    case "${arch}" in amd64 | arm64) ;; *) die "no Go tarball for ${arch}" ;; esac
    url="https://dl.google.com/go/go${want}.linux-${arch}.tar.gz"
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' RETURN
    say "go ${want} from ${url}"
    curl -fsSL -o "${tmp}/go.tgz" "${url}"
    sum="$(curl -fsSL "${url}.sha256")"
    [[ "${sum}" =~ ^[0-9a-f]{64}$ ]] || die "bad checksum from ${url}.sha256"
    echo "${sum}  ${tmp}/go.tgz" | sha256sum -c --quiet || die "go tarball checksum mismatch"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${tmp}/go.tgz"
  fi
  # /usr/local/bin is on the secure_path of sudo. /usr/local/go/bin is not,
  # and vm/cloudlab/bootstrap.sh checks go under sudo.
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

# Primary key fingerprints, one per line. apt trusts each primary key in
# a signed-by file, so a second key that rides along must also fail the check.
key_fprs() {
  gpg --homedir "$1" --show-keys --with-colons "$2" 2>/dev/null |
    awk -F: '$1 == "pub" || $1 == "sub" { k = $1 } $1 == "fpr" && k == "pub" { print $10; k = "" }'
}

install_vagrant() {
  if command -v vagrant >/dev/null 2>&1; then
    say "vagrant $(vagrant --version) already installed"
    return
  fi
  local tmp fprs
  # Distros dropped vagrant after the BSL change. The repo of HashiCorp has
  # it, but lags a new Ubuntu release. So use the last LTS that it serves.
  local codename
  codename="$(lsb_release -cs)"
  if ! curl -fsI "https://apt.releases.hashicorp.com/dists/${codename}/Release" >/dev/null 2>&1; then
    say "HashiCorp has no ${codename} repo yet; using noble"
    codename=noble
  fi
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  curl -fsSL -o "${tmp}/key.asc" https://apt.releases.hashicorp.com/gpg
  fprs="$(key_fprs "${tmp}" "${tmp}/key.asc")"
  [[ "${fprs}" == "${HASHICORP_KEY_FPR}" ]] ||
    die "HashiCorp apt key is ${fprs:-unreadable}, expected ${HASHICORP_KEY_FPR}. If HashiCorp rotated it, confirm the new fingerprint with them and rerun with HASHICORP_KEY_FPR=<it>"
  gpg --homedir "${tmp}" --dearmor --yes -o /usr/share/keyrings/hashicorp.gpg "${tmp}/key.asc"
  echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com ${codename} main" \
    >/etc/apt/sources.list.d/hashicorp.list
  apt-get update
  apt-get install -y vagrant
}

install_libvirt() {
  local had_iface=1 pkgs=("${LIBVIRT_PKGS[@]}")
  if apt-cache show "${IFACE_PKG}" >/dev/null 2>&1; then
    pkgs+=("${IFACE_PKG}")
    dpkg -s "${IFACE_PKG}" >/dev/null 2>&1 || had_iface=0
  fi
  apt-get install -y --no-install-recommends "${pkgs[@]}"
  usermod -aG libvirt,kvm "${USER_NAME}"
  systemctl enable --now libvirtd >/dev/null 2>&1 || true
  # A running libvirtd loads drivers only at start. Restart only when a driver
  # was just installed: the restart leaves libvirtd deaf for a second or two.
  [[ ${had_iface} -eq 1 ]] || systemctl restart libvirtd >/dev/null 2>&1 || true
  if [[ "$(sudo -u "${USER_NAME}" -H vagrant plugin list 2>/dev/null)" != *vagrant-libvirt* ]]; then
    say "vagrant-libvirt plugin (as ${USER_NAME})"
    sudo -u "${USER_NAME}" -H vagrant plugin install vagrant-libvirt
  fi
}

install_virtualbox() {
  apt-get install -y "${VIRTUALBOX_PKGS[@]}"
  usermod -aG vboxusers "${USER_NAME}"
  if [[ -r /sys/module/kvm/parameters/enable_virt_at_load ]]; then
    echo "options kvm enable_virt_at_load=0" >/etc/modprobe.d/pi-fortress-kvm.conf
    if kvm_holds_vtx; then
      REBOOT_NOTE="KVM still holds VT-x: reboot (or unload kvm_intel/kvm_amd and kvm) before vm/bin/up.sh"
    fi
  fi
  if command -v mokutil >/dev/null 2>&1 && [[ "$(mokutil --sb-state 2>/dev/null)" == *enabled* ]] &&
    ! vboxdrv_loaded; then
    REBOOT_NOTE="${REBOOT_NOTE:+${REBOOT_NOTE}; }Secure Boot is on and vboxdrv is not loaded: enrol the MOK key the dkms install asked for, at the next boot"
  fi
}

MODE=libvirt
CHECK=0
for a in "$@"; do
  case "${a}" in
    --check) CHECK=1 ;;
    libvirt | virtualbox | both) MODE="${a}" ;;
    -h | --help)
      sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: ${a} (libvirt | virtualbox | both | --check)" ;;
  esac
done

if [[ ${CHECK} -eq 1 ]]; then
  check "${MODE}"
  exit 0
fi

[[ ${EUID} -eq 0 ]] || die "run with sudo, or --check without it"
command -v apt-get >/dev/null || die "apt only (Debian, Ubuntu)"
USER_NAME="${SUDO_USER:-}"
[[ -n "${USER_NAME}" && "${USER_NAME}" != root ]] ||
  die "run it as your own user through sudo: vagrant plugins and boxes live in that user's home"
if [[ "${MODE}" != virtualbox && ! -e /dev/kvm ]]; then
  die "no /dev/kvm: enable VT-x/AMD-V in firmware, or nested virtualization on a cloud VM"
fi

export DEBIAN_FRONTEND=noninteractive
REBOOT_NOTE=""

say "common packages"
apt-get update
apt-get install -y --no-install-recommends "${COMMON_PKGS[@]}"
install_go
install_vagrant
case "${MODE}" in
  libvirt) install_libvirt ;;
  virtualbox) install_virtualbox ;;
  both)
    install_libvirt
    install_virtualbox
    ;;
esac

echo
sudo -u "${USER_NAME}" -H "${ROOT}/scripts/lab_deps.sh" --check "${MODE}" || true
[[ -z "${REBOOT_NOTE}" ]] || say "NOTE: ${REBOOT_NOTE}"
cat <<EOF

Groups added for ${USER_NAME} apply from the next login (or: newgrp libvirt).
Next:
  libvirt:    sudo vm/cloudlab/bootstrap.sh --up        (networks, lab up, enrol, smoke test)
  virtualbox: ./vm/bin/up.sh && ./vm/bin/apply.sh && make lab-test
EOF
