#!/usr/bin/env bash
# Try Pi Fortress in the cloud lab, with one command on a new cloud VM
# (Ubuntu 24.04, amd64, nested virtualization on):
#
#   curl -fsSL https://raw.githubusercontent.com/nrnjn42/pi-fortress/main/install-lab.sh | sudo bash
#
# It checks the host, clones the repository as a normal user, then runs
# vm/cloudlab/bootstrap.sh --up: host packages, the lab networks, the
# gateway and agent VMs, one enrolled agent and a smoke test. Manual:
# docs/cloud_lab.md. The lab makes its own networks on the host, so use a
# machine that you can give to it.
#
# Settings (environment):
#   PF_LAB_USER  user that runs the lab. Default: the user that ran sudo,
#                or a new user `pflab` when you are logged in as root.
#   PF_LAB_DIR   checkout directory. Default: ~PF_LAB_USER/pi-fortress.
#   PF_REPO      default https://github.com/nrnjn42/pi-fortress
#   PF_REF       branch or tag to clone. Default: main.
#
# The whole script is in main(), and main runs on the last line. Thus a
# download that stops part-way runs nothing. Under `curl | bash` stdin is
# the script itself, so each step reads /dev/null instead.
set -euo pipefail

PF_REPO="${PF_REPO:-https://github.com/nrnjn42/pi-fortress}"
PF_REF="${PF_REF:-main}"

die() {
  echo "install-lab: $*" >&2
  exit 1
}

# To stderr: lab_user prints its result on stdout.
note() {
  echo "install-lab: $*" >&2
}

check_host() {
  [[ "$(uname -s)" == Linux ]] || die "Linux only"
  [[ "$(uname -m)" == x86_64 ]] || die "amd64 (x86_64) only: the lab VMs are amd64 (this host is $(uname -m))"
  command -v apt-get >/dev/null || die "apt only: use Ubuntu 24.04 (Debian may work)"
  local id="" ver=""
  # shellcheck disable=SC1091
  [[ -r /etc/os-release ]] && { id="$(. /etc/os-release && echo "${ID:-}")"; ver="$(. /etc/os-release && echo "${VERSION_ID:-}")"; }
  [[ "${id}" == ubuntu && "${ver}" == 24.04 ]] ||
    note "this host is ${id:-unknown} ${ver}; the lab is tested on Ubuntu 24.04. Continuing."
  [[ -e /dev/kvm ]] ||
    die "no /dev/kvm: this machine cannot run VMs. Use a bare-metal machine, or a cloud VM with nested virtualization on (GCP: --enable-nested-virtualization; AWS: a .metal instance)"
  local mem_kb
  mem_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
  (( mem_kb >= 7 * 1024 * 1024 )) ||
    die "$(( mem_kb / 1024 / 1024 )) GB RAM; the lab needs 8 GB (16 GB recommended)"
}

check_disk() {
  local dir="$1" free_gb
  free_gb="$(df -BG --output=avail "${dir}" | tail -1 | tr -dc '0-9')"
  (( free_gb >= 60 )) || die "${free_gb} GB free on ${dir}; the lab needs about 100 GB (60 GB with one agent VM)"
  (( free_gb >= 100 )) || note "${free_gb} GB free on ${dir}; about 100 GB is recommended"
}

lab_user() {
  local u="${PF_LAB_USER:-${SUDO_USER:-}}"
  if [[ -z "${u}" || "${u}" == root ]]; then
    u=pflab
    if ! id "${u}" >/dev/null 2>&1; then
      note "logged in as root; making the user ${u} to run the lab (vagrant refuses root)"
      useradd --create-home --shell /bin/bash "${u}"
    fi
  fi
  id "${u}" >/dev/null 2>&1 || die "no user ${u}"
  echo "${u}"
}

main() {
  [[ "$(id -u)" -eq 0 ]] || die "run with sudo: curl -fsSL <url>/install-lab.sh | sudo bash"
  check_host

  local user home dir
  user="$(lab_user)"
  home="$(getent passwd "${user}" | cut -d: -f6)"
  [[ -d "${home}" ]] || die "no home directory for ${user}"
  dir="${PF_LAB_DIR:-${home}/pi-fortress}"
  check_disk "${home}"

  note "this takes a while (packages, a Go toolchain, VM images, then the VMs). If your SSH session can drop, stop now and run it again inside tmux."

  if ! command -v git >/dev/null; then
    note "installing git"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git ca-certificates
  fi

  if [[ -d "${dir}/.git" ]]; then
    note "using the existing checkout ${dir} ($(runuser -u "${user}" -- git -C "${dir}" rev-parse --short HEAD)); to update it: git -C ${dir} pull"
  else
    [[ ! -e "${dir}" ]] || die "${dir} exists and is not a git checkout; move it, or set PF_LAB_DIR"
    note "cloning ${PF_REPO} (${PF_REF}) into ${dir}"
    runuser -u "${user}" -- git clone --quiet --depth 1 --branch "${PF_REF}" "${PF_REPO}" "${dir}"
  fi

  # bootstrap.sh runs the host half as root, then the lab as SUDO_USER.
  SUDO_USER="${user}" "${dir}/vm/cloudlab/bootstrap.sh" --up

  local login="sudo -iu ${user}"
  [[ "${SUDO_USER:-}" == "${user}" ]] && login="(you are ${user})"
  cat <<EOF

install-lab: the lab is up. Next, as ${user} ${login}:

  cd ${dir}
  vm/cloudlab/lab.sh status
  vm/cloudlab/lab.sh ssh agent      # the agent VM; its only way out is the gateway
  vm/cloudlab/lab.sh ssh pi         # the gateway VM: sudo pf status

Then follow "Getting started" from step 2:
  https://github.com/nrnjn42/pi-fortress/blob/main/docs/user_guide/getting_started.md

Remove the lab:
  vm/cloudlab/lab.sh destroy && sudo vm/cloudlab/lab.sh host-clean
EOF
}

main "$@" </dev/null
