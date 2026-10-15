#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

if ! command -v VBoxManage >/dev/null 2>&1; then
  echo "VirtualBox is not installed (VBoxManage not on PATH)." >&2
  exit 1
fi
if ! command -v vagrant >/dev/null 2>&1; then
  echo "Vagrant is not installed." >&2
  exit 1
fi

vagrant up pi --provider=virtualbox
vagrant up agent --provider=virtualbox
# Named here, not left to autostart. A bare `vagrant up` should not start
# two more VMs for a user who wanted only the Pi and an agent.
vagrant up house --provider=virtualbox
vagrant up desk --provider=virtualbox
echo
echo "VMs are up. Next: make lab-test"
echo "  ssh pi:    vagrant ssh pi"
echo "  ssh agent: vagrant ssh agent"
echo "  ssh house: vagrant ssh house"
echo "  ssh desk:  vagrant ssh desk"
