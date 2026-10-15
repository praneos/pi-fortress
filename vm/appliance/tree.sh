#!/bin/bash
# tree.sh SRC [ROOT]: install the policy tree and the library of apply
# from a checkout, so that pf apply runs with no /vagrant. A sealed fence
# takes the /etc/pi-fortress branch of apply.sh: POLICY=/etc/pi-fortress
# and PI_LIB=/usr/local/lib/pi-fortress. provision.sh copies only part of
# each. install.sh fence runs this script from /vagrant before the seal
# unmounts it. apply_test.sh runs it into a fake ROOT.
#
# generated/ has only the fetched feeds, so a first boot with no network
# still compiles. alert.url (the webhook of the builder) and the enrolment
# and CA files under generated/ stay behind.
set -euo pipefail

SRC="${1:-}"
ROOT="${2:-/}"
ROOT="${ROOT%/}"
if [[ ! -d "${SRC}/vm/pi/lib" || ! -d "${SRC}/vm/policy" ]]; then
  echo "tree.sh: SRC=${SRC} is not a pi-fortress checkout" >&2
  exit 1
fi
etc="${ROOT}/etc/pi-fortress"
lib="${ROOT}/usr/local/lib/pi-fortress"
install -d -m 0755 "${etc}/generated" "${lib}/lib"

for f in "${SRC}"/vm/policy/*; do
  [[ -f "${f}" && "${f##*/}" != alert.url ]] || continue
  install -m 0644 "${f}" "${etc}/"
done
for f in "${SRC}"/vm/policy/generated/*.domains "${SRC}"/vm/policy/generated/*.ips "${SRC}"/vm/policy/generated/feeds.map; do
  [[ -f "${f}" ]] && install -m 0644 "${f}" "${etc}/generated/"
done
install -m 0644 "${SRC}/vm/pi/net.env" "${etc}/net.env"

for f in "${SRC}"/vm/pi/*.service "${SRC}"/vm/pi/*.timer "${SRC}"/vm/pi/*.path "${SRC}"/vm/pi/*.rules "${SRC}/vm/pi/logrotate.conf"; do
  [[ -f "${f}" ]] && install -m 0644 "${f}" "${lib}/"
done
for f in "${SRC}"/vm/pi/*.sh; do
  [[ "${f}" == *_test.sh ]] && continue
  install -m 0755 "${f}" "${lib}/"
done
install -m 0644 "${SRC}"/vm/pi/lib/*.sh "${lib}/lib/"
if [[ -f "${SRC}/vm/agent/setup.sh" ]]; then
  install -m 0644 "${SRC}/vm/agent/setup.sh" "${lib}/agent-setup.sh"
fi
echo "tree.sh: ${SRC} -> ${ROOT:-/}"
