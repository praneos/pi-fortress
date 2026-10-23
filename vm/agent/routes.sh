#!/bin/bash
set -euo pipefail

AGENT_ENV="${PF_AGENT_ENV:-/etc/pi-fortress/agent.env}"
CA_DIR="${PF_CA_DIR:-/etc/pi-fortress}"

sha256_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# CA_SHA256 in agent.env pins the CA that this box trusts. Provisioning
# records it, from PF_CA_SHA256 or (PF_CA_TOFU=1, set only by
# provision.sh) from the first ca.pem that it fetches. After that, each
# boot fetches http://PI_IP/ca.pem again over plain HTTP on the agent
# cable. Without a pin, any device that can answer for PI_IP there could
# give the box a CA of its choice. With a pin, the box gets the CA that it
# already trusts.
record_pin() {
  local sum="$1"
  if grep -q '^CA_SHA256=' "${AGENT_ENV}" 2>/dev/null; then
    sed -i "s/^CA_SHA256=.*/CA_SHA256=${sum}/" "${AGENT_ENV}"
  else
    install -d -m 0755 "${AGENT_ENV%/*}"
    echo "CA_SHA256=${sum}" >>"${AGENT_ENV}"
  fi
  echo "agent: pinned the egress CA, sha256 ${sum}, in ${AGENT_ENV}"
}

# split_certs FILE DIR writes each certificate of FILE to DIR/1.pem,
# DIR/2.pem, ... in the order of the file.
split_certs() {
  awk -v d="$2" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = d "/" n ".pem" }
    f { print > f }
    /-----END CERTIFICATE-----/ { if (f) close(f); f = "" }
  ' "$1"
}

# ca_extends TRUSTED FETCHED succeeds when the box can take FETCHED in
# place of the CA set TRUSTED that it already trusts. pf engine ca rotate
# on the Pi serves such a set. Each certificate in FETCHED must be one of:
#   - a certificate in TRUSTED;
#   - a link: a CA certificate that a certificate in TRUSTED signed;
#   - a root with the key of such a link.
# Thus a new root gets trust only through a signature of a root that the
# box trusts already. A device that answers for the Pi can copy the real
# set and add its own root, but it cannot sign the link for that root.
# FETCHED must also keep one of two roots of TRUSTED:
#   - the newest root: the root with the latest notBefore. When two roots
#     have the same notBefore, the root that comes first in TRUSTED is the
#     newest;
#   - the first root of TRUSTED. The Pi puts the current root first.
# Thus retire after promote (it removes the old root) is accepted. Retire
# before promote (it stops a rotation and removes the next root) is also
# accepted. A set that removes the root that the engine signs with, after
# promote, is refused. Such a set would make the box trust a root that
# the engine does not use, and the box could not take the next set of the
# Pi. A TRUSTED with no root accepts no set.
ca_extends() {
  local trusted="$1" fetched="$2" d f fp h start keys="" known="" got="" late=() n=0 rc=1
  local newest="" newest_start=0 first=""
  command -v openssl >/dev/null 2>&1 || return 1
  d="$(mktemp -d)"
  mkdir -p "${d}/t" "${d}/f"
  split_certs "${trusted}" "${d}/t"
  split_certs "${fetched}" "${d}/f"
  for f in "${d}"/t/*.pem; do
    [[ -f "${f}" ]] || continue
    fp="$(openssl x509 -noout -fingerprint -sha256 -in "${f}" 2>/dev/null)" || fp=""
    known+="${fp}"$'\n'
    # A root: the subject is the issuer.
    h="$(openssl x509 -noout -subject_hash -issuer_hash -in "${f}" 2>/dev/null)" || continue
    [[ -n "${fp}" && "${h%%$'\n'*}" == "${h##*$'\n'}" ]] || continue
    [[ -n "${first}" ]] || first="${fp}"
    start="$(openssl x509 -noout -startdate -in "${f}" 2>/dev/null)" || continue
    [[ "${start}" == notBefore=?* ]] || continue
    start="$(date -u -d "${start#notBefore=}" +%s 2>/dev/null)" || continue
    if [[ -z "${newest}" ]] || ((start > newest_start)); then
      newest="${fp}" newest_start="${start}"
    fi
  done
  for f in "${d}"/f/*.pem; do
    [[ -f "${f}" ]] || continue
    n=$((n + 1))
    if ! fp="$(openssl x509 -noout -fingerprint -sha256 -in "${f}" 2>/dev/null)"; then
      n=0
      break
    fi
    got+="${fp}"$'\n'
    if grep -qxF "${fp}" <<<"${known}"; then
      continue
    fi
    if openssl x509 -noout -ext basicConstraints -in "${f}" 2>/dev/null | grep -q 'CA:TRUE' \
       && openssl verify -CAfile "${trusted}" "${f}" >/dev/null 2>&1; then
      keys+="$(openssl x509 -noout -pubkey -in "${f}" | sha256sum | awk '{print $1}')"$'\n'
      continue
    fi
    late+=("${f}")
  done
  if ((n > 0)); then
    rc=0
    for f in ${late[@]+"${late[@]}"}; do
      if ! grep -qxF "$(openssl x509 -noout -pubkey -in "${f}" 2>/dev/null | sha256sum | awk '{print $1}')" <<<"${keys}"; then
        rc=1
        break
      fi
    done
  fi
  if ((rc == 0)) && ! { [[ -n "${newest}" ]] && grep -qxF "${newest}" <<<"${got}"; } \
     && ! { [[ -n "${first}" ]] && grep -qxF "${first}" <<<"${got}"; }; then
    echo "agent: the fetched CA set keeps neither the newest nor the first pinned root; keeping the pin" >&2
    rc=1
  fi
  rm -rf "${d}"
  return "${rc}"
}

# trust_ca FILE puts each certificate of FILE in the system store as its
# own file. openssl rehash skips a file with more than one certificate.
# It removes the files of a certificate that is no longer in the set.
trust_ca() {
  local store="${PF_CA_STORE:-/usr/local/share/ca-certificates}" d f i=0
  d="$(mktemp -d)"
  split_certs "$1" "${d}"
  install -d -m 0755 "${store}"
  rm -f "${store}"/pi-fortress-egress-*.crt
  for f in "${d}"/*.pem; do
    [[ -f "${f}" ]] || continue
    i=$((i + 1))
    if ((i == 1)); then
      install -m 0644 "${f}" "${store}/pi-fortress-egress.crt"
    else
      install -m 0644 "${f}" "${store}/pi-fortress-egress-${i}.crt"
    fi
  done
  rm -rf "${d}"
}

# pick_ca sets ca to the CA to trust, or "". First it tries the copy on
# the gateway: the engine signs with that CA. /vagrant is the desk
# checkout, and the Pi shares it only in the lab. A real Pi keeps
# generated/ on its own disk, and no ship copies it back. Thus the file
# there is absent or is left over from a lab run. A leftover installed
# cleanly, said "trusted", and then failed all HTTPS requests (Pi,
# 2026-09-21). The files below are for a gateway that does not answer
# yet. With a pin, the script skips a file of any origin that does not
# match it. Thus a mismatch keeps the CA that the box already trusts.
pick_ca() {
  local pin="${CA_SHA256:-}" fetched sum candidate
  ca=""
  if [[ -n "${pin}" && ! "${pin}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "agent: CA_SHA256='${pin}' in ${AGENT_ENV} is not a sha256; trusting no new CA" >&2
    pin=invalid
  fi
  fetched="$(mktemp)"
  if curl -fsS --max-time 5 "http://${PI_IP}/ca.pem" -o "${fetched}" 2>/dev/null \
     && grep -q "BEGIN CERTIFICATE" "${fetched}"; then
    sum="$(sha256_of "${fetched}")"
    if [[ -z "${pin}" && "${PF_CA_TOFU:-0}" == 1 ]]; then
      record_pin "${sum}"
      pin="${sum}"
    fi
    if [[ -z "${pin}" ]]; then
      echo "agent: WARNING: no CA_SHA256 in ${AGENT_ENV}; trusting http://${PI_IP}/ca.pem unpinned. Re-provision, or set CA_SHA256 to the Pi's 'sudo sha256sum /var/lib/pi-fortress/www/ca.pem'." >&2
    fi
    if [[ -z "${pin}" || "${sum}" == "${pin}" ]]; then
      install -D -m 0644 "${fetched}" "${CA_DIR}/egress-ca.pem"
      ca="${CA_DIR}/egress-ca.pem"
    elif [[ "$(sha256_of "${CA_DIR}/egress-ca.pem")" == "${pin}" ]] \
         && ca_extends "${CA_DIR}/egress-ca.pem" "${fetched}"; then
      # A rotation on the Pi (pf engine ca): the pinned set signed the
      # new one. Trust the new set and pin it.
      echo "agent: http://${PI_IP}/ca.pem is a CA set that the pinned CA signed; taking it"
      install -D -m 0644 "${fetched}" "${CA_DIR}/egress-ca.pem"
      record_pin "${sum}"
      ca="${CA_DIR}/egress-ca.pem"
    else
      echo "agent: http://${PI_IP}/ca.pem has sha256 ${sum}, not the pinned ${pin}; keeping the CA already trusted. If the Pi's CA really changed, set CA_SHA256 in ${AGENT_ENV} to its sha256 or re-provision." >&2
    fi
  fi
  rm -f "${fetched}"
  [[ -z "${ca}" ]] || return 0
  local gen_egress=/vagrant/vm/policy/generated/egress-ca.pem gen_mitm=/vagrant/vm/policy/generated/mitm-ca.pem
  if [[ -n "${PF_GEN_DIR:-}" ]]; then
    gen_egress="${PF_GEN_DIR}/egress-ca.pem" gen_mitm="${PF_GEN_DIR}/mitm-ca.pem"
  fi
  local tries="${PF_CA_WAIT:-20}" i
  for ((i = 0; i <= tries; i++)); do
    for candidate in \
      "${gen_egress}" \
      "${CA_DIR}/egress-ca.pem" \
      "${gen_mitm}" \
      "${CA_DIR}/mitm-ca.pem"
    do
      # The first pass also takes the copies on the box. The waits
      # after it are for the generated/ of the lab Pi to appear.
      if ((i > 0)) && [[ "${candidate}" == "${CA_DIR}"/* ]]; then
        continue
      fi
      [[ -f "${candidate}" ]] || continue
      if [[ -n "${pin}" && "$(sha256_of "${candidate}")" != "${pin}" ]]; then
        continue
      fi
      ca="${candidate}"
      return 0
    done
    ((i < tries)) && sleep 2
  done
  return 0
}

# When sourced (by the test), stop at the definitions. In all other uses,
# the script is run.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

if [[ -f /vagrant/vm/pi/net.env ]]; then
  # shellcheck source=/dev/null
  source /vagrant/vm/pi/net.env
elif [[ -f /etc/pi-fortress/net.env ]]; then
  # shellcheck source=/dev/null
  source /etc/pi-fortress/net.env
else
  echo "agent: net.env not found" >&2
  exit 1
fi

# provision.sh writes this: the NIC that faces the Pi, and the address of
# this VM when there is more than one agent. net.env has the address of
# the first agent, and the Pi shares net.env. Thus net.env cannot do it.
if [[ -f "${AGENT_ENV}" ]]; then
  # shellcheck source=/dev/null
  source "${AGENT_ENV}"
fi
AGENT_IP="${PF_AGENT_IP:-${AGENT_IP}}"

# Find by network, not by address. With the VirtualBox NAT adapter cut,
# this must work before anything assigns the address. With more than one
# agent, the address is different for each VM.
INT_IF="$(ip -4 -o addr show to "${AGENT_NET}" 2>/dev/null | awk '{print $2; exit}')"
INT_IF="${INT_IF%%@*}"
NAT_IF="$(ip -4 -o addr show to "${VBOX_NAT_NET}" 2>/dev/null | awk '{print $2; exit}')"
NAT_IF="${NAT_IF%%@*}"

# No interface has an agent address yet. When bridged onto the real
# cable, this is the normal case at boot. Vagrant no longer configures
# the interface, because it would do that over the ssh session that now
# uses it. NET_IF is the interface that faced the Pi at provisioning.
if [[ -z "${INT_IF}" && -n "${NET_IF:-}" && -e "/sys/class/net/${NET_IF}" ]]; then
  ip link set "${NET_IF}" up
  ip addr add "${AGENT_IP}/${AGENT_NET##*/}" dev "${NET_IF}" 2>/dev/null || true
  INT_IF="${NET_IF}"
fi

if [[ -z "${INT_IF}" ]]; then
  echo "agent: no interface on ${AGENT_NET} and no NET_IF to bring up" >&2
  ip -br addr || true
  exit 1
fi
# The nft lock below contains this name. Use the name grammar of render.
if [[ ! "${INT_IF}" =~ ^[A-Za-z][A-Za-z0-9._-]{0,14}$ ]]; then
  echo "agent: '${INT_IF}' is not an interface name the lock can carry" >&2
  exit 1
fi

ok=0
for _ in $(seq 1 30); do
  if ping -c 1 -W 1 "${PI_IP}" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "agent: ${PI_IP} not reachable on ${INT_IF} yet; applying routes anyway" >&2
fi

while ip route del default >/dev/null 2>&1; do
  :
done
ip route add default via "${PI_IP}" dev "${INT_IF}"

if [[ -f /etc/resolv.conf ]]; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
fi
cat >/etc/resolv.conf <<EOF
nameserver ${PI_IP}
EOF
chattr +i /etc/resolv.conf 2>/dev/null || true

install -d -m 0755 /etc/sysctl.d
cat >/etc/sysctl.d/99-pi-fortress-agent.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
sysctl -p /etc/sysctl.d/99-pi-fortress-agent.conf >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
for _v6 in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
  echo 1 >"${_v6}" 2>/dev/null || true
done

install -d -m 0755 /etc/pi-fortress
lock=/etc/nftables.conf
cat >"${lock}" <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet agent_lock {
  chain output {
    type filter hook output priority filter; policy drop;
    meta nfproto ipv6 counter drop
    tcp dport 80 ip daddr != ${PI_IP} counter drop
    udp dport 443 counter drop
    tcp dport 853 counter drop
    udp dport 853 counter drop
    ct state established,related accept
    ct state invalid drop
    oifname != "${INT_IF}" oifname != "lo" counter drop
    ip daddr ${PI_IP} udp dport 53 accept
    ip daddr ${PI_IP} tcp dport 53 accept
    ip daddr ${PI_IP} tcp dport 80 accept
    ip daddr ${PI_IP} icmp type echo-request accept
    tcp dport 443 accept
    tcp dport 22 accept
  }
}
EOF
chmod 0755 "${lock}"
nft -f "${lock}"

pick_ca
if [[ -n "${ca}" ]]; then
  trust_ca "${ca}"
  rm -f /usr/local/share/ca-certificates/pi-fortress-mitm.crt
  update-ca-certificates >/dev/null 2>&1 || true
  echo "agent: trusted egress CA from ${ca}"
else
  echo "agent: egress CA not found yet; HTTPS via TLS inspection will fail until apply on pi" >&2
fi

echo "agent: ${AGENT_IP} default via ${PI_IP} dev ${INT_IF} (NAT_IF=${NAT_IF:-none})"
# The route to the gateway exists from here. The first run of the timer
# possibly came before it.
systemctl start --no-block pi-fortress-agent-clock.timer pi-fortress-agent-clock.service >/dev/null 2>&1 || true
