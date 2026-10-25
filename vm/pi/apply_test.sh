#!/bin/bash
# Renders the nft ruleset that apply.sh loads, without root or a Pi. It
# checks two things. With no house segment, the output is byte-for-byte
# the golden file: the agent fence never drifts. With a house segment,
# each golden line is still present in order, and the house rules are at
# their correct positions.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
apply="${here}/apply.sh"
golden="${here}/testdata/nft.no-house.golden"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

cat >"${tmp}/net.env" <<'EOF'
AGENT_NET=10.77.0.0/24
PI_IP=10.77.0.1
AGENT_IP=10.77.0.10
DNS_UPSTREAM=9.9.9.9
EOF

render() {
  PF_NET_ENV="${tmp}/net.env" PF_HOUSE_ENV="${1}" PF_SEGMENTS_DIR="${2:-/nonexistent}" \
    PF_INT_IF="${PF_INT_IF:-eth0}" PF_WAN_IF=wlan0 \
    PF_ELEMENTS='elements = { 203.0.113.9 }' PF_DOH_ELEMENTS='elements = { 198.51.100.7 }' \
    PF_DIRECT_ELEMENTS='elements = { 203.0.113.64/26 }' \
    PF_HOUSE_DIRECT_ELEMENTS='elements = { 198.51.100.128/28 }' \
    bash "${apply}" --render-nft
}

fail() { echo "apply_test: $*" >&2; exit 1; }

render /nonexistent/house.env >"${tmp}/no-house.nft"
if ! diff -u "${golden}" "${tmp}/no-house.nft"; then
  fail "no-house ruleset drifted from testdata/nft.no-house.golden"
fi

# With a checkout, the lists come from the checkout. Apply names that tree
# when a list in /etc/pi-fortress differs from it. It is quiet when the
# copies are equal or when /etc/pi-fortress has no copy. The copy of apply
# in a temp tree stops at the lib lookup; the line comes before that. A box
# with a /vagrant checkout uses that tree, so the check skips there.
if [[ ! -f /vagrant/vm/pi/net.env ]]; then
  pt="${tmp}/pt"
  mkdir -p "${pt}/vm/pi" "${pt}/vm/policy" "${tmp}/pt-etc"
  cp "${apply}" "${pt}/vm/pi/apply.sh"
  cp "${tmp}/net.env" "${pt}/vm/pi/net.env"
  for _n in a b c d e f g; do
    echo "${_n}.example" >"${pt}/vm/policy/${_n}.domains"
  done
  echo "192.0.2.1" >"${pt}/vm/policy/blacklist.ips"
  tree_run() {
    PF_TEST_ETC="${tmp}/pt-etc" PF_NET_ENV_LOCAL=/nonexistent \
      bash "${pt}/vm/pi/apply.sh" --render-nft 2>&1 || true
  }
  tree_run | grep -q 'lists come from' && fail "tree warning with no copy in /etc/pi-fortress"
  cp "${pt}/vm/policy/"* "${tmp}/pt-etc/"
  tree_run | grep -q 'lists come from' && fail "tree warning when the copies are equal"
  echo "203.0.113.5" >>"${tmp}/pt-etc/blacklist.ips"
  tree_run | grep -qxF "pi-fortress: lists come from ${pt}/vm/policy, not ${tmp}/pt-etc; these differ: blacklist.ips" ||
    fail "no tree warning for a changed /etc copy: $(tree_run)"
  for _n in a b c d e f g; do
    echo "x.example" >>"${tmp}/pt-etc/${_n}.domains"
  done
  tree_run | grep -qxF "pi-fortress: lists come from ${pt}/vm/policy, not ${tmp}/pt-etc; these differ: a.domains b.domains c.domains d.domains e.domains (+3 more)" ||
    fail "the tree warning is not bounded: $(tree_run)"
fi

cat >"${tmp}/house.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_ADMIN_IP=10.78.0.20
EOF
render "${tmp}/house.env" >"${tmp}/house.nft"

# Each golden line stays, in order (the agent block does not change).
if ! grep -vxF -f <(grep -v '^$' "${tmp}/house.nft") "${golden}" | grep -v '^$' | grep -q .; then
  :
else
  fail "a golden line is missing from the house ruleset"
fi

want() {
  grep -qF -- "$1" "${tmp}/house.nft" || fail "missing: $1"
}
want 'iifname "eth0" oifname "eth1" counter drop'
want 'iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept'
want 'iifname "eth1" oifname "eth0" counter drop'
want 'iifname "eth1" oifname "wlan0" accept'
want 'iifname "eth1" udp dport 443 counter drop'
want 'iifname "eth1" udp dport 53 reject with icmp type port-unreachable'
want 'iifname "eth1" tcp dport 53 reject with tcp reset'
want 'iifname "eth1" ip daddr @blacklist_v4 counter drop'
want 'iifname "eth1" udp sport 68 udp dport 67 accept'
# The house gate feeds from and checks its own set, on both web ports.
want 'set resolved_house_v4 {'
want 'iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop'
# Strict egress (the default): the gateway checks each new TLS flow by
# name. It drops a port that is not an allowed port. A local address
# (this includes the uplink router) is never a house destination.
want 'iifname "eth1" tcp dport { 443, 465, 993, 5223, 5228, 8443 } ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @reserved_v4 ct mark set ct mark and 0xff0fffff or 0x00100000'
want 'iifname "eth1" ip daddr @reserved_v4 counter drop'
want 'iifname "eth1" jump house_egress'
want 'chain house_egress {'
want 'iifname "eth1" ct mark and 0x00f00000 == 0x00100000 counter queue num 1'
# Each segment reads its own direct-IP list. The house elements go only
# into the house set. The agent elements do not go into it.
awk '/set house_direct_ip_v4/,/^  }/' "${tmp}/house.nft" >"${tmp}/house-direct-set.nft"
grep -qF '198.51.100.128/28' "${tmp}/house-direct-set.nft" || fail "house_direct_ip.allow elements did not land in house_direct_ip_v4"
grep -qF '203.0.113.64/26' "${tmp}/house-direct-set.nft" && fail "direct_ip.allow elements leaked into house_direct_ip_v4"
awk '/set direct_ip_v4/,/^  }/' "${tmp}/house.nft" | grep -qF '198.51.100.128/28' && fail "house_direct_ip.allow elements leaked into direct_ip_v4"
grep -q 'iifname "eth1" .*@direct_ip_v4' "${tmp}/house.nft" && fail "the house gate still reads the agent's direct_ip_v4"
want 'iifname "eth1" tcp dport 53 meter house_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop'
want 'iifname "eth1" udp dport 53 meter house_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop'
want 'iifname "eth1" ip saddr 10.78.0.20 tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept'
want 'ip saddr 10.78.0.0/24 oifname "wlan0" counter masquerade'
want 'log prefix "pi-fortress house-drop: "'

# Isolation comes before all agent forward rules. The first match is in
# forward; isolate_ct has the same drop for established flows.
iso="$(grep -n 'iifname "eth0" oifname "eth1" counter drop' "${tmp}/house.nft" | head -1 | cut -d: -f1)"
want 'ct state established jump isolate_ct'
agent="$(grep -n 'iifname "eth0" meta nfproto ipv6 counter drop' "${tmp}/house.nft" | tail -1 | cut -d: -f1)"
[[ "${iso}" -lt "${agent}" ]] || fail "isolation rule is not before the agent forward block"

# The house never reaches the engine or the CA server.
if grep -q 'iifname "eth1" tcp dport 8080' "${tmp}/house.nft" || grep -q 'iifname "eth1" tcp dport 80 accept' "${tmp}/house.nft"; then
  fail "house input reaches 8080 or 80"
fi
if grep -q 'iifname "eth1" tcp dport 443 redirect' "${tmp}/house.nft"; then
  fail "house 443 is redirected into the engine"
fi

# HOUSE_SSH_TO: when it is not set, the house->agent ssh hole above goes
# to AgentIP only. This is byte-for-byte what an existing house.env always
# rendered (the `want` line above proved that). When it is set, it
# replaces AgentIP as the destination. Reason: AGENT_COUNT can put more
# than one VM on the agent segment. The admin machine must reach all of
# them, not only the first.
cat >"${tmp}/house-sshto.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_ADMIN_IP=10.78.0.20
HOUSE_SSH_TO=10.77.0.10-10.77.0.12
EOF
render "${tmp}/house-sshto.env" >"${tmp}/house-sshto.nft"
grep -qF 'iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept' "${tmp}/house-sshto.nft" \
  || fail "HOUSE_SSH_TO did not widen the house->agent hole"
grep -qF 'ip daddr 10.77.0.10 tcp dport 22 ct state new accept' "${tmp}/house-sshto.nft" \
  && fail "HOUSE_SSH_TO set still rendered the old single-AgentIP hole"

# Only the ip saddr pin opens the hole, not this key. Thus HOUSE_SSH_TO
# with no HOUSE_ADMIN_IP must render no house->agent ssh rule.
cat >"${tmp}/house-sshto-noadmin.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_SSH_TO=10.77.0.10-10.77.0.12
EOF
render "${tmp}/house-sshto-noadmin.env" >"${tmp}/house-sshto-noadmin.nft"
grep -q 'ip daddr 10.77.0.10-10.77.0.12 tcp dport 22' "${tmp}/house-sshto-noadmin.nft" \
  && fail "HOUSE_SSH_TO without HOUSE_ADMIN_IP rendered a hole"

# The check for HOUSE_SSH_TO uses AGENT_NET, the fence that holds its
# addresses, not HOUSE_NET. The refusals are the same as for SSH_TO of a segment.
cat >"${tmp}/house-ssh-outside.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_SSH_TO=10.77.0.10-10.78.0.5
EOF
if render "${tmp}/house-ssh-outside.env" >/dev/null 2>"${tmp}/house-ssh-outside.err"; then
  fail "HOUSE_SSH_TO outside AGENT_NET was accepted"
fi
grep -q 'HOUSE_SSH_TO=10.77.0.10-10.78.0.5 is outside AGENT_NET' "${tmp}/house-ssh-outside.err" \
  || fail "HOUSE_SSH_TO outside AGENT_NET refusal has no clear message: $(cat "${tmp}/house-ssh-outside.err")"

# A reversed a-b range loads into nft with no error and matches no packet
# (no address is both >= b and <= a). Refuse it here, not at nft -c.
cat >"${tmp}/house-ssh-backwards.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_SSH_TO=10.77.0.12-10.77.0.10
EOF
if render "${tmp}/house-ssh-backwards.env" >/dev/null 2>"${tmp}/house-ssh-backwards.err"; then
  fail "a backwards HOUSE_SSH_TO range was accepted"
fi
grep -q '10.77.0.12 is above 10.77.0.10' "${tmp}/house-ssh-backwards.err" \
  || fail "backwards HOUSE_SSH_TO refusal has no clear message: $(cat "${tmp}/house-ssh-backwards.err")"

# HOUSE_PRIVATE_DNS: when absent (above) or off, the set and the accept do
# not exist. When on, the accept is after the blacklist and ipv6 drops (a
# DNS-pin hole, never a blocklist hole). It is before the DoH-set and 853
# drops. The gate lets 443 through before its drop. Forward names the
# uplink. When a tunnel exists, forward names the tunnel, never the uplink.
if grep -q 'house_private_dns' "${tmp}/house.nft"; then
  fail "private DNS set rendered without HOUSE_PRIVATE_DNS"
fi
printf 'HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=off\n' >"${tmp}/privoff.env"
PF_HOUSE_PRIVATE_DNS_ELEMENTS='elements = { 76.76.2.0/24 }' render "${tmp}/privoff.env" >"${tmp}/privoff.nft"
printf 'HOUSE_IF=eth1\n' >"${tmp}/privnone.env"
render "${tmp}/privnone.env" >"${tmp}/privnone.nft"
cmp -s "${tmp}/privoff.nft" "${tmp}/privnone.nft" || fail "HOUSE_PRIVATE_DNS=off changed the ruleset"
printf 'HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\n' >"${tmp}/priv.env"
PF_HOUSE_PRIVATE_DNS_ELEMENTS='elements = { 76.76.2.0/24 }' render "${tmp}/priv.env" >"${tmp}/priv.nft"
grep -qF 'set house_private_dns_v4 {' "${tmp}/priv.nft" || fail "private DNS: set missing"
grep -qF '76.76.2.0/24' "${tmp}/priv.nft" || fail "private DNS: elements missing"
acc="$(grep -n 'iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } accept' "${tmp}/priv.nft" | cut -d: -f1)"
dot="$(grep -n 'iifname "eth1" tcp dport 853 counter drop' "${tmp}/priv.nft" | cut -d: -f1)"
doh="$(grep -n 'iifname "eth1" ip daddr @dns_bypass_v4 counter drop' "${tmp}/priv.nft" | cut -d: -f1)"
blk="$(grep -n 'iifname "eth1" ip daddr @blacklist_v4 counter drop' "${tmp}/priv.nft" | cut -d: -f1)"
v6="$(grep -n 'iifname "eth1" meta nfproto ipv6 counter drop' "${tmp}/priv.nft" | head -1 | cut -d: -f1)"
[[ -n "${acc}" && -n "${dot}" && "${acc}" -lt "${dot}" ]] || fail "private DNS: accept is not before the 853 drop"
[[ -n "${doh}" && "${acc}" -lt "${doh}" ]] || fail "private DNS: accept is not before the DoH-set drop"
[[ -n "${blk}" && "${acc}" -gt "${blk}" ]] || fail "private DNS: accept is before the blacklist drop"
[[ -n "${v6}" && "${acc}" -gt "${v6}" ]] || fail "private DNS: accept is before the ipv6 drop"
grep -qE 'iifname "eth1" tcp dport 853 ip daddr @house_private_dns_v4 ct state new .* ct mark set' "${tmp}/priv.nft" \
  || fail "private DNS: strict does not check the pins by name"
! grep -qF 'house_private_dns_clients' "${tmp}/priv.nft" \
  || fail "private DNS: the blanket gate exemption is back; the SNI check replaced it"
grep -qF 'iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } oifname "wlan0" accept' "${tmp}/priv.nft" \
  || fail "private DNS: forward accept is not scoped to the uplink"
if grep 'house_private_dns_v4' "${tmp}/priv.nft" | grep -qE 'udp|l4proto'; then
  fail "private DNS: UDP (QUIC, DoQ) to the providers is accepted"
fi
printf 'HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\nWG_IF=wg0\n' >"${tmp}/privwg.env"
PF_HOUSE_PRIVATE_DNS_ELEMENTS='elements = { 76.76.2.0/24 }' render "${tmp}/privwg.env" >"${tmp}/privwg.nft"
grep -qF 'iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } oifname "wg0" accept' "${tmp}/privwg.nft" \
  || fail "private DNS with WG_IF: forward accept does not name the tunnel"
if grep 'house_private_dns_v4' "${tmp}/privwg.nft" | grep -qF '"wlan0"'; then
  fail "private DNS with WG_IF: an accept names the uplink, round the kill-switch"
fi
grep -qF 'log prefix "pi-fortress house-killswitch: "' "${tmp}/privwg.nft" || fail "private DNS with WG_IF: kill-switch lost"

# apply.sh refuses two interfaces that collide.
cat >"${tmp}/bad.env" <<'EOF'
HOUSE_IF=eth0
EOF
if render "${tmp}/bad.env" >/dev/null 2>&1; then
  fail "HOUSE_IF equal to INT_IF was accepted"
fi

# apply.sh refuses PI_IP on the uplink. The agent rules would open the WAN.
if PF_NET_ENV="${tmp}/net.env" PF_HOUSE_ENV=/nonexistent/house.env PF_INT_IF=wlan0 PF_WAN_IF=wlan0 PF_ELEMENTS='elements = { 203.0.113.9 }' PF_DOH_ELEMENTS='elements = { 198.51.100.7 }' bash "${apply}" --render-nft >/dev/null 2>"${tmp}/same.err"; then
  fail "INT_IF equal to WAN_IF was accepted"
fi
grep -q "INT_IF and WAN_IF are both wlan0" "${tmp}/same.err" || fail "INT_IF == WAN_IF refusal has no clear message"

# apply.sh parses house.env and never sources it. It refuses each of these
# and names the line: a shell metacharacter, an unknown key, a bad address, a stray line.
refuse() {
  printf '%s\n' "$2" >"${tmp}/refuse.env"
  if render "${tmp}/refuse.env" >/dev/null 2>"${tmp}/refuse.err"; then
    fail "house.env accepted: $2"
  fi
  grep -q "refuse.env:1: $1" "${tmp}/refuse.err" || fail "house.env refusal for '$2' lacks '$1': $(cat "${tmp}/refuse.err")"
}
refuse 'HOUSE_IF is not an interface name' "HOUSE_IF='eth0;reboot'"
refuse 'HOUSE_IF is not an interface name' 'HOUSE_IF=eth0;reboot'
refuse 'HOUSE_IF is not an interface name' 'HOUSE_IF=$(id)'
refuse 'HOUSE_IF is not an interface name' 'HOUSE_IF=abcdefghijklmnop'
refuse "unknown key 'PATH'" 'PATH=/tmp'
refuse 'HOUSE_ADMIN_IP is not an IPv4 address' 'HOUSE_ADMIN_IP=10.78.0.999'
refuse 'HOUSE_NET is not an IPv4 CIDR' 'HOUSE_NET=10.78.0.0'
refuse 'HOUSE_SSH_TO is not an IPv4 address or a-b range' 'HOUSE_SSH_TO=10.77.0.0/24'
refuse 'not KEY=VALUE' 'reboot'
refuse 'HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS' 'HOUSE_DEV_MODE=on'
refuse 'HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS' 'HOUSE_DEV_MODE=off'
refuse 'HOUSE_PRIVATE_DNS is not on or off' 'HOUSE_PRIVATE_DNS=yes'

# Comments, blank lines and empty optional values still parse.
cat >"${tmp}/ok.env" <<'EOF'
# a comment

HOUSE_IF=enx00e04c680001
HOUSE_ADMIN_IP=
HOUSE_DNS_UPSTREAM=1.1.1.1
EOF
render "${tmp}/ok.env" >"${tmp}/ok.nft" || fail "valid house.env refused"
grep -qF 'iifname "enx00e04c680001" tcp dport 53 accept' "${tmp}/ok.nft" || fail "valid house.env did not render"

# Plain segments (docs/user_guide/pi_setup.md). An empty segments.d renders
# the golden byte-for-byte. The no-house diff above already proved this
# for an absent directory.
mkdir -p "${tmp}/empty.d"
render /nonexistent/house.env "${tmp}/empty.d" >"${tmp}/empty.nft"
if ! diff -u "${golden}" "${tmp}/empty.nft"; then
  fail "an empty segments.d drifted from testdata/nft.no-house.golden"
fi

mkdir -p "${tmp}/desk.d"
cat >"${tmp}/desk.d/desk.env" <<'EOF'
IF=eth0.79
NET=10.79.0.0/30
IP=10.79.0.1
ADMIN=yes
SSH_TO=10.77.0.10-10.77.0.12
EOF
render /nonexistent/house.env "${tmp}/desk.d" >"${tmp}/desk.nft"

seg() {
  grep -qF -- "$1" "${tmp}/desk.nft" || fail "desk: missing: $1"
}
seg 'iifname "eth0.79" meta nfproto ipv6 counter drop'
seg 'iifname "eth0.79" ip daddr @blacklist_v4 counter drop'
seg 'iifname "eth0.79" tcp dport 22 ct state new meter seg_desk_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop'
seg 'iifname "eth0.79" tcp dport 22 ct state new accept'
seg 'iifname "eth0.79" icmp type echo-request meter seg_desk_ping { ip saddr limit rate over 10/second burst 20 packets } counter drop'
seg 'iifname "eth0.79" ct state new add @seg_desk_conn_v4 { ip saddr ct count over 128 } jump seg_desk_connlimit'
seg 'iifname "eth0.79" icmp type echo-request accept'
seg 'iifname "eth0" oifname "eth0.79" counter drop'
seg 'iifname "eth0.79" oifname "eth0" ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept'
seg 'iifname "eth0.79" oifname "eth0" counter drop'
seg 'iifname "eth0.79" oifname "wlan0" accept'
seg 'ip saddr 10.79.0.0/30 oifname "wlan0" counter masquerade'

# A plain segment resolves through this box. The port is open behind a
# flood meter. The 80/443 gate has its own set. A lookup to a different
# server gets a reject. The gateway does not NAT it out.
seg 'iifname "eth0.79" tcp dport 53 accept'
seg 'iifname "eth0.79" udp dport 53 accept'
seg 'iifname "eth0.79" tcp dport 53 meter desk_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop'
seg 'iifname "eth0.79" udp dport 53 meter desk_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop'
seg 'iifname "eth0.79" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 ip daddr != 10.77.0.10-10.77.0.12 counter drop'
seg 'iifname "eth0.79" udp dport 53 reject with icmp type port-unreachable'
seg 'iifname "eth0.79" tcp dport 53 reject with tcp reset'
seg '  set resolved_desk_v4 {'
# The port must open before the drop of the chain. If not, the accept is
# in the ruleset but no packet reaches it.
dns53="$(grep -n 'iifname "eth0.79" udp dport 53 accept' "${tmp}/desk.nft" | head -1 | cut -d: -f1)"
segdrop="$(grep -n 'iifname "eth0.79" counter drop' "${tmp}/desk.nft" | head -1 | cut -d: -f1)"
[[ -n "${dns53}" && -n "${segdrop}" && "${dns53}" -lt "${segdrop}" ]] ||
  fail "desk: the resolver port opens after the segment's own drop"
# Without INSPECT=on, a plain segment does not get the TLS fence. Without
# DHCP=on, it gets no DHCP. The desk runs the agent VMs and needs rsync and
# ssh to go through without a break. Its addresses are static.
for pat in 'eth0.79" tcp dport 8080' 'eth0.79" tcp dport 443 redirect' 'eth0.79" udp sport 68'; do
  if grep -qF -- "${pat}" "${tmp}/desk.nft"; then
    fail "desk: plain segment got a policed rule: ${pat}"
  fi
done
if grep 'redirect to' "${tmp}/desk.nft" | grep -q 'eth0.79'; then
  fail "desk: the 443 inspection reached a plain segment"
fi
grep -c 'redirect to :8080' "${tmp}/desk.nft" | grep -qx 1 || fail "desk: the 443 inspection rule count changed"
grep -qF 'iifname "eth0" tcp dport 443 redirect to :8080' "${tmp}/desk.nft" || fail "desk: the 443 inspection left the agent interface"

# INSPECT=on gives the desk the fence of the agent network: its 443 goes
# to the engine, which listens on the desk address (SEG_INSPECT in
# apply.env), and the engine port opens before the drop of the desk.
mkdir -p "${tmp}/inspect.d"
cp "${tmp}/desk.d/desk.env" "${tmp}/inspect.d/desk.env"
echo 'INSPECT=on' >>"${tmp}/inspect.d/desk.env"
PF_ENV_OUT="${tmp}/inspect.env" render /nonexistent/house.env "${tmp}/inspect.d" >"${tmp}/inspect.nft"
grep -qF 'iifname "eth0.79" tcp dport 443 redirect to :8080' "${tmp}/inspect.nft" || fail "inspect: no 443 redirect on the desk"
grep -c 'redirect to :8080' "${tmp}/inspect.nft" | grep -qx 2 || fail "inspect: want one redirect for the agent and one for the desk"
grep -qF "SEG_INSPECT=('on')" "${tmp}/inspect.env" || fail "inspect: apply.env does not carry SEG_INSPECT"
fence="$(grep -n 'iifname "eth0.79" tcp dport 8080 accept' "${tmp}/inspect.nft" | head -1 | cut -d: -f1)"
segdrop="$(grep -n 'iifname "eth0.79" counter drop' "${tmp}/inspect.nft" | head -1 | cut -d: -f1)"
[[ -n "${fence}" && -n "${segdrop}" && "${fence}" -lt "${segdrop}" ]] ||
  fail "inspect: the engine port opens after the desk's own drop"
# --render-nft exits before the env files of the units. The script text
# must send the segment address to the engine and the subnet to the
# broker, through the env files that are fence inputs.
grep -qF -- '-inspect-listen ${SEG_IP[${_i}]}:8080' "${apply}" ||
  fail "inspect: apply does not give the engine the segment address"
grep -qF -- '-fence-net ${SEG_NET[${_i}]}' "${apply}" ||
  fail "inspect: apply does not give the broker the segment subnet"
grep -qF 'ENGINE_INSPECT="${ENGINE_INSPECT} -max-conns 512"' "${apply}" && grep -qF 'BROKER_BUDGET="${BROKER_BUDGET} -max-conns 512"' "${apply}" ||
  fail "inspect: the engine and the broker do not get the same larger cap"

# Isolation is before the agent forward block. Thus the gateway first
# compares a desk packet with the cross-segment rules.
iso="$(grep -n 'iifname "eth0.79" oifname "eth0" counter drop' "${tmp}/desk.nft" | head -1 | cut -d: -f1)"
agent="$(grep -n 'iifname "eth0" udp dport 443 counter drop' "${tmp}/desk.nft" | tail -1 | cut -d: -f1)"
[[ -n "${iso}" && -n "${agent}" && "${iso}" -lt "${agent}" ]] || fail "desk: isolation is not before the agent forward block"

# ADMIN=no and no SSH_TO: neither hole is rendered.
mkdir -p "${tmp}/guest.d"
cat >"${tmp}/guest.d/guest.env" <<'EOF'
IF=eth2
NET=10.80.0.0/24
IP=10.80.0.1
EOF
render /nonexistent/house.env "${tmp}/guest.d" >"${tmp}/guest.nft"
if grep -q 'eth2" tcp dport 22' "${tmp}/guest.nft"; then
  fail "guest: ADMIN defaulted to yes"
fi
if grep -q 'iifname "eth2" oifname "eth0" ip daddr' "${tmp}/guest.nft"; then
  fail "guest: an ssh hole was rendered without SSH_TO"
fi
grep -qF 'iifname "eth2" oifname "eth0" counter drop' "${tmp}/guest.nft" || fail "guest: no drop toward the agent segment"

# Two segments and the house: the gateway drops each pair in both directions.
mkdir -p "${tmp}/both.d"
cp "${tmp}/desk.d/desk.env" "${tmp}/both.d/desk.env"
cp "${tmp}/guest.d/guest.env" "${tmp}/both.d/guest.env"
render "${tmp}/house.env" "${tmp}/both.d" >"${tmp}/both.nft"
while read -r a b; do
  grep -qF -- "iifname \"${a}\" oifname \"${b}\" counter drop" "${tmp}/both.nft" ||
    fail "both: no drop from ${a} to ${b}"
done <<'EOF'
eth0.79 eth2
eth2 eth0.79
eth0.79 eth1
eth1 eth0.79
eth2 eth1
eth1 eth2
eth0 eth0.79
eth0 eth2
EOF

# With a VLAN agent interface, nothing can come from the raw trunk port.
# The gateway drops untagged frames before the conntrack accept. Thus
# they cannot use an established flow.
PF_INT_IF=eth0.20 render /nonexistent/house.env "${tmp}/desk.d" >"${tmp}/trunk.nft"
for chain in input forward; do
  line="$(sed -n "/chain ${chain} {/,/^  }/p" "${tmp}/trunk.nft" | sed -n 3p)"
  [[ "${line}" == '    iifname "eth0" counter drop' ]] ||
    fail "trunk: ${chain} rule 1 is '${line}', not the untagged drop"
done
# Input starts with the DNS flood meters. Thus check all rules before the
# conntrack accept, not rule 1.
for chain in input forward; do
  head="$(sed -n "/chain ${chain} {/,/ct state established,related accept/p" "${tmp}/desk.nft")"
  grep -qx '    ct state established,related accept' <<<"${head}" || fail "trunk: ${chain} has no conntrack accept"
  if grep -qx '    iifname "eth0" counter drop' <<<"${head}"; then
    fail "trunk: an untagged drop was rendered for a non-VLAN INT_IF (${chain}, ahead of the conntrack accept)"
  fi
done

# apply.sh parses segment files and never sources them. It refuses a
# segment that collides with a different interface or range. It does not
# silently merge two trust tiers.
seg_refuse() {
  rm -rf "${tmp}/bad.d"
  mkdir -p "${tmp}/bad.d"
  printf '%s\n' "$3" >"${tmp}/bad.d/$2"
  if render "${tmp}/house.env" "${tmp}/bad.d" >/dev/null 2>"${tmp}/bad.err"; then
    fail "segment accepted: $2 $3"
  fi
  grep -qF "$1" "${tmp}/bad.err" || fail "refusal for '$3' lacks '$1': $(cat "${tmp}/bad.err")"
}
seg_refuse 'IF is not an interface name' one.env 'IF=eth0;reboot'
seg_refuse "unknown key 'PATH'" one.env 'PATH=/tmp'
seg_refuse 'not KEY=VALUE' one.env 'reboot'
seg_refuse 'ADMIN is not yes or no' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=maybe'
seg_refuse 'SSH_TO is not an IPv4 address' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.0/24'
seg_refuse '10.77.0.12 is above 10.77.0.10' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.12-10.77.0.10'
seg_refuse 'IF, NET and IP are all required' one.env 'IF=eth3'
seg_refuse 'is not a segment name' 'Desk.env' $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1'
seg_refuse 'collides with INT_IF' one.env $'IF=eth0\nNET=10.80.0.0/24\nIP=10.80.0.1'
seg_refuse 'collides with INT_IF' one.env $'IF=eth1\nNET=10.80.0.0/24\nIP=10.80.0.1'
seg_refuse 'collides with INT_IF' one.env $'IF=wlan0\nNET=10.80.0.0/24\nIP=10.80.0.1'
seg_refuse 'is not inside NET' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.81.0.1'
seg_refuse 'overlaps AGENT_NET' one.env $'IF=eth3\nNET=10.77.0.0/25\nIP=10.77.0.1'
seg_refuse 'overlaps HOUSE_NET' one.env $'IF=eth3\nNET=10.78.0.128/25\nIP=10.78.0.129'
seg_refuse 'is outside AGENT_NET' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.78.0.5'
seg_refuse 'is outside AGENT_NET' one.env $'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.10-10.78.0.5'

rm -rf "${tmp}/bad.d"
mkdir -p "${tmp}/bad.d"
printf 'IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n' >"${tmp}/bad.d/one.env"
printf 'IF=eth3\nNET=10.81.0.0/24\nIP=10.81.0.1\n' >"${tmp}/bad.d/two.env"
if render "${tmp}/house.env" "${tmp}/bad.d" >/dev/null 2>"${tmp}/bad.err"; then
  fail "two segments on one interface were accepted"
fi
grep -qF 'share IF=eth3' "${tmp}/bad.err" || fail "shared-interface refusal is unclear: $(cat "${tmp}/bad.err")"
printf 'IF=eth4\nNET=10.80.0.0/25\nIP=10.80.0.1\n' >"${tmp}/bad.d/two.env"
if render "${tmp}/house.env" "${tmp}/bad.d" >/dev/null 2>"${tmp}/bad.err"; then
  fail "two segments with overlapping ranges were accepted"
fi
grep -qF 'overlap on' "${tmp}/bad.err" || fail "overlap refusal is unclear: $(cat "${tmp}/bad.err")"

# A VLAN on the house cable is only as isolated as the AP that tags it.
# Thus apply refuses ADMIN, SSH_TO and the agent network there. A
# house-trust segment renders with a warning on stderr and exit 0.
seg_refuse 'segment one: IF=eth1.30 is a VLAN on HOUSE_IF=eth1, and ADMIN=yes' one.env $'IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nADMIN=yes'
seg_refuse 'segment one: IF=eth1.30 is a VLAN on HOUSE_IF=eth1, and SSH_TO=10.77.0.10' one.env $'IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nSSH_TO=10.77.0.10'
if PF_INT_IF=eth1.20 render "${tmp}/house.env" >/dev/null 2>"${tmp}/hv.err"; then
  fail "the agent network on a VLAN of HOUSE_IF was accepted"
fi
grep -qF 'INT_IF=eth1.20 is a VLAN on HOUSE_IF=eth1' "${tmp}/hv.err" || fail "agent-on-house-VLAN refusal is unclear: $(cat "${tmp}/hv.err")"
mkdir -p "${tmp}/iot.d"
printf 'IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n' >"${tmp}/iot.d/iot.env"
render "${tmp}/house.env" "${tmp}/iot.d" >"${tmp}/iot.nft" 2>"${tmp}/iot.err" || fail "a house-trust VLAN on HOUSE_IF was refused: $(cat "${tmp}/iot.err")"
grep -qF 'pi-fortress: WARNING segment iot (IF=eth1.30) rides the house cable (HOUSE_IF=eth1)' "${tmp}/iot.err" || fail "no house-cable warning: $(cat "${tmp}/iot.err")"
grep -qF 'iifname "eth1.30" oifname "eth1" counter drop' "${tmp}/iot.nft" || fail "iot: no drop toward the house"
render "${tmp}/house.env" "${tmp}/desk.d" >/dev/null 2>"${tmp}/desk.err" || fail "the desk VLAN beside the house was refused: $(cat "${tmp}/desk.err")"
if grep -q 'house cable' "${tmp}/desk.err"; then
  fail "warned about a VLAN off the house cable: $(cat "${tmp}/desk.err")"
fi


# DNS over TLS. The keys are in net.env, and apply sources net.env. Thus
# DOT_IPS must stay correct as a shell assignment. Without quotes, the
# shell would run the second address as a command.
dot_env() {
  printf 'AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nAGENT_IP=10.77.0.10\nDNS_UPSTREAM=9.9.9.9\n%s\n' "$1" >"${tmp}/dot.env"
}
dot_render() {
  PF_NET_ENV="${tmp}/dot.env" PF_HOUSE_ENV="${1:-/nonexistent/house.env}" PF_SEGMENTS_DIR=/nonexistent \
    PF_INT_IF=eth0 PF_WAN_IF=wlan0 \
    PF_ELEMENTS='elements = { 203.0.113.9 }' PF_DOH_ELEMENTS='elements = { 198.51.100.7 }' \
    PF_DIRECT_ELEMENTS='elements = { 203.0.113.64/26 }' \
    PF_HOUSE_DIRECT_ELEMENTS='elements = { 198.51.100.128/28 }' \
    bash "${apply}" --render-nft
}

# Off by default: without the two keys, the render must be the golden.
# If not, each box that did not opt in has drifted.
dot_env ''
dot_render >"${tmp}/dot-off.nft" || fail "net.env without the DoT keys was refused"
diff -u "${golden}" "${tmp}/dot-off.nft" >/dev/null || fail "absent DoT keys changed the ruleset"

dot_env $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9 149.112.112.112"'
dot_render >"${tmp}/dot.nft" || fail "a valid DoT net.env was refused"
dotwant() { grep -qF -- "$1" "${tmp}/dot.nft" || fail "missing from the DoT render: $1"; }
dotwant 'meta skuid "pf-dns" ip daddr { 9.9.9.9, 149.112.112.112 } tcp dport 853 accept'
dotwant 'meta skuid "pf-dns" counter drop'
dotwant 'udp dport 53 oifname != "lo" counter drop'
dotwant 'tcp dport 53 oifname != "lo" counter drop'

# The pins have no value above the broker drop (the broker would escape
# through the DoT accept) or outside chain output.
awk '/chain output/,/^  }/' "${tmp}/dot.nft" >"${tmp}/dot-output.nft"
grep -qF 'dport 853 accept' "${tmp}/dot-output.nft" || fail "the DoT pins are not in chain output"
_broker="$(grep -n 'skuid "pf-broker" counter drop' "${tmp}/dot-output.nft" | cut -d: -f1)"
_stub="$(grep -n 'skuid "pf-dns" ip daddr' "${tmp}/dot-output.nft" | cut -d: -f1)"
[[ -n "${_broker}" && -n "${_stub}" && "${_stub}" -gt "${_broker}" ]] || fail "the DoT accept is not below the broker drop"

# Nothing on the segments changes. DoT is about the Pi-to-upstream link,
# and the agent fence must not move. The one exception is the plaintext
# path of the fakeip broker to DNS_UPSTREAM (render fakeIPGate). With DoT
# on, its resolver is the stub on lo, so that accept is correctly absent.
grep -vxF -f <(grep -v '^$' "${tmp}/dot.nft") "${golden}" | grep -v '^$' |
  grep -vF 'meta skuid "pf-broker" ip daddr 9.9.9.9 ' | grep -q . \
  && fail "a golden line is missing from the DoT ruleset"

# With DoT on, each resolver on the box forwards to the loopback stub,
# not to an upstream address. That redirect is the full mechanism. The
# output chain drops plaintext 53 that is not on lo. Thus a forward that
# still points at 9.9.9.9 would give a resolver that answers nothing.
dot_env $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9 149.112.112.112"'
PF_ENV_OUT="${tmp}/dot.env.out" dot_render >/dev/null || fail "DoT render refused with PF_ENV_OUT"
grep -q "^DNS_FORWARD='127.0.0.1'$" "${tmp}/dot.env.out" \
  || fail "DoT is on but the agent resolver still forwards upstream: $(grep '^DNS_FORWARD=' "${tmp}/dot.env.out")"

# A WireGuard house is the only segment on the box that still uses
# plaintext 53. It sends it out through the tunnel: pf dns forwards it to
# 10.64.0.1 over a socket bound to wg0, because an encrypted link goes to
# the far end. Routing selects wg0 before chain output runs. Thus those
# packets have oifname "wg0", not "lo", and pf dns owns them. Without a
# pf-dns carve-out above the pf-dns drop, the house resolves nothing
# while DoT is on (seen 2026-09-23).
printf 'HOUSE_IF=eth1\nWG_IF=wg0\n' >"${tmp}/dot-wg.env"
dot_env $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9"'
dot_render "${tmp}/dot-wg.env" >"${tmp}/dot-wg.nft" || fail "DoT alongside a WireGuard house was refused"
awk '/chain output/,/^  }/' "${tmp}/dot-wg.nft" >"${tmp}/dot-wg-output.nft"
for _p in udp tcp; do
  grep -qF "meta skuid \"pf-dns\" ip daddr 10.64.0.1 ${_p} dport 53 oifname \"wg0\" accept" "${tmp}/dot-wg-output.nft" \
    || fail "wg+DoT: the house's ${_p} forward to the tunnel resolver is dropped by the plaintext pins"
done
_carve="$(grep -n 'ip daddr 10.64.0.1 udp dport 53' "${tmp}/dot-wg-output.nft" | cut -d: -f1)"
_uiddrop="$(grep -n 'skuid "pf-dns" counter drop' "${tmp}/dot-wg-output.nft" | cut -d: -f1)"
_plaindrop="$(grep -n 'udp dport 53 oifname != "lo" counter drop' "${tmp}/dot-wg-output.nft" | cut -d: -f1)"
[[ -n "${_carve}" && -n "${_uiddrop}" && -n "${_plaindrop}" && "${_carve}" -lt "${_uiddrop}" && "${_uiddrop}" -lt "${_plaindrop}" ]] \
  || fail "wg+DoT: the tunnel carve-out is not above the pf-dns drop, which would drop the house's own resolver"
# The carve-out is for the tunnel only. A plaintext 53 accept that names
# the uplink would be exactly the leak that the pins must stop.
grep -q 'dport 53 oifname "wlan0"' "${tmp}/dot-wg-output.nft" \
  && fail "wg+DoT: plaintext 53 is accepted on the uplink"
# A house without a tunnel shares the agent stub over lo. It must get
# nothing here. The golden covers that render.
printf 'HOUSE_IF=eth1\n' >"${tmp}/dot-nowg.env"
dot_render "${tmp}/dot-nowg.env" >"${tmp}/dot-nowg.nft" || fail "DoT with a plain house was refused"
awk '/chain output/,/^  }/' "${tmp}/dot-nowg.nft" | grep -q 'dport 53 oifname "' \
  && fail "wg+DoT: a house with no tunnel gained a plaintext 53 accept"

dot_refuse() {
  dot_env "$2"
  if dot_render >/dev/null 2>"${tmp}/dot.err"; then
    fail "net.env accepted: $2"
  fi
  grep -qF "$1" "${tmp}/dot.err" || fail "DoT refusal for '$2' lacks '$1': $(cat "${tmp}/dot.err")"
}
dot_refuse 'set together or not at all' 'DOT_AUTH_NAME=dns.quad9.net'
dot_refuse 'set together or not at all' 'DOT_IPS="9.9.9.9"'
dot_refuse 'is not a DNS name' $'DOT_AUTH_NAME=quad9\nDOT_IPS="9.9.9.9"'
dot_refuse 'is not a DNS name' $'DOT_AUTH_NAME="dns.quad9.net; reboot"\nDOT_IPS="9.9.9.9"'
dot_refuse 'is not an IPv4 address' $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9 nine.nine"'
dot_refuse 'is not an IPv4 address' $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.999"'
dot_refuse 'lists an address twice' $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9 149.112.112.112 9.9.9.9"'

# Public Wi-Fi uplink (docs/user_guide/public_wifi.md). The key is in net.env, as
# the DoT keys are. Thus this proves that apply exports it to pf render.
# 0 gives the golden. apply refuses 1 without a different way in, because
# 1 closes SSH on the uplink.
dot_env 'UNTRUSTED_UPLINK=0'
dot_render >"${tmp}/uplink-off.nft" || fail "UNTRUSTED_UPLINK=0 was refused"
diff -u "${golden}" "${tmp}/uplink-off.nft" >/dev/null || fail "UNTRUSTED_UPLINK=0 changed the ruleset"
dot_refuse 'is not 0 or 1' 'UNTRUSTED_UPLINK=yes'
dot_refuse 'Nothing was changed.' 'UNTRUSTED_UPLINK=1'
printf 'HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\n' >"${tmp}/uplink-house.env"
dot_env 'UNTRUSTED_UPLINK=1'
dot_render "${tmp}/uplink-house.env" >"${tmp}/uplink.nft" || fail "UNTRUSTED_UPLINK=1 with a house admin was refused"
grep -qE 'iifname "wlan0" (tcp dport 22|icmp)' "${tmp}/uplink.nft" && fail "UNTRUSTED_UPLINK=1 left SSH or ping open on the uplink"
uplinkwant() { grep -qF -- "$1" "${tmp}/uplink.nft" || fail "missing from the UNTRUSTED_UPLINK=1 render: $1"; }
uplinkwant 'iifname "wlan0" udp sport 67 udp dport 68 accept'
uplinkwant 'iifname "wlan0" meta nfproto ipv6 counter drop'
uplinkwant 'oifname "wlan0" udp dport { 5353, 5355 } counter drop'
uplinkwant 'ip saddr 10.78.0.5 tcp dport 22'

# The resolver gate (`docs/fence.md` §5.2). Its position is the main point.
# It is after conntrack, so ct state new holds and a flush on apply does
# not cut live flows. It is before dstnat, so the destination is still the origin.
gate() {
  awk '/chain resolver_gate/,/^  }/' "${tmp}/no-house.nft"
}
gate | grep -qF 'type filter hook prerouting priority -150; policy accept;' || fail "resolver_gate is not a prerouting filter at -150"
# fakeip is the default: the gate passes the pool. When pinned to forward,
# it passes the addresses that pf dns resolved, byte for byte the forward golden.
gate | grep -qF 'iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != 198.18.0.0/16 counter drop' || fail "agent gate rule missing or reshaped"
AGENT_DNS=forward render /nonexistent/house.env >"${tmp}/forward.nft" || fail "AGENT_DNS=forward render was refused"
diff -u "${here}/testdata/nft.no-house.forward.golden" "${tmp}/forward.nft" || fail "AGENT_DNS=forward drifted from testdata/nft.no-house.forward.golden"
awk '/chain resolver_gate/,/^  }/' "${tmp}/forward.nft" | grep -qF 'iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != @resolved_v4 counter drop' || fail "forward agent gate rule missing or reshaped"
[[ "$(gate | grep -c 'counter drop')" -eq 1 ]] || fail "no-house gate has more than the agent rule"
grep -qF 'set resolved_house_v4' "${tmp}/no-house.nft" && fail "house resolved set rendered without a house"
awk '/set resolved_v4/,/^  }/' "${tmp}/no-house.nft" | grep -qF 'flags timeout' || fail "resolved_v4 lacks flags timeout"
awk '/set resolved_v4/,/^  }/' "${tmp}/no-house.nft" | grep -qF 'timeout 2h' || fail "resolved_v4 has no set-level timeout; dnsmasq-added elements would never expire"
awk '/set direct_ip_v4/,/^  }/' "${tmp}/no-house.nft" | grep -qF '203.0.113.64/26' || fail "direct_ip.allow elements did not land in direct_ip_v4"
# Paranoid mode (docs/paranoid_mode.md K5): the agent gate no longer exempts
# @direct_ip_v4 from its drop. Thus the address list of the operator cannot
# skip the forward allow set. The house gate reads @house_direct_ip_v4.
PF_PARANOID=1 render "${tmp}/house.env" >"${tmp}/paranoid.nft" || fail "PARANOID=1 render was refused"
awk '/chain resolver_gate/,/^  }/' "${tmp}/paranoid.nft" >"${tmp}/paranoid-gate.nft"
grep -qF 'iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != 198.18.0.0/16 counter drop' "${tmp}/paranoid-gate.nft" \
  || fail "paranoid: the agent gate still carves out @direct_ip_v4"
grep -qF 'iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop' "${tmp}/paranoid-gate.nft" \
  || fail "paranoid: the house gate lost its @house_direct_ip_v4 carve-out"
grep -qF 'set direct_ip_v4 {' "${tmp}/paranoid.nft" || fail "paranoid: the direct_ip_v4 set is gone"
if PF_PARANOID=2 render "${tmp}/house.env" >/dev/null 2>"${tmp}/paranoid.err"; then
  fail "PARANOID=2 was accepted"
fi
grep -q "PARANOID='2' is not 0 or 1" "${tmp}/paranoid.err" || fail "PARANOID=2 refusal is unclear: $(cat "${tmp}/paranoid.err")"

# PARANOID=on for one plain segment (docs/paranoid_mode.md, plain
# segments). Its resolver enforces it with allow.<name>.domains beside
# segments.d, and its existing gate enforces it. Thus the ruleset does not
# change. apply refuses it without a usable allowlist or with the gate off.
# The PARANOID of the agent and of the desk are independent in both directions.
mkdir -p "${tmp}/pdesk/segments.d"
cp "${tmp}/desk.d/desk.env" "${tmp}/pdesk/segments.d/desk.env"
echo "PARANOID=on" >>"${tmp}/pdesk/segments.d/desk.env"
if render /nonexistent/house.env "${tmp}/pdesk/segments.d" >/dev/null 2>"${tmp}/pdesk.err"; then
  fail "PARANOID=on with no allow.desk.domains was accepted"
fi
grep -qF "${tmp}/pdesk/allow.desk.domains is missing or unreadable" "${tmp}/pdesk.err" ||
  fail "the missing-allowlist refusal does not name the file: $(cat "${tmp}/pdesk.err")"
printf '# the desk\n' >"${tmp}/pdesk/allow.desk.domains"
if render /nonexistent/house.env "${tmp}/pdesk/segments.d" >/dev/null 2>"${tmp}/pdesk.err"; then
  fail "PARANOID=on with an allowlist of comments was accepted"
fi
grep -qF "allow.desk.domains has no usable name" "${tmp}/pdesk.err" || fail "empty-allowlist refusal: $(cat "${tmp}/pdesk.err")"
cp "${here}/allow.segment.domains.example" "${tmp}/pdesk/allow.desk.domains"
PF_ENV_OUT="${tmp}/pdesk.env" render /nonexistent/house.env "${tmp}/pdesk/segments.d" >"${tmp}/pdesk.nft" ||
  fail "a paranoid desk with the shipped seed as its allowlist was refused"
diff -u "${tmp}/desk.nft" "${tmp}/pdesk.nft" || fail "PARANOID=on changed the desk's ruleset"
grep -qxF "SEG_PARANOID=('on')" "${tmp}/pdesk.env" || fail "apply.env: $(cat "${tmp}/pdesk.env")"
grep -qxF "SEG_ALLOW=('${tmp}/pdesk/allow.desk.domains')" "${tmp}/pdesk.env" || fail "apply.env: $(cat "${tmp}/pdesk.env")"
grep -qxF "PARANOID='0'" "${tmp}/pdesk.env" || fail "the desk's PARANOID reached the agent's: $(cat "${tmp}/pdesk.env")"
PF_ENV_OUT="${tmp}/pdesk-agent.env" PF_PARANOID=1 render /nonexistent/house.env "${tmp}/pdesk/segments.d" >"${tmp}/pdesk-agent.nft" ||
  fail "agent and desk paranoid together were refused"
PF_PARANOID=1 render /nonexistent/house.env "${tmp}/desk.d" >"${tmp}/desk-agent.nft" || fail "agent paranoid with a plain desk was refused"
grep -qxF "PARANOID='1'" "${tmp}/pdesk-agent.env" && grep -qxF "SEG_PARANOID=('on')" "${tmp}/pdesk-agent.env" ||
  fail "both armed: $(cat "${tmp}/pdesk-agent.env")"
diff <(grep -F '"eth0.79"' "${tmp}/pdesk.nft") <(grep -F '"eth0.79"' "${tmp}/pdesk-agent.nft") >/dev/null ||
  fail "the agent's PARANOID changed the desk's rules"
diff -u "${tmp}/desk-agent.nft" "${tmp}/pdesk-agent.nft" || fail "the desk's PARANOID changed the ruleset under an armed agent"
cp "${tmp}/pdesk/segments.d/desk.env" "${tmp}/pdesk/desk.env.on"
echo "BLOCK_DIRECT_IP=off" >>"${tmp}/pdesk/segments.d/desk.env"
if render /nonexistent/house.env "${tmp}/pdesk/segments.d" >/dev/null 2>"${tmp}/pdesk.err"; then
  fail "PARANOID=on with BLOCK_DIRECT_IP=off was accepted"
fi
grep -qF "PARANOID=on needs the resolved-address gate" "${tmp}/pdesk.err" || fail "PARANOID=on + BLOCK_DIRECT_IP=off refusal: $(cat "${tmp}/pdesk.err")"
sed 's/^PARANOID=on$/PARANOID=1/' "${tmp}/pdesk/desk.env.on" >"${tmp}/pdesk/segments.d/desk.env"
if render /nonexistent/house.env "${tmp}/pdesk/segments.d" >/dev/null 2>"${tmp}/pdesk.err"; then
  fail "a segment's PARANOID=1 was accepted; segments take on or off"
fi
grep -qF "PARANOID is not on or off" "${tmp}/pdesk.err" || fail "segment PARANOID=1 refusal: $(cat "${tmp}/pdesk.err")"
# The seed: the test copies the function out of apply and runs it as is.
# Each plain segment without an allowlist gets the shipped one. It never
# overwrites a file of the operator. A name that render would refuse
# writes nothing. A box without the seed file does not change.
(
  # shellcheck source=/dev/null
  source <(sed -n '/^seed_segment_allow() {$/,/^}$/p' "${apply}")
  declare -F seed_segment_allow >/dev/null || fail "seed_segment_allow is gone from apply.sh"
  grep -qF 'seed_segment_allow "${PF_SEGMENTS_DIR:-/etc/pi-fortress/segments.d}" "${PI_LIB}/allow.segment.domains.example"' "${apply}" ||
    fail "apply does not seed the segment allowlists from PI_LIB"
  grep -qF 'install -m 0644 "${SRC}"/vm/pi/allow.segment.domains.example /usr/local/lib/pi-fortress/allow.segment.domains.example' "${here}/provision.sh" ||
    fail "provision.sh does not put the segment allowlist seed in PI_LIB"
  sd="${tmp}/seed/segments.d"
  mkdir -p "${sd}"
  printf 'IF=eth0.79\n' >"${sd}/desk.env"
  printf 'IF=eth2\n' >"${sd}/guest.env"
  printf 'IF=eth3\n' >"${sd}/Bad.env"
  printf 'mine.example\n' >"${tmp}/seed/allow.guest.domains"
  seed_segment_allow "${sd}" "${tmp}/no-such-seed"
  [[ ! -e "${tmp}/seed/allow.desk.domains" ]] || fail "seeding ran without a seed file"
  seed_segment_allow "${sd}" "${here}/allow.segment.domains.example"
  cmp -s "${here}/allow.segment.domains.example" "${tmp}/seed/allow.desk.domains" || fail "the desk was not seeded"
  for n in anthropic.com claude.ai claude.com; do
    grep -qxF "${n}" "${tmp}/seed/allow.desk.domains" || fail "the seed lacks ${n}"
  done
  [[ "$(cat "${tmp}/seed/allow.guest.domains")" == mine.example ]] || fail "seeding overwrote an operator's allowlist"
  [[ ! -e "${tmp}/seed/allow.Bad.domains" ]] || fail "a bad segment name was seeded"
  [[ "$(stat -c %a "${tmp}/seed/allow.desk.domains")" == 644 ]] || fail "the seeded allowlist is not 0644, so pf dns cannot read it"
)

# AGENT_DNS=fakeip (internal/render fakeIPGate) goes to pf render from
# the environment of apply. The gate admits the pool where it admitted
# @resolved_v4. apply.env gives AGENT_DNS and FAKEIP_NET back, as checked.
# The golden diff above pins forward mode. That output does not change.
AGENT_DNS=fakeip FAKEIP_NET=100.64.8.0/22 PF_ENV_OUT="${tmp}/fakeip.env" render /nonexistent/house.env >"${tmp}/fakeip.nft" \
  || fail "AGENT_DNS=fakeip render was refused"
grep -qF 'iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != 100.64.8.0/22 counter drop' "${tmp}/fakeip.nft" \
  || fail "fakeip: apply did not pass AGENT_DNS and FAKEIP_NET to pf render; the agent gate is not on the pool"
grep -qF 'pi-fortress broker-blacklist: ' "${tmp}/fakeip.nft" || fail "fakeip: the blocklist did not move to the broker's output"
grep -qx "AGENT_DNS='fakeip'" "${tmp}/fakeip.env" || fail "fakeip: apply.env does not carry AGENT_DNS"
grep -qx "FAKEIP_NET='100.64.8.0/22'" "${tmp}/fakeip.env" || fail "fakeip: apply.env does not carry FAKEIP_NET"
if AGENT_DNS=fakeip FAKEIP_NET=10.77.0.0/24 render /nonexistent/house.env >/dev/null 2>"${tmp}/fakeip.err"; then
  fail "a FAKEIP_NET overlapping AGENT_NET was accepted"
fi
grep -q 'FAKEIP_NET' "${tmp}/fakeip.err" || fail "FAKEIP_NET refusal is unclear: $(cat "${tmp}/fakeip.err")"

# Connection budgets (internal/render/connlimit.go) go from net.env to pf
# render through the exports of apply. An override renders. 0 removes the
# rule. apply refuses a value that render cannot read, before anything loads.
AGENT_CONN_PER_IP=192 AGENT_CONN_TOTAL=0 render /nonexistent/house.env >"${tmp}/conn.nft" \
  || fail "a connection budget override was refused"
grep -qF 'add @agent_conn_v4 { ip saddr ct count over 192 } jump agent_connlimit' "${tmp}/conn.nft" \
  || fail "apply did not pass AGENT_CONN_PER_IP to pf render"
grep -qF 'ct count over 4096' "${tmp}/conn.nft" && fail "AGENT_CONN_TOTAL=0 still renders the segment total"
grep -qF 'ct count over 4096 jump agent_connlimit' "${tmp}/no-house.nft" \
  || fail "the default agent segment total is not in the default render"
if AGENT_NEW_PER_IP=50 render /nonexistent/house.env >/dev/null 2>"${tmp}/conn.err"; then
  fail "AGENT_NEW_PER_IP without a burst was accepted"
fi
grep -q 'AGENT_NEW_PER_IP' "${tmp}/conn.err" || fail "AGENT_NEW_PER_IP refusal is unclear: $(cat "${tmp}/conn.err")"
# The new-flow total for the full house segment.
grep -qF 'iifname "eth1" ct state new meta l4proto tcp limit rate over 1000/second burst 5000 packets jump house_connlimit' \
  "${tmp}/house.nft" || fail "the default house new-flow total is not in the house render"
HOUSE_NEW_TOTAL=2000/8000 render "${tmp}/house.env" | grep -qF 'limit rate over 2000/second burst 8000 packets jump house_connlimit' \
  || fail "apply did not pass HOUSE_NEW_TOTAL to pf render"
# The new-flow total for each plain segment.
grep -qF 'iifname "eth0.79" ct state new meta l4proto tcp limit rate over 300/second burst 600 packets jump seg_desk_connlimit' \
  "${tmp}/desk.nft" || fail "the default desk new-flow total is not in the desk render"
SEG_NEW_TOTAL=400/2000 render /nonexistent/house.env "${tmp}/desk.d" | grep -qF 'limit rate over 400/second burst 2000 packets jump seg_desk_connlimit' \
  || fail "apply did not pass SEG_NEW_TOTAL to pf render"
for _k in AGENT_CONN_PER_IP AGENT_NEW_PER_IP AGENT_CONN_TOTAL HOUSE_CONN_PER_IP HOUSE_NEW_PER_IP HOUSE_CONN_TOTAL \
  HOUSE_NEW_TOTAL SEG_CONN_PER_IP SEG_NEW_PER_IP SEG_CONN_TOTAL SEG_NEW_TOTAL; do
  grep -q "^${_k}=" "${here}/net.env" || fail "net.env does not document ${_k}"
  grep -qF "${_k}=\"\${${_k}:-}\"" "${apply}" || fail "apply.sh does not export ${_k} to pf render"
done

# Resource caps: each
# long-running pf unit has a memory ceiling, a task and file ceiling, and
# an OOM rank. It never stops its restarts. pf dns ranks below the broker,
# so house DNS outlives the fence in a global OOM.
for _u in pf-broker pf-engine dns-agent-go dns-stub@ dns-house observe alert monitor www; do
  _f="${here}/${_u}.service"
  for _d in MemoryHigh MemoryMax TasksMax LimitNOFILE OOMScoreAdjust; do
    _re="^${_d}=[0-9]"
    # alert posts the pressure alert, so the OOM killer takes it last
    # (alert.service). DNS and DHCP keep the house up, so they go late too.
    [[ "${_u}" == alert && "${_d}" == OOMScoreAdjust ]] && _re='^OOMScoreAdjust=-900$'
    [[ "${_u}" == dns-* && "${_d}" == OOMScoreAdjust ]] && _re='^OOMScoreAdjust=-500$'
    grep -qE "${_re}" "${_f}" || fail "${_u}.service has no ${_d}"
  done
  grep -q '^StartLimitIntervalSec=0$' "${_f}" || fail "${_u}.service can give up restarting"
done
# alert keeps memory, CPU and disk time for the pressure alert. The lock
# needs an infinite LimitMEMLOCK (alert.service gives the reason).
for _l in MemoryMin=32M CPUWeight=1000 IOWeight=1000 Nice=-10 LimitMEMLOCK=infinity; do
  grep -qx "${_l}" "${here}/alert.service" || fail "alert.service lacks ${_l}"
done
grep -q '^ProcSubset=pid' "${here}/alert.service" && fail "alert.service hides /proc/pressure and /proc/meminfo from the pressure watch"
# The two daemons that an agent drives back off while a kill loop
# continues. House DNS and DHCP keep a fixed short restart.
for _u in pf-broker pf-engine; do
  grep -q '^RestartSteps=[1-9]' "${here}/${_u}.service" || fail "${_u}.service has no growing restart back-off"
  grep -q '^RestartMaxDelaySec=[1-9]' "${here}/${_u}.service" || fail "${_u}.service back-off has no ceiling"
done
for _u in dns-agent-go dns-stub@ dns-house; do
  grep -q '^RestartSteps=' "${here}/${_u}.service" && fail "${_u}.service backs off; house DNS must restart at once"
done
_oom() { sed -n 's/^OOMScoreAdjust=//p' "${here}/$1.service"; }
(( $(_oom dns-agent-go) < $(_oom pf-broker) )) || fail "pf dns does not rank below the broker for the OOM killer"
(( $(_oom pf-engine) < $(_oom pf-broker) )) || fail "the engine does not rank below the broker for the OOM killer"
# Kill order: fetch, broker, the rest of the fence, unranked processes,
# DNS and DHCP, then alert and sshd.
(( $(_oom fetch) > $(_oom pf-broker) )) || fail "the feed refresh does not go before the broker for the OOM killer"
for _u in dns-agent-go dns-house dns-stub@ dhcp@; do
  (( $(_oom "${_u}") < 0 && $(_oom "${_u}") > $(_oom alert) )) || fail "${_u}.service does not rank between unranked processes and alert"
done
grep -q '^Environment=GOMEMLIMIT=' "${here}/pf-broker.service" || fail "pf-broker.service sets no GOMEMLIMIT"

# apply writes the journal, the connection table and the sshd OOM rank on
# each run. Thus an existing Pi gets them on its next ship.
for _l in 'SystemMaxUse=200M' 'SystemKeepFree=1G' 'RuntimeMaxUse=64M' \
  'net.netfilter.nf_conntrack_max=131072' 'net.netfilter.nf_conntrack_tcp_timeout_established=86400' \
  'net.netfilter.nf_conntrack_tcp_timeout_time_wait=30' \
  'OOMScoreAdjust=-900' '/etc/systemd/journald.conf.d/pi-fortress.conf' \
  '/etc/sysctl.d/97-pi-fortress-conntrack.conf' '/etc/modules-load.d/pi-fortress-conntrack.conf' \
  '/etc/systemd/system/ssh.service.d/pi-fortress.conf'; do
  grep -qF -- "${_l}" "${apply}" || fail "apply.sh does not write ${_l}"
done
grep -qF 'under 1 GiB' "${here}/status.sh" || fail "status.sh does not warn on low disk"

# The gate must run before the redirect rewrites the destination.
_gate_line="$(grep -n 'chain resolver_gate' "${tmp}/no-house.nft" | cut -d: -f1)"
_nat_line="$(grep -n 'type nat hook prerouting priority dstnat' "${tmp}/no-house.nft" | cut -d: -f1)"
[[ -n "${_gate_line}" && -n "${_nat_line}" ]] || fail "gate or nat prerouting chain missing"

# Agent SSH allowlist (docs/ssh_allow.md). Empty is the default. The
# golden diff above already proved that it renders nothing. A list that
# is not empty opens exactly one hole, and only above the two TCP 22 drops.
PF_SSH_ELEMENTS='elements = { 203.0.113.64/26 }' render /nonexistent/house.env >"${tmp}/ssh.nft"
sshwant() { grep -qF -- "$1" "${tmp}/ssh.nft" || fail "ssh: missing: $1"; }
sshwant 'set ssh_allow_v4 {'
sshwant '    flags interval'
sshwant 'iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 accept'
sshwant 'iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 ct state new limit rate 30/minute burst 60 packets log prefix "pi-fortress ssh-allow: " level info counter accept'
grep -qF 'ssh_allow_v4' "${tmp}/no-house.nft" && fail "ssh: an empty list rendered the set or an accept"

# The dest drops still win. The gateway drops a blacklisted or DoH-bypass
# address, also when it is in the allow list.
awk '/chain filter_prerouting/,/^  }/' "${tmp}/ssh.nft" >"${tmp}/ssh-raw.nft"
n() { grep -n -- "$2" "$1" | head -1 | cut -d: -f1; }
_blk="$(n "${tmp}/ssh-raw.nft" '@blacklist_v4 counter drop')"
_doh="$(n "${tmp}/ssh-raw.nft" '@dns_bypass_v4 counter drop')"
_acc="$(n "${tmp}/ssh-raw.nft" '@ssh_allow_v4 accept')"
# Under fakeip (the default), the raw drop skips the pool. For the pool,
# the forward chain sends a TCP reset instead (render fakeIPGate). In
# both modes, the raw drop is below the accept.
_drop="$(n "${tmp}/ssh-raw.nft" 'tcp dport 22 .*counter drop')"
[[ -n "${_blk}" && -n "${_doh}" && -n "${_acc}" && -n "${_drop}" ]] || fail "ssh: a prerouting rule is missing"
[[ "${_blk}" -lt "${_doh}" && "${_doh}" -lt "${_acc}" && "${_acc}" -lt "${_drop}" ]] ||
  fail "ssh: prerouting order is blk=${_blk} doh=${_doh} accept=${_acc} drop=${_drop}"
grep -qF 'ct state' "${tmp}/ssh-raw.nft" \
  && fail "ssh: a ct match reached priority raw, where conntrack has not run"

# forward: established flows never meet the rate limit. The accept is
# the line immediately above the drop that it overrides.
awk '/chain forward/,/^  }/' "${tmp}/ssh.nft" >"${tmp}/ssh-fwd.nft"
_est="$(n "${tmp}/ssh-fwd.nft" 'ct state established,related accept')"
_acc="$(n "${tmp}/ssh-fwd.nft" '@ssh_allow_v4')"
_drop="$(n "${tmp}/ssh-fwd.nft" 'tcp dport 22 counter drop')"
[[ -n "${_est}" && -n "${_acc}" && "${_est}" -lt "${_acc}" ]] || fail "ssh: forward accept is above the conntrack accept"
[[ $((_drop - _acc)) -eq 1 ]] || fail "ssh: forward accept is not immediately before the 22 drop"

# The Pi's own sshd stays closed to the agent segment.
awk '/chain input/,/^  }/' "${tmp}/ssh.nft" | grep -qE 'iifname "eth0".*dport 22' \
  && fail "ssh: the agent segment may reach the Pi on 22"

# The house and the desk keep their own 22 holes, in the other direction.
# The gateway still applies isolation before the egress accept.
mkdir -p "${tmp}/ssh.d"
cp "${tmp}/desk.d/desk.env" "${tmp}/ssh.d/desk.env"
PF_SSH_ELEMENTS='elements = { 203.0.113.64/26 }' render "${tmp}/house.env" "${tmp}/ssh.d" >"${tmp}/ssh-house.nft"
while read -r pat; do
  grep -qF -- "${pat}" "${tmp}/ssh-house.nft" || fail "ssh: the other direction changed: ${pat}"
done <<'EOF'
iifname "eth1" ip saddr 10.78.0.20 tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept
iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept
iifname "eth0.79" oifname "eth0" ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept
EOF
awk '/chain forward/,/^  }/' "${tmp}/ssh-house.nft" >"${tmp}/ssh-house-fwd.nft"
_iso="$(n "${tmp}/ssh-house-fwd.nft" 'iifname "eth0" oifname "eth1" counter drop')"
_acc="$(n "${tmp}/ssh-house-fwd.nft" '@ssh_allow_v4')"
[[ -n "${_iso}" && -n "${_acc}" && "${_iso}" -lt "${_acc}" ]] || fail "ssh: isolation is not before the ssh forward accept"

# The Vagrantfile pins the hypervisor settings on each VM. It gives an
# agent a filtered copy of the checkout. One edit can remove each of these.
_vf="${here}/../../Vagrantfile"
_vms="$(grep -c '^ *vb\.name = ' "${_vf}")"
_pins="$(grep -c 'vb\.customize \["modifyvm", :id, \*VB_LOCKDOWN\]' "${_vf}")"
[[ "${_vms}" -gt 0 && "${_vms}" == "${_pins}" ]] \
  || fail "Vagrantfile: ${_vms} VirtualBox VMs but ${_pins} carry VB_LOCKDOWN"
grep -qF -- '--vrde off' "${_vf}" || fail "Vagrantfile: VB_LOCKDOWN no longer turns vrde off"
grep -qF 'rsync__args: AGENT_RSYNC_ARGS' "${_vf}" || fail "Vagrantfile: the agent share is no longer filtered"
grep -A8 '^AGENT_RSYNC_ARGS' "${_vf}" | grep -qF -- "--exclude=*" \
  || fail "Vagrantfile: AGENT_RSYNC_ARGS does not end in --exclude=*, so it filters nothing"

# The output lock of the agent (vm/agent). The test checks it here because
# this is the only shell harness in the tree. The two copies must stay the
# same. Without the accept, a listed dest never leaves the agent box.
for _lock in "${here}/../agent/routes.sh" "${here}/../agent/setup.sh"; do
  grep -qF 'tcp dport 22 accept' "${_lock}" || fail "agent lock: ${_lock} does not accept TCP 22 toward the Pi"
  if grep -qF 'tcp dport 22 counter drop' "${_lock}"; then
    fail "agent lock: ${_lock} still drops TCP 22 before the Pi decides"
  fi
done

# House WireGuard. The house render without WG
# above still has the unmarked WAN accept. This env must not have it.
cat >"${tmp}/wg.env" <<'EOF'
HOUSE_IF=eth1
HOUSE_ADMIN_IP=10.78.0.20
WG_IF=wg0
EOF
render "${tmp}/wg.env" >"${tmp}/wg.nft" || fail "HOUSE_IF + WG_IF was refused"
wgwant() { grep -qF -- "$1" "${tmp}/wg.nft" || fail "wg: missing: $1"; }
wgwant 'set vpn_bypass_v4 {'
wgwant 'iifname "eth1" ip daddr @vpn_bypass_v4 meta mark set 0x1'
wgwant 'iifname "eth1" oifname "wlan0" meta mark 0x1 counter accept'
wgwant 'iifname "eth1" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu'
wgwant 'iifname "eth1" oifname "wg0" accept'
wgwant 'log prefix "pi-fortress house-killswitch: "'
wgwant 'ip saddr 10.78.0.0/24 oifname "wlan0" counter masquerade'
wgwant 'ip saddr 10.78.0.0/24 oifname "wg0" counter masquerade'
# Isolation and the ssh hole do not change.
wgwant 'iifname "eth0" oifname "eth1" counter drop'
wgwant 'iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept'
if grep -qE 'iifname "eth1" oifname "wlan0" accept$' "${tmp}/wg.nft"; then
  fail "wg: unmarked oifname wlan0 accept is still there (kill switch missing)"
fi
awk '/set vpn_bypass_v4/,/^  }/' "${tmp}/wg.nft" | grep -q 'flags interval' \
  && fail "wg: vpn_bypass_v4 has flags interval; dnsmasq cannot add to it"
# The mark is in filter_prerouting (raw), not forward.
awk '/chain filter_prerouting/,/^  }/' "${tmp}/wg.nft" | grep -qF 'meta mark set 0x1' \
  || fail "wg: bypass mark is not in filter_prerouting"
# The SNI rules clear their own bits in forward, after routing. Only
# the bypass mark itself must be set before it.
awk '/chain forward/,/^  }/' "${tmp}/wg.nft" | grep -qF 'meta mark set 0x1' \
  && fail "wg: bypass mark is in forward (too late for routing)"
# Desk/agent NAT is still WAN_IF. Only the house masquerades on wg0.
grep -qF 'ip saddr 10.77.0.0/24 oifname "wlan0" counter masquerade' "${tmp}/wg.nft" \
  || fail "wg: agent NAT left WAN_IF"

# The other half of the tunnel: the policy routing that wg-routes.sh installs.
# The test runs it here with a stub `ip`. This is sufficient to read back the
# rule set without root, a tunnel or a second machine. Table 100 holds only
# a default route. Thus each selector that reaches it means "into the
# tunnel". The important part is which packets the rules above it pull
# out, and in what order.
routes="${here}/wg-routes.sh"
[[ -x "${routes}" ]] || fail "wg-routes.sh is not executable"
mkdir -p "${tmp}/bin"
cat >"${tmp}/bin/ip" <<'EOF'
#!/bin/bash
# The three queries wg-routes.sh makes about a live tunnel, answered as
# a healthy wg0 would; everything else is a mutation and gets logged.
case "$*" in
  "link show wg0") exit 0 ;;
  "-4 -o addr show dev wg0") echo "9: wg0    inet 10.64.9.2/32 scope global wg0"; exit 0 ;;
  "rule show") exit 0 ;;
esac
printf '%s\n' "$*" >>"${IP_LOG}"
exit 0
EOF
printf '#!/bin/bash\nexit 0\n' >"${tmp}/bin/sysctl"
chmod +x "${tmp}/bin/ip" "${tmp}/bin/sysctl"
# wg-routes.sh reads segments.d when SEG_NETS is unset. Never the one on the box.
export SEGMENTS_DIR="${tmp}/no-segments.d"
wg_routes() {
  IP_LOG="${tmp}/ip.log" PATH="${tmp}/bin:${PATH}" \
    HOUSE_NET=10.78.0.0/24 AGENT_NET=10.77.0.0/24 \
    HOUSE_ENV=/nonexistent/house.env NET_ENV=/nonexistent/net.env \
    bash "${routes}" "$1" wg0
}
: >"${tmp}/ip.log"
wg_routes up >/dev/null || fail "wg-routes.sh up refused a healthy tunnel"
prio_of() { grep -E "^rule add from $1 priority [0-9]+\$" "${tmp}/ip.log" | grep -oE '[0-9]+$' | tail -1 || true; }
_tunnel="$(prio_of '10\.78\.0\.0/24 lookup 100')"
_local="$(prio_of '10\.78\.0\.0/24 to 10\.78\.0\.0/24 lookup main')"
_agent="$(prio_of '10\.78\.0\.0/24 to 10\.77\.0\.0/24 lookup main')"
[[ -n "${_tunnel}" ]] || fail "wg-routes: nothing sends HOUSE_NET into table 100"
# Without this rule, the house is dark, not only leaky. The Pi answers
# the house from HOUSE_IP, and the `from HOUSE_NET` of priority ${_tunnel}
# matches that address. Thus DNS answers and DHCP ACKs go into the tunnel,
# and the segment never again hears from its own gateway.
[[ -n "${_local}" ]] || fail "wg-routes: no rule keeps house-to-house traffic on the copper"
[[ "${_local}" -lt "${_tunnel}" ]] || fail "wg-routes: the house-local rule (${_local}) sits below the tunnel rule (${_tunnel}); table 100 wins and the house has no gateway"
[[ -n "${_agent}" && "${_agent}" -lt "${_tunnel}" ]] || fail "wg-routes: the house-to-agent ssh hole does not sit above the tunnel rule"
: >"${tmp}/ip.log"
wg_routes down >/dev/null || fail "wg-routes.sh down failed"
grep -qE "^rule del priority ${_local}\$" "${tmp}/ip.log" \
  || fail "wg-routes: down leaves priority ${_local} installed, so a later up stacks a stale rule"

# This is how the ExecStartPost of wg-quick runs it: no environment, and a
# house.env with no HOUSE_NET line. That is the normal case (render gives
# the default). On the first real tunnel (2026-09-23), this exited 1 on
# the empty grep, and each start of wg-quick@wg0 failed.
printf 'HOUSE_IF=eth1\nWG_IF=wg0\n' >"${tmp}/wg-nonet.env"
printf 'AGENT_NET=10.77.0.0/24\n' >"${tmp}/wg-net.env"
: >"${tmp}/ip.log"
IP_LOG="${tmp}/ip.log" PATH="${tmp}/bin:${PATH}" HOUSE_ENV="${tmp}/wg-nonet.env" NET_ENV="${tmp}/wg-net.env" \
  NET_ENV_LOCAL=/nonexistent env -u HOUSE_NET -u AGENT_NET bash "${routes}" up wg0 >/dev/null \
  || fail "wg-routes.sh up fails when house.env has no HOUSE_NET, which is how the unit calls it"
grep -qE '^rule add from 10\.78\.0\.0/24 lookup 100 priority' "${tmp}/ip.log" \
  || fail "wg-routes.sh did not default HOUSE_NET to 10.78.0.0/24"
grep -qxF 'rule add fwmark 0x1 lookup main priority 90' "${tmp}/ip.log" \
  || fail "wg-routes.sh did not default the bypass mark to 0x1"
# The bypass rule routes the mark that render sets, not a literal 0x1. The
# mark comes from the environment that apply gives the unit, or else from house.env.
printf 'HOUSE_IF=eth1\nWG_IF=wg0\nWG_BYPASS_MARK=0x4\n' >"${tmp}/wg-mark.env"
for _how in env file; do
  : >"${tmp}/ip.log"
  if [[ "${_how}" == env ]]; then
    IP_LOG="${tmp}/ip.log" PATH="${tmp}/bin:${PATH}" HOUSE_ENV="${tmp}/wg-nonet.env" NET_ENV="${tmp}/wg-net.env" \
      NET_ENV_LOCAL=/nonexistent WG_BYPASS_MARK=0x2 bash "${routes}" up wg0 >/dev/null || fail "wg-routes.sh up with WG_BYPASS_MARK=0x2"
    _want=0x2
  else
    IP_LOG="${tmp}/ip.log" PATH="${tmp}/bin:${PATH}" HOUSE_ENV="${tmp}/wg-mark.env" NET_ENV="${tmp}/wg-net.env" \
      NET_ENV_LOCAL=/nonexistent env -u WG_BYPASS_MARK bash "${routes}" up wg0 >/dev/null || fail "wg-routes.sh up with house.env WG_BYPASS_MARK=0x4"
    _want=0x4
  fi
  grep -qxF "rule add fwmark ${_want} lookup main priority 90" "${tmp}/ip.log" \
    || fail "wg-routes.sh (${_how}) did not route mark ${_want} around the tunnel: $(grep fwmark "${tmp}/ip.log")"
done
if IP_LOG="${tmp}/ip.log" PATH="${tmp}/bin:${PATH}" HOUSE_ENV="${tmp}/wg-nonet.env" NET_ENV="${tmp}/wg-net.env" \
  NET_ENV_LOCAL=/nonexistent WG_BYPASS_MARK='0x1 lookup 100' bash "${routes}" up wg0 >/dev/null 2>&1; then
  fail "wg-routes.sh accepted a WG_BYPASS_MARK that is not a hex fwmark"
fi
# apply gives the unit the values that it calculated. Thus the unit never guesses.
grep -qF 'Environment=HOUSE_NET=${HOUSE_NET} AGENT_NET=${AGENT_NET} WG_BYPASS_MARK=${WG_BYPASS_MARK}' "${here}/apply.sh" \
  || fail "the wg-quick drop-in does not pass HOUSE_NET and AGENT_NET to wg-routes.sh"

# A stopped tunnel parks. The tunnel routes go away. The house keeps its own
# subnet and the blackhole after it. down (WG_IF emptied) removes all.
: >"${tmp}/ip.log"
wg_routes park >/dev/null || fail "wg-routes.sh park failed"
grep -qE '^rule add from 10\.78\.0\.0/24 blackhole priority 101$' "${tmp}/ip.log" \
  || fail "wg-routes: a stopped tunnel does not keep the house blackholed; it would route out the uplink"
grep -qE '^rule add from 10\.78\.0\.0/24 to 10\.78\.0\.0/24 lookup main priority 94$' "${tmp}/ip.log" \
  || fail "wg-routes: park drops the house-local rule, so the Pi's replies to the house hit the blackhole"
grep -qE '^rule add from 10\.78\.0\.0/24 lookup 100' "${tmp}/ip.log" \
  && fail "wg-routes: park still sends the house into table 100"
grep -qE '^rule del priority 100$' "${tmp}/ip.log" || fail "wg-routes: park leaves the tunnel rule in place"
grep -qF 'ExecStopPost=-/usr/local/lib/pi-fortress/wg-routes.sh park ${WG_IF}' "${here}/apply.sh" \
  || fail "wg-quick's stop does not park: stopping the tunnel would drop the routing kill switch"
# park never leaves a moment with neither the tunnel rule nor the
# blackhole. It adds the blackhole before 100 goes, and never deletes it.
_bh="$(grep -nE '^rule add from 10\.78\.0\.0/24 blackhole priority 101$' "${tmp}/ip.log" | head -1 | cut -d: -f1)"
_del100="$(grep -nE '^rule del priority 100$' "${tmp}/ip.log" | head -1 | cut -d: -f1)"
[[ -n "${_bh}" && -n "${_del100}" && "${_bh}" -lt "${_del100}" ]] \
  || fail "wg-routes: park removes the tunnel rule (line ${_del100}) before the blackhole is in (line ${_bh})"
grep -qE '^rule del priority 101$' "${tmp}/ip.log" && fail "wg-routes: park deletes the blackhole"

# SSH_FROM from the house into a plain segment. A rule above the tunnel
# rule keeps a house SYN to a segment NET out of the tunnel, on up and on
# park. down removes those rules again.
for _how in up park; do
  : >"${tmp}/ip.log"
  SEG_NETS="10.79.0.0/30 10.80.0.0/24" wg_routes "${_how}" >/dev/null || fail "wg-routes.sh ${_how} with SEG_NETS failed"
  for _n in 10.79.0.0/30 10.80.0.0/24; do
    grep -qxF "rule add from 10.78.0.0/24 to ${_n} lookup main priority 96" "${tmp}/ip.log" \
      || fail "wg-routes ${_how}: no main-table rule from the house to segment ${_n}; SSH_FROM would go into the tunnel"
  done
  [[ "${_how}" == up ]] && { [[ 96 -lt "${_tunnel}" ]] || fail "wg-routes: the segment rule sits below the tunnel rule"; }
done
: >"${tmp}/ip.log"
wg_routes down >/dev/null || fail "wg-routes.sh down failed"
grep -qxF 'rule del priority 96' "${tmp}/ip.log" || fail "wg-routes: down leaves the house-to-segment rules"
# With SEG_NETS unset (a drop-in from before apply passed it), the script reads segments.d.
mkdir -p "${tmp}/wg-segs.d"
printf 'IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n' >"${tmp}/wg-segs.d/desk.env"
: >"${tmp}/ip.log"
SEGMENTS_DIR="${tmp}/wg-segs.d" wg_routes up >/dev/null || fail "wg-routes.sh up reading segments.d failed"
grep -qxF 'rule add from 10.78.0.0/24 to 10.79.0.0/30 lookup main priority 96' "${tmp}/ip.log" \
  || fail "wg-routes: SEG_NETS unset did not fall back to segments.d"
if SEG_NETS="10.79.0.0/30 lookup 100" wg_routes up >/dev/null 2>&1; then
  fail "wg-routes.sh accepted a segment NET that is not a CIDR"
fi
grep -qF '"SEG_NETS=${SEG_NET[*]:-}"' "${here}/apply.sh" \
  || fail "the wg-quick drop-in does not hand the segment NETs to wg-routes.sh"
# wg-quick@X reads /etc/wireguard/X.conf. With a fixed wg0.conf, a
# different WG_IF never came up.
grep -qF 'install -m 0600 "${WORKDIR}/wg.conf" "/etc/wireguard/${WG_IF}.conf"' "${here}/apply.sh" \
  || fail "apply does not write /etc/wireguard/\${WG_IF}.conf"
grep -qF '/etc/wireguard/wg0.conf' "${here}/apply.sh" && fail "apply still writes a fixed /etc/wireguard/wg0.conf"

printf 'HOUSE_IF=eth1\nWG_IF=wlan0\n' >"${tmp}/wg-collide.env"
if render "${tmp}/wg-collide.env" >/dev/null 2>"${tmp}/wg.err"; then
  fail "WG_IF equal to WAN_IF was accepted"
fi
grep -q "WG_IF=wlan0 collides" "${tmp}/wg.err" || fail "WG_IF == WAN_IF refusal is unclear: $(cat "${tmp}/wg.err")"

printf 'WG_IF=wg0\n' >"${tmp}/wg-nohouse.env"
if render "${tmp}/wg-nohouse.env" >/dev/null 2>"${tmp}/wg.err"; then
  fail "WG_IF without HOUSE_IF was accepted"
fi
grep -q "requires HOUSE_IF" "${tmp}/wg.err" || fail "WG_IF without HOUSE_IF refusal is unclear: $(cat "${tmp}/wg.err")"

refuse 'WG_IF is not an interface name' 'WG_IF=wg0;reboot'
refuse 'WG_BYPASS_MARK is not a hex fwmark' 'WG_BYPASS_MARK=1'

# wg-conf.sh rewrites a vendor Mullvad file and does not refuse it. Thus rotation is drop-file + apply.
conf="${here}/wg-conf.sh"
[[ -x "${conf}" ]] || fail "wg-conf.sh is not executable"
cat >"${tmp}/mullvad.conf" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.64.9.2/32,fc00:bbbb:bbbb:bb01::2/128
DNS = 10.64.0.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 146.70.1.2:51820
EOF
bash "${conf}" "${tmp}/mullvad.conf" >"${tmp}/wg0.conf" || fail "wg-conf.sh refused a typical Mullvad file"
grep -qF 'Table = off' "${tmp}/wg0.conf" || fail "wg-conf: Table = off missing"
grep -qF 'MTU = 1420' "${tmp}/wg0.conf" || fail "wg-conf: MTU missing"
grep -qF 'PersistentKeepalive = 25' "${tmp}/wg0.conf" || fail "wg-conf: keepalive missing"
grep -qF 'Address = 10.64.9.2/32' "${tmp}/wg0.conf" || fail "wg-conf: v4 address missing"
grep -qF 'AllowedIPs = 0.0.0.0/0' "${tmp}/wg0.conf" || fail "wg-conf: AllowedIPs missing"
grep -qF 'Endpoint = 146.70.1.2:51820' "${tmp}/wg0.conf" || fail "wg-conf: endpoint missing"
grep -q 'fc00:\|::/0\|DNS =' "${tmp}/wg0.conf" && fail "wg-conf: v6, ::/0 or DNS= survived"
cat >"${tmp}/mullvad-host.conf" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.64.9.2/32
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = sg-sin-wg-001.mullvad.net:51820
EOF
if bash "${conf}" "${tmp}/mullvad-host.conf" >/dev/null 2>"${tmp}/conf.err"; then
  fail "wg-conf.sh accepted a hostname Endpoint"
fi
grep -q 'IPv4:port' "${tmp}/conf.err" || fail "hostname Endpoint refusal is unclear: $(cat "${tmp}/conf.err")"

# provision.sh takes the checkout from SRC. The check runs before apt.
# Thus a wrong path gives a message, not a half-provisioned box.
prov="${here}/provision.sh"
if SRC="${tmp}/nope" bash "${prov}" >"${tmp}/prov.out" 2>"${tmp}/prov.err"; then
  fail "provision.sh accepted an SRC that is not a checkout"
fi
grep -q 'is not a pi-fortress checkout' "${tmp}/prov.err" ||
  fail "provision.sh refusal is unclear: $(cat "${tmp}/prov.err")"
grep -q 'apt-get\|install' "${tmp}/prov.out" && fail "provision.sh acted before checking SRC"
grep -qE '(^|[^A-Za-z_])/vagrant/' "${prov}" && fail "provision.sh still hardcodes a /vagrant path"
grep -q 'SRC="\${SRC:-/vagrant}"' "${prov}" || fail "provision.sh lost the /vagrant default the lab mounts"

# A second provision keeps the lists of the operator. On a box with no
# tree, /etc/pi-fortress is the policy. provision.sh seeds each list of
# PI_OWNED (Makefile) only when it is absent, and never copies one over.
_owned="$(sed -n 's/^PI_OWNED = //p' "${here}/../../Makefile")"
[[ -n "${_owned}" ]] || fail "no PI_OWNED in the Makefile"
_seed="$(awk '/^for _f in blacklist\.ips /,/; do$/' "${prov}" | tr '\\\n;' '   ')"
for _l in allow.domains dns_types.allow git_push.allow blacklist.ips never_block.domains sources.json; do
  [[ " ${_seed} " == *" ${_l} "* ]] || fail "provision.sh does not seed ${_l} only when absent"
done
for _l in ${_owned}; do
  if grep -E "^[[:space:]]*(cp|install)[[:space:]].*/etc/pi-fortress/${_l//./\\.}([[:space:]]|$)" "${prov}"; then
    fail "provision.sh copies over ${_l}, a list of the operator"
  fi
done

# The two scripts refuse a host that is not a Pi, a lab VM or the appliance.
# They name the host and the override, before they change anything. A fake
# device-tree model acts as a desktop. apt-get and systemctl are stubs that
# leave a mark. Thus a guard that lets this through fails here, and does
# not act. The test skips this in a lab VM, where /vagrant allows it.
if [[ ! -d /vagrant/vm/pi && ! -f /etc/pi-fortress/appliance.role ]]; then
  printf 'Some Desktop\0' >"${tmp}/model"
  mkdir -p "${tmp}/guardbin"
  for _c in apt-get systemctl nft nmcli install; do
    printf '#!/bin/bash\ntouch "%s"\nexit 1\n' "${tmp}/guard.acted" >"${tmp}/guardbin/${_c}"
    chmod +x "${tmp}/guardbin/${_c}"
  done
  for _s in "${prov}" "${apply}"; do
    if PATH="${tmp}/guardbin:${PATH}" PF_TEST_MODEL="${tmp}/model" SRC="${here}/../.." bash "${_s}" >"${tmp}/guard.out" 2>&1; then
      fail "${_s##*/} ran on a host whose model is 'Some Desktop'"
    fi
    grep -q "refuses to run on .*Some Desktop.*PF_ALLOW_ANY_HOST=1" "${tmp}/guard.out" ||
      fail "${_s##*/} host refusal is unclear: $(cat "${tmp}/guard.out")"
    [[ ! -e "${tmp}/guard.acted" ]] || fail "${_s##*/} acted before refusing the host"
  done
  # The Pi model passes the guard and stops at the root check. Thus run it
  # only as a non-root user. As root, it would continue and act on this host.
  if [[ "${EUID}" -ne 0 ]]; then
    printf 'Raspberry Pi 5 Model B Rev 1.0\0' >"${tmp}/model"
    PATH="${tmp}/guardbin:${PATH}" PF_TEST_MODEL="${tmp}/model" bash "${apply}" --local >"${tmp}/guard.out" 2>&1 || true
    grep -q 'refuses to run on' "${tmp}/guard.out" && fail "apply.sh refused a Raspberry Pi model"
    grep -q 'apply must run as root' "${tmp}/guard.out" ||
      fail "apply.sh on a Pi model did not reach its root check: $(cat "${tmp}/guard.out")"
    # A non-Pi box that pf install made a gateway passes because of its role file.
    printf 'Some Desktop\0' >"${tmp}/model"
    : >"${tmp}/gateway.role"
    PATH="${tmp}/guardbin:${PATH}" PF_TEST_MODEL="${tmp}/model" PF_TEST_GATEWAY_ROLE="${tmp}/gateway.role" bash "${apply}" --local >"${tmp}/guard.out" 2>&1 || true
    grep -q 'refuses to run on' "${tmp}/guard.out" && fail "apply.sh refused a box with a gateway role"
    grep -q 'apply must run as root' "${tmp}/guard.out" ||
      fail "apply.sh with a gateway role did not reach its root check: $(cat "${tmp}/guard.out")"
  fi
fi

# apply sources the operator overlay after net.env, and nothing ships it.
# Thus the render uses a value that is set there.
cat >"${tmp}/net.env.local" <<'EOF'
PI_IP=10.77.0.9
EOF
PF_NET_ENV_LOCAL="${tmp}/net.env.local" render /nonexistent/house.env >"${tmp}/overlay.nft" ||
  fail "the overlay broke the render"
grep -qF '10.77.0.9' "${tmp}/overlay.nft" || fail "net.env.local did not override PI_IP"
render /nonexistent/house.env >"${tmp}/no-overlay.nft"
grep -qF '10.77.0.9' "${tmp}/no-overlay.nft" && fail "the overlay leaked into a run without it"

# Debian's stubby owns 127.0.0.1:53 whenever it is not masked, in both
# DoT states.
grep -q 'systemctl unmask stubby.service' "${apply}" &&
  fail "apply still hands loopback 53 back to Debian's stubby"
grep -q '^systemctl mask stubby.service' "${apply}" ||
  fail "apply no longer masks Debian's stubby unconditionally"

# GO_DNS is retired. A box that still has the key in net.env or the
# overlay must get a message. apply must not silently ignore the key. An
# operator who sets GO_DNS=0 to roll back and gets a clean apply would
# think that the box uses dnsmasq again. The refusal occurs before anything
# on the box changes. Thus it is safe to fail, instead of a warning.
printf 'GO_DNS=0\n' >"${tmp}/go-dns-stale.local"
if PF_NET_ENV_LOCAL="${tmp}/go-dns-stale.local" render /nonexistent/house.env >/dev/null 2>"${tmp}/go-dns.err"; then
  fail "a stale GO_DNS=0 was accepted"
fi
grep -q 'GO_DNS is retired' "${tmp}/go-dns.err" ||
  fail "the GO_DNS refusal does not name the key: $(cat "${tmp}/go-dns.err")"
grep -q "${tmp}/go-dns-stale.local" "${tmp}/go-dns.err" ||
  fail "the GO_DNS refusal does not say which file holds it: $(cat "${tmp}/go-dns.err")"
# The per-slot hourly budget (net.env, docs/fence.md 5.2d). A typo in
# one of these four gets to the broker as a flag that it refuses. The
# fence is then down until a person reads the journal. Thus apply checks
# them before anything on the box changes. apply also refuses a stop below
# its own warn. That stop would quarantine the slot before the alert that
# must give the operator a chance to examine it.
printf 'SLOT_WARN_REQUESTS=lots\n' >"${tmp}/budget-bad.local"
if PF_NET_ENV_LOCAL="${tmp}/budget-bad.local" render /nonexistent/house.env >/dev/null 2>"${tmp}/budget.err"; then
  fail "a non-numeric SLOT_WARN_REQUESTS was accepted"
fi
grep -q "SLOT_WARN_REQUESTS='lots'" "${tmp}/budget.err" ||
  fail "the budget refusal does not name the key and value: $(cat "${tmp}/budget.err")"
printf 'SLOT_WARN_REQUESTS=3000\nSLOT_STOP_REQUESTS=100\n' >"${tmp}/budget-inverted.local"
if PF_NET_ENV_LOCAL="${tmp}/budget-inverted.local" render /nonexistent/house.env >/dev/null 2>"${tmp}/budget-inv.err"; then
  fail "a stop below its own warn was accepted"
fi
grep -q 'quarantined before the warning' "${tmp}/budget-inv.err" ||
  fail "the inverted-budget refusal does not say why: $(cat "${tmp}/budget-inv.err")"
# The shipped default is both stops off, which is not "below the warn".
printf 'SLOT_STOP_REQUESTS=0\nSLOT_STOP_UPLOAD_MB=0\n' >"${tmp}/budget-off.local"
if ! PF_NET_ENV_LOCAL="${tmp}/budget-off.local" render /nonexistent/house.env >/dev/null 2>"${tmp}/budget-off.err"; then
  fail "the shipped budget defaults were refused: $(cat "${tmp}/budget-off.err")"
fi
# The flags get to the broker through PF_BROKER_FLAGS, not through a
# ${VAR} in the unit. An older net.env without the key would expand to a
# bare flag that the parser refuses. Then the fence would not start.
grep -q 'slot-warn-requests=${SLOT_WARN_REQUESTS}' "${apply}" ||
  fail "apply no longer passes the budget to the broker"
if grep -q 'slot-warn-requests' "${here}/pf-broker.service"; then
  fail "the budget is in the unit's ExecStart, where an absent net.env key becomes a bare flag"
fi
# PARANOID=1 renders on its own. pf dns has a paranoid posture. Apply
# refused PARANOID=1 together with GO_DNS before. That pair, paranoid mode
# on pf dns, is now the only shape.
if ! PF_PARANOID=1 render "${tmp}/house.env" >/dev/null 2>"${tmp}/go-dns-paranoid.err"; then
  fail "PARANOID=1 was refused: $(cat "${tmp}/go-dns-paranoid.err")"
fi
# --render-nft exits before the resolver half. Thus this test cannot read
# the rendered dns.json. vm/itest asserts it on a box that has applied.
# This test can check the script text. The segment must have the forward
# set. The set must be the files that the engine and the broker use. If not,
# the resolver and the fence would answer by different policies.
grep -q '"paranoid": true' "${here}/apply.sh" ||
  fail "apply.sh never marks a segment paranoid"
grep -q '"allow": "/etc/pi-fortress/allow.domains"' "${here}/apply.sh" ||
  fail "apply.sh does not hand pf dns allow.domains"
grep -q '"core_hosts": "/etc/pi-fortress/core.hosts"' "${here}/apply.sh" ||
  fail "apply.sh does not hand pf dns core.hosts"
grep -q '"key_rules": "/etc/pi-fortress/key_prefixes.rules"' "${here}/apply.sh" ||
  fail "apply.sh does not hand pf dns key_prefixes.rules for the agent segment"
grep -q '"address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow"' "${here}/apply.sh" ||
  fail "apply.sh does not make the agent segment address-only with dns_types.allow"
# The agent listener and the plain-segment listeners (one printf each).
# The house forwards all types.
[[ "$(grep -c '"address_only"' "${here}/apply.sh")" -eq 2 ]] ||
  fail "address_only is not on exactly the agent and plain-segment listeners in apply.sh"
grep -q '"log": %s, "key_rules": "/etc/pi-fortress/key_prefixes.rules", "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow", "dns_types": %s%s}' "${here}/apply.sh" ||
  fail "apply.sh does not give plain segments the agent's DNS guards and DNS_TYPES"
# Fake-IP: the pool and journal are on the agent segment only, and only
# with AGENT_DNS=fakeip. Thus the dns.json of forward mode does not change.
grep -qF '\"fakeip_net\": $(json_str "${FAKEIP_NET}" FAKEIP_NET), \"fakeip_journal\"' "${here}/apply.sh" ||
  fail "apply.sh does not hand pf dns the fake-IP pool and journal"
[[ "$(grep -c 'fakeip_net' "${here}/apply.sh")" -eq 1 ]] ||
  fail "fakeip_net appears on more than the agent segment in apply.sh"
grep -q '"${DNS_RESOLVER_PARANOID}" "${DNS_RESOLVER_FAKEIP}"$' "${here}/apply.sh" ||
  fail "the agent segment's dns.json line does not carry DNS_RESOLVER_FAKEIP"
grep -q 'export AGENT_DNS="${AGENT_DNS:-}" FAKEIP_NET="${FAKEIP_NET:-}"' "${here}/apply.sh" ||
  fail "apply.sh does not export AGENT_DNS and FAKEIP_NET to pf render"
# The journal: pf dns writes it. Only the broker reads it, through a group
# that only the broker is in. The group is on the directory, so pf dns needs no chown.
grep -q 'groupadd --system pf-fakeip' "${here}/apply.sh" || fail "apply.sh does not create the pf-fakeip group"
grep -q 'usermod -aG pf-fakeip pf-broker' "${here}/apply.sh" || fail "the broker is not in pf-fakeip"
grep -q 'install -d -o pf-dns -g pf-fakeip -m 2750 "${FAKEIP_JOURNAL_DIR}"' "${here}/apply.sh" ||
  fail "the fake-IP journal directory is not pf-dns:pf-fakeip 2750"
grep -q '^SupplementaryGroups=pf-fortress pf-fakeip$' "${here}/pf-broker.service" ||
  fail "pf-broker.service does not run with pf-fakeip, so it cannot read the journal"
# The broker flags are in their own file, as the paranoid flags are. The
# resolver is DNS_FORWARD: the upstream with DoT off, the stub with DoT on.
grep -q '^EnvironmentFile=-/etc/pi-fortress/fakeip.flags$' "${here}/pf-broker.service" ||
  fail "pf-broker.service does not read fakeip.flags"
grep -q ' \$PF_FAKEIP_BROKER_FLAGS$' "${here}/pf-broker.service" ||
  fail "pf-broker.service ExecStart does not pass PF_FAKEIP_BROKER_FLAGS"
grep -qF 'PF_FAKEIP_BROKER_FLAGS="-fakeip-net %s -fakeip-journal %s -resolver %s"' "${here}/apply.sh" ||
  fail "apply.sh does not write the broker's fake-IP flags"
grep -qF 'BROKER_RESOLVER="${DNS_FORWARD/\#/:}"' "${here}/apply.sh" ||
  fail "the broker's fake-IP resolver is not DNS_FORWARD"
grep -qF "printf 'PF_FAKEIP_BROKER_FLAGS=\n'" "${here}/apply.sh" ||
  fail "forward mode does not clear PF_FAKEIP_BROKER_FLAGS"
grep -q 'lab_echo' "${here}/apply.sh" ||
  fail "apply.sh does not pass the lab echo marker to pf dns"
# The Go daemon does not drop its own privilege. Thus the unit must not
# have the capabilities that dnsmasq had only to drop its own privilege.
unit="${here}/dns-agent-go.service"
[[ -f "${unit}" ]] || fail "vm/pi/dns-agent-go.service is missing"
grep -q '^User=pf-dns' "${unit}" || fail "dns-agent-go.service does not drop to pf-dns"
grep -qE '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW$' "${unit}" ||
  fail "dns-agent-go.service bounding set is not the three net capabilities"
grep -q 'CAP_SET\|CAP_CHOWN\|CAP_DAC_OVERRIDE' "${unit}" &&
  fail "dns-agent-go.service kept a dnsmasq privilege-drop capability"
# Only the log directory and the directory of the fake-IP journal. The "-"
# is there because a forward-mode box never makes the second.
grep -q '^ReadWritePaths=/var/log/pi-fortress -/var/lib/pi-fortress/dns$' "${unit}" ||
  fail "dns-agent-go.service writes more than the log and fake-IP journal directories"
# This daemon parses DNS off the wire from both segments. It is the only
# resolver of the box. Thus it gets the same seccomp box as the other pf units
# (pf-broker and pf-engine are the same binary under the same filter).
# No @chown re-add: no code that pf dns reaches chowns a file. It reopens
# its log on HUP with O_APPEND and keeps the owner that apply.sh gave it.
for _l in \
  'RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX' \
  'RestrictSUIDSGID=yes' \
  'SystemCallArchitectures=native' \
  'SystemCallFilter=@system-service' \
  'SystemCallFilter=~@privileged'; do
  grep -qxF "${_l}" "${unit}" || fail "dns-agent-go.service has no '${_l}'"
done
grep -qxF 'SystemCallFilter=@chown' "${unit}" &&
  fail "dns-agent-go.service re-adds @chown; pf dns chowns nothing"


# Phase 2: the unit takes a segment list, not one flag per value. The
# old form could describe only one segment. Thus it cannot express a
# house on pf dns.
grep -q 'pf dns -config /etc/pi-fortress/dns.json' "${unit}" ||
  fail "dns-agent-go.service does not start pf dns from the segment list"
grep -q '^EnvironmentFile=' "${unit}" &&
  fail "dns-agent-go.service still reads the one-variable-per-flag env file"

# The house dnsmasq parses DHCP off the wire from all devices that the
# house connects. It was the last long-running daemon with no seccomp
# filter. systemd now starts it as an account of its own. Thus the privilege
# drop of dnsmasq never runs, and the unit can deny @privileged. That drop
# was the only reason the unit had SETUID, SETGID, CHOWN and DAC_OVERRIDE.
hunit="${here}/dns-house.service"
[[ -f "${hunit}" ]] || fail "vm/pi/dns-house.service is missing"
grep -q '^User=pf-dhcp-house$' "${hunit}" ||
  fail "dns-house.service does not start as the pf-dhcp-house account: $(grep '^User=' "${hunit}")"
grep -qF -- '--user=pf-dhcp-house ' "${hunit}" ||
  fail "dns-house.service does not give dnsmasq --user=pf-dhcp-house, the account that it runs as"
# Each DHCP instance has its own account. Each one can then write only its
# own lease file and log, also when the two share a directory.
grep -q '^User=pf-dhcp-%i$' "${here}/dhcp@.service" ||
  fail "dhcp@.service does not start each instance as its own account: $(grep '^User=' "${here}/dhcp@.service")"
grep -qF -- '--user=pf-dhcp-%i ' "${here}/dhcp@.service" ||
  fail "dhcp@.service does not give dnsmasq --user=pf-dhcp-%i, the account that it runs as"
grep -qE '^User=dnsmasq$|--user=dnsmasq' "${hunit}" "${here}/dhcp@.service" &&
  fail "a DHCP unit still runs as the shared dnsmasq account"
grep -qx '  dhcp_account house' "${apply}" ||
  fail "apply.sh does not make the pf-dhcp-house account before it gives the files to it"
grep -q '^Group=nogroup$' "${hunit}" ||
  fail "dns-house.service does not name a group; dnsmasq's built-in default is dip"
for _l in \
  'CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW' \
  'AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW' \
  'RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX' \
  'SystemCallArchitectures=native' \
  'SystemCallFilter=@system-service' \
  'SystemCallFilter=~@privileged'; do
  grep -qxF "${_l}" "${hunit}" || fail "dns-house.service has no '${_l}'"
done
grep -vE '^[[:space:]]*#' "${hunit}" | grep -qE 'CAP_SETUID|CAP_SETGID|CAP_CHOWN|CAP_DAC_OVERRIDE' &&
  fail "dns-house.service still carries a capability only dnsmasq's own privilege drop needed"
# A killed DHCP daemon restarts in two seconds and leaves a SECCOMP
# audit line. EPERM in a rare renew path makes one device silently lose
# its lease weeks later. Thus the default action stays kill.
grep -q '^SystemCallErrorNumber=' "${hunit}" &&
  fail "dns-house.service turns a filtered call into an errno; the siblings all kill"
# dnsmasq is unprivileged from the first instruction. Thus it can no longer
# open these two as root and give them to itself when it drops privilege.
for _f in /var/lib/pi-fortress/house.leases /var/log/pi-fortress/dnsmasq-house-dhcp.log; do
  grep -qF "chown pf-dhcp-house:root ${_f}" "${apply}" ||
    fail "apply.sh does not give ${_f} to the pf-dhcp-house account"
done
grep -qF 'chown root:root /var/lib/pi-fortress/house.leases' "${apply}" &&
  fail "apply.sh still leaves the lease file root-owned; an unprivileged dnsmasq cannot write it"

# apply writes the segment list in the half that --render-nft exits
# before. Thus vm/itest asserts it on a box that actually ran an apply.
# This test can check that the script builds a list and never gives the
# agent set to the house.
grep -q 'install -m 0644 "${WORKDIR}/dns.json" /etc/pi-fortress/dns.json' "${apply}" ||
  fail "apply does not install the pf dns segment list"
grep -q '"nft_set": "resolved_house_v4"' "${apply}" ||
  fail "apply never gives the house segment its own nft set"
# A plain segment also resolves through this box. Thus the list has
# one entry for each segments.d file. Its set and its log have the name of
# the segment. Reason: a name resolved on one segment must not open an
# address on a different segment, and a row must show who asked.
grep -q '"nft_set": "resolved_%s_v4"' "${apply}" ||
  fail "apply never gives a plain segment its own nft set"
grep -qF '/var/log/pi-fortress/dns-${_sname}.jsonl' "${apply}" ||
  fail "apply does not give a plain segment a query log of its own"
grep -qF '"${_sname//-/_}"' "${apply}" ||
  fail "a dashed segment name reaches an nftables set name unsanitised"
# With port=0, dnsmasq does DHCP and nothing else.
grep -q '^port=0$' "${apply}" ||
  fail "apply has no DHCP-only house conf"

# Log rotation. The jsonl writers and the tailers both reopen by path. Thus a
# rename is safe. dnsmasq holds its two logs open, so they need the signal.
conf="${here}/logrotate.conf"
[[ -f "${conf}" ]] || fail "vm/pi/logrotate.conf is missing"
# The DHCP log has its own stanza. It is recreated with the owner that it
# had, the account of the daemon. The daemon cannot chown a file that root
# made, and would log nowhere.
grep -A12 '^/var/log/pi-fortress/dnsmasq-house-dhcp.log {' "${conf}" | grep -qx '    create 0640' \
  || fail "logrotate.conf: dnsmasq-house-dhcp.log is not rotated, or not recreated with the owner it had"
grep -A12 '^/var/log/pi-fortress/dnsmasq-house-dhcp.log {' "${conf}" | grep -qF 'kill -s USR2 pi-fortress-dns-house.service' \
  || fail "logrotate.conf: dnsmasq is not told to reopen its DHCP log"
grep -A8 "^/var/log/pi-fortress/notice.jsonl {" "${conf}" | grep -q "create 0640 root pf-fortress" \
  || fail "logrotate.conf: notice.jsonl is not rotated, or not recreated readable by pf alert"
grep -q '^for _f in .*/var/lib/pi-fortress/alert-notice.offset' "${apply}" \
  || fail "apply.sh does not make alert-notice.offset for pf-sidecar, which cannot create it"
grep -q '^chown root:pf-fortress /var/log/pi-fortress/notice.jsonl' "${apply}" \
  || fail "apply.sh does not hand notice.jsonl to the group pf alert reads it as"
grep -q 'install -m 0644 "${PI_LIB}/logrotate.conf" /etc/pi-fortress/logrotate.conf' "${apply}" ||
  fail "apply.sh does not install logrotate.conf"
if grep -vE '^[[:space:]]*#' "${apply}" | grep '/etc/logrotate.d' | grep -qv 'rm -f'; then
  fail "apply.sh still touches /etc/logrotate.d other than to remove the pre-timer conf"
fi
grep -q 'rm -f /etc/logrotate.d/pi-fortress' "${apply}" ||
  fail "apply.sh does not remove a pre-timer conf from /etc/logrotate.d"
grep -q 'install -m 0644 "${SRC}"/vm/pi/logrotate.conf /etc/pi-fortress/logrotate.conf' "${here}/provision.sh" ||
  fail "provision.sh does not install logrotate.conf at /etc/pi-fortress"

# Hourly rotation runs on our own timer with our own state file. Thus the
# daily logrotate.timer of the system does not see this conf. It also does
# not conflict with this conf about the last rotation time of a path.
for _u in logrotate.service logrotate.timer; do
  [[ -f "${here}/${_u}" ]] || fail "vm/pi/${_u} is missing"
  grep -q "install -m 0644 \"\${PI_LIB}/${_u}\" /etc/systemd/system/pi-fortress-${_u}" "${apply}" ||
    fail "apply.sh does not install ${_u}"
done
grep -q 'systemctl enable --now pi-fortress-logrotate.timer' "${apply}" ||
  fail "apply.sh does not enable pi-fortress-logrotate.timer"
grep -q '^OnCalendar=\*:0/15$' "${here}/logrotate.timer" ||
  fail "logrotate.timer does not fire every 15 minutes"
grep -q 'logrotate --state /var/lib/pi-fortress/logrotate.state /etc/pi-fortress/logrotate.conf' "${here}/logrotate.service" ||
  fail "logrotate.service does not run our conf with its own state file"

# git_push.allow (docs/git_push.md): the Pi owns it. apply installs or
# removes it. A change restarts the fence. The broker points at it.
grep -qE '^PI_OWNED = .*\bgit_push\.allow\b' "${here}/../../Makefile" || fail "git_push.allow is not in PI_OWNED"
grep -qF 'install -m 0644 "${POLICY}/git_push.allow" /etc/pi-fortress/git_push.allow' "${apply}" ||
  fail "apply.sh does not install git_push.allow"
grep -qF 'rm -f /etc/pi-fortress/git_push.allow' "${apply}" || fail "apply.sh keeps a git_push.allow the policy dir dropped"
grep -qF -e '-git-push /etc/pi-fortress/git_push.allow' "${here}/pf-broker.service" || fail "pf-broker.service does not pass -git-push"
# The fence restart on a changed git_push.allow is asserted with the
# other fence inputs, below the --local runs.

# The feed maps that pf observe uses to label blocked events go with the
# compiled lists.
for _m in domain-map:blocked-domains.map ip-map:blocked-ips.map; do
  _f="${_m%%:*}"; _m="${_m#*:}"
  grep -qF -e "--out-${_f} \"\${WORKDIR}/${_m}\"" "${apply}" || fail "apply.sh does not ask pf compile for ${_m}"
  grep -qF "install -m 0644 \"\${WORKDIR}/${_m}\" /etc/pi-fortress/${_m}" "${apply}" ||
    fail "apply.sh does not install ${_m}"
done
for _f in strip.jsonl unknown.jsonl use.jsonl observe.jsonl audit.jsonl \
  dns.jsonl ship.jsonl notice.jsonl dnsmasq-house-dhcp.log; do
  grep -q "^/var/log/pi-fortress/${_f}\( {\)\?$" "${conf}" ||
    fail "logrotate.conf does not rotate ${_f}"
done
# The house is no longer the only second resolver. Each plain segment
# gets one, and apply gives its log the name of the segment. A stanza for
# each name cannot be written in advance. Thus the glob covers all of them.
grep -q '^/var/log/pi-fortress/dns-\*\.jsonl\( {\)\?$' "${conf}" ||
  fail "logrotate.conf does not rotate the per-segment query logs"
grep -qE '^[[:space:]]*copytruncate' "${conf}" &&
  fail "logrotate.conf uses copytruncate; every writer and reader reopens by path"
grep -q 'systemctl kill -s USR2 pi-fortress-dns-house.service' "${conf}" ||
  fail "logrotate.conf does not tell the house dnsmasq to reopen its log"
grep -qE '^[[:space:]]*/var/log/pi-fortress/monitor/' "${conf}" &&
  fail "logrotate.conf rotates the monitor day files, which pf monitor prunes itself"
# The DNS query logs are the reason for the hourly timer: 48 hourly
# rotations keep two days of query history.
awk '/^\/var\/log\/pi-fortress\/dns\.jsonl$/,/^}$/' "${conf}" >"${tmp}/dns.stanza"
for _d in hourly 'rotate 48' 'maxsize 50M'; do
  grep -qE "^[[:space:]]*${_d}$" "${tmp}/dns.stanza" ||
    fail "the query log stanza lost '${_d}'"
done
grep -qE '^[[:space:]]*daily$' "${tmp}/dns.stanza" &&
  fail "the query log stanza is still daily"

# The rename from dnsmasq.log also moves the offset sidecar. If not, pf
# observe reads a log that it already counted from byte 0, and counts each
# name in it two times. Both moves, or neither.
for _p in dnsmasq.log:dns.jsonl dnsmasq-house.log:dns-house.jsonl; do
  grep -qF "/var/log/pi-fortress/${_p%%:*}:/var/log/pi-fortress/${_p##*:}" "${apply}" ||
    fail "apply.sh does not rename ${_p%%:*} to ${_p##*:}"
done
grep -qF 'mv "${_oldoff}" "${_newoff}"' "${apply}" ||
  fail "apply.sh renames the query log without its offset sidecar"

# Forwarding is fail-closed. Before, the box kept ip_forward=1 in
# /etc/sysctl.d, but the ruleset that makes forwarding safe was only
# conditional. Thus an apply that died before the nft load left the stock
# accept-policy conf of Debian enabled and started: an open router. The
# order below is the full fix. Thus the test asserts it by line number.
prov="${here}/provision.sh"
# The OS hardening files (lib/harden.sh), written into a scratch root with
# stub sysctl and systemctl. provision.sh writes them on a fresh box and
# apply.sh on each full apply, so an upgraded box has the same files.
hroot="${tmp}/hardenroot"
mkdir -p "${hroot}/bin" "${hroot}/uubin" "${hroot}/work"
printf '#!/bin/sh\n' >"${hroot}/uubin/unattended-upgrade"
chmod +x "${hroot}/uubin/unattended-upgrade"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >>"%s"\n[[ "$3" == *.live ]] && cp "$3" "%s"\nexit 0\n' "${hroot}/sysctl.log" "${hroot}/live" >"${hroot}/bin/sysctl"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >>"%s"\n' "${hroot}/systemctl.log" >"${hroot}/bin/systemctl"
chmod +x "${hroot}/bin"/*
# Only the stubs and these host tools: the host may have its own
# unattended-upgrade, sshd or ssh-keygen.
for _c in bash cat cmp cp install grep mkdir rm sort stat tr; do
  ln -s "$(type -P "${_c}")" "${hroot}/bin/${_c}"
done
# harden_run [uu]: the three steps of apply.sh. "uu" puts a stub
# unattended-upgrade on PATH; without it, the package is missing.
harden_run() {
  (
    # shellcheck source=lib/harden.sh
    source "${here}/lib/harden.sh"
    HARDEN_SYSCTL_D="${hroot}/sysctl.d" HARDEN_APT_D="${hroot}/apt.conf.d" HARDEN_WORK="${hroot}/work"
    PATH="${hroot}/bin"
    if [[ "${1:-}" == uu ]]; then
      PATH="${PATH}:${hroot}/uubin"
    fi
    harden_sysctl_write
    harden_sysctl_load
    harden_apt
  )
}
harden_run uu 2>"${hroot}/err" || fail "the hardening steps failed: $(cat "${hroot}/err")"
cp "${hroot}/sysctl.d/99-pi-fortress.conf" "${tmp}/sysctl.conf"
for _l in kernel.kptr_restrict=2 kernel.yama.ptrace_scope=2 fs.protected_regular=2 net.ipv4.tcp_syncookies=1; do
  grep -qxF "${_l}" "${tmp}/sysctl.conf" || fail "99-pi-fortress.conf lacks ${_l}"
done
grep -qF 'label=Debian-Security' "${hroot}/apt.conf.d/52-pi-fortress-upgrades" || fail "no security origin in 52-pi-fortress-upgrades"
grep -qxF 'APT::Periodic::Unattended-Upgrade "1";' "${hroot}/apt.conf.d/20auto-upgrades" || fail "20auto-upgrades does not turn on unattended upgrades"
grep -qx 'enable unattended-upgrades' "${hroot}/systemctl.log" || fail "the hardening did not enable unattended-upgrades"
[[ ! -s "${hroot}/err" ]] || fail "the hardening warned with the package present: $(cat "${hroot}/err")"
# Forwarding: the file says 0 for the next boot, but the live load must
# not turn off the forwarding that apply enabled after the ruleset.
grep -q 'ip_forward' "${hroot}/live" && fail "the live sysctl load sets ip_forward; each apply would cut the agent off"
grep -qx 'kernel.kptr_restrict=2' "${hroot}/live" || fail "the live sysctl load lost the other values"
# Idempotent: a second run with no change writes nothing.
touch -d '2000-01-01' "${hroot}/sysctl.d/99-pi-fortress.conf" "${hroot}/apt.conf.d"/*
harden_run uu 2>/dev/null
[[ -z "$(find "${hroot}/sysctl.d" "${hroot}/apt.conf.d" -type f -newermt '2001-01-01')" ]] ||
  fail "a second hardening run rewrote a file that did not change"
# A box without the package: one warning, the files still written.
harden_run 2>"${hroot}/err" || fail "the hardening failed without unattended-upgrades"
grep -q 'unattended-upgrades is not installed' "${hroot}/err" || fail "no warning when unattended-upgrades is missing"
# Only on a full apply, after the --local exit, and from provision.sh.
_local_exit="$(grep -n '^if \[\[ "${LOCAL_ONLY}" -eq 1 \]\]; then$' "${apply}" | tail -1 | cut -d: -f1)"
for _f in harden_sysctl_write harden_sysctl_load harden_apt; do
  _at="$(grep -n "^${_f}$" "${apply}" | head -1 | cut -d: -f1)"
  [[ -n "${_at}" && "${_at}" -gt "${_local_exit}" ]] || fail "apply.sh does not run ${_f} on a full apply"
done
grep -q '^harden_sysctl_write$' "${prov}" || fail "provision.sh does not write the sysctl file"
grep -q '^harden_apt$' "${prov}" || fail "provision.sh does not write the unattended-upgrades config"
grep -qx 'net.ipv4.ip_forward=0' "${tmp}/sysctl.conf" ||
  fail "lib/harden.sh does not ship net.ipv4.ip_forward=0 in /etc/sysctl.d/99-pi-fortress.conf"
grep -qx 'net.ipv4.ip_forward=1' "${tmp}/sysctl.conf" &&
  fail "lib/harden.sh persists ip_forward=1 again; a boot without a good ruleset would route"

# The hardware watchdog (harden_watchdog). A fake sysfs class directory
# stands in for the device. The stubs are the ones of the hardening above.
wroot="${tmp}/wdroot"
mkdir -p "${wroot}/work" "${wroot}/sys"
wd_run() {
  (
    # shellcheck source=lib/harden.sh
    source "${here}/lib/harden.sh"
    HARDEN_SYSTEM_CONF_D="${wroot}/system.conf.d" HARDEN_WATCHDOG_SYS="${wroot}/sys" HARDEN_WORK="${wroot}/work"
    HW_WATCHDOG="$1"
    PATH="${hroot}/bin"
    harden_watchdog
  )
}
_wconf="${wroot}/system.conf.d/pi-fortress-watchdog.conf"
: >"${hroot}/systemctl.log"
wd_run auto >/dev/null 2>"${wroot}/err" || fail "harden_watchdog failed with no device: $(cat "${wroot}/err")"
[[ ! -e "${_wconf}" && ! -s "${hroot}/systemctl.log" ]] || fail "HW_WATCHDOG=auto enabled the watchdog on a box with no watchdog device"
# A device with a 15 s maximum. A larger value fails in systemd.
mkdir -p "${wroot}/sys/watchdog0"
echo 15 >"${wroot}/sys/watchdog0/max_timeout"
wd_run auto >/dev/null || fail "harden_watchdog failed with a device"
for _l in '[Manager]' 'RuntimeWatchdogSec=15s' 'RebootWatchdogSec=15s'; do
  grep -qxF "${_l}" "${_wconf}" || fail "the watchdog conf for a 15 s device lacks ${_l}"
done
grep -qx 'daemon-reexec' "${hroot}/systemctl.log" || fail "a new watchdog conf did not re-execute systemd"
: >"${hroot}/systemctl.log"
wd_run auto >/dev/null
[[ ! -s "${hroot}/systemctl.log" ]] || fail "an unchanged watchdog conf re-executed systemd"
echo 600 >"${wroot}/sys/watchdog0/max_timeout"
wd_run auto >/dev/null
for _l in RuntimeWatchdogSec=30s RebootWatchdogSec=120s; do
  grep -qx "${_l}" "${_wconf}" || fail "a device with a long maximum did not get ${_l}"
done
# max_timeout 0: the kernel pings the device itself, so any value is
# accepted (the Pi 5 device does this).
echo 0 >"${wroot}/sys/watchdog0/max_timeout"
wd_run auto >/dev/null
for _l in RuntimeWatchdogSec=30s RebootWatchdogSec=120s; do
  grep -qx "${_l}" "${_wconf}" || fail "a device with no hardware maximum did not get ${_l}"
done
# No maximum to read: 15 s, which each device takes.
rm -f "${wroot}/sys/watchdog0/max_timeout"
wd_run auto >/dev/null
grep -qx 'RuntimeWatchdogSec=15s' "${_wconf}" || fail "a device with no max_timeout did not get 15 s"
# 0 removes the conf and re-executes systemd one time.
: >"${hroot}/systemctl.log"
wd_run 0 >/dev/null || fail "HW_WATCHDOG=0 failed"
[[ ! -e "${_wconf}" ]] || fail "HW_WATCHDOG=0 left the watchdog conf"
grep -qx 'daemon-reexec' "${hroot}/systemctl.log" || fail "HW_WATCHDOG=0 did not re-execute systemd"
: >"${hroot}/systemctl.log"
wd_run 0 >/dev/null
[[ ! -s "${hroot}/systemctl.log" ]] || fail "HW_WATCHDOG=0 with no conf re-executed systemd"
_at="$(grep -n '^harden_watchdog$' "${apply}" | head -1 | cut -d: -f1)"
[[ -n "${_at}" && "${_at}" -gt "${_local_exit}" ]] || fail "apply.sh does not run harden_watchdog on a full apply"
grep -qx 'HW_WATCHDOG=auto' "${here}/net.env" || fail "net.env does not document HW_WATCHDOG"
grep -qF "HW_WATCHDOG='\${HW_WATCHDOG}' is not auto, 0 or 1" "${apply}" || fail "apply.sh does not check HW_WATCHDOG"

# The kernel command line (harden_cmdline): the memory cgroup and PSI.
croot="${tmp}/cmdroot"
mkdir -p "${croot}"
cl_run() {
  (
    # shellcheck source=lib/harden.sh
    source "${here}/lib/harden.sh"
    HARDEN_CMDLINE="${croot}/cmdline.txt" HARDEN_REBOOT_FLAG="${croot}/reboot-required"
    harden_cmdline
  )
}
printf 'console=tty1 root=PARTUUID=x rootwait  ' >"${croot}/cmdline.txt"
cl_run >/dev/null || fail "harden_cmdline failed"
[[ "$(cat "${croot}/cmdline.txt")" == 'console=tty1 root=PARTUUID=x rootwait cgroup_enable=memory psi=1' ]] ||
  fail "harden_cmdline wrote '$(cat "${croot}/cmdline.txt")'"
[[ "$(wc -l <"${croot}/cmdline.txt")" == 1 && -e "${croot}/reboot-required" ]] || fail "harden_cmdline left more than one line or no reboot flag"
[[ "$(cat "${croot}/cmdline.txt.pi-fortress.bak")" == 'console=tty1 root=PARTUUID=x rootwait  ' ]] || fail "harden_cmdline kept no copy of the old line"
rm -f "${croot}/reboot-required"
cl_run >/dev/null
[[ ! -e "${croot}/reboot-required" ]] || fail "harden_cmdline changed a line that already had both flags"
printf 'root=x psi=0\n' >"${croot}/cmdline.txt"
cl_run >/dev/null
[[ "$(cat "${croot}/cmdline.txt")" == 'root=x psi=0 cgroup_enable=memory' ]] || fail "harden_cmdline overrode the psi= of the operator"
printf 'root=x\nroot=y\n' >"${croot}/cmdline.txt"
cl_run >/dev/null 2>&1
[[ "$(cat "${croot}/cmdline.txt")" == $'root=x\nroot=y' ]] || fail "harden_cmdline edited a cmdline.txt of two lines"
rm -f "${croot}/cmdline.txt"
cl_run >/dev/null || fail "harden_cmdline failed with no cmdline.txt (a lab VM)"
grep -qF 'HARDEN_CMDLINE=/boot/firmware/cmdline.txt HARDEN_REBOOT_FLAG=/var/run/reboot-required harden_cmdline' "${here}/provision.sh" ||
  fail "provision.sh does not add the memory cgroup and PSI to the kernel command line"

# Key-only SSH (harden_ssh). The sshd stub passes -t unless sshd.bad
# exists, and prints sshd.T for -T. The ssh-keygen stub takes a file
# that holds an ed25519 key line, as ssh-keygen -l does.
printf '#!/bin/bash\nif [[ "$1" == -t ]]; then [[ ! -e "%s" ]]; exit; fi\ncat "%s" 2>/dev/null\n' "${hroot}/sshd.bad" "${hroot}/sshd.T" >"${hroot}/bin/sshd"
printf '#!/bin/bash\n[[ "$1" == -l && "$2" == -f ]] && grep -qE "(^|[ ])ssh-ed25519 AAAA" "$3"\n' >"${hroot}/bin/ssh-keygen"
chmod +x "${hroot}/bin/sshd" "${hroot}/bin/ssh-keygen"
hhome="${hroot}/home"
hconf="${hroot}/sshd_config.d/99-pi-fortress.conf"
mkdir -p "${hhome}/op/.ssh"
chmod 0755 "${hhome}/op"
chmod 0700 "${hhome}/op/.ssh"
: >"${hhome}/op/.ssh/authorized_keys"
chmod 0600 "${hhome}/op/.ssh/authorized_keys"
ssh_run() {
  (
    # shellcheck source=lib/harden.sh
    source "${here}/lib/harden.sh"
    HARDEN_SSHD_D="${hroot}/sshd_config.d" HARDEN_HOME="${hhome}" HARDEN_WORK="${hroot}/work"
    PATH="${hroot}/bin"
    harden_ssh
  ) >"${hroot}/ssh.out" 2>"${hroot}/ssh.err" || fail "harden_ssh failed: $(cat "${hroot}/ssh.err")"
}
: >"${hroot}/systemctl.log"
# No key, only a key with a forced command, a key that sshd ignores
# (group-writable file): password login stays on, with a warning.
for _keys in '' 'command="/bin/true" ssh-ed25519 AAAAC3Nza op' 'ssh-ed25519 AAAAC3Nza op'; do
  printf '%s\n' "${_keys}" >"${hhome}/op/.ssh/authorized_keys"
  if [[ -n "${_keys}" && "${_keys}" != command=* ]]; then
    chmod 0620 "${hhome}/op/.ssh/authorized_keys"
  fi
  ssh_run
  [[ ! -e "${hconf}" ]] || fail "harden_ssh turned off passwords with no usable key ('${_keys}')"
  grep -q 'password login stays on' "${hroot}/ssh.err" || fail "harden_ssh did not warn that password login is on ('${_keys}')"
  chmod 0600 "${hhome}/op/.ssh/authorized_keys"
done
grep -q reload "${hroot}/systemctl.log" && fail "harden_ssh reloaded sshd with no usable key"
# sshd -t refuses the drop-in: it does not stay.
touch "${hroot}/sshd.bad"
ssh_run
[[ ! -e "${hconf}" ]] || fail "harden_ssh kept a drop-in that sshd -t refused"
grep -q 'sshd rejected' "${hroot}/ssh.err" || fail "harden_ssh did not warn when sshd -t failed"
grep -q reload "${hroot}/systemctl.log" && fail "harden_ssh reloaded sshd after sshd -t failed"
# A usable key: key-only, one reload, and no second reload on the next run.
mv "${hroot}/sshd.bad" "${hroot}/sshd.ok"
ssh_run
grep -qx 'PasswordAuthentication no' "${hconf}" || fail "harden_ssh did not write the key-only drop-in"
grep -qx 'KbdInteractiveAuthentication no' "${hconf}" || fail "the key-only drop-in leaves keyboard-interactive on"
grep -q 'login keys for: op' "${hroot}/ssh.out" || fail "harden_ssh did not name the users with a key"
[[ "$(grep -c '^reload ssh' "${hroot}/systemctl.log")" == 1 ]] || fail "harden_ssh did not reload sshd once"
ssh_run
[[ "$(grep -c '^reload ssh' "${hroot}/systemctl.log")" == 1 ]] || fail "harden_ssh reloaded sshd with no change"
# A changed drop-in that sshd refuses: the old one comes back.
echo 'PasswordAuthentication no' >"${hconf}"
mv "${hroot}/sshd.ok" "${hroot}/sshd.bad"
ssh_run
[[ "$(cat "${hconf}")" == 'PasswordAuthentication no' ]] || fail "harden_ssh did not put back the drop-in that sshd accepted"
mv "${hroot}/sshd.bad" "${hroot}/sshd.ok"
# An earlier file keeps passwords on: the effective value says so.
echo 'passwordauthentication yes' >"${hroot}/sshd.T"
ssh_run
grep -q 'sshd still takes passwords' "${hroot}/ssh.err" || fail "harden_ssh did not warn that sshd -T still shows passwords"
for _f in "${apply}" "${prov}"; do
  grep -q '^harden_ssh$' "${_f}" || fail "${_f##*/} does not run harden_ssh"
done
_nft_line="$(grep -n '^nft -f /etc/nftables.conf$' "${apply}" | head -1 | cut -d: -f1)"
_fwd_line="$(grep -n '^sysctl -w net.ipv4.ip_forward=1' "${apply}" | head -1 | cut -d: -f1)"
[[ -n "${_nft_line}" ]] || fail "apply.sh no longer loads /etc/nftables.conf"
[[ -n "${_fwd_line}" ]] || fail "apply.sh never enables ip_forward; the Pi would route nothing"
[[ "${_fwd_line}" -gt "${_nft_line}" ]] ||
  fail "apply.sh enables ip_forward (line ${_fwd_line}) before the ruleset is loaded (line ${_nft_line})"
# Boot and shutdown have the same coupling. The drop-in enables forwarding
# only if our table came up with /etc/nftables.conf. It disables forwarding
# when the ruleset is flushed.
grep -qF "ExecStartPost=-/bin/sh -c 'nft list table inet fortress >/dev/null 2>&1 && sysctl -w net.ipv4.ip_forward=1 >/dev/null'" "${apply}" ||
  fail "apply.sh does not gate boot-time forwarding on the fortress table being loaded"
grep -qF "ExecStopPost=-/bin/sh -c 'sysctl -w net.ipv4.ip_forward=0 >/dev/null'" "${apply}" ||
  fail "apply.sh leaves forwarding on after the ruleset is flushed"
grep -qF 'install -m 0644 "${WORKDIR}/10-pi-fortress-forward.conf" /etc/systemd/system/nftables.service.d/10-pi-fortress-forward.conf' "${apply}" ||
  fail "apply.sh does not install the nftables.service forwarding drop-in"
# provision.sh is not the only path onto a box. ship/upgrade runs only
# apply. Without this, the ruleset was live only and a reboot lost it.
grep -q '^systemctl enable nftables.service' "${apply}" ||
  fail "apply.sh does not enable nftables.service; a ship-upgraded box loses the ruleset at the next boot"
grep -q 'systemctl enable --now nftables' "${apply}" &&
  fail "apply.sh restarts nftables, which would flush the ruleset it just loaded"

# NetworkManager is necessary on a Pi. agent-net, house-net, each
# segment and the VLAN trunk are nmcli profiles. Before, a box without it
# silently skipped the full block and ran 600 more lines. Then settled()
# blamed the cable. The refusal must occur before the ruleset loads.
# Thus the test asserts it by line number, as for the forwarding order.
_nm_gate="$(grep -n '^if ! command -v nmcli >/dev/null 2>&1; then$' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_nm_gate}" ]] || fail "apply.sh no longer refuses an unaddressed box without nmcli"
[[ "${_nm_gate}" -lt "${_nft_line}" ]] ||
  fail "apply.sh checks for nmcli (line ${_nm_gate}) after loading the ruleset (line ${_nft_line})"
awk "NR >= ${_nm_gate} && NR <= ${_nm_gate} + 20" "${apply}" >"${tmp}/nm-gate"
# The appliance image and the VirtualBox lab have no NetworkManager and
# never needed one. Thus the gate depends on the addresses, not on nmcli.
grep -qF 'addr_missing "${INT_IF}" "${PI_IP}"' "${tmp}/nm-gate" ||
  fail "the nmcli gate does not ask whether the interfaces are already addressed; it would refuse the appliance and the lab"
grep -qxE '[[:space:]]*exit 1' "${tmp}/nm-gate" ||
  fail "the nmcli gate warns but does not refuse; an unaddressed box would run on to the end"
grep -qF 'echo "pi-fortress: no nmcli;' "${apply}" ||
  fail "apply.sh skips the NetworkManager block without saying so"
_nm_apt="$(grep -n 'network-manager' "${prov}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_nm_apt}" ]] ||
  fail "provision.sh does not install network-manager; a Pi OS Lite image without it is never addressed"
awk "NR >= ${_nm_apt} - 3 && NR < ${_nm_apt}" "${prov}" | grep -qxF 'if [[ "${PF_LAB:-}" != 1 ]]; then' ||
  fail "provision.sh installs network-manager unconditionally; in the lab ifupdown owns eth0 and eth1 and NM must not join them"

# The resolver of the box. A stub that never bound its port left
# resolv.conf pinned at the stub with nothing behind it. dot_pin_check
# accepts exactly that state. Thus apply ended with "applied" on a box
# that could not resolve anything. This included the feed fetch of the
# next run.
netman="${here}/lib/netman.sh"
grep -q '^stub_ready() {' "${netman}" ||
  fail "lib/netman.sh has no stub_ready; a systemctl restart that exits 0 does not mean the stub is answering"
grep -qF '/dev/tcp/${addr}/53' "${netman}" ||
  fail "stub_ready does not connect to the stub; binding is not answering"
grep -qF 'DOT_STUB_DOWN' "${netman}" ||
  fail "dot_pin_check ignores whether the stub came up; a resolv.conf pinned at a dead stub reads as correct"
# A VLAN parent that still has an address never becomes a trunk port.
# The house untagged on its own port, with one SSID for each VLAN tagged
# on it, is a supported layout (render checkHouseCable). Thus it is kept
# with no notice. Each other addressed parent still gets the notice to move it.
(
  # shellcheck source=lib/netman.sh
  source "${netman}"
  INT_IF=eth0 WAN_IF=wlan0 HOUSE_IF=eth1
  SEG_IF=(eth1.30 eth1.40 eth0.79 eth2 eth2.50)
  trunk_keep eth1 2>"${tmp}/trunk-house.err" || fail "HOUSE_IF=eth1 carrying VLAN segments was made a trunk port"
  [[ ! -s "${tmp}/trunk-house.err" ]] || fail "the trunk notice still fires for HOUSE_IF carrying house-cable VLANs: $(cat "${tmp}/trunk-house.err")"
  trunk_keep eth0 2>"${tmp}/trunk-int.err" || fail "INT_IF=eth0 with a VLAN child was made a trunk port"
  grep -qF 'eth0 is a VLAN parent and still addressed; not made a trunk port. Move it to a VLAN child' "${tmp}/trunk-int.err" ||
    fail "no notice for an addressed INT_IF parent: $(cat "${tmp}/trunk-int.err")"
  trunk_keep eth2 2>"${tmp}/trunk-seg.err" || fail "a segment's untagged parent was made a trunk port"
  grep -qF 'eth2 is a VLAN parent and still addressed' "${tmp}/trunk-seg.err" ||
    fail "no notice for a segment untagged on a VLAN parent: $(cat "${tmp}/trunk-seg.err")"
  if trunk_keep eth3 2>"${tmp}/trunk-free.err"; then
    fail "an unaddressed VLAN parent was kept off the trunk path"
  fi
  [[ ! -s "${tmp}/trunk-free.err" ]] || fail "a notice for an unaddressed parent: $(cat "${tmp}/trunk-free.err")"
  HOUSE_IF="" SEG_IF=()
  if trunk_keep eth1 2>/dev/null; then
    fail "with no house, eth1 is a plain trunk and was kept"
  fi
  true
)
grep -qF 'trunk_keep "${_p}" && continue' "${apply}" || fail "apply.sh does not ask trunk_keep before nm_trunk"
grep -qF 'is a VLAN parent and still addressed' "${apply}" && fail "apply.sh still prints its own copy of the trunk notice"

# A removed segment, or one whose IF moved, loses the seg-<name>
# profile that nm_profile made for it. Thus the VLAN does not keep the
# address after its firewall rules are gone. Only seg-<segment name>
# profiles belong to pi-fortress. No other connection changes. A profile
# that the current SSH session comes through stays, with a warning. A
# delete would cut the session that makes the change. nmcli, ip and ss
# are stubs over a scratch connection table.
nmb="${tmp}/nmbin"
mkdir -p "${nmb}"
cat >"${nmb}/nmcli" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >>"${NM_LOG}"
field() { awk -F'|' -v u="$1" -v c="$2" '$2 == u {print $c}' "${NM_DB}"; }
case "$*" in
  "-t -f NAME,UUID con show") awk -F'|' '{print $1 ":" $2}' "${NM_DB}" ;;
  "-g connection.interface-name con show uuid "*) field "$6" 3 ;;
  "-g ipv4.addresses con show uuid "*) field "$6" 4 ;;
  "-t -f NAME con show") awk -F'|' '{print $1}' "${NM_DB}" ;;
  "con add type ethernet ifname "*) printf '%s|u-add-%s|%s|\n' "$8" "$6" "$6" >>"${NM_DB}" ;;
  "con delete uuid "*)
    grep -q "|$4|" "${NM_DB}" || exit 10
    grep -v "|$4|" "${NM_DB}" >"${NM_DB}.new"
    mv "${NM_DB}.new" "${NM_DB}"
    ;;
esac
exit 0
EOF
cat >"${nmb}/ip" <<'EOF'
#!/bin/bash
[[ "$*" == "-o -4 addr show" ]] && cat "${IP_ADDRS}"
exit 0
EOF
cat >"${nmb}/ss" <<'EOF'
#!/bin/bash
[[ "$*" == "-Htnp state established" ]] && cat "${SS_OUT}"
exit 0
EOF
chmod +x "${nmb}"/*
nmdb() {
  cat >"${tmp}/nm.db" <<'EOF'
Wired connection 1|u-wired|eth3|
agent-net|u-agent|eth0|10.77.0.1/24
house-net|u-house|eth1|10.78.0.1/24
trunk-eth2|u-trunk|eth2|
seg-desk|u-desk|eth0.79|10.79.0.1/30
seg-iot|u-iot|eth1.30|10.30.0.1/24
seg-Cam|u-cam|eth1.40|10.40.0.1/24
segment-lab|u-seglab|eth1.50|10.50.0.1/24
myseg-iot|u-myseg|eth1.60|10.60.0.1/24
seg-|u-empty|eth1.70|10.70.0.1/24
EOF
  : >"${tmp}/nm.log"
  printf '3: eth0.79    inet 10.79.0.1/30 brd 10.79.0.3 scope global eth0.79\n4: eth1.30    inet 10.30.0.1/24 brd 10.30.0.255 scope global eth1.30\n5: wlan0    inet 192.168.1.20/24 brd 192.168.1.255 scope global wlan0\n' >"${tmp}/ip.addrs"
  : >"${tmp}/ss.out"
}
# prune NAMES IFS: seg_prune over SEG_NAME and SEG_IF (space separated).
# It prints SEG_KEPT on the last line.
prune() {
  (
    # shellcheck source=lib/netman.sh
    source "${netman}"
    PATH="${nmb}:${PATH}" NM_DB="${tmp}/nm.db" NM_LOG="${tmp}/nm.log" IP_ADDRS="${tmp}/ip.addrs" SS_OUT="${tmp}/ss.out"
    export NM_DB NM_LOG IP_ADDRS SS_OUT
    read -r -a SEG_NAME <<<"$1"
    read -r -a SEG_IF <<<"$2"
    seg_prune
    echo "kept:${SEG_KEPT}"
  )
}
grep -q '^seg_prune() {' "${netman}" || fail "lib/netman.sh has no seg_prune; a removed segment keeps its NetworkManager profile and its address"

# The iot segment is gone. Its profile goes, with one line of output.
# Nothing else changes: not the other pi-fortress profiles, not a name
# that only looks like one, not the connections of the operator.
nmdb
unset SSH_CONNECTION
prune "desk" "eth0.79" >"${tmp}/prune.out" 2>"${tmp}/prune.err" || fail "seg_prune failed: $(cat "${tmp}/prune.err")"
grep -q '^seg-iot|' "${tmp}/nm.db" && fail "the removed segment's profile seg-iot is still there"
grep -qxF 'con delete uuid u-iot' "${tmp}/nm.log" || fail "seg-iot was not deleted by its UUID: $(cat "${tmp}/nm.log")"
[[ "$(grep -c '^con delete' "${tmp}/nm.log")" -eq 1 ]] || fail "seg_prune deleted more than the stale profile: $(grep '^con delete' "${tmp}/nm.log")"
for _c in 'Wired connection 1' agent-net house-net trunk-eth2 seg-desk seg-Cam segment-lab myseg-iot seg-; do
  grep -q "^${_c}|" "${tmp}/nm.db" || fail "seg_prune deleted ${_c}, which is not a stale pi-fortress segment profile"
done
grep -qxF 'pi-fortress: pruned NetworkManager profile seg-iot (eth1.30): segment iot is gone' "${tmp}/prune.err" ||
  fail "the prune is not reported in one line: $(cat "${tmp}/prune.err")"
[[ "$(wc -l <"${tmp}/prune.err")" -eq 1 ]] || fail "seg_prune said more than one line for one profile: $(cat "${tmp}/prune.err")"
grep -qx 'kept: ' "${tmp}/prune.out" || fail "SEG_KEPT is not empty with nothing kept: $(cat "${tmp}/prune.out")"

# Nothing stale: nothing deleted and nothing said.
nmdb
prune "desk iot" "eth0.79 eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed with nothing stale"
grep -q '^con delete' "${tmp}/nm.log" && fail "seg_prune deleted a profile whose segment and IF are unchanged: $(grep '^con delete' "${tmp}/nm.log")"
[[ ! -s "${tmp}/prune.err" ]] || fail "seg_prune spoke with nothing to prune: $(cat "${tmp}/prune.err")"

# The IF of the desk moved from eth0.79 to eth0.80. seg_prune deletes the
# old profile, so nm_profile makes a new one. The old VLAN does not keep
# its address beside the new one.
nmdb
prune "desk iot" "eth0.80 eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed on an IF change"
grep -q '^seg-desk|' "${tmp}/nm.db" && fail "seg-desk on the old IF eth0.79 was left in place"
grep -qxF 'pi-fortress: pruned NetworkManager profile seg-desk (eth0.79): segment desk moved to IF=eth0.80' "${tmp}/prune.err" ||
  fail "the IF change is not reported: $(cat "${tmp}/prune.err")"
grep -q '^seg-iot|' "${tmp}/nm.db" || fail "an IF change on the desk deleted seg-iot"

# The lockout guard. The session that runs apply comes in on 10.79.0.1,
# the address of the desk. A removed desk keeps seg-desk. The output tells
# why and how to remove it manually. seg_prune still succeeds.
nmdb
SSH_CONNECTION="10.79.0.2 51234 10.79.0.1 22" prune "iot" "eth1.30" >"${tmp}/prune.out" 2>"${tmp}/prune.err" ||
  fail "seg_prune failed when it kept the admin's link: $(cat "${tmp}/prune.err")"
grep -q '^seg-desk|' "${tmp}/nm.db" || fail "seg_prune deleted seg-desk, the profile this SSH session arrives through"
grep -q '^con delete' "${tmp}/nm.log" && fail "seg_prune deleted something while guarding the admin's link: $(grep '^con delete' "${tmp}/nm.log")"
for _w in 'WARNING kept NetworkManager profile seg-desk on eth0.79' 'segment desk is gone' 'SSH session' '10.79.0.1' 'sudo nmcli con delete seg-desk'; do
  grep -qF -- "${_w}" "${tmp}/prune.err" || fail "the lockout warning does not say '${_w}': $(cat "${tmp}/prune.err")"
done
grep -qx 'kept: desk ' "${tmp}/prune.out" || fail "the kept segment is not in SEG_KEPT: $(cat "${tmp}/prune.out")"

# sudo drops SSH_CONNECTION by default. Thus the guard also reads the
# sessions that sshd holds. Here the session address is on the interface
# but not in the address list of the profile.
nmdb
sed -i 's/^seg-desk|u-desk|eth0.79|.*/seg-desk|u-desk|eth0.79|/' "${tmp}/nm.db"
printf '0      0         10.79.0.1:22      10.79.0.2:51234 users:(("sshd-session",pid=812,fd=4))\n0      0     192.168.1.20:22   192.168.1.5:40000 users:(("sshd-session",pid=900,fd=4))\n' >"${tmp}/ss.out"
unset SSH_CONNECTION
prune "iot" "eth1.30" >"${tmp}/prune.out" 2>"${tmp}/prune.err" || fail "seg_prune failed guarding an sshd session"
grep -q '^seg-desk|' "${tmp}/nm.db" || fail "seg_prune deleted seg-desk while sshd holds a session on its interface (SSH_CONNECTION unset, as under sudo)"
grep -qF 'WARNING kept NetworkManager profile seg-desk on eth0.79' "${tmp}/prune.err" || fail "no warning for the session sshd holds: $(cat "${tmp}/prune.err")"
# A session on the uplink protects nothing on a segment.
nmdb
printf '0      0     192.168.1.20:22   192.168.1.5:40000 users:(("sshd-session",pid=900,fd=4))\n' >"${tmp}/ss.out"
SSH_CONNECTION="192.168.1.5 40000 192.168.1.20 22" prune "iot" "eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed with a session on the uplink"
grep -q '^seg-desk|' "${tmp}/nm.db" && fail "a session on the uplink kept the removed desk's profile"

# The IF change with the admin on the old link: kept, and nm_profile does
# not run for the desk, because a change of the kept profile in place would
# also move it off the link.
nmdb
SSH_CONNECTION="10.79.0.2 51234 10.79.0.1 22" prune "desk iot" "eth0.80 eth1.30" >"${tmp}/prune.out" 2>"${tmp}/prune.err" || fail "seg_prune failed on a guarded IF change"
grep -q '^seg-desk|u-desk|eth0.79|' "${tmp}/nm.db" || fail "a guarded IF change deleted or rewrote seg-desk"
grep -qF 'segment desk moved to IF=eth0.80' "${tmp}/prune.err" || fail "the guarded IF change does not name the new IF: $(cat "${tmp}/prune.err")"
grep -qx 'kept: desk ' "${tmp}/prune.out" || fail "the guarded IF change is not in SEG_KEPT"


# A pruned segment on an untagged physical port leaves that port empty.
# NetworkManager then makes a "Wired connection" for it that DHCPs
# all that is connected, and can take the default route. Thus the port is
# parked with an inert pf-parked-<if> profile instead. A VLAN child gets
# no such profile, and a port that a different role still claims also gets none.
_park_add='con add type ethernet ifname eth4 con-name pf-parked-eth4 ipv4.method disabled ipv4.never-default yes ipv6.method disabled connection.autoconnect yes'
nmdb
echo 'seg-printer|u-printer|eth4|10.44.0.1/24' >>"${tmp}/nm.db"
prune "desk iot" "eth0.79 eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed on a raw port: $(cat "${tmp}/prune.err")"
grep -q '^seg-printer|' "${tmp}/nm.db" && fail "the removed raw-port segment's profile is still there"
grep -qxF "${_park_add}" "${tmp}/nm.log" || fail "eth4 was not parked with an inert profile: $(grep '^con add' "${tmp}/nm.log")"
grep -q '^pf-parked-eth4|u-add-eth4|eth4|$' "${tmp}/nm.db" || fail "no pf-parked-eth4 on eth4 after the prune"
[[ "$(grep -c '^con add' "${tmp}/nm.log")" -eq 1 && "$(grep -c '^con delete' "${tmp}/nm.log")" -eq 1 ]] ||
  fail "parking touched more than the one port: $(grep -E '^con (add|delete)' "${tmp}/nm.log")"
grep -qxF 'pi-fortress: pruned NetworkManager profile seg-printer (eth4): segment printer is gone' "${tmp}/prune.err" || fail "the raw-port prune is not reported: $(cat "${tmp}/prune.err")"
grep -qF 'pi-fortress: parked eth4 with the inert profile pf-parked-eth4' "${tmp}/prune.err" || fail "parking is not reported: $(cat "${tmp}/prune.err")"
[[ "$(wc -l <"${tmp}/prune.err")" -eq 2 ]] || fail "a parked prune is more than two lines: $(cat "${tmp}/prune.err")"
for _c in 'Wired connection 1' agent-net house-net trunk-eth2 seg-desk seg-iot seg-Cam segment-lab myseg-iot seg-; do
  grep -q "^${_c}|" "${tmp}/nm.db" || fail "parking deleted ${_c}"
done
# The VLAN child is not parked.
nmdb
prune "desk" "eth0.79" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed"
grep -q '^con add' "${tmp}/nm.log" && fail "a pruned VLAN child was parked: $(grep '^con add' "${tmp}/nm.log")"
# A raw port that is already parked, or that the house now claims, does
# not get a second profile.
for _case in parked claimed; do
  nmdb
  echo 'seg-printer|u-printer|eth4|10.44.0.1/24' >>"${tmp}/nm.db"
  [[ "${_case}" == parked ]] && echo 'pf-parked-eth4|u-old-park|eth4|' >>"${tmp}/nm.db"
  _house=""
  [[ "${_case}" == claimed ]] && _house=eth4
  HOUSE_IF="${_house}" prune "desk iot" "eth0.79 eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed (${_case})"
  grep -q '^con add' "${tmp}/nm.log" && fail "a ${_case} port was parked again: $(grep '^con add' "${tmp}/nm.log")"
  grep -q 'parked' "${tmp}/prune.err" && fail "a ${_case} port was reported parked: $(cat "${tmp}/prune.err")"
done
# The lockout guard has priority: a parked profile does not replace a kept one.
nmdb
echo 'seg-printer|u-printer|eth4|10.44.0.1/24' >>"${tmp}/nm.db"
SSH_CONNECTION="10.44.0.9 50000 10.44.0.1 22" prune "desk iot" "eth0.79 eth1.30" >/dev/null 2>"${tmp}/prune.err" || fail "seg_prune failed guarding a raw port"
grep -q '^seg-printer|' "${tmp}/nm.db" || fail "the admin's raw-port link was deleted"
grep -qE '^con (add|delete)' "${tmp}/nm.log" && fail "the guarded raw port was touched: $(grep -E '^con (add|delete)' "${tmp}/nm.log")"

# nm_unpark: a parked port that a segment, the house, the agents, the
# uplink or a trunk claims again loses its parked profile, by UUID. An
# unclaimed port keeps it. A pf-parked- name on a different interface is
# not ours to judge.
unpark() {
  (
    # shellcheck source=lib/netman.sh
    source "${netman}"
    PATH="${nmb}:${PATH}" NM_DB="${tmp}/nm.db" NM_LOG="${tmp}/nm.log"
    export NM_DB NM_LOG
    read -r -a SEG_NAME <<<"$1"
    read -r -a SEG_IF <<<"$2"
    nm_unpark
  )
}
grep -q '^nm_unpark() {' "${netman}" || fail "lib/netman.sh has no nm_unpark; a parked port would fight the role that claims it again"
nmdb
printf 'pf-parked-eth4|u-park4|eth4|\npf-parked-eth5|u-park5|eth5|\npf-parked-eth6|u-park6|eth7|\npf-parked-eth8|u-park8|eth8|\n' >>"${tmp}/nm.db"
VLAN_PARENTS="eth8 " unpark "desk iot printer" "eth0.79 eth1.30 eth4" >/dev/null 2>"${tmp}/unpark.err" || fail "nm_unpark failed: $(cat "${tmp}/unpark.err")"
grep -q '^pf-parked-eth4|' "${tmp}/nm.db" && fail "pf-parked-eth4 survived a segment claiming eth4 again"
grep -q '^pf-parked-eth8|' "${tmp}/nm.db" && fail "pf-parked-eth8 survived eth8 becoming a trunk port"
grep -qxF 'con delete uuid u-park4' "${tmp}/nm.log" || fail "pf-parked-eth4 was not deleted by UUID"
[[ "$(grep -c '^con delete' "${tmp}/nm.log")" -eq 2 ]] || fail "nm_unpark deleted more than the two claimed ports: $(grep '^con delete' "${tmp}/nm.log")"
for _c in pf-parked-eth5 pf-parked-eth6 'Wired connection 1' agent-net house-net trunk-eth2 seg-desk seg-iot seg-Cam; do
  grep -q "^${_c}|" "${tmp}/nm.db" || fail "nm_unpark deleted ${_c}"
done
grep -qxF 'pi-fortress: unparked eth4: removed pf-parked-eth4, the port is in use again' "${tmp}/unpark.err" || fail "unparking is not reported: $(cat "${tmp}/unpark.err")"
nmdb
printf 'pf-parked-eth4|u-park4|eth4|\n' >>"${tmp}/nm.db"
for _k in INT_IF WAN_IF HOUSE_IF; do
  : >"${tmp}/nm.log"
  cp "${tmp}/nm.db" "${tmp}/nm.db.keep"
  case "${_k}" in
    INT_IF) INT_IF=eth4 unpark desk eth0.79 2>/dev/null ;;
    WAN_IF) WAN_IF=eth4 unpark desk eth0.79 2>/dev/null ;;
    HOUSE_IF) HOUSE_IF=eth4 unpark desk eth0.79 2>/dev/null ;;
  esac
  grep -qxF 'con delete uuid u-park4' "${tmp}/nm.log" || fail "${_k}=eth4 did not unpark eth4"
  cp "${tmp}/nm.db.keep" "${tmp}/nm.db"
done
_unpark_line="$(grep -nx '  nm_unpark' "${apply}" | head -1 | cut -d: -f1 || true)"
_trunk_line="$(grep -nF 'trunk_keep "${_p}" && continue' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_unpark_line}" && -n "${_trunk_line}" && "${_unpark_line}" -lt "${_trunk_line}" ]] ||
  fail "apply.sh does not unpark claimed ports before the trunk and segment profiles are made"
# apply prunes before it makes the profiles, and skips a kept one.
_prune_line="$(grep -nx '  seg_prune' "${apply}" | head -1 | cut -d: -f1 || true)"
_profile_line="$(grep -nF 'if nm_profile "${_con}" "${SEG_IF[${_i}]}"' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_prune_line}" && -n "${_profile_line}" && "${_prune_line}" -lt "${_profile_line}" ]] ||
  fail "apply.sh does not run seg_prune before the segment profiles are made"
grep -qF '[[ "${SEG_KEPT}" == *" ${SEG_NAME[${_i}]} "* ]] && continue' "${apply}" ||
  fail "apply.sh runs nm_profile on a segment whose old profile seg_prune kept for the admin's link"

# DHCP on a plain segment (segments.d DHCP=on). Render gives apply the
# checked range, and the ruleset opens UDP 67 only on that segment.
mkdir -p "${tmp}/dhcp.d"
printf 'IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n' >"${tmp}/dhcp.d/iot.env"
cp "${tmp}/desk.d/desk.env" "${tmp}/dhcp.d/desk.env"
PF_ENV_OUT="${tmp}/dhcp.env" render "${tmp}/house.env" "${tmp}/dhcp.d" >"${tmp}/dhcp.nft" 2>"${tmp}/dhcp.err" ||
  fail "a DHCP segment on the house cable was refused: $(cat "${tmp}/dhcp.err")"
grep -qx "SEG_DHCP=('off' 'on')" "${tmp}/dhcp.env" || fail "apply.env does not carry SEG_DHCP: $(grep '^SEG_DHCP=' "${tmp}/dhcp.env")"
grep -qx "SEG_DHCP_START=('' '10.30.0.100')" "${tmp}/dhcp.env" || fail "apply.env does not carry SEG_DHCP_START"
grep -qx "SEG_DHCP_END=('' '10.30.0.199')" "${tmp}/dhcp.env" || fail "apply.env does not carry SEG_DHCP_END"
grep -qF 'iifname "eth1.30" udp sport 68 udp dport 67 accept' "${tmp}/dhcp.nft" || fail "the DHCP segment's input does not take UDP 67"
grep -qF 'iifname "eth1.30" ip saddr != 10.30.0.0/24 jump seg_iot_spoof' "${tmp}/dhcp.nft" || fail "the DHCP segment has no spoof exception"
grep 'dport 67' "${tmp}/dhcp.nft" | grep -qF '"eth0.79"' && fail "UDP 67 opened on the desk, which has no DHCP"
grep -qF 'must not run its own DHCP' "${tmp}/dhcp.err" || fail "the house-cable warning does not tell the AP to keep its DHCP off"

# lib/dhcp.sh, the half that apply runs: one instance per DHCP segment, its
# conf DHCP-only and bound to the segment. Nothing remains when DHCP
# goes off or the segment is removed. The test runs it against a stub
# systemctl, chown and dnsmasq under a scratch root.
dhcp_lib="${here}/lib/dhcp.sh"
droot="${tmp}/dhcproot"
mkdir -p "${tmp}/dhcpbin" "${droot}/etc" "${droot}/lib" "${droot}/log" "${droot}/units" "${droot}/work"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >>"%s"\n' "${droot}/systemctl.log" >"${tmp}/dhcpbin/systemctl"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >>"%s"\n' "${droot}/chown.log" >"${tmp}/dhcpbin/chown"
printf '#!/bin/bash\n[[ "$1" == --test ]] || exit 1\nprintf "%%s\\n" "$*" >>"%s"\n' "${droot}/dnsmasq.log" >"${tmp}/dhcpbin/dnsmasq"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >>"%s"\n' "${droot}/useradd.log" >"${tmp}/dhcpbin/useradd"
printf '#!/bin/bash\n[[ "$1" == -u ]] && grep -q " ${2}$" "%s" 2>/dev/null\n' "${droot}/useradd.log" >"${tmp}/dhcpbin/id"
chmod +x "${tmp}/dhcpbin"/*
# dhcp_sync IOT: desk and, unless IOT is "gone", iot with DHCP=IOT.
dhcp_sync() {
  (
    # shellcheck source=lib/dhcp.sh
    source "${dhcp_lib}"
    DHCP_ETC="${droot}/etc" DHCP_STATE="${droot}/lib" DHCP_LOGS="${droot}/log" DHCP_UNITS="${droot}/units"
    WORKDIR="${droot}/work" PI_LIB="${here}" PATH="${tmp}/dhcpbin:${PATH}"
    SEG_NAME=(desk) SEG_IF=(eth0.79) SEG_IP=(10.79.0.1) SEG_DHCP=(off) SEG_DHCP_START=('') SEG_DHCP_END=('')
    if [[ "$1" != gone ]]; then
      SEG_NAME+=(iot) SEG_IF+=(eth1.30) SEG_IP+=(10.30.0.1) SEG_DHCP+=("$1") SEG_DHCP_START+=(10.30.0.100) SEG_DHCP_END+=(10.30.0.199)
    fi
    seg_dhcp_sync
  )
}
: >"${droot}/systemctl.log"
dhcp_sync on 2>"${droot}/on.err" || fail "seg_dhcp_sync failed: $(cat "${droot}/on.err")"
dconf="${droot}/etc/dhcp-iot.conf"
[[ -f "${dconf}" ]] || fail "no dnsmasq conf for the DHCP segment"
[[ ! -e "${droot}/etc/dhcp-desk.conf" ]] || fail "a conf was written for the desk, which has no DHCP"
for _l in 'interface=eth1.30' 'except-interface=lo' 'bind-dynamic' 'port=0' 'dhcp-range=10.30.0.100,10.30.0.199,12h' \
  'dhcp-option=option:router,10.30.0.1' 'dhcp-option=option:dns-server,10.30.0.1' \
  "dhcp-leasefile=${droot}/lib/dhcp-iot.leases" "log-facility=${droot}/log/dhcp-iot.log"; do
  grep -qxF -- "${_l}" "${dconf}" || fail "dhcp-iot.conf lacks '${_l}':$(printf '\n%s' "$(cat "${dconf}")")"
done
[[ "$(grep -c '^dhcp-option=' "${dconf}")" -eq 2 ]] || fail "dhcp-iot.conf sends more than the router and the resolver"
[[ "$(grep -c '^interface=' "${dconf}")" -eq 1 ]] || fail "dhcp-iot.conf binds more than one interface"
grep -qE '^(conf-dir|conf-file|domain|dhcp-script|dhcp-boot|enable-tftp|server)=' "${dconf}" &&
  fail "dhcp-iot.conf pulls in or hands out something beyond the lease: $(grep -E '^(conf-dir|conf-file|domain|dhcp-script|dhcp-boot|enable-tftp|server)=' "${dconf}")"
grep -qF -- "--test --conf-file=${droot}/work/dhcp-iot.conf" "${droot}/dnsmasq.log" || fail "the conf was installed without dnsmasq --test"
[[ -f "${droot}/units/pi-fortress-dhcp@.service" ]] || fail "the template unit was not installed"
cmp -s "${droot}/units/pi-fortress-dhcp@.service" "${here}/dhcp@.service" || fail "the installed unit is not vm/pi/dhcp@.service"
grep -qx 'enable pi-fortress-dhcp@iot.service' "${droot}/systemctl.log" || fail "the instance was not enabled"
grep -qx 'restart pi-fortress-dhcp@iot.service' "${droot}/systemctl.log" || fail "the instance was not restarted"
grep -q 'desk' "${droot}/systemctl.log" && fail "systemctl was asked about the desk: $(grep desk "${droot}/systemctl.log")"
for _f in "${droot}/lib/dhcp-iot.leases" "${droot}/log/dhcp-iot.log"; do
  [[ "$(stat -c %a "${_f}")" == 640 ]] || fail "${_f##*/} is not 0640"
done
grep -qxF "pf-dhcp-iot:root ${droot}/lib/dhcp-iot.leases ${droot}/log/dhcp-iot.log" "${droot}/chown.log" ||
  fail "the lease file and the log are not given to the pf-dhcp-iot account: $(cat "${droot}/chown.log")"
grep -q 'dnsmasq' "${droot}/chown.log" && fail "a segment file is given to the shared dnsmasq account: $(cat "${droot}/chown.log")"
[[ "$(grep -c ' pf-dhcp-iot$' "${droot}/useradd.log")" -eq 1 ]] ||
  fail "seg_dhcp_sync did not make the pf-dhcp-iot account: $(cat "${droot}/useradd.log")"
grep -qxF -- '--system --no-create-home --gid nogroup --home /nonexistent --shell /usr/sbin/nologin pf-dhcp-iot' "${droot}/useradd.log" ||
  fail "the pf-dhcp-iot account is not a system account with no login: $(cat "${droot}/useradd.log")"
grep -q 'desk' "${droot}/useradd.log" && fail "an account was made for the desk, which has no DHCP"
if command -v /usr/sbin/dnsmasq >/dev/null 2>&1; then
  /usr/sbin/dnsmasq --test --conf-file="${dconf}" >/dev/null 2>&1 || fail "the real dnsmasq refuses dhcp-iot.conf: $(/usr/sbin/dnsmasq --test --conf-file="${dconf}" 2>&1)"
fi
# The unit is the same as the house unit, line for line, except the names.
diff <(grep -v '^#' "${here}/dns-house.service" | sed 's/house segment DHCP/DHCP for segment %i/') \
  <(grep -v '^#' "${here}/dhcp@.service" | sed -e 's#pi-fortress-dhcp-%i#pi-fortress-dns-house#g' -e 's#dhcp-%i.conf#dns-house.conf#' -e 's#dhcp-%i.leases#house.leases#' -e 's#pf-dhcp-%i#pf-dhcp-house#g') >/dev/null ||
  fail "dhcp@.service drifted from dns-house.service beyond its names"
grep -qF -- '--conf-file=/etc/pi-fortress/dhcp-%i.conf' "${here}/dhcp@.service" || fail "dhcp@.service does not read its own conf"
grep -v '^#' "${here}/dhcp@.service" | grep -qF -- 'conf-dir' && fail "dhcp@.service reads a conf-dir"

# DHCP off: stopped, disabled, and conf, leases, enable link and template
# removed. systemctl is a stub, so the test makes the link that enable would make.
mkdir -p "${droot}/units/multi-user.target.wants"
ln -sf "${droot}/units/pi-fortress-dhcp@.service" "${droot}/units/multi-user.target.wants/pi-fortress-dhcp@iot.service"
: >"${droot}/systemctl.log"
dhcp_sync off 2>"${droot}/off.err" || fail "seg_dhcp_sync failed with DHCP off: $(cat "${droot}/off.err")"
grep -qx 'disable --now pi-fortress-dhcp@iot.service' "${droot}/systemctl.log" || fail "DHCP off did not stop and disable the instance"
grep -qx 'daemon-reload' "${droot}/systemctl.log" || fail "DHCP off did not reload systemd after removing the template"
for _f in etc/dhcp-iot.conf lib/dhcp-iot.leases units/pi-fortress-dhcp@.service units/multi-user.target.wants/pi-fortress-dhcp@iot.service; do
  [[ ! -e "${droot}/${_f}" && ! -L "${droot}/${_f}" ]] || fail "DHCP off left ${_f}"
done
grep -qF 'segment iot has no DHCP now' "${droot}/off.err" || fail "DHCP off removed the instance without saying so"
: >"${droot}/systemctl.log"
dhcp_sync off 2>/dev/null
[[ ! -s "${droot}/systemctl.log" ]] || fail "a box with no DHCP segment touched systemd again: $(cat "${droot}/systemctl.log")"

# The segment removed fully, and a file that render could never
# write, which stays as it is.
dhcp_sync on 2>/dev/null || fail "seg_dhcp_sync failed turning DHCP back on"
touch "${droot}/etc/dhcp-Not.Ours.conf"
: >"${droot}/systemctl.log"
dhcp_sync gone 2>/dev/null || fail "seg_dhcp_sync failed with the segment removed"
grep -qx 'disable --now pi-fortress-dhcp@iot.service' "${droot}/systemctl.log" || fail "a removed segment's instance was not stopped"
[[ "$(grep -c ' pf-dhcp-iot$' "${droot}/useradd.log")" -eq 1 ]] ||
  fail "seg_dhcp_sync made the pf-dhcp-iot account again although it exists: $(cat "${droot}/useradd.log")"
[[ ! -e "${droot}/etc/dhcp-iot.conf" && ! -e "${droot}/lib/dhcp-iot.leases" ]] || fail "a removed segment left its conf or leases"
[[ -e "${droot}/etc/dhcp-Not.Ours.conf" ]] || fail "seg_dhcp_sync removed a file that is not one of its own"
grep -q 'Not' "${droot}/systemctl.log" && fail "systemctl was asked about a file that is not one of ours"

# apply runs it, after the house block, with paths under its own
# /etc and /var, so that the rewrite of the appliance test reaches them.
grep -qF 'source "${LIB_DIR}/dhcp.sh"' "${apply}" || fail "apply.sh does not source lib/dhcp.sh"
grep -qx 'seg_dhcp_sync || exit 1' "${apply}" || fail "apply.sh does not run seg_dhcp_sync"
for _l in 'DHCP_ETC=/etc/pi-fortress' 'DHCP_STATE=/var/lib/pi-fortress' 'DHCP_LOGS=/var/log/pi-fortress' 'DHCP_UNITS=/etc/systemd/system'; do
  grep -qF "${_l}" "${apply}" || fail "apply.sh does not set ${_l}"
done
grep -qF 'pi-fortress-dhcp@${SEG_NAME[${_i}]}.service' "${apply}" || fail "settled() does not check each segment's DHCP instance"
_house_dhcp="$(grep -n 'install -m 0644 "${PI_LIB}/dns-house.service"' "${apply}" | cut -d: -f1)"
_seg_dhcp="$(grep -nx 'seg_dhcp_sync || exit 1' "${apply}" | cut -d: -f1)"
[[ -n "${_house_dhcp}" && -n "${_seg_dhcp}" && "${_seg_dhcp}" -gt "${_house_dhcp}" ]] || fail "segment DHCP is not set up after the house's"
# Rotated as the house DHCP log is: made again with the owner that it had,
# the account of its instance, which gets a signal to reopen it.
grep -A12 '^/var/log/pi-fortress/dhcp-\*\.log {' "${conf}" | grep -qx '    create 0640' ||
  fail "logrotate.conf: the segment DHCP logs are not rotated, or not recreated with the owner they had"

# Reservations on a DHCP segment: dhcp.<name>.hosts next to segments.d,
# in the house.hosts form. Render checks them and gives them to apply in
# apply.env. seg_dhcp_conf writes each as a dhcp-host line into the conf
# of that segment, and into no other conf.
mkdir -p "${tmp}/hosts/segments.d"
printf 'IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n' >"${tmp}/hosts/segments.d/iot.env"
printf 'IF=eth1.40\nNET=10.40.0.0/24\nIP=10.40.0.1\nDHCP=on\nDHCP_START=10.40.0.100\nDHCP_END=10.40.0.199\n' >"${tmp}/hosts/segments.d/cam.env"
printf '# the door camera keeps its address\n02:00:00:00:00:0A,10.30.0.50,cam-door\n02:00:00:00:00:0b,10.30.0.150\n' >"${tmp}/hosts/dhcp.iot.hosts"
PF_ENV_OUT="${tmp}/hosts.env" render "${tmp}/house.env" "${tmp}/hosts/segments.d" >/dev/null 2>"${tmp}/hosts.err" ||
  fail "a segment with reservations was refused: $(cat "${tmp}/hosts.err")"
grep -qx "SEG_DHCP_HOSTS=('' '02:00:00:00:00:0a,10.30.0.50,cam-door 02:00:00:00:00:0b,10.30.0.150')" "${tmp}/hosts.env" ||
  fail "apply.env does not carry the checked reservations: $(grep '^SEG_DHCP_HOSTS=' "${tmp}/hosts.env")"
printf '02:00:00:00:00:0c,10.30.0.1\n' >"${tmp}/hosts/dhcp.iot.hosts"
render "${tmp}/house.env" "${tmp}/hosts/segments.d" >/dev/null 2>"${tmp}/hosts.err" && fail "a reservation of the Pi's own address was rendered"
grep -qF 'is IP, the address the Pi answers on. Nothing was changed.' "${tmp}/hosts.err" || fail "the refusal does not say why: $(cat "${tmp}/hosts.err")"
(
  # shellcheck source=lib/dhcp.sh
  source "${dhcp_lib}"
  DHCP_STATE=/var/lib/pi-fortress DHCP_LOGS=/var/log/pi-fortress
  seg_dhcp_conf iot eth1.30 10.30.0.1 10.30.0.100 10.30.0.199 '02:00:00:00:00:0a,10.30.0.50,cam-door 02:00:00:00:00:0b,10.30.0.150' >"${tmp}/hosts-iot.conf"
  seg_dhcp_conf cam eth1.40 10.40.0.1 10.40.0.100 10.40.0.199 '' >"${tmp}/hosts-cam.conf"
)
for _l in 'dhcp-host=02:00:00:00:00:0a,10.30.0.50,cam-door' 'dhcp-host=02:00:00:00:00:0b,10.30.0.150'; do
  grep -qxF -- "${_l}" "${tmp}/hosts-iot.conf" || fail "dhcp-iot.conf lacks '${_l}':$(printf '\n%s' "$(cat "${tmp}/hosts-iot.conf")")"
done
[[ "$(grep -c '^dhcp-host=' "${tmp}/hosts-iot.conf")" -eq 2 ]] || fail "dhcp-iot.conf has other dhcp-host lines than its two reservations"
grep -q '^dhcp-host' "${tmp}/hosts-cam.conf" && fail "a segment without reservations got a dhcp-host line"
grep -qE '^dhcp-hostsfile=' "${tmp}/hosts-iot.conf" && fail "the reservations went to a hosts file instead of the conf"
if command -v /usr/sbin/dnsmasq >/dev/null 2>&1; then
  /usr/sbin/dnsmasq --test --conf-file="${tmp}/hosts-iot.conf" >/dev/null 2>&1 || fail "the real dnsmasq refuses the reservations: $(/usr/sbin/dnsmasq --test --conf-file="${tmp}/hosts-iot.conf" 2>&1)"
fi
# seg_dhcp_sync gives each segment its own entry of SEG_DHCP_HOSTS.
(
  # shellcheck source=lib/dhcp.sh
  source "${dhcp_lib}"
  DHCP_ETC="${droot}/etc" DHCP_STATE="${droot}/lib" DHCP_LOGS="${droot}/log" DHCP_UNITS="${droot}/units"
  WORKDIR="${droot}/work" PI_LIB="${here}" PATH="${tmp}/dhcpbin:${PATH}"
  SEG_NAME=(cam iot) SEG_IF=(eth1.40 eth1.30) SEG_IP=(10.40.0.1 10.30.0.1) SEG_DHCP=(on on)
  SEG_DHCP_START=(10.40.0.100 10.30.0.100) SEG_DHCP_END=(10.40.0.199 10.30.0.199)
  SEG_DHCP_HOSTS=('' '02:00:00:00:00:0a,10.30.0.50,cam-door')
  seg_dhcp_sync 2>/dev/null
) || fail "seg_dhcp_sync failed with reservations"
grep -qxF 'dhcp-host=02:00:00:00:00:0a,10.30.0.50,cam-door' "${droot}/etc/dhcp-iot.conf" || fail "seg_dhcp_sync did not write iot's reservation into dhcp-iot.conf"
grep -q '^dhcp-host' "${droot}/etc/dhcp-cam.conf" && fail "iot's reservation landed in dhcp-cam.conf"
grep -qF '"${SEG_DHCP_HOSTS[${i}]:-}"' "${dhcp_lib}" || fail "seg_dhcp_sync does not pass SEG_DHCP_HOSTS, or breaks under set -u on an apply.env without it"
grep -A12 '^/var/log/pi-fortress/dhcp-\*\.log {' "${conf}" | grep -qF "kill -s USR2 'pi-fortress-dhcp@*.service'" ||
  fail "logrotate.conf: the segment dnsmasq instances are not told to reopen their logs"
_ready_line="$(grep -n '^  if ! stub_ready "${DOT_ADDR}"; then$' "${apply}" | head -1 | cut -d: -f1 || true)"
_pin_line="$(grep -n '^  box_dns_pin on$' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_ready_line}" ]] || fail "apply.sh never waits for the stub before pinning the box's resolver"
[[ -n "${_pin_line}" ]] || fail "apply.sh no longer pins the box's resolver"
[[ "${_ready_line}" -lt "${_pin_line}" ]] ||
  fail "apply.sh pins the box's resolver (line ${_pin_line}) before checking the stub answers (line ${_ready_line})"

# Per-segment DoT providers (docs/user_guide/home_network.md). The house keeps
# its own name and addresses in house.env. If none are set, it shares the
# stub of the agents. If they are set, it forwards to a second stub.
dot_env $'DOT_AUTH_NAME=dns.quad9.net\nDOT_IPS="9.9.9.9 149.112.112.112"'
printf 'HOUSE_IF=eth1\n' >"${tmp}/h-plain.env"
PF_ENV_OUT="${tmp}/h-plain.out" dot_render "${tmp}/h-plain.env" >/dev/null \
  || fail "a house with no provider of its own was refused"
grep -q "^HOUSE_DNS_FORWARD='127.0.0.1'$" "${tmp}/h-plain.out" \
  || fail "a house with no provider of its own does not share the agents' stub: $(grep '^HOUSE_DNS_FORWARD=' "${tmp}/h-plain.out")"

printf 'HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=abcd1234xyz.dns.controld.com\nHOUSE_DOT_IPS="76.76.2.22 76.76.10.22"\n' >"${tmp}/h-dot.env"
PF_ENV_OUT="${tmp}/h-dot.out" dot_render "${tmp}/h-dot.env" >"${tmp}/h-dot.nft" \
  || fail "a house with its own DoT provider was refused"
grep -q "^HOUSE_DNS_FORWARD='127.0.0.2'$" "${tmp}/h-dot.out" \
  || fail "the house provider did not move the house forward to its own stub: $(grep '^HOUSE_DNS_FORWARD=' "${tmp}/h-dot.out")"
grep -q "^HOUSE_DOT_IPS='76.76.2.22 76.76.10.22'$" "${tmp}/h-dot.out" \
  || fail "apply.env does not carry HOUSE_DOT_IPS, so apply cannot build the second stub"
# One uid rule for both stubs, with the union in DOT_IPS order.
grep -qF 'meta skuid "pf-dns" ip daddr { 9.9.9.9, 149.112.112.112, 76.76.2.22, 76.76.10.22 } tcp dport 853 accept' "${tmp}/h-dot.nft" \
  || fail "the 853 pin does not cover both providers: $(grep -F 'dport 853 accept' "${tmp}/h-dot.nft")"

# house.env has shell format, and some tools source it (vm/itest does). Thus
# a value with a space in it must survive that. Without quotes, the shell
# reads the second address as a command, with the first in its environment.
# That is how this was found: "76.76.10.22: command not found".
( set -euo pipefail; . "${tmp}/h-dot.env" >/dev/null 2>&1 ) \
  || fail "house.env with a DoT address list cannot be sourced; the second address runs as a command"

# The refusals. A house provider is a second stub next to the stub of the
# box. It is not a way to enable DoT for the house alone.
h_refuse() {
  printf '%s\n' "$2" >"${tmp}/h-bad.env"
  if dot_render "${tmp}/h-bad.env" >/dev/null 2>"${tmp}/h-bad.err"; then
    fail "house.env accepted: $2"
  fi
  grep -qF "$1" "${tmp}/h-bad.err" || fail "refusal for '$2' lacks '$1': $(cat "${tmp}/h-bad.err")"
}
h_refuse 'set together or not at all' $'HOUSE_IF=eth1\nHOUSE_DOT_IPS="76.76.2.22"'
# A quote in the middle is not quoting. It is an injection attempt.
h_refuse 'is not an IPv4 address' $'HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=a.example.com\nHOUSE_DOT_IPS=76.76.2.22";reboot;"'
h_refuse 'is not a DNS name' $'HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=76.76.2.22\nHOUSE_DOT_IPS="76.76.2.22"'
h_refuse 'lists an address twice' $'HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=a.example.com\nHOUSE_DOT_IPS="76.76.2.22 76.76.2.22"'
h_refuse 'pick the DoT provider or the plaintext address' $'HOUSE_IF=eth1\nHOUSE_DNS_UPSTREAM=1.1.1.1\nHOUSE_DOT_AUTH_NAME=a.example.com\nHOUSE_DOT_IPS="76.76.2.22"'
dot_env ''
h_refuse 'HOUSE_DOT_IPS is set but DOT_IPS is not' $'HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=a.example.com\nHOUSE_DOT_IPS="76.76.2.22"'

# The stub template runs both instances from one set of hardening
# directives. A second concrete unit would become different from the first.
[[ -f "${here}/dns-stub@.service" ]] || fail "vm/pi/dns-stub@.service is missing"
grep -qF 'ExecStart=/usr/local/sbin/pf dns -config /etc/pi-fortress/dns-stub-%i.json' "${here}/dns-stub@.service" \
  || fail "the stub unit is not per-instance -config; both providers would share one file, or it passes flags pf dns no longer has"
# Same seccomp box as the agent resolver -- it is the same binary, and the
# lookups of the box itself go through it -- without AF_NETLINK, which
# only the nft fork on the agent side needs.
for _l in \
  'RestrictAddressFamilies=AF_INET AF_UNIX' \
  'RestrictSUIDSGID=yes' \
  'SystemCallArchitectures=native' \
  'SystemCallFilter=@system-service' \
  'SystemCallFilter=~@privileged'; do
  grep -qxF "${_l}" "${here}/dns-stub@.service" || fail "dns-stub@.service has no '${_l}'"
done
# provision disables avahi: the mDNS of the Pi itself loops back into the input
# chain, and fills the drop log and the Events screen with its own address.
grep -qE '^systemctl disable --now avahi-daemon\.socket avahi-daemon\.service' "${here}/provision.sh" \
  || fail "provision.sh no longer disables avahi-daemon"

# The agent gets its CA from the gateway before it looks in /vagrant:
# on a real Pi, /vagrant holds the copy of the desk, which is not the Pi CA.
_routes="${here}/../agent/routes.sh"
_fetch="$(grep -n 'http://${PI_IP}/ca.pem' "${_routes}" | head -1 | cut -d: -f1)"
_file="$(grep -n '/vagrant/vm/policy/generated/egress-ca.pem' "${_routes}" | head -1 | cut -d: -f1)"
[[ -n "${_fetch}" && -n "${_file}" && "${_fetch}" -lt "${_file}" ]] \
  || fail "agent/routes.sh does not fetch the gateway's ca.pem before reading /vagrant"

# status.sh reads the same per-instance files that apply writes. It
# still looked for dns-stub.env after 83cbf26. Thus it reported "plaintext,
# no DoT stub" on a box that sent all queries over TLS (Pi, 2026-09-21).
grep -qF '/etc/pi-fortress/dns-stub-*.json' "${here}/status.sh" \
  || fail "status.sh does not look for the dns-stub-<inst>.json files apply writes"
grep -qF 'dns-stub.env' "${here}/status.sh" \
  && fail "status.sh still reads the retired dns-stub.env"
grep -qF 'pi-fortress-dns-stub@house.service' "${apply}" \
  || fail "apply.sh never manages the house stub instance"

# All tests above render. --render-nft exits before apply changes
# anything. Thus the half of the script that changes the box -- the
# argument loop and the --local branch -- had only a review as coverage.
# The two blocks below run the real script. The first runs as this user,
# because a refusal must come before the root check to be useful.
# The second runs under a fake root with stubs for the system commands,
# as vm/appliance/apply_test.sh runs a full apply.

# The argument loop had no default branch. Thus apply ignored a word that
# it did not know: `pf apply -h` -- which the pf usage tells the operator
# to type -- left RENDER=0 and LOCAL_ONLY=0, and ran the full fetch,
# install and fence restart. A request for help is not consent to
# reconfigure the box, and a typo is not consent.
if ! _argout="$(bash "${apply}" -h 2>&1)"; then
  fail "apply.sh -h did not exit 0: ${_argout}"
fi
grep -qF 'usage: pf apply' <<<"${_argout}" || fail "apply.sh -h printed no usage: ${_argout}"
if ! _argout="$(bash "${apply}" --help 2>&1)"; then
  fail "apply.sh --help did not exit 0: ${_argout}"
fi
for _bad in --bogus -x --local=yes render-nft; do
  if _argout="$(bash "${apply}" "${_bad}" 2>&1)"; then
    fail "apply.sh accepted ${_bad}"
  fi
  grep -qF -- "${_bad}" <<<"${_argout}" || fail "apply.sh refusal for ${_bad} does not name it: ${_argout}"
done
# Only a mode that the script implements may be combined with a different mode.
if _argout="$(bash "${apply}" --local --render-nft 2>&1)"; then
  fail "apply.sh accepted --local with --render-nft"
fi

# Go also judges the same argument before pf apply takes the production
# lock. If not, a request for help still costs an exclusive lock and an exec.
pfbin="${PF_BIN:-${here}/../../bin/pf}"
[[ -x "${pfbin}" ]] || fail "no pf at ${pfbin} (make split-bin, or set PF_BIN)"

# The stub config that apply writes must be one that the pf next to it accepts.
# On 2026-09-18, pf dns replaced its per-segment flags with -config, but the
# stub unit still gave them. Thus DoT on any box meant no DNS --
# and no test here found it, because the test only rendered the DoT path of apply.
# stub_config is the apply function itself, taken out and run as is, and
# its output goes through the real -check for both instances.
(
  # shellcheck source=/dev/null
  source <(sed -n -e '/^json_str() {$/,/^}$/p' -e '/^json_list() {$/,/^}$/p' -e '/^stub_config() {$/,/^}$/p' "${apply}")
  declare -F stub_config >/dev/null || fail "stub_config is gone from apply.sh"
  DOT_ADDR=127.0.0.1 DOT_AUTH_NAME=dns.quad9.net DOT_IPS="9.9.9.9 149.112.112.112"
  HOUSE_DOT_ADDR=127.0.0.2 HOUSE_DOT_AUTH_NAME=a.example.com HOUSE_DOT_IPS="76.76.2.22"
  WG_IF=wg0
  for inst in main house; do
    stub_config "${inst}" >"${tmp}/dns-stub-${inst}.json"
    "${pfbin}" dns -config "${tmp}/dns-stub-${inst}.json" -check >/dev/null 2>"${tmp}/stub-check.err" \
      || fail "pf dns -check refuses the ${inst} stub config apply writes: $(cat "${tmp}/stub-check.err")"
  done
  grep -q '"dot_ips": \["9.9.9.9 149.112.112.112"\]' "${tmp}/dns-stub-main.json" \
    || fail "the main stub config lost DOT_IPS: $(cat "${tmp}/dns-stub-main.json")"
  # The stub of a WireGuard house dials through the tunnel. The stub of
  # the box stays on the uplink.
  grep -q '"dot_iface": "wg0"' "${tmp}/dns-stub-house.json" \
    || fail "the house stub is not bound to WG_IF: $(cat "${tmp}/dns-stub-house.json")"
  grep -q '"dot_iface": ""' "${tmp}/dns-stub-main.json" \
    || fail "the main stub is bound to an interface: $(cat "${tmp}/dns-stub-main.json")"
  grep -q '"sinkhole": \[\], "nft_set": "", "log": ""' "${tmp}/dns-stub-main.json" \
    || fail "the stub config gained a sinkhole, set or log the box's own lookups must not have"
)
# HOUSE_BLOCK_VPN: the VPN/proxy feed is compiled, installed, and put
# in the sinkhole of the house resolver, unless the key is off. Not in the
# agent list: the agent has no VPN to reach.
grep -qF -- '--out-house-vpn-dns "${WORKDIR}/house-vpn.domains"' "${apply}" || fail "apply does not compile the house VPN list"
grep -qF 'install -m 0644 "${WORKDIR}/house-vpn.domains" /etc/pi-fortress/house-vpn-domains.conf' "${apply}" || fail "apply does not install the house VPN list"
grep -qF '[[ "${HOUSE_BLOCK_VPN:-}" == off ]] && DNS_RESOLVER_HOUSE_VPN=""' "${apply}" || fail "HOUSE_BLOCK_VPN=off does not take the VPN list out of the house resolver"
[[ "$(grep -c 'DNS_RESOLVER_HOUSE_VPN}' "${apply}")" -eq 1 ]] || fail "the house VPN list is served somewhere other than the house segment"
# The SNI check: the house segment reads the queue that render names, and the
# fragment that apply splices in is valid JSON that pf dns -check accepts.
grep -qF '"nft_set": "resolved_house_v4", "log": %s%s}' "${apply}" || fail "the house segment has no slot for the SNI fields"
[[ -f "$(dirname "${apply}")/../policy/house_ech.ips" ]] || fail "house_ech.ips is not shipped"
(
  HOUSE_SNI_QUEUE=1
  eval "$(sed -n '/^    DNS_RESOLVER_HOUSE_SNI=""$/,/^    fi$/p' "${apply}" | sed 's/^    //')"
  [[ -n "${DNS_RESOLVER_HOUSE_SNI}" ]] || fail "HOUSE_SNI_QUEUE=1 gave the house segment no SNI fields"
  printf '{"listen": 53, "nft_table": "inet fortress", "segments": [{"name": "house", "iface": "lo", "ip": "127.0.0.2", "upstream": "127.0.0.1:53", "sinkhole": [], "nft_set": "", "log": ""%s}]}\n' \
    "${DNS_RESOLVER_HOUSE_SNI}" >"${tmp}/sni-dns.json"
  grep -qF '"sni_queue": 1, "sni_ech_ips": "/etc/pi-fortress/house-ech.ips", "sni_opaque_ips": "/etc/pi-fortress/house-whatsapp.ips"' "${tmp}/sni-dns.json" || fail "SNI fields: $(cat "${tmp}/sni-dns.json")"
  "${pfbin}" dns -config "${tmp}/sni-dns.json" -check >/dev/null 2>"${tmp}/sni-check.err" \
    || fail "pf dns -check refuses the house SNI fields: $(cat "${tmp}/sni-check.err")"
  HOUSE_ALLOW_WHATSAPP=off
  eval "$(sed -n '/^    DNS_RESOLVER_HOUSE_SNI=""$/,/^    fi$/p' "${apply}" | sed 's/^    //')"
  [[ "${DNS_RESOLVER_HOUSE_SNI}" != *sni_opaque_ips* ]] || fail "HOUSE_ALLOW_WHATSAPP=off still lets non-TLS flows into Meta's ranges"
)
# The dns.json entry of a paranoid plain segment: the segment loop of apply,
# taken out and run as is over the arrays that render gives back, and the
# result through the real -check. The armed desk has its own
# allowlist and no core_hosts. The unarmed guest has neither.
(
  # shellcheck source=/dev/null
  source <(sed -n -e '/^json_str() {$/,/^}$/p' -e '/^json_list() {$/,/^}$/p' "${apply}")
  _loop="$(sed -n '/# The agent.s PARANOID never reaches a plain segment/,/^  done$/p' "${apply}")"
  [[ "${_loop}" == *'_sparanoid'* ]] || fail "the plain-segment dns.json loop is gone from apply.sh"
  printf 'github.com\n' >"${tmp}/allow.desk.domains"
  SEG_NAME=(desk guest) SEG_IF=(eth0.79 eth2) SEG_IP=(10.79.0.1 10.80.0.1)
  SEG_PARANOID=(on off) SEG_ALLOW=("${tmp}/allow.desk.domains" "")
  DNS_RESOLVER_UPSTREAM=127.0.0.1:53
  {
    printf '{"listen": 53, "nft_table": "inet fortress", "segments": [\n    {"iface": "lo", "ip": "127.0.0.1", "upstream": "127.0.0.1:53", "sinkhole": [], "nft_set": "", "log": ""}'
    eval "${_loop}"
    printf '\n]}\n'
  } >"${tmp}/seg-dns.json"
  grep -qF '"nft_set": "resolved_desk_v4", "log": "/var/log/pi-fortress/dns-desk.jsonl", "key_rules": "/etc/pi-fortress/key_prefixes.rules", "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow", "dns_types": "", "paranoid": true, "allow": "'"${tmp}"'/allow.desk.domains"}' "${tmp}/seg-dns.json" ||
    fail "the armed desk's dns.json entry: $(cat "${tmp}/seg-dns.json")"
  grep -qF '"nft_set": "resolved_guest_v4", "log": "/var/log/pi-fortress/dns-guest.jsonl", "key_rules": "/etc/pi-fortress/key_prefixes.rules", "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow", "dns_types": ""}' "${tmp}/seg-dns.json" ||
    fail "the unarmed guest's dns.json entry changed: $(cat "${tmp}/seg-dns.json")"
  grep -q 'core_hosts' "${tmp}/seg-dns.json" && fail "a plain segment was handed core.hosts"
  # On a Pi, the guard files are in /etc/pi-fortress. Here, -check reads the
  # copies in the repo. The text check above already checked the real paths.
  sed -e "s#/etc/pi-fortress/key_prefixes.rules#${here}/../policy/key_prefixes.rules#g" \
    -e "s#/etc/pi-fortress/dns_types.allow#${here}/../policy/dns_types.allow#g" \
    "${tmp}/seg-dns.json" >"${tmp}/seg-dns.check.json"
  mv "${tmp}/seg-dns.check.json" "${tmp}/seg-dns.json"
  "${pfbin}" dns -config "${tmp}/seg-dns.json" -check >"${tmp}/seg-check.out" 2>"${tmp}/seg-check.err" ||
    fail "pf dns -check refuses the paranoid desk: $(cat "${tmp}/seg-check.err")"
  grep -q '^desk .* paranoid=1' "${tmp}/seg-check.out" || fail "-check does not show the desk armed: $(cat "${tmp}/seg-check.out")"
  grep '^guest ' "${tmp}/seg-check.out" | grep -q 'paranoid=' && fail "-check shows the unarmed guest armed"
  rm "${tmp}/allow.desk.domains"
  "${pfbin}" dns -config "${tmp}/seg-dns.json" -check >/dev/null 2>&1 && fail "pf dns -check accepted a paranoid desk with no allowlist"
  true
)
# HOUSE_ALLOW_WHATSAPP: the Meta ranges are shipped, compiled into the
# house set and installed for pf dns.
[[ -f "$(dirname "${apply}")/../policy/house_whatsapp.ips" ]] || fail "house_whatsapp.ips is not shipped"
grep -qF -- '--out-house-whatsapp-nft "${WORKDIR}/house-whatsapp.nft"' "${apply}" || fail "apply does not compile the WhatsApp ranges"
grep -qF 'install -m 0644 "${POLICY}/house_whatsapp.ips" /etc/pi-fortress/house-whatsapp.ips' "${apply}" || fail "apply does not install the WhatsApp ranges"
printf 'HOUSE_IF=eth1\n' >"${tmp}/wa.env"
PF_HOUSE_WHATSAPP_ELEMENTS='elements = { 57.144.0.0/14 }' render "${tmp}/wa.env" >"${tmp}/wa.nft"
grep -qF 'elements = { 57.144.0.0/14 }' "${tmp}/wa.nft" || fail "WhatsApp: set elements missing"
grep -qF 'tcp dport 5222 ip daddr @house_whatsapp_v4 return' "${tmp}/wa.nft" || fail "WhatsApp: 5222 to Meta not allowed"
grep -qF 'ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop' "${tmp}/wa.nft" || fail "WhatsApp: its port 80 fallback is dropped by the gate"
printf 'HOUSE_IF=eth1\nHOUSE_ALLOW_WHATSAPP=off\n' >"${tmp}/wa-off.env"
render "${tmp}/wa-off.env" >"${tmp}/wa-off.nft"
! grep -qF 'house_whatsapp_v4' "${tmp}/wa-off.nft" || fail "HOUSE_ALLOW_WHATSAPP=off still renders the Meta set"

# Also, the check comes before the ruleset: a refused stub after nft -f gives
# a box with plaintext 53 dropped and no resolver.
_stubchk="$(grep -n 'pf dns refuses the ${inst} DoT stub configuration' "${apply}" | head -1 | cut -d: -f1)"
_nftload="$(grep -n '^nft -f /etc/nftables.conf$' "${apply}" | head -1 | cut -d: -f1)"
[[ -n "${_stubchk}" && -n "${_nftload}" && "${_stubchk}" -lt "${_nftload}" ]] \
  || fail "the DoT stub check is not before the ruleset load"

# apply carries the resolved-address sets across that one load. A full apply
# and --local get to the same three lines. Thus a proof of exactly one
# load, with a save above it and a restore below it, covers both paths. A
# second `nft -f` in any location would need its own pair. Without one,
# the gate drops a client that answers from its own DNS cache,
# until that cache expires (the desk, 2026-09-22).
_carrysave="$(grep -n 'nftsets save' "${apply}" | head -1 | cut -d: -f1 || true)"
_carryrest="$(grep -n 'nftsets restore' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_carrysave}" && "${_carrysave}" -lt "${_nftload}" ]] \
  || fail "nothing saves the resolved-address sets before the ruleset load"
[[ -n "${_carryrest}" && "${_carryrest}" -gt "${_nftload}" ]] \
  || fail "nothing puts the resolved-address sets back after the ruleset load"
[[ "$(grep -c '^nft -f ' "${apply}")" -eq 1 ]] \
  || fail "apply.sh loads the ruleset in more than one place; each load needs its own save and restore"
if ! _argout="$("${pfbin}" apply -h 2>&1)"; then
  fail "pf apply -h did not exit 0: ${_argout}"
fi
grep -qF 'usage: pf apply' <<<"${_argout}" || fail "pf apply -h printed no usage: ${_argout}"
"${pfbin}" apply --bogus >/dev/null 2>"${tmp}/pf-bad.err" && fail "pf apply accepted --bogus"
grep -qF -- '--bogus' "${tmp}/pf-bad.err" || fail "pf apply refusal does not name --bogus: $(cat "${tmp}/pf-bad.err")"

# --local under a fake root. It is the edit-and-reload path of the operator,
# and the TUI runs it. Before, it returned ~70 lines before it copied
# core.hosts, allow.domains and key_prefixes.rules into
# /etc/pi-fortress. Thus a permission revoked in the policy tree stayed live
# while the command printed "local policy reloaded". Its restart decision
# came from three hand-picked flags. On a box whose
# policy dir IS /etc/pi-fortress, the same-file guard pins the
# git_push.allow flag to 0 permanently. Thus an in-place edit to the push
# allowlist never got to the broker.
lwan="$(ls /sys/class/net 2>/dev/null | grep -vx lo | head -1 || true)"
if [[ -z "${lwan}" ]]; then
  echo "apply_test: --local fake-root run skipped, no non-loopback interface" >&2
else
  lsrc="${tmp}/lsrc"
  mkdir -p "${lsrc}/vm/agent" "${lsrc}/bin"
  cp -a "${here}" "${lsrc}/vm/pi"
  cp -a "${here}/../policy" "${lsrc}/vm/policy"
  cp "${here}/../agent/setup.sh" "${lsrc}/vm/agent/"
  rm -rf "${lsrc}/vm/pi/pf" "${lsrc}/vm/policy/generated"
  mkdir "${lsrc}/vm/policy/generated"
  echo 'blocked.example' >"${lsrc}/vm/policy/generated/blacklist.domains"
  echo '192.0.2.66' >"${lsrc}/vm/policy/generated/blacklist.ips"
  install -m 0755 "${pfbin}" "${lsrc}/bin/pf"

  lstub="${tmp}/lstub"
  mkdir -p "${lstub}"
  for _c in dnsmasq useradd groupadd usermod getent chown sysctl journalctl; do
    printf '#!/bin/sh\nexit 0\n' >"${lstub}/${_c}"
  done
  # nft records each call, and the script that the carry gives it on stdin.
  # Thus the test can ask what apply did around the load, and need not infer
  # it. nft answers the two listings that the carry reads with one live element.
  # NFT_FAIL names a call that must fail: the run that proves that a refused
  # carry never fails the apply uses it.
  cat >"${lstub}/nft" <<'EOF'
#!/bin/sh
printf 'argv: %s\n' "$*" >>"${NFT_LOG}"
if [ -n "${NFT_FAIL:-}" ] && [ "$*" = "${NFT_FAIL}" ]; then
  echo "nft: refused on purpose" >&2
  exit 1
fi
case "$*" in
  "list sets table inet fortress")
    printf 'table inet fortress {\n\tset blacklist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n\tset resolved_v4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout 2h\n\t}\n}\n'
    ;;
  "list set inet fortress resolved_v4")
    printf 'table inet fortress {\n\tset resolved_v4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout 2h\n\t\telements = { 203.0.113.77 timeout 2h expires 1h58m12s }\n\t}\n}\n'
    ;;
  "-f -") sed 's/^/stdin: /' >>"${NFT_LOG}" ;;
esac
exit 0
EOF
  printf '#!/bin/sh\necho "2: lo    inet 10.77.0.1/24"\n' >"${lstub}/ip"
  # The stub records each unit action. Thus the test can ask what apply
  # decided to restart, and need not infer it. is-active answers yes: the
  # restart predicate is for a box whose fence is already up.
  cat >"${lstub}/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${SYSTEMCTL_LOG}"
exit 0
EOF
  cat >"${lstub}/install" <<'EOF'
#!/bin/bash
a=()
while [[ $# -gt 0 ]]; do
  case "$1" in -o | -g) shift 2 ;; *) a+=("$1"); shift ;; esac
done
exec /usr/bin/install "${a[@]}"
EOF
  chmod 0755 "${lstub}"/*
  # The PATH of the run is the stubs plus these host tools and nothing else.
  # Thus a fake-root apply can never reach the real nmcli, wg or
  # services of the desktop.
  lsafe="${tmp}/lsafe"
  mkdir -p "${lsafe}"
  for _c in bash sh env cat cp mv rm rmdir mkdir chmod ln ls sed grep awk head tail tr cut sort uniq \
    wc date mktemp dirname basename readlink realpath touch cmp id sleep flock stat find diff tee \
    xargs sha256sum true false; do
    if _p="$(type -P "${_c}")"; then
      ln -s "${_p}" "${lsafe}/${_c}"
    fi
  done

  # apply.sh with its absolute paths moved under ROOT, and the root check
  # satisfied without root.
  lrewrite() {
    sed -E -e 's#"\$\{EUID\}" -ne 0#1 -ne 1#' \
      -e "s#(^|[^A-Za-z0-9_.~/-])/(etc|usr/local|var|run|vagrant)(/|[^A-Za-z0-9_.-]|\$)#\1$2/\2\3#g" "$1" >"$1.new"
    mv "$1.new" "$1"
  }
  # $3 is the mode. The default is --local.
  local_apply() {
    local _mode="${3:---local}"
    : >"$1.systemctl"
    : >"$1.nft"
    PATH="${lstub}:${lsafe}" PF_ALLOW_ANY_HOST=1 PF_INT_IF=lo PF_WAN_IF="${lwan}" SYSTEMCTL_LOG="$1.systemctl" \
      NFT_LOG="$1.nft" NFT_FAIL="${NFT_FAIL:-}" \
      bash "$2" "${_mode}" >"$1.log" 2>&1 || { tail -20 "$1.log" >&2; fail "apply ${_mode} failed under ${1##*/}"; }
  }

  # A /vagrant checkout: the policy tree and /etc/pi-fortress are two
  # different directories, so the test can see what --local installs.
  lab2="${tmp}/lroot"
  mkdir -p "${lab2}/vagrant" "${lab2}/usr/local/sbin" "${lab2}/etc/systemd/system"
  cp -a "${lsrc}/vm" "${lsrc}/bin" "${lab2}/vagrant/"
  lrewrite "${lab2}/vagrant/vm/pi/apply.sh" "${lab2}"
  local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
  grep -q 'local policy reloaded' "${lab2}.log" || fail "apply --local did not report a local reload"
  for _f in core.hosts allow.domains key_prefixes.rules dns_types.allow; do
    cmp -s "${lab2}/vagrant/vm/policy/${_f}" "${lab2}/etc/pi-fortress/${_f}" ||
      fail "apply --local printed success without installing ${_f}; the fence keeps the old one"
  done
  # The load flushes the table. Thus apply must read the address that the
  # resolver put in resolved_v4 before the load, and write it back after,
  # with no more time than it had left. If not, the gate drops a desktop that
  # answers from systemd-resolved, until the cache of the desktop expires.
  _ln() { grep -n "$1" "${lab2}.nft" | head -1 | cut -d: -f1 || true; }
  _lsave="$(_ln '^argv: list set inet fortress resolved_v4$')"
  # The rewritten copy loads its ruleset from under ROOT, not from /etc.
  _lload="$(_ln '^argv: -f /.*/etc/nftables.conf$')"
  _ladd="$(_ln '^stdin: add element inet fortress resolved_v4 ')"
  [[ -n "${_lsave}" ]] || fail "apply --local never read resolved_v4 before loading the ruleset"
  [[ -n "${_ladd}" ]] || fail "apply --local never put the resolved addresses back after the load"
  [[ "${_lsave}" -lt "${_lload}" && "${_ladd}" -gt "${_lload}" ]] ||
    fail "the resolved-address carry does not straddle the ruleset load"
  grep -q '^stdin: add element inet fortress resolved_v4 { 203.0.113.77 timeout 70[0-9][0-9]s }$' "${lab2}.nft" ||
    fail "the carried element came back with something other than the ~7092s it had left: $(grep '^stdin: ' "${lab2}.nft")"
  grep -q '^stdin: add element inet fortress blacklist_v4' "${lab2}.nft" &&
    fail "the carry re-added a compiled set, putting back what compile just took out"
  grep -q 'resolved addresses carried across the reload' "${lab2}.log" ||
    fail "apply --local said nothing about the addresses it carried"

  # core.hosts.local: the shipped seed has only comments and adds nothing
  # (the cmp above). With lines in it, the installed core.hosts is the
  # shipped file, the marker, then the local file, one time, however often
  # apply runs. When it is empty again, it is the shipped file byte for byte.
  _mark='# ---- core.hosts.local (pf apply appends it here; edit that file, not this) ----'
  cp "${lab2}/vagrant/vm/policy/core.hosts.local" "${tmp}/core.hosts.local.seed"
  printf '%s\n' '# mine' 'gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN' >"${lab2}/vagrant/vm/policy/core.hosts.local"
  { cat "${lab2}/vagrant/vm/policy/core.hosts"; printf '%s\n' "${_mark}"; cat "${lab2}/vagrant/vm/policy/core.hosts.local"; } >"${tmp}/core.hosts.want"
  for _run in 1 2; do
    local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
    cmp -s "${tmp}/core.hosts.want" "${lab2}/etc/pi-fortress/core.hosts" ||
      fail "run ${_run}: installed core.hosts is not core.hosts + marker + core.hosts.local: $(diff "${tmp}/core.hosts.want" "${lab2}/etc/pi-fortress/core.hosts")"
  done
  grep -q 'restart pi-fortress-broker.service' "${lab2}.systemctl" &&
    fail "an unchanged core.hosts.local restarted the fence on the second run"
  cp "${tmp}/core.hosts.local.seed" "${lab2}/vagrant/vm/policy/core.hosts.local"
  local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
  cmp -s "${lab2}/vagrant/vm/policy/core.hosts" "${lab2}/etc/pi-fortress/core.hosts" ||
    fail "a core.hosts.local emptied back to comments left its lines installed"
  rm "${lab2}/vagrant/vm/policy/core.hosts.local"
  local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
  cmp -s "${lab2}/vagrant/vm/policy/core.hosts" "${lab2}/etc/pi-fortress/core.hosts" ||
    fail "with no core.hosts.local the installed core.hosts is not the shipped one"
  # A header that may never carry a credential stops the apply in pf
  # compile. pf compile names the file and line, and apply installs nothing.
  printf '%s\n' 'gitlab.com GITLAB_TOKEN:User-Agent' >"${lab2}/vagrant/vm/policy/core.hosts.local"
  if PATH="${lstub}:${lsafe}" PF_ALLOW_ANY_HOST=1 PF_INT_IF=lo PF_WAN_IF="${lwan}" SYSTEMCTL_LOG="${lab2}.systemctl" \
    NFT_LOG="${lab2}.nft" bash "${lab2}/vagrant/vm/pi/apply.sh" --local >"${lab2}.bad.log" 2>&1; then
    fail "apply --local accepted User-Agent as a credential header"
  fi
  grep -q 'core.hosts.local:1:.*User-Agent' "${lab2}.bad.log" ||
    fail "the refusal does not name core.hosts.local:1 and the header: $(tail -3 "${lab2}.bad.log")"
  grep -qx 'gitlab.com GITLAB_TOKEN:User-Agent' "${lab2}/etc/pi-fortress/core.hosts" && fail "a refused core.hosts.local was installed"
  cp "${tmp}/core.hosts.local.seed" "${lab2}/vagrant/vm/policy/core.hosts.local"

  # key_prefixes.rules.local, in the same way: the installed rules are the
  # shipped rules, the marker, then the local rules, one time. A change to
  # it restarts the fence. A rule with no literal prefix stops the apply
  # in pf compile, which names the file, and apply installs nothing.
  _kmark='# ---- key_prefixes.rules.local (pf apply appends it here; edit that file, not this) ----'
  _klocal="${lab2}/vagrant/vm/policy/key_prefixes.rules.local"
  cp "${_klocal}" "${tmp}/key_prefixes.rules.local.seed"
  printf '%s\n' '# mine' 'acme	acme_[A-Za-z0-9]{32,}	ACME_TOKEN' >"${_klocal}"
  { cat "${lab2}/vagrant/vm/policy/key_prefixes.rules"; printf '%s\n' "${_kmark}"; cat "${_klocal}"; } >"${tmp}/key_prefixes.rules.want"
  for _run in 1 2; do
    local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
    cmp -s "${tmp}/key_prefixes.rules.want" "${lab2}/etc/pi-fortress/key_prefixes.rules" ||
      fail "run ${_run}: installed key_prefixes.rules is not the shipped rules + marker + local rules: $(diff "${tmp}/key_prefixes.rules.want" "${lab2}/etc/pi-fortress/key_prefixes.rules")"
    if [[ "${_run}" -eq 1 ]]; then
      grep -q 'restart pi-fortress-broker.service' "${lab2}.systemctl" ||
        fail "a new key_prefixes.rules.local rule did not restart the fence"
    fi
  done
  grep -q 'restart pi-fortress-broker.service' "${lab2}.systemctl" &&
    fail "an unchanged key_prefixes.rules.local restarted the fence on the second run"
  printf 'acme\t[A-Za-z0-9]{40,}\n' >"${_klocal}"
  if PATH="${lstub}:${lsafe}" PF_ALLOW_ANY_HOST=1 PF_INT_IF=lo PF_WAN_IF="${lwan}" SYSTEMCTL_LOG="${lab2}.systemctl" \
    NFT_LOG="${lab2}.nft" bash "${lab2}/vagrant/vm/pi/apply.sh" --local >"${lab2}.bad.log" 2>&1; then
    fail "apply --local accepted a key_prefixes.rules.local rule with no literal prefix"
  fi
  grep -q 'key_prefixes.rules.local.*acme' "${lab2}.bad.log" ||
    fail "the refusal does not name key_prefixes.rules.local and the rule: $(tail -3 "${lab2}.bad.log")"
  grep -qF '[A-Za-z0-9]{40,}' "${lab2}/etc/pi-fortress/key_prefixes.rules" && fail "a refused key_prefixes.rules.local was installed"
  cp "${tmp}/key_prefixes.rules.local.seed" "${_klocal}"
  local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
  cmp -s "${lab2}/vagrant/vm/policy/key_prefixes.rules" "${lab2}/etc/pi-fortress/key_prefixes.rules" ||
    fail "a key_prefixes.rules.local emptied back to comments left its rules installed"

  # doh.ips.local and doh.domains.local add to the shipped DoH lists. pf
  # compile reads them from the policy dir, the same as the shipped lists.
  cp "${lab2}/vagrant/vm/policy/doh.domains.local" "${tmp}/doh.domains.local.seed"
  echo 'doh.resolver.example' >>"${lab2}/vagrant/vm/policy/doh.domains.local"
  local_apply "${lab2}" "${lab2}/vagrant/vm/pi/apply.sh"
  grep -qx 'address=/doh.resolver.example/0.0.0.0' "${lab2}/etc/pi-fortress/doh-domains.conf" ||
    fail "a doh.domains.local name is not in the installed DoH sinkhole"
  grep -qx 'address=/dns.google/0.0.0.0' "${lab2}/etc/pi-fortress/doh-domains.conf" ||
    fail "doh.domains.local replaced the shipped DoH names, not added to them"
  cp "${tmp}/doh.domains.local.seed" "${lab2}/vagrant/vm/policy/doh.domains.local"

  # An /etc/pi-fortress box: the policy dir and the installed copies are
  # the same files. Here, before, the same-file guard hid the full change.
  app2="${tmp}/lroot2"
  mkdir -p "${app2}/etc/pi-fortress" "${app2}/usr/local/lib/pi-fortress" "${app2}/usr/local/sbin" \
    "${app2}/etc/systemd/system"
  cp -a "${lsrc}/vm/policy/." "${app2}/etc/pi-fortress/"
  cp -a "${lsrc}/vm/pi/." "${app2}/usr/local/lib/pi-fortress/"
  install -m 0755 "${pfbin}" "${app2}/usr/local/lib/pi-fortress/pf"
  cp "${here}/net.env" "${app2}/etc/pi-fortress/net.env"
  lrewrite "${app2}/usr/local/lib/pi-fortress/apply.sh" "${app2}"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  grep -q 'restart pi-fortress-broker.service' "${app2}.systemctl" ||
    fail "the first --local on a fresh box did not start the fence on its inputs"
  # Nothing changed: the second run must not drop the agents' connections.
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  grep -q 'restart pi-fortress-broker.service' "${app2}.systemctl" &&
    fail "an unchanged --local restarted the fence anyway"
  # An in-place edit to the push allowlist is a policy change, the same as
  # other edits. The broker reads that file one time at start.
  echo 'github.com acme/widget' >>"${app2}/etc/pi-fortress/git_push.allow"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  grep -q 'restart pi-fortress-broker.service' "${app2}.systemctl" ||
    fail "an in-place git_push.allow edit did not restart the fence"
  # An edit to a file that has no flag is also a policy change.
  echo 'widget.example.com' >>"${app2}/etc/pi-fortress/allow.domains"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  grep -q 'restart pi-fortress-broker.service' "${app2}.systemctl" ||
    fail "an allow.domains edit did not restart the fence"
  # A cache warm-up is never a reason to leave the fence half-loaded: a
  # refused re-add costs the operator one line and an empty set. The box did
  # that before the carry existed. local_apply fails the test on a non-zero
  # apply. Thus the assertion is that the run returns.
  NFT_FAIL='-f -'
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  NFT_FAIL=''
  grep -qE '^argv: -f /.*/etc/nftables.conf$' "${app2}.nft" ||
    fail "a refused carry stopped the ruleset from loading"
  grep -q 'could not put the resolved addresses back' "${app2}.log" ||
    fail "a refused carry passed in silence: $(tail -5 "${app2}.log")"

  # The same-file box: core.hosts.local is next to core.hosts in
  # /etc/pi-fortress, and core.hosts is both the source and the installed
  # copy. The local part is replaced in place, never stacked. It is removed
  # when the local file is removed.
  cp "${app2}/etc/pi-fortress/core.hosts" "${tmp}/core.hosts.app2"
  printf '%s\n' 'gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN' >"${app2}/etc/pi-fortress/core.hosts.local"
  { cat "${tmp}/core.hosts.app2"; printf '%s\n' "${_mark}"; cat "${app2}/etc/pi-fortress/core.hosts.local"; } >"${tmp}/core.hosts.want2"
  for _run in 1 2; do
    local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
    cmp -s "${tmp}/core.hosts.want2" "${app2}/etc/pi-fortress/core.hosts" ||
      fail "same-file run ${_run}: core.hosts is not shipped + marker + local: $(diff "${tmp}/core.hosts.want2" "${app2}/etc/pi-fortress/core.hosts")"
  done
  printf '%s\n' 'gitlab.com GITLAB_TOKEN:X-Other' >"${app2}/etc/pi-fortress/core.hosts.local"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  grep -q 'restart pi-fortress-broker.service' "${app2}.systemctl" ||
    fail "a core.hosts.local edit did not restart the fence"
  if [[ "$(grep -cxF -- "${_mark}" "${app2}/etc/pi-fortress/core.hosts")" -ne 1 ]] ||
    ! grep -qx 'gitlab.com GITLAB_TOKEN:X-Other' "${app2}/etc/pi-fortress/core.hosts" ||
    grep -qx 'gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN' "${app2}/etc/pi-fortress/core.hosts"; then
    fail "same-file: an edited core.hosts.local was stacked rather than replaced: $(tail -4 "${app2}/etc/pi-fortress/core.hosts")"
  fi
  rm "${app2}/etc/pi-fortress/core.hosts.local"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  cmp -s "${tmp}/core.hosts.app2" "${app2}/etc/pi-fortress/core.hosts" ||
    fail "same-file: a removed core.hosts.local left its lines in core.hosts"

  # The same-file box keeps key_prefixes.rules.local across a provision.
  # provision.sh copies the shipped key_prefixes.rules over the installed
  # one. The next apply puts the local rules back below the marker, one time.
  cp "${app2}/etc/pi-fortress/key_prefixes.rules" "${tmp}/key_prefixes.rules.app2"
  printf '%s\n' 'acme	acme_[A-Za-z0-9]{32,}	ACME_TOKEN' >"${app2}/etc/pi-fortress/key_prefixes.rules.local"
  { cat "${tmp}/key_prefixes.rules.app2"; printf '%s\n' "${_kmark}"; cat "${app2}/etc/pi-fortress/key_prefixes.rules.local"; } >"${tmp}/key_prefixes.rules.want2"
  for _run in 1 2 provision; do
    if [[ "${_run}" == provision ]]; then
      cp "${here}/../policy/key_prefixes.rules" "${app2}/etc/pi-fortress/key_prefixes.rules"
    fi
    local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
    cmp -s "${tmp}/key_prefixes.rules.want2" "${app2}/etc/pi-fortress/key_prefixes.rules" ||
      fail "same-file run ${_run}: key_prefixes.rules is not shipped + marker + local: $(diff "${tmp}/key_prefixes.rules.want2" "${app2}/etc/pi-fortress/key_prefixes.rules")"
  done
  rm "${app2}/etc/pi-fortress/key_prefixes.rules.local"
  local_apply "${app2}" "${app2}/usr/local/lib/pi-fortress/apply.sh"
  cmp -s "${tmp}/key_prefixes.rules.app2" "${app2}/etc/pi-fortress/key_prefixes.rules" ||
    fail "same-file: a removed key_prefixes.rules.local left its rules in key_prefixes.rules"

  # --refresh, the unattended timer path. A refresh that changes only the
  # block list does not restart the fence: the sinkhole and the nft sets
  # get the new list, and nobody is there to accept dropped connections.
  # A refresh that also finds a change to another fence input restarts
  # the fence, as --local does, and records the fence state. If not, the
  # broker stays on the old core.hosts while the ruleset is new.
  # The pf of this root is a wrapper. Its fetch writes FAKE_FEED as the
  # feed output and never goes to the network. All other commands go to
  # the real pf.
  ref="${tmp}/lroot3"
  mkdir -p "${ref}/etc/pi-fortress" "${ref}/usr/local/lib/pi-fortress" "${ref}/usr/local/sbin" \
    "${ref}/etc/systemd/system"
  cp -a "${lsrc}/vm/policy/." "${ref}/etc/pi-fortress/"
  cp -a "${lsrc}/vm/pi/." "${ref}/usr/local/lib/pi-fortress/"
  cp "${here}/net.env" "${ref}/etc/pi-fortress/net.env"
  install -m 0755 "${pfbin}" "${tmp}/pf-real"
  cat >"${ref}/usr/local/lib/pi-fortress/pf" <<EOF
#!/bin/bash
if [[ "\$1" == fetch ]]; then
  while [[ \$# -gt 0 && "\$1" != --out ]]; do shift; done
  printf '%s\n' "\${FAKE_FEED:?}" >"\$2/blacklist.domains"
  exit 0
fi
exec "${tmp}/pf-real" "\$@"
EOF
  chmod 0755 "${ref}/usr/local/lib/pi-fortress/pf"
  lrewrite "${ref}/usr/local/lib/pi-fortress/apply.sh" "${ref}"
  _rapply="${ref}/usr/local/lib/pi-fortress/apply.sh"
  _restarted() { grep -q "restart pi-fortress-$2.service" "$1.systemctl"; }
  export FAKE_FEED='feed-a.example'
  local_apply "${ref}" "${_rapply}"
  _restarted "${ref}" broker || fail "refresh setup: the first --local did not start the fence"
  # The list alone changes.
  FAKE_FEED='feed-b.example'
  local_apply "${ref}" "${_rapply}" --refresh
  grep -q 'feed-b.example' "${ref}/etc/pi-fortress/blocked-domains.conf" ||
    fail "a --refresh did not install the new feed list"
  if _restarted "${ref}" broker || _restarted "${ref}" engine; then
    fail "a --refresh that changed only the block list restarted the fence"
  fi
  grep -q 'fence keeps the old name list' "${ref}.log" ||
    fail "a list-only --refresh did not say that the fence keeps the old list: $(tail -3 "${ref}.log")"
  # The list and core.hosts.local change.
  FAKE_FEED='feed-c.example'
  printf '%s\n' 'gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN' >"${ref}/etc/pi-fortress/core.hosts.local"
  local_apply "${ref}" "${_rapply}" --refresh
  if ! _restarted "${ref}" broker || ! _restarted "${ref}" engine; then
    fail "a --refresh with a list change and a core.hosts.local change did not restart the fence"
  fi
  cmp -s "${ref}/etc/pi-fortress/core.hosts" "${ref}/etc/pi-fortress/fence.state/core.hosts" ||
    fail "a --refresh that restarted the fence did not record the fence state"
  # The state is recorded. Thus the same refresh again restarts nothing.
  local_apply "${ref}" "${_rapply}" --refresh
  _restarted "${ref}" broker && fail "an unchanged --refresh restarted the fence"
  # --local is as before: a list change alone restarts the fence.
  echo 'feed-d.example' >"${ref}/etc/pi-fortress/generated/blacklist.domains"
  local_apply "${ref}" "${_rapply}"
  _restarted "${ref}" broker || fail "a --local with only a list change did not restart the fence"
  unset FAKE_FEED
fi

# Also the shape behind those runs: the restart decision comes from the
# inputs of the fence, not from a flag per file. Thus if a file is not in
# FENCE_INPUTS, the broker and the engine never get its policy change,
# however it was made.
awk '/^FENCE_INPUTS=\(/,/^\)/' "${apply}" >"${tmp}/fence-inputs"
for _f in paranoid.flags fakeip.flags git_push.allow core.hosts allow.domains key_prefixes.rules \
  broker.env engine.env net.env; do
  grep -qF "/etc/pi-fortress/${_f}" "${tmp}/fence-inputs" ||
    fail "${_f} is not in FENCE_INPUTS, so a change to it never restarts the fence"
done
# The operator overlay goes in by its variable, because PF_NET_ENV_LOCAL
# moves it. The units read it as an EnvironmentFile, as they read the base.
grep -qF '${NET_ENV_LOCAL}' "${tmp}/fence-inputs" ||
  fail "the net.env.local overlay is not in FENCE_INPUTS, so an override never restarts the fence"
for _u in "${here}/pf-engine.service" "${here}/pf-broker.service"; do
  grep -qF 'EnvironmentFile=-/etc/pi-fortress/net.env.local' "${_u}" ||
    fail "$(basename "${_u}") does not read the net.env.local overlay, so an overridden PI_IP or AGENT_NET reaches the ruleset but not the daemon"
done
# blocked-domains.conf is the one input that apply compiles, not copies.
# Thus it gets the same answer through the compare that already exists.
grep -qF 'FENCE_CHANGED="${BLOCKED_CHANGED}"' "${apply}" ||
  fail "a changed blocked-domains.conf is not part of the fence restart decision"

# "Applied, not settled" is exit 3, and the refresh timer counts 3 as
# done. If one side changes alone, a missing house adapter causes a
# twenty-retry restart loop again (2026-09-22), or a real failure gets
# no retry.
if grep -q 'settled || _settled=[^3]' "${here}/apply.sh" || ! grep -q 'settled || _settled=3' "${here}/apply.sh"; then
  fail "apply.sh no longer exits 3 for an unsettled apply"
fi
grep -qx 'SuccessExitStatus=3' "${here}/fetch.service" || fail "fetch.service does not count apply's unsettled exit 3 as done"

# Root works by name in the directory of the broker. Thus a link or a second
# hard link there must stop apply before root touches it. No broker
# may run, because it could put a link there after the check.
(
  # shellcheck source=/dev/null
  source <(sed -n '/^broker_store_plain() {$/,/^}$/p' "${apply}")
  declare -F broker_store_plain >/dev/null || fail "broker_store_plain is gone from apply.sh"
  bd="${tmp}/broker"
  mkdir -p "${bd}"
  broker_store_plain "${bd}" secrets.env secrets.env.lock >/dev/null || fail "an empty broker directory was refused"
  : >"${bd}/secrets.env"
  broker_store_plain "${bd}" secrets.env secrets.env.lock >/dev/null || fail "a plain secrets.env was refused"
  ln -s "${tmp}/elsewhere" "${bd}/secrets.env.lock"
  _out="$(broker_store_plain "${bd}" secrets.env secrets.env.lock)" && fail "a dangling link at secrets.env.lock was accepted"
  [[ "${_out}" == "${bd}/secrets.env.lock" ]] || fail "the refusal named ${_out}, not the link"
  rm "${bd}/secrets.env.lock"
  ln "${bd}/secrets.env" "${tmp}/second-name"
  broker_store_plain "${bd}" secrets.env >/dev/null && fail "a secrets.env with a second hard link was accepted"
  rm "${tmp}/second-name"
  mkdir "${bd}/secrets.disabled"
  broker_store_plain "${bd}" secrets.disabled >/dev/null && fail "a directory at secrets.disabled was accepted"
  true
)
_stop="$(grep -n '^systemctl stop pi-fortress-broker.service' "${apply}" | head -1 | cut -d: -f1 || true)"
_check="$(grep -nF 'broker_store_plain "${BROKER_DIR}"' "${apply}" | head -1 | cut -d: -f1 || true)"
_first="$(grep -nF -e ' "${SECRETS}"' -e ' "${BROKER_DIR}/' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_stop}" && -n "${_check}" && -n "${_first}" && "${_stop}" -lt "${_check}" && "${_check}" -lt "${_first}" ]] ||
  fail "apply works by name in the broker's directory before stopping the broker and checking those names"

# www writes claims-redeemed/, where the ledger is. Thus root gets to the
# ledger through the descriptor of pf, and never chowns or chmods it by name.
grep -qF '"${PF}" www -init-ledger -dir "${WWW}"' "${apply}" || fail "apply no longer makes the ledger through pf www -init-ledger"
grep -qE '(touch|chown|chmod) .*ledger\.jsonl' "${apply}" && fail "apply works on the ledger by name in a directory www can write"

# Only root writes claims/. www reads it, and writes only claims-redeemed/.
grep -qF 'install -d -m 2750 -o root -g pf-fortress "${WWW}/claims"' "${apply}" || fail "apply does not make claims/ 2750 root:pf-fortress"
grep -qF 'install -d -m 2770 -o root -g pf-fortress "${WWW}/claims-redeemed"' "${apply}" || fail "apply does not make claims-redeemed/ 2770 root:pf-fortress"
[[ "$(grep '^ReadWritePaths=' "${here}/www.service")" == "ReadWritePaths=/var/lib/pi-fortress/www/claims-redeemed" ]] ||
  fail "www.service must have claims-redeemed as its only writable path"

# observe and alert write only their own state. Neither can write
# claims-redeemed/ or any other state under /var/lib/pi-fortress.
[[ "$(grep '^ReadWritePaths=' "${here}/observe.service")" == "ReadWritePaths=/var/lib/pi-fortress/observe /var/log/pi-fortress" ]] ||
  fail "observe.service must write only its state directory and the logs"
[[ "$(grep '^ReadWritePaths=' "${here}/alert.service")" == "ReadWritePaths=-/var/lib/pi-fortress/alert.offset -/var/lib/pi-fortress/alert-notice.offset -/var/lib/pi-fortress/alert.last" ]] ||
  fail "alert.service must write only its three state files"
# The units name the paths that the daemons use.
grep -qF 'const StateDir = "/var/lib/pi-fortress/observe"' "${here}/../../internal/observe/observe.go" ||
  fail "pf observe keeps its state outside the directory that observe.service can write"
for _f in alert.offset alert-notice.offset alert.last; do
  grep -qF "\"/var/lib/pi-fortress/${_f}\"" "${here}/../../internal/alert/alert.go" ||
    fail "pf alert does not write /var/lib/pi-fortress/${_f}, which alert.service names"
done
# The pressure state is in the StateDirectory of alert. A rename needs a
# directory that the unit can write.
grep -qx 'StateDirectory=pi-fortress/alert' "${here}/alert.service" || fail "alert.service has no state directory for pressure.json"
grep -qF 'DefaultStatePath = "/var/lib/pi-fortress/alert/pressure.json"' "${here}/../../internal/alert/pressure.go" ||
  fail "pf alert keeps its pressure state outside the StateDirectory of alert.service"
# apply makes the directory and the files before it starts the units.
# provision.sh makes the directory too: it can start observe before the
# first apply.
_mk="$(grep -nF 'install -d -m 0755 "${OBSERVE_STATE}"' "${apply}" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nF 'systemctl restart pi-fortress-observe.service' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "apply does not make the observe state directory before it starts observe"
_mk="$(grep -n '^for _f in /var/lib/pi-fortress/alert.offset /var/lib/pi-fortress/alert.last /var/lib/pi-fortress/alert-notice.offset; do' "${apply}" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nF 'systemctl restart pi-fortress-alert.service' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "apply does not make the alert state files before it starts alert"
_mk="$(grep -nF 'install -d -m 0755 /var/lib/pi-fortress/observe' "${here}/provision.sh" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nF 'systemctl restart pi-fortress-observe' "${here}/provision.sh" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "provision.sh does not make the observe state directory before it starts observe"
# An install from before kept the observe state at the top of
# /var/lib/pi-fortress. apply moves it into the directory one time, with
# observe stopped. A file at the top is newer than a copy in the directory.
# The state of other daemons stays where it is.
(
  ob="${tmp}/obsmove"
  lib="${ob}/var/lib/pi-fortress"
  mkdir -p "${lib}/observe"
  # shellcheck disable=SC2329 # the eval of the apply step below calls it
  systemctl() { printf '%s\n' "$*" >>"${ob}/systemctl.log"; }
  for _f in observe.json observe.json.lock dns.offset dns-house.offset dns-desk.offset journal.cursor strip.offset \
    alert.offset alert.last house.leases; do
    printf 'top %s\n' "${_f}" >"${lib}/${_f}"
  done
  printf 'stale\n' >"${lib}/observe/observe.json"
  _move="$(sed -n '/^OBSERVE_STATE=/,/^fi$/p' "${apply}" | sed "s#/var/lib/pi-fortress#${lib}#g")"
  [[ -n "${_move}" ]] || fail "the observe state move is gone from apply.sh"
  eval "${_move}"
  for _f in observe.json dns.offset dns-house.offset dns-desk.offset journal.cursor strip.offset; do
    [[ -e "${lib}/${_f}" ]] && fail "apply left ${_f} at the top of the state directory"
    [[ "$(cat "${lib}/observe/${_f}")" == "top ${_f}" ]] || fail "apply did not move ${_f} into observe/"
  done
  [[ -e "${lib}/observe.json.lock" ]] && fail "apply left the old observe lock"
  for _f in alert.offset alert.last house.leases; do
    [[ "$(cat "${lib}/${_f}")" == "top ${_f}" ]] || fail "apply moved ${_f}, which is not observe state"
  done
  grep -qx 'stop pi-fortress-observe.service' "${ob}/systemctl.log" || fail "apply moved the observe state with observe running"
  : >"${ob}/systemctl.log"
  eval "${_move}"
  if [[ -s "${ob}/systemctl.log" ]]; then
    fail "apply stopped observe with nothing to move"
  fi
)

# The root oneshots run sandboxed. fetch runs apply --refresh, and ship and
# ship-deadman run a full apply. All three stay root, because apply loads
# nft, sets sysctls and adds accounts.
for _u in fetch ship ship-deadman; do
  for _l in NoNewPrivileges=yes PrivateTmp=yes ProtectSystem=strict ProtectKernelModules=yes ProtectKernelLogs=yes \
    ProtectControlGroups=yes RestrictNamespaces=yes MemoryMax=1G TasksMax=256 SystemCallArchitectures=native \
    SystemCallFilter=@system-service 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK'; do
    grep -qxF "${_l}" "${here}/${_u}.service" || fail "${_u}.service has no '${_l}'"
  done
  grep -q '^User=' "${here}/${_u}.service" && fail "${_u}.service names a User=; apply needs root"
  # apply writes sysctls, and makes setgid directories.
  grep -qE '^(ProtectKernelTunables|RestrictSUIDSGID)=yes' "${here}/${_u}.service" &&
    fail "${_u}.service blocks the sysctl writes or the setgid directories of apply"
  # ss -p reads the sshd sessions of another uid only with SYS_PTRACE.
  if grep -qF 'ss -Htnp' "${apply}"; then
    grep '^CapabilityBoundingSet=' "${here}/${_u}.service" | grep -qw CAP_SYS_PTRACE ||
      fail "${_u}.service takes SYS_PTRACE away, so apply cannot see the admin SSH sessions"
  fi
done
[[ "$(grep '^ProtectHome=' "${here}/fetch.service")" == "ProtectHome=yes" ]] || fail "fetch.service can read /home"
[[ "$(grep '^CapabilityBoundingSet=' "${here}/fetch.service")" == "CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN CAP_FOWNER CAP_FSETID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_LINUX_IMMUTABLE CAP_SYS_PTRACE CAP_AUDIT_WRITE" ]] ||
  fail "fetch.service has a different capability set"
[[ "$(grep '^ReadWritePaths=' "${here}/fetch.service")" == "ReadWritePaths=/etc /usr/local /var/lib/pi-fortress /var/log/pi-fortress -/var/lib/systemd/timesync -/run/pi-fortress -/opt/pi-fortress/vm/policy/generated -/vagrant/vm/policy/generated" ]] ||
  fail "fetch.service has a different set of writable paths"
[[ "$(grep '^InaccessiblePaths=' "${here}/fetch.service")" == "InaccessiblePaths=-/etc/pi-fortress/broker -/var/lib/pi-fortress/engine -/var/lib/pi-fortress/www" ]] ||
  fail "fetch.service can read the secrets, the CA key or the claims"
# Those three are inaccessible to fetch. Thus the --local half of apply,
# which fetch runs, must not use them.
_local="$(sed -n '1,/^if \[\[ "${LOCAL_ONLY}" -eq 1 \]\]; then$/p' "${apply}")"
grep -qE 'BROKER_DIR|ENGINE_DIR|/etc/pi-fortress/broker([/"[:space:]]|$)|/var/lib/pi-fortress/(engine|www)|[{]WWW[}]' <<<"${_local}" &&
  fail "apply --local uses a path that fetch.service cannot read"
# The swap renames below /opt. A home is read: harden_ssh counts the login keys.
for _u in ship ship-deadman; do
  [[ "$(grep '^ProtectHome=' "${here}/${_u}.service")" == "ProtectHome=read-only" ]] ||
    fail "${_u}.service must read /home for the key check of harden_ssh, and not write it"
  [[ "$(grep '^ReadWritePaths=' "${here}/${_u}.service")" == "ReadWritePaths=/etc /opt /usr/local /var/lib/pi-fortress /var/log/pi-fortress -/var/lib/systemd/timesync -/run/pi-fortress -/vagrant/vm/policy/generated" ]] ||
    fail "${_u}.service has a different set of writable paths"
done
grep -qxF 'HARDEN_HOME=/home' "${apply}" || fail "harden_ssh no longer reads /home; ship.service can drop ProtectHome=read-only"
# A revert is the same swap and apply as a ship, so the two sandboxes are the same.
diff <(grep -E '^[A-Z][A-Za-z]+=' "${here}/ship.service" | grep -vE '^(Description|Documentation|After|ExecStart|TimeoutStartSec)=') \
  <(grep -E '^[A-Z][A-Za-z]+=' "${here}/ship-deadman.service" | grep -vE '^(Description|Documentation|After|ExecStart|TimeoutStartSec)=') >/dev/null ||
  fail "ship-deadman.service and ship.service have different sandboxes"
# Each path without "-" exists before the unit can start. apply makes the
# state and log directories before it enables the timers. provision.sh
# makes them before it enables ship.path. apply makes the lock directory
# and the tmpfiles line that makes it again at each boot.
_mk="$(grep -nxF 'install -d -m 0755 /var/log/pi-fortress /var/lib/pi-fortress' "${apply}" | head -1 | cut -d: -f1 || true)"
for _t in pi-fortress-ship-deadman.timer pi-fortress-fetch.timer; do
  _start="$(grep -nF "systemctl enable --now ${_t}" "${apply}" | head -1 | cut -d: -f1 || true)"
  [[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
    fail "apply does not make /var/lib/pi-fortress and /var/log/pi-fortress before it enables ${_t}"
done
_mk="$(grep -nxF 'install -d -m 0755 /var/lib/pi-fortress /var/log/pi-fortress' "${here}/provision.sh" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nxF 'systemctl enable --now pi-fortress-ship.path' "${here}/provision.sh" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "provision.sh does not make /var/lib/pi-fortress and /var/log/pi-fortress before it enables ship.path"
grep -qF 'echo "d ${LOCK_DIR} 0750 root pf-fence -" >/etc/tmpfiles.d/pi-fortress.conf' "${apply}" ||
  fail "apply no longer writes the tmpfiles line for /run/pi-fortress"

# wg-alert and the two DHCP units write only their own state. None can
# write claims-redeemed/ or any other state under /var/lib/pi-fortress.
[[ "$(grep '^ReadWritePaths=' "${here}/wg-alert.service")" == "ReadWritePaths=/var/lib/pi-fortress/wg.last" ]] ||
  fail "wg-alert.service must write only wg.last"
[[ "$(grep '^ReadWritePaths=' "${here}/dns-house.service")" == "ReadWritePaths=/var/lib/pi-fortress/house.leases /var/log/pi-fortress" ]] ||
  fail "dns-house.service must write only its lease file and the logs"
[[ "$(grep '^ReadWritePaths=' "${here}/dhcp@.service")" == "ReadWritePaths=/var/lib/pi-fortress/dhcp-%i.leases /var/log/pi-fortress" ]] ||
  fail "dhcp@.service must write only its lease file and the logs"
# The units name the paths that the daemons use.
grep -qF 'const DefaultWGLast = "/var/lib/pi-fortress/wg.last"' "${here}/../../internal/alert/wg.go" ||
  fail "pf alert wg does not write the wg.last that wg-alert.service names"
grep -qxF 'dhcp-leasefile=/var/lib/pi-fortress/house.leases' "${apply}" ||
  fail "the house dnsmasq does not use the lease file that dns-house.service names"
grep -qxF 'DHCP_STATE=/var/lib/pi-fortress' "${apply}" && grep -qxF 'dhcp-leasefile=${DHCP_STATE}/dhcp-${name}.leases' "${here}/lib/dhcp.sh" ||
  fail "a segment dnsmasq does not use the lease file that dhcp@.service names"
# A file in ReadWritePaths must exist before the unit starts.
_mk="$(grep -nxF '    touch /var/lib/pi-fortress/wg.last' "${apply}" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nF 'systemctl enable --now pi-fortress-wg-alert.timer' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "apply does not make wg.last before it enables the wg-alert timer"
_mk="$(grep -nxF '  touch /var/lib/pi-fortress/house.leases' "${apply}" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nxF '  systemctl restart pi-fortress-dns-house.service' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "apply does not make house.leases before it starts dns-house"
_mk="$(grep -nF 'touch "${DHCP_STATE}/dhcp-${n}.leases"' "${here}/lib/dhcp.sh" | head -1 | cut -d: -f1 || true)"
_start="$(grep -nF 'systemctl restart "pi-fortress-dhcp@${n}.service"' "${here}/lib/dhcp.sh" | head -1 | cut -d: -f1 || true)"
[[ -n "${_mk}" && -n "${_start}" && "${_mk}" -lt "${_start}" ]] ||
  fail "seg_dhcp_sync does not make the lease file before it starts the instance"

# Each file that apply and provision write with > gets its mode from the
# umask. Thus neither script may inherit the umask of the caller.
for _s in apply.sh provision.sh; do
  _head="$(sed -n 1,6p "${here}/${_s}")"
  [[ $'\n'"${_head}"$'\n' == *$'\numask 022\n'* ]] || fail "${_s} does not pin umask 022 before it writes anything"
done

# An egress change of a segment ends its open flows, except the flows of
# the box itself and the flows between the agent, the house and the
# segments. conntrack and ip are fakes: the test reads no real table.
(
  # shellcheck source=/dev/null
  source <(sed -n -e '/^egress_state() {$/,/^}$/p' -e '/^egress_cut() {$/,/^}$/p' -e '/^egress_cuts() {$/,/^}$/p' "${apply}")
  declare -F egress_cuts >/dev/null || fail "egress_cuts is gone from apply.sh"
  ec="${tmp}/egresscut"
  mkdir -p "${ec}/bin"
  cat >"${ec}/bin/conntrack" <<'EOF'
#!/bin/bash
echo "$*" >>"${CT_LOG}"
case "$1 $2" in
  "-L -s") cat "${CT_DIR}/list-src" ;;
  "-L -d") cat "${CT_DIR}/list-dst" ;;
  -D*) exit "${CT_DEL_RC:-0}" ;;
esac
EOF
  cat >"${ec}/bin/ip" <<'EOF'
#!/bin/bash
echo "2: wlan0    inet 192.168.1.10/24 brd 192.168.1.255 scope global wlan0"
echo "5: eth0.79    inet 10.79.0.1/30 brd 10.79.0.3 scope global eth0.79"
EOF
  chmod +x "${ec}/bin/conntrack" "${ec}/bin/ip"
  # The desk (10.79.0.2) to the web twice, to the Pi on the segment and
  # uplink addresses, UDP out, and SSH out through ssh_allow. Admin SSH
  # to an agent (10.77.0.20) from the desk (SSH_TO), the house admin
  # (HOUSE_SSH_TO) and a guest host. Into the desk: SSH_FROM, and the Pi.
  cat >"${ec}/list-src" <<'EOF'
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=203.0.113.9 sport=50005 dport=22 src=203.0.113.9 dst=192.168.1.10 sport=22 dport=50005 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=10.77.0.20 sport=50004 dport=22 src=10.77.0.20 dst=10.79.0.2 sport=22 dport=50004 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.78.0.20 dst=10.77.0.20 sport=40002 dport=22 src=10.77.0.20 dst=10.78.0.20 sport=22 dport=40002 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.80.0.5 dst=10.77.0.20 sport=40003 dport=22 src=10.77.0.20 dst=10.80.0.5 sport=22 dport=40003 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=198.51.100.7 sport=50000 dport=443 src=198.51.100.7 dst=192.168.1.10 sport=443 dport=50000 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=198.51.100.7 sport=50001 dport=443 src=198.51.100.7 dst=192.168.1.10 sport=443 dport=50001 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=10.79.0.1 sport=50002 dport=22 src=10.79.0.1 dst=10.79.0.2 sport=22 dport=50002 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.79.0.2 dst=192.168.1.10 sport=50003 dport=22 src=192.168.1.10 dst=10.79.0.2 sport=22 dport=50003 [ASSURED] mark=0 use=1
udp      17 29 src=10.79.0.2 dst=192.0.2.1 sport=40000 dport=3478 [UNREPLIED] src=192.0.2.1 dst=192.168.1.10 sport=3478 dport=40000 mark=0 use=1
EOF
  cat >"${ec}/list-dst" <<'EOF'
tcp      6 431999 ESTABLISHED src=10.78.0.20 dst=10.79.0.2 sport=40001 dport=22 src=10.79.0.2 dst=10.78.0.20 sport=22 dport=40001 [ASSURED] mark=0 use=1
icmp     1 29 src=10.79.0.1 dst=10.79.0.2 type=8 code=0 id=7 src=10.79.0.2 dst=10.79.0.1 type=0 code=0 id=7 mark=0 use=1
EOF
  export CT_LOG="${ec}/ct.log" CT_DIR="${ec}"
  PATH="${ec}/bin:${PATH}"
  PI_IP=10.77.0.1 AGENT_NET=10.77.0.0/24 HOUSE_IP=10.78.0.1 HOUSE_NET=10.78.0.0/24 HOUSE_EGRESS_FP=aaaa
  SEG_NAME=(desk guest) SEG_NET=(10.79.0.0/30 10.80.0.0/24) SEG_IP=(10.79.0.1 10.80.0.1) SEG_EGRESS_FP=(bbbb cccc)
  st="${ec}/state/egress.state"
  : >"${CT_LOG}"

  # With no state file (a lost file, or the first apply), each segment
  # counts as changed. An empty file is the same.
  egress_state >"${ec}/new"
  mkdir -p "${ec}/state"
  : >"${st}"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on an empty state"
  grep -c -- '^-L -s ' "${CT_LOG}" | grep -qx 3 || fail "an empty state did not end the flows of each segment: $(cat "${CT_LOG}")"
  : >"${CT_LOG}"
  mv "${st}" "${ec}/state.old"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "the first egress_cuts failed"
  for _n in 10.78.0.0/24 10.79.0.0/30 10.80.0.0/24; do
    grep -qx -- "-L -s ${_n}" "${CT_LOG}" || fail "no state file did not end the flows of ${_n}: $(cat "${CT_LOG}")"
  done
  grep -q -- '-D -s 10.79.0.2 -d 10.79.0.1' "${CT_LOG}" && fail "no state file ended a flow of the Pi"
  grep -q -- '-D -s 10.78.0.20 -d 10.77.0.20' "${CT_LOG}" && fail "no state file ended the admin SSH from the house to an agent"
  [[ "$(stat -c %a "${st}")" == 600 ]] || fail "the egress state is not 0600"
  grep -qx 'seg:desk bbbb 10.79.0.0/30' "${st}" || fail "the egress state has no desk line: $(cat "${st}")"
  : >"${CT_LOG}"

  # The same values end nothing.
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "an unchanged egress_cuts failed"
  [[ -s "${CT_LOG}" ]] && fail "an unchanged policy called conntrack"

  # A new desk value ends the desk flows to the outside, and only those.
  # The SSH sessions between the agent, the house and the segments stay:
  # isolate_ct decides them.
  SEG_EGRESS_FP=(dddd cccc)
  egress_state >"${ec}/new"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on a changed desk"
  sort "${CT_LOG}" >"${ec}/ct.sorted"
  printf '%s\n' '-D -s 10.79.0.2 -d 192.0.2.1' '-D -s 10.79.0.2 -d 198.51.100.7' '-D -s 10.79.0.2 -d 203.0.113.9' \
    '-L -d 10.79.0.0/30' '-L -s 10.79.0.0/30' >"${ec}/ct.want"
  diff -u "${ec}/ct.want" "${ec}/ct.sorted" || fail "the desk cut deleted the wrong flows (a flow of the Pi, an admin SSH, or the guest)"
  grep -qx 'pi-fortress: the egress policy of desk changed; ended the open flows of 3 address pair(s) in 10.79.0.0/30' "${ec}/out" ||
    fail "no cut line for the desk: $(cat "${ec}/out")"
  grep -qx 'seg:desk dddd 10.79.0.0/30' "${st}" || fail "the egress state did not take the new desk value"

  # Exit 1 (the flow closed after the list) is no failure. Exit 2 warns.
  # Neither stops apply.
  : >"${CT_LOG}"
  HOUSE_EGRESS_FP=eeee
  egress_state >"${ec}/new"
  CT_DEL_RC=1 egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on conntrack exit 1"
  grep -q 'WARN' "${ec}/out" && fail "conntrack exit 1 gave a warning: $(cat "${ec}/out")"
  grep -q -- '-L -s 10.78.0.0/24' "${CT_LOG}" || fail "a new house value did not end the house flows"
  HOUSE_EGRESS_FP=ffff
  egress_state >"${ec}/new"
  CT_DEL_RC=2 egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on conntrack exit 2"
  grep -q 'WARN conntrack failed for house' "${ec}/out" || fail "conntrack exit 2 gave no warning: $(cat "${ec}/out")"

  # Without conntrack, apply warns, records the value, and continues. The
  # PATH has only the tools that egress_cuts needs.
  mkdir -p "${ec}/noct"
  for _t in awk dirname install; do
    ln -s "$(command -v "${_t}")" "${ec}/noct/${_t}"
  done
  SEG_EGRESS_FP=(dddd 9999)
  egress_state >"${ec}/new"
  PATH="${ec}/noct" egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed without conntrack"
  grep -qx 'pi-fortress: WARN conntrack is not installed; the open flows of guest keep the old egress policy until they close (apt-get install -y conntrack)' "${ec}/out" ||
    fail "no warning without conntrack: $(cat "${ec}/out")"
  grep -qx 'seg:guest 9999 10.80.0.0/24' "${st}" || fail "the egress state did not take the value without conntrack"

  # A segment removed from the policy ends its flows, from its old subnet.
  # So does a removed house.
  : >"${CT_LOG}"
  SEG_NAME=(desk) SEG_NET=(10.79.0.0/30) SEG_IP=(10.79.0.1) SEG_EGRESS_FP=(dddd)
  egress_state >"${ec}/new"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on a removed segment"
  grep -v -- '^-D ' "${CT_LOG}" | sort >"${ec}/ct.sorted"
  printf '%s\n' '-L -d 10.80.0.0/24' '-L -s 10.80.0.0/24' >"${ec}/ct.want"
  diff -u "${ec}/ct.want" "${ec}/ct.sorted" || fail "a removed segment did not end its flows, or ended others"
  grep -q '^seg:guest ' "${st}" && fail "the egress state keeps the removed segment"
  grep -qx -- '-D -s 10.80.0.5 -d 10.77.0.20' "${CT_LOG}" || fail "a removed segment kept its SSH to an agent"
  grep -q -- '-D -s 10.79.0.2 -d 10.77.0.20' "${CT_LOG}" && fail "a removed segment ended the SSH of the desk to an agent"
  : >"${CT_LOG}"
  HOUSE_EGRESS_FP=
  egress_state >"${ec}/new"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "egress_cuts failed on a removed house"
  grep -qx -- '-L -s 10.78.0.0/24' "${CT_LOG}" || fail "a removed house did not end its flows: $(cat "${CT_LOG}")"
  grep -q -- '-L -s 10.79.0.0/30' "${CT_LOG}" && fail "a removed house ended the desk flows"
  grep -qx -- '-D -s 10.78.0.20 -d 10.77.0.20' "${CT_LOG}" || fail "a removed house kept its SSH to an agent"
  egress_cuts "${st}" "${ec}/new" >"${ec}/out" 2>&1 || fail "a second egress_cuts failed after a removal"
  grep -c -- '^-L -s ' "${CT_LOG}" | grep -qx 1 || fail "a removal ended flows again at the next apply: $(cat "${CT_LOG}")"
)
grep -qF 'egress_cuts "${EGRESS_STATE}"' "${apply}" || fail "apply no longer ends the flows of a changed egress policy"
_load="$(grep -n '^nft -f /etc/nftables.conf$' "${apply}" | head -1 | cut -d: -f1 || true)"
_cut="$(grep -nF 'egress_cuts "${EGRESS_STATE}"' "${apply}" | head -1 | cut -d: -f1 || true)"
[[ -n "${_load}" && -n "${_cut}" && "${_load}" -lt "${_cut}" ]] || fail "apply ends flows before the new ruleset is loaded"

echo "apply_test: ok"
