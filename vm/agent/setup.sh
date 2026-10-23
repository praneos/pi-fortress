#!/bin/bash
set -euo pipefail

USAGE='sudo bash setup.sh <pi> <ca.pem sha256>'
if [[ "${EUID}" -ne 0 ]]; then
  echo "pi-fortress setup: run as root (${USAGE})" >&2
  exit 1
fi

# The Pi address is an argument. The script never guesses it from the
# default route: a desktop that still points to the house router would
# fetch a CA from the wrong box. The only other sources are PI_IP in the
# environment and the net.env of the lab.
PI_IP="${1:-${PI_IP:-}}"
if [[ -z "${PI_IP}" && -f /etc/pi-fortress/net.env ]]; then
  PI_IP="$(grep -E '^PI_IP=' /etc/pi-fortress/net.env | tail -1 | cut -d= -f2-)"
fi
if [[ -z "${PI_IP}" ]]; then
  echo "pi-fortress setup: Pi address required (${USAGE})" >&2
  exit 1
fi
RE_IPV4='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
if [[ ! "${PI_IP}" =~ ${RE_IPV4} ]]; then
  echo "pi-fortress setup: '${PI_IP}' is not an IPv4 address (${USAGE})" >&2
  exit 1
fi
INT_IF="${INT_IF:-}"
# The nft lock below contains INT_IF. The interface name grammar of render
# stops a quote or a newline that could rewrite the lock.
RE_IFNAME='^[A-Za-z][A-Za-z0-9._-]{0,14}$'
if [[ -n "${INT_IF}" && ! "${INT_IF}" =~ ${RE_IFNAME} ]]; then
  echo "pi-fortress setup: INT_IF '${INT_IF}' is not an interface name" >&2
  exit 1
fi
# The sha256 of the CA, read from the Pi (or given by the claim script).
# ca.pem comes over the same plain HTTP as this script. Any device that
# answers for the Pi address could give its own CA. The agent would then
# trust that CA for all of its TLS connections. The sha256 is required for
# that fetch, so a swapped CA stops here. The only way past it is
# PI_FORTRESS_CA, a file that the operator put on the box.
CA_SHA256="${2:-}"
if [[ -n "${CA_SHA256}" && ! "${CA_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "pi-fortress setup: '${CA_SHA256}' is not a sha256 (${USAGE})" >&2
  exit 1
fi

find_cmd() {
  local name="$1"
  local p
  if command -v "${name}" >/dev/null 2>&1; then
    command -v "${name}"
    return 0
  fi
  for p in /usr/sbin /sbin /usr/bin /bin; do
    if [[ -x "${p}/${name}" ]]; then
      printf '%s\n' "${p}/${name}"
      return 0
    fi
  done
  return 1
}

detect_family() {
  local id like
  if [[ ! -f /etc/os-release ]]; then
    echo "unknown"
    return
  fi
  # shellcheck source=/dev/null
  . /etc/os-release
  id="$(printf '%s' "${ID:-}" | tr '[:upper:]' '[:lower:]')"
  like="$(printf '%s' "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
  case "${id}" in
    ubuntu|debian|linuxmint|pop|elementary|raspbian|zorin) echo debian; return ;;
    fedora|rhel|centos|rocky|almalinux|ol|amzn|nobara) echo rhel; return ;;
    arch|manjaro|endeavouros|cachyos|archarm) echo arch; return ;;
    opensuse*|sles|sled) echo suse; return ;;
    nixos)
      echo nixos
      return
      ;;
  esac
  case " ${like} " in
    *" debian "*|*" ubuntu "*) echo debian; return ;;
    *" rhel "*|*" fedora "*|*" centos "*) echo rhel; return ;;
    *" suse "*|*" sles "*) echo suse; return ;;
    *" arch "*) echo arch; return ;;
  esac
  echo "unknown"
}

FAMILY="$(detect_family)"
case "${FAMILY}" in
  debian|rhel|arch|suse) ;;
  nixos)
    echo "pi-fortress setup: NixOS needs a module, not curl|bash" >&2
    exit 1
    ;;
  *)
    echo "pi-fortress setup: unsupported distro (need Ubuntu/Debian, Fedora/RHEL/Rocky/Alma/Amazon Linux, Arch, or openSUSE)" >&2
    if [[ -f /etc/os-release ]]; then
      grep -E '^(ID|ID_LIKE)=' /etc/os-release >&2 || true
    fi
    exit 1
    ;;
esac

# The output lock below is the purpose of the enrolment. Without nft on
# the box, nothing here is useful. The script checks this before any change.
NFT=""
if [[ "${PI_FORTRESS_SKIP_NET:-}" != 1 ]]; then
  if ! NFT="$(find_cmd nft)"; then
    echo "pi-fortress setup: nft is required (install nftables off-box first; the agent output lock is an nft table)" >&2
    exit 1
  fi
fi

echo "pi-fortress setup: Pi=${PI_IP} family=${FAMILY}"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
if [[ -n "${PI_FORTRESS_CA:-}" ]]; then
  if [[ ! -f "${PI_FORTRESS_CA}" ]]; then
    echo "pi-fortress setup: PI_FORTRESS_CA not a file: ${PI_FORTRESS_CA}" >&2
    exit 1
  fi
  cp "${PI_FORTRESS_CA}" "${tmp}"
else
  if [[ -z "${CA_SHA256}" ]]; then
    echo "pi-fortress setup: ca.pem comes over plain HTTP, so its sha256 is required; on the Pi: sudo sha256sum /var/lib/pi-fortress/www/ca.pem (${USAGE})" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "pi-fortress setup: curl is required (install it off-box; HTTPS through the Pi needs the CA first)" >&2
    exit 1
  fi
  if ! curl -fsS --max-time 10 --max-filesize 65536 "http://${PI_IP}/ca.pem" -o "${tmp}"; then
    echo "pi-fortress setup: could not fetch http://${PI_IP}/ca.pem" >&2
    exit 1
  fi
fi
if ! grep -q "BEGIN CERTIFICATE" "${tmp}"; then
  echo "pi-fortress setup: ca.pem is not a certificate" >&2
  exit 1
fi
if [[ -n "${CA_SHA256}" ]] && ! echo "${CA_SHA256}  ${tmp}" | sha256sum -c --status; then
  echo "pi-fortress setup: ca.pem does not match the sha256 the Pi gave (${CA_SHA256}); not trusting it" >&2
  exit 1
fi

install -d -m 0755 /etc/pi-fortress
install -m 0644 "${tmp}" /etc/pi-fortress/egress-ca.pem
rm -f /usr/local/share/ca-certificates/pi-fortress-mitm.crt \
  /etc/pki/ca-trust/source/anchors/pi-fortress-mitm.crt \
  /etc/ca-certificates/trust-source/anchors/pi-fortress-mitm.crt \
  /etc/pki/trust/anchors/pi-fortress-mitm.pem \
  /etc/docker/certs.d/pi-fortress-mitm.crt

BUNDLE=""
UPDATE_CA=""
case "${FAMILY}" in
  debian)
    if ! UPDATE_CA="$(find_cmd update-ca-certificates)"; then
      echo "pi-fortress setup: install ca-certificates (apt) off-box first" >&2
      exit 1
    fi
    install -d -m 0755 /usr/local/share/ca-certificates
    # During a CA rotation ca.pem holds more than one certificate.
    # openssl rehash skips such a file, so each one gets its own file.
    rm -f /usr/local/share/ca-certificates/pi-fortress-egress-*.crt
    awk -v d=/usr/local/share/ca-certificates '
      /-----BEGIN CERTIFICATE-----/ { n++; f = d "/pi-fortress-egress" (n > 1 ? "-" n : "") ".crt" }
      f { print > f }
      /-----END CERTIFICATE-----/ { if (f) close(f); f = "" }
    ' "${tmp}"
    chmod 0644 /usr/local/share/ca-certificates/pi-fortress-egress*.crt
    "${UPDATE_CA}" >/dev/null
    BUNDLE=/etc/ssl/certs/ca-certificates.crt
    ;;
  rhel)
    if ! UPDATE_CA="$(find_cmd update-ca-trust)"; then
      echo "pi-fortress setup: install ca-certificates (dnf) off-box first" >&2
      exit 1
    fi
    install -d -m 0755 /etc/pki/ca-trust/source/anchors
    install -m 0644 "${tmp}" /etc/pki/ca-trust/source/anchors/pi-fortress-egress.crt
    "${UPDATE_CA}" extract
    if [[ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]]; then
      BUNDLE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    else
      BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
    fi
    ;;
  arch)
    if ! UPDATE_CA="$(find_cmd update-ca-trust)"; then
      echo "pi-fortress setup: install ca-certificates (pacman) off-box first" >&2
      exit 1
    fi
    install -d -m 0755 /etc/ca-certificates/trust-source/anchors
    install -m 0644 "${tmp}" /etc/ca-certificates/trust-source/anchors/pi-fortress-egress.crt
    "${UPDATE_CA}"
    if [[ -f /etc/ca-certificates/extracted/tls-ca-bundle.pem ]]; then
      BUNDLE=/etc/ca-certificates/extracted/tls-ca-bundle.pem
    else
      BUNDLE=/etc/ssl/certs/ca-certificates.crt
    fi
    ;;
  suse)
    if ! UPDATE_CA="$(find_cmd update-ca-certificates)"; then
      echo "pi-fortress setup: install ca-certificates (zypper) off-box first" >&2
      exit 1
    fi
    install -d -m 0755 /etc/pki/trust/anchors
    install -m 0644 "${tmp}" /etc/pki/trust/anchors/pi-fortress-egress.pem
    "${UPDATE_CA}" >/dev/null
    if [[ -f /var/lib/ca-certificates/ca-bundle.pem ]]; then
      BUNDLE=/var/lib/ca-certificates/ca-bundle.pem
    else
      BUNDLE=/etc/ssl/ca-bundle.pem
    fi
    ;;
esac

if [[ -z "${BUNDLE}" || ! -f "${BUNDLE}" ]]; then
  echo "pi-fortress setup: CA tools ran but system bundle not found" >&2
  exit 1
fi

export SSL_CERT_FILE="${BUNDLE}"
export REQUESTS_CA_BUNDLE="${BUNDLE}"
export CURL_CA_BUNDLE="${BUNDLE}"
export GIT_SSL_CAINFO="${BUNDLE}"
export NODE_EXTRA_CA_CERTS=/etc/pi-fortress/egress-ca.pem

install -d -m 0755 /etc/profile.d /etc/sysctl.d
cat >/etc/profile.d/pi-fortress.sh <<EOF
export SSL_CERT_FILE=${BUNDLE}
export REQUESTS_CA_BUNDLE=${BUNDLE}
export CURL_CA_BUNDLE=${BUNDLE}
export GIT_SSL_CAINFO=${BUNDLE}
export NODE_EXTRA_CA_CERTS=/etc/pi-fortress/egress-ca.pem
EOF
chmod 0644 /etc/profile.d/pi-fortress.sh

env_file=/etc/environment
touch "${env_file}"
for kv in \
  "SSL_CERT_FILE=${BUNDLE}" \
  "REQUESTS_CA_BUNDLE=${BUNDLE}" \
  "CURL_CA_BUNDLE=${BUNDLE}" \
  "GIT_SSL_CAINFO=${BUNDLE}" \
  "NODE_EXTRA_CA_CERTS=/etc/pi-fortress/egress-ca.pem"
do
  key="${kv%%=*}"
  if grep -q "^${key}=" "${env_file}"; then
    sed -i "s|^${key}=.*|${kv}|" "${env_file}"
  else
    printf '%s\n' "${kv}" >>"${env_file}"
  fi
done

cat >/etc/sysctl.d/99-pi-fortress-agent.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

if [[ "${PI_FORTRESS_SKIP_NET:-}" == 1 ]]; then
  echo "pi-fortress setup: CA installed (${FAMILY}), bundle=${BUNDLE} (skip net/DNS/HTTPS)"
  echo "pi-fortress setup: done"
  exit 0
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
  fi
fi
if [[ -d /etc/NetworkManager/conf.d ]] || command -v nmcli >/dev/null 2>&1; then
  install -d -m 0755 /etc/NetworkManager/conf.d
  cat >/etc/NetworkManager/conf.d/90-pi-fortress-dns.conf <<'EOF'
[main]
dns=none
rc-manager=unmanaged
EOF
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload NetworkManager >/dev/null 2>&1 || true
  fi
fi
install -d -m 0755 /etc/dhcp/dhclient-enter-hooks.d
cat >/etc/dhcp/dhclient-enter-hooks.d/pin-dns <<'EOF'
make_resolv_conf() { :; }
EOF
chmod 755 /etc/dhcp/dhclient-enter-hooks.d/pin-dns
if [[ -f /etc/resolv.conf ]] || [[ -L /etc/resolv.conf ]]; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
  rm -f /etc/resolv.conf
fi
printf 'nameserver %s\n' "${PI_IP}" >/etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true

if command -v nmcli >/dev/null 2>&1; then
  nmcli radio wifi off >/dev/null 2>&1 || true
fi
command -v rfkill >/dev/null 2>&1 && rfkill block wifi >/dev/null 2>&1 || true

if [[ -z "${INT_IF}" ]]; then
  INT_IF="$(ip -4 route get "${PI_IP}" 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
  INT_IF="${INT_IF%%@*}"
fi
if [[ -z "${INT_IF}" ]]; then
  echo "pi-fortress setup: no interface routes to ${PI_IP}; cable the box to the Pi first (or set INT_IF)" >&2
  exit 1
fi
if [[ ! "${INT_IF}" =~ ${RE_IFNAME} ]]; then
  echo "pi-fortress setup: the route to ${PI_IP} leaves by '${INT_IF}', which is not an interface name the lock can carry" >&2
  exit 1
fi
while ip route del default >/dev/null 2>&1; do
  :
done
ip route add default via "${PI_IP}" dev "${INT_IF}"

# Output lock: the same table that vm/agent/routes.sh loads on the lab VM.
# Policy drop. Only DNS, the CA server and ping to the Pi, TCP 443 (the Pi
# redirects it into the engine), and TCP 22 leave the box. They leave only
# on the cable to the Pi. The Pi controls which SSH destinations are
# reachable, from ssh_allow.ips (docs/ssh_allow.md). An empty list (the
# default) still drops all port 22 packets at the Pi. At each boot, a
# oneshot loads the lock again before the network starts. Thus a USB
# tether or a second default route cannot go around the Pi.
install -d -m 0755 /usr/local/lib/pi-fortress
cat >/usr/local/lib/pi-fortress/agent-lock.nft <<EOF
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
chmod 0644 /usr/local/lib/pi-fortress/agent-lock.nft
"${NFT}" -c -f /usr/local/lib/pi-fortress/agent-lock.nft
"${NFT}" delete table inet agent_lock >/dev/null 2>&1 || true
"${NFT}" -f /usr/local/lib/pi-fortress/agent-lock.nft
if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
  cat >/etc/systemd/system/pi-fortress-agent-lock.service <<EOF
[Unit]
Description=pi-fortress agent output lock (nft)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-${NFT} delete table inet agent_lock
ExecStart=${NFT} -f /usr/local/lib/pi-fortress/agent-lock.nft

[Install]
WantedBy=sysinit.target
EOF
  # Nothing behind the Pi can reach a time server: the lock above allows
  # no NTP, and the Pi forwards none. Without a fix, the clock drifts until
  # certificates fail validation. A laptop after a long sleep gets there
  # immediately. The CA server puts a Date header on a port that the lock
  # already allows, over the same cable as the CA. TLS needs only accuracy
  # to one second. vm/agent/provision.sh installs the same unit.
  cat >/usr/local/lib/pi-fortress/clock.sh <<EOF
#!/bin/bash
set -euo pipefail
stamp="\$(curl -fsSI --max-time 5 "http://${PI_IP}/ca.pem" | sed -n 's/^[Dd]ate: //p' | tr -d '\\r')"
[[ -n "\${stamp}" ]] || { echo "agent clock: no Date header from ${PI_IP}" >&2; exit 1; }
want="\$(date -d "\${stamp}" +%s)"
off=\$(( want - \$(date +%s) ))
if (( off > 2 || off < -2 )); then
  date -s "@\${want}" >/dev/null
  echo "agent clock: stepped \${off}s to the gateway's"
fi
EOF
  chmod 0755 /usr/local/lib/pi-fortress/clock.sh
  cat >/etc/systemd/system/pi-fortress-agent-clock.service <<'EOF'
[Unit]
Description=pi-fortress agent clock from the gateway's Date header
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/pi-fortress/clock.sh
EOF
  cat >/etc/systemd/system/pi-fortress-agent-clock.timer <<'EOF'
[Unit]
Description=pi-fortress agent clock, at boot and every 15 minutes

[Timer]
OnBootSec=20s
OnUnitActiveSec=15min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable pi-fortress-agent-lock.service >/dev/null 2>&1 || true
  systemctl enable --now pi-fortress-agent-clock.timer >/dev/null 2>&1 || true
fi

if command -v docker >/dev/null 2>&1; then
  install -d -m 0755 /etc/docker/certs.d
  install -m 0644 /etc/pi-fortress/egress-ca.pem /etc/docker/certs.d/pi-fortress-egress.crt
fi

echo "pi-fortress setup: CA installed (${FAMILY}), DNS=${PI_IP}, bundle=${BUNDLE}, output lock on ${INT_IF}"

# Three tries. ping succeeds on any reply. One lost echo does not show a
# missing gateway. It failed the enrolment on a link that dropped a few
# percent of ICMP, but carried DNS and TLS without a loss.
if ! ping -c 3 -i 0.5 -W 2 "${PI_IP}" >/dev/null 2>&1; then
  echo "pi-fortress setup: ping ${PI_IP} failed (3 tries)" >&2
  exit 1
fi
dns_ok=0
if command -v dig >/dev/null 2>&1; then
  if dig +time=2 +tries=1 "@${PI_IP}" example.com A >/dev/null 2>&1; then
    dns_ok=1
  fi
fi
if [[ "${dns_ok}" -eq 0 ]] && command -v getent >/dev/null 2>&1; then
  if getent ahostsv4 example.com >/dev/null 2>&1; then
    dns_ok=1
  fi
fi
if [[ "${dns_ok}" -eq 0 ]]; then
  echo "pi-fortress setup: DNS via ${PI_IP} failed" >&2
  exit 1
fi

https_code() {
  curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 --http1.1 --cacert /etc/pi-fortress/egress-ca.pem "$1" || true
}

https_ok() {
  case "$(https_code "$1")" in
    200|301|302|303|307|308) return 0 ;;
  esac
  return 1
}

inspect_ok=0
for _try in 1 2 3; do
  if https_ok "https://pf-open-echo.test/"; then
    inspect_ok=1
    break
  fi
  sleep 1
done
if [[ "${inspect_ok}" -ne 1 ]]; then
  echo "pi-fortress setup: https://pf-open-echo.test failed. CA or TLS inspection broken." >&2
  echo "pi-fortress setup: default $(ip -4 route show default 2>/dev/null | tr '\n' ' ')" >&2
  echo "pi-fortress setup: echo-a $(dig +short +time=2 +tries=1 "@${PI_IP}" pf-open-echo.test A 2>/dev/null | tr '\n' ' ')" >&2
  curl -4 -sS -v --max-time 8 --http1.1 --cacert /etc/pi-fortress/egress-ca.pem -o /dev/null https://pf-open-echo.test/ >&2 || true
  exit 1
fi
echo "pi-fortress setup: inspect https://pf-open-echo.test OK"

code=""
for _try in 1 2 3; do
  code="$(https_code "https://example.com/")"
  case "${code}" in
    200|301|302|303|307|308)
      echo "pi-fortress setup: https://example.com -> ${code} OK"
      echo "pi-fortress setup: done"
      exit 0
      ;;
  esac
  sleep 1
done
echo "pi-fortress setup: https://example.com failed (HTTP ${code:-none}); TLS inspection still OK" >&2
echo "pi-fortress setup: done"
