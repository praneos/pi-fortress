#!/bin/bash
# Rewrite a vendor Mullvad wg-quick file into the Pi's /etc/wireguard/<WG_IF>.conf.
# Drops IPv6, DNS=, ::/0; injects Table=off, MTU=1420, PersistentKeepalive=25.
# Refuse only if PrivateKey or a numeric Endpoint is missing.
set -euo pipefail

src="${1:-}"
if [[ -z "${src}" || ! -f "${src}" ]]; then
  echo "pi-fortress: wg-conf: need a Mullvad config file" >&2
  exit 1
fi

priv=""
addr=""
pubkey=""
endpoint=""
while IFS= read -r line || [[ -n "${line}" ]]; do
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "${line}" || "${line}" == \[* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  key="${key%"${key##*[![:space:]]}"}"
  val="${val#"${val%%[![:space:]]*}"}"
  val="${val%"${val##*[![:space:]]}"}"
  case "${key}" in
    PrivateKey) priv="${val}" ;;
    Address)
      for part in ${val//,/ }; do
        part="${part#"${part%%[![:space:]]*}"}"
        part="${part%"${part##*[![:space:]]}"}"
        case "${part}" in
          *:*) continue ;;
          */*)
            host="${part%/*}"
            bits="${part##*/}"
            [[ "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && "${bits}" =~ ^[0-9]+$ ]] || continue
            addr="${host}/${bits}"
            break
            ;;
          *)
            [[ "${part}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
            addr="${part}/32"
            break
            ;;
        esac
      done
      ;;
    PublicKey) pubkey="${val}" ;;
    Endpoint) endpoint="${val}" ;;
  esac
done <"${src}"

if [[ -z "${priv}" ]]; then
  echo "pi-fortress: wg-conf: ${src} has no PrivateKey" >&2
  exit 1
fi
if [[ ! "${endpoint}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$ ]]; then
  echo "pi-fortress: wg-conf: ${src} Endpoint must be IPv4:port (boot must not depend on DNS)" >&2
  exit 1
fi
if [[ -z "${pubkey}" ]]; then
  echo "pi-fortress: wg-conf: ${src} has no PublicKey" >&2
  exit 1
fi
if [[ -z "${addr}" ]]; then
  echo "pi-fortress: wg-conf: ${src} has no IPv4 Address" >&2
  exit 1
fi

cat <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${addr}
Table = off
MTU = 1420

[Peer]
PublicKey = ${pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}
PersistentKeepalive = 25
EOF
