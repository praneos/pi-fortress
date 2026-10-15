#!/bin/bash
# routes_test.sh: tests the egress-CA pin of routes.sh (pick_ca), with a
# curl stub and all paths in a temp dir. It sources routes.sh. When
# sourced, routes.sh stops after its definitions, so nothing on this host changes.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT
fail() { echo "agent routes_test: $*" >&2; exit 1; }

mkdir -p "${t}/bin"
# curl -fsS --max-time 5 URL -o FILE: copies FAKE_CA to FILE, or fails
# when FAKE_CA is empty (the Pi does not answer).
cat >"${t}/bin/curl" <<'EOF'
#!/bin/bash
out=""
while [[ $# -gt 0 ]]; do
  [[ "$1" == -o ]] && { out="$2"; shift; }
  shift
done
[[ -n "${FAKE_CA:-}" && -n "${out}" ]] || exit 22
cp "${FAKE_CA}" "${out}"
EOF
chmod +x "${t}/bin/curl"
printf -- '-----BEGIN CERTIFICATE-----\nreal\n-----END CERTIFICATE-----\n' >"${t}/real.pem"
printf -- '-----BEGIN CERTIFICATE-----\nevil\n-----END CERTIFICATE-----\n' >"${t}/evil.pem"
real_sum="$(sha256sum "${t}/real.pem" | awk '{print $1}')"

# pick DIR [VAR=VALUE]...: runs pick_ca in a subshell, with PF_CA_DIR and
# agent.env under DIR. Prints "ca=<path>" last.
pick() {
  local d="$1"
  shift
  mkdir -p "${d}/etc"
  (
    export PATH="${t}/bin:${PATH}" PF_AGENT_ENV="${d}/etc/agent.env" PF_CA_DIR="${d}/etc" PF_GEN_DIR="${d}/gen" PF_CA_WAIT=0 PI_IP=10.77.0.1
    for kv in "$@"; do export "${kv?}"; done
    # shellcheck source=/dev/null
    source "${here}/routes.sh"
    pick_ca
    echo "ca=${ca:-}"
  ) 2>&1
}

# No pin, outside provisioning: the old behaviour, with a warning.
out="$(pick "${t}/old" FAKE_CA="${t}/real.pem")"
[[ "${out}" == *"ca=${t}/old/etc/egress-ca.pem" ]] || fail "unpinned box did not take the fetched CA: ${out}"
[[ "${out}" == *"WARNING: no CA_SHA256"* ]] || fail "unpinned fetch was not warned about: ${out}"

# Provisioning (PF_CA_TOFU=1) records the pin it fetched.
out="$(pick "${t}/tofu" FAKE_CA="${t}/real.pem" PF_CA_TOFU=1)"
grep -qxF "CA_SHA256=${real_sum}" "${t}/tofu/etc/agent.env" || fail "provisioning did not record the CA pin: ${out}"
[[ "${out}" != *"WARNING"* ]] || fail "a pinned fetch warned: ${out}"
cmp -s "${t}/real.pem" "${t}/tofu/etc/egress-ca.pem" || fail "provisioning did not install the fetched CA"

# A matching pin takes the fetch.
out="$(pick "${t}/match" FAKE_CA="${t}/real.pem" CA_SHA256="${real_sum}")"
[[ "${out}" == *"ca=${t}/match/etc/egress-ca.pem" ]] || fail "matching pin refused: ${out}"

# A different CA on the wire: the box refuses it, logs it, and keeps the trusted CA.
mkdir -p "${t}/swap/etc"
cp "${t}/real.pem" "${t}/swap/etc/egress-ca.pem"
out="$(pick "${t}/swap" FAKE_CA="${t}/evil.pem" CA_SHA256="${real_sum}" PF_CA_TOFU=1)"
cmp -s "${t}/real.pem" "${t}/swap/etc/egress-ca.pem" || fail "a CA that does not match the pin overwrote the trusted one"
[[ "${out}" == *"not the pinned ${real_sum}"* ]] || fail "pin mismatch not logged: ${out}"
[[ "${out}" == *"ca=${t}/swap/etc/egress-ca.pem" ]] || fail "pin mismatch did not keep the trusted CA: ${out}"

# A mismatch with nothing trusted yet, and a lab generated/ copy that is
# not the pinned CA either: nothing is trusted.
mkdir -p "${t}/none/gen"
cp "${t}/evil.pem" "${t}/none/gen/egress-ca.pem"
out="$(pick "${t}/none" FAKE_CA="${t}/evil.pem" CA_SHA256="${real_sum}")"
[[ "${out}" == *"ca=" && "${out}" != *"ca=/"* ]] || fail "an unpinned CA was trusted from somewhere: ${out}"

# The Pi does not answer: the pinned box uses its own copy.
mkdir -p "${t}/down/etc"
cp "${t}/real.pem" "${t}/down/etc/egress-ca.pem"
out="$(pick "${t}/down" CA_SHA256="${real_sum}")"
[[ "${out}" == *"ca=${t}/down/etc/egress-ca.pem" ]] || fail "pinned box with the Pi down lost its CA: ${out}"

# A pin that is not a sha256 trusts nothing new.
out="$(pick "${t}/bad" FAKE_CA="${t}/real.pem" CA_SHA256=deadbeef)"
[[ "${out}" == *"is not a sha256"* && "${out}" != *"ca=/"* ]] || fail "a malformed pin let a CA through: ${out}"
[[ ! -e "${t}/bad/etc/egress-ca.pem" ]] || fail "a malformed pin installed a CA"

# provision.sh passes the pin on, and runs the first routes.sh as TOFU.
# shellcheck disable=SC2016
grep -qF 'CA_SHA256=${CA_SHA256}' "${here}/provision.sh" || fail "provision.sh does not write CA_SHA256 into agent.env"
grep -qxF 'PF_CA_TOFU=1 /usr/local/sbin/pi-fortress-agent-routes' "${here}/provision.sh" || fail "provision.sh does not record the pin on its first routes run"
echo "agent routes_test: ok"
