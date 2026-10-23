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

# A CA rotation on the Pi (pf engine ca). Real certificates: root a is
# pinned, b is the next root, l is the link (the key of b, signed by a),
# c is a root of a different device, e is a leaf that a signed.
if command -v openssl >/dev/null 2>&1; then
  k="${t}/k"
  mkdir -p "${k}"
  cat >"${k}/cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = keyCertSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = CA:FALSE
EOF
  ossl() { openssl "$@" >/dev/null 2>&1 || fail "openssl $1 failed"; }
  for r in a b c; do
    ossl req -x509 -config "${k}/cnf" -extensions ca -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "${k}/${r}.key" -out "${k}/${r}.pem" -days 2 -subj "/CN=root ${r}"
    # notBefore has a resolution of one second. Root b must be newer than root a.
    [[ "${r}" != a ]] || sleep 1
  done
  ossl req -new -config "${k}/cnf" -key "${k}/b.key" -subj "/CN=root b (link)" -out "${k}/l.csr"
  ossl x509 -req -in "${k}/l.csr" -CA "${k}/a.pem" -CAkey "${k}/a.key" -set_serial 2 -days 2 \
    -extfile "${k}/cnf" -extensions ca -out "${k}/l.pem"
  ossl req -new -config "${k}/cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${k}/e.key" -subj "/CN=CA:TRUE" -out "${k}/e.csr"
  ossl x509 -req -in "${k}/e.csr" -CA "${k}/a.pem" -CAkey "${k}/a.key" -set_serial 3 -days 2 \
    -extfile "${k}/cnf" -extensions leaf -out "${k}/e.pem"
  # Same bytes as the Pi serves: the PEM of each cert, one after the other.
  set_of() { cat "$@"; }

  # rot DIR PINNED FETCHED: a box that trusts PINNED fetches FETCHED.
  rot() {
    mkdir -p "$1/etc"
    cp "$2" "$1/etc/egress-ca.pem"
    pick "$1" FAKE_CA="$3" CA_SHA256="$(sha256sum "$2" | awk '{print $1}')"
  }
  set_of "${k}/a.pem" "${k}/b.pem" "${k}/l.pem" >"${k}/rotate.pem"
  set_of "${k}/b.pem" "${k}/a.pem" "${k}/l.pem" >"${k}/promote.pem"
  rot_sum="$(sha256sum "${k}/rotate.pem" | awk '{print $1}')"

  out="$(rot "${t}/rot" "${k}/a.pem" "${k}/rotate.pem")"
  [[ "${out}" == *"ca=${t}/rot/etc/egress-ca.pem" ]] || fail "a set that the pinned root signed was refused: ${out}"
  cmp -s "${k}/rotate.pem" "${t}/rot/etc/egress-ca.pem" || fail "the rotated set was not installed"
  grep -qxF "CA_SHA256=${rot_sum}" "${t}/rot/etc/agent.env" || fail "the pin did not move to the rotated set: ${out}"

  # An agent that missed the rotate step and fetches after promote.
  out="$(rot "${t}/late" "${k}/a.pem" "${k}/promote.pem")"
  cmp -s "${k}/promote.pem" "${t}/late/etc/egress-ca.pem" || fail "the set after promote was refused by a box pinned to the old root: ${out}"

  # After promote and after retire, a box pinned to the rotated set.
  out="$(rot "${t}/prom" "${k}/rotate.pem" "${k}/promote.pem")"
  cmp -s "${k}/promote.pem" "${t}/prom/etc/egress-ca.pem" || fail "the set after promote was refused: ${out}"
  out="$(rot "${t}/ret" "${k}/promote.pem" "${k}/b.pem")"
  cmp -s "${k}/b.pem" "${t}/ret/etc/egress-ca.pem" || fail "the set after retire was refused: ${out}"
  # A box that missed promote: it fetches the set after retire.
  out="$(rot "${t}/ret-late" "${k}/rotate.pem" "${k}/b.pem")"
  cmp -s "${k}/b.pem" "${t}/ret-late/etc/egress-ca.pem" || fail "the set after retire was refused by a box pinned to the rotated set: ${out}"
  grep -qxF "CA_SHA256=$(sha256sum "${k}/b.pem" | awk '{print $1}')" "${t}/ret-late/etc/agent.env" || fail "the pin did not move to the retired set: ${out}"

  # Retire before promote stops a rotation. A box pinned to the set of
  # rotate (a first) takes the set with root a only.
  out="$(rot "${t}/stop-rotate" "${k}/rotate.pem" "${k}/a.pem")"
  cmp -s "${k}/a.pem" "${t}/stop-rotate/etc/egress-ca.pem" || fail "stop-rotate: the set after a stopped rotation was refused: ${out}"
  grep -qxF "CA_SHA256=$(sha256sum "${k}/a.pem" | awk '{print $1}')" "${t}/stop-rotate/etc/agent.env" || fail "stop-rotate: the pin did not move to the stopped set: ${out}"

  # After promote (b first), a set with root a only keeps neither the
  # newest nor the first pinned root: the box keeps its pin.
  out="$(rot "${t}/drop-promote" "${k}/promote.pem" "${k}/a.pem")"
  cmp -s "${k}/promote.pem" "${t}/drop-promote/etc/egress-ca.pem" || fail "drop-promote: a set without the current root replaced the pinned set: ${out}"
  ! grep -q '^CA_SHA256=' "${t}/drop-promote/etc/agent.env" 2>/dev/null || fail "drop-promote: the pin moved: ${out}"
  [[ "${out}" == *"keeps neither the newest nor the first pinned root"* ]] || fail "drop-promote: the refusal was not logged: ${out}"

  # Sets that the pinned root did not sign: each one keeps root a.
  set_of "${k}/a.pem" "${k}/c.pem" >"${k}/added.pem"
  set_of "${k}/a.pem" "${k}/b.pem" >"${k}/nolink.pem"
  set_of "${k}/a.pem" "${k}/e.pem" >"${k}/leaf.pem"
  set_of "${k}/c.pem" >"${k}/other.pem"
  for bad in added nolink leaf other; do
    out="$(rot "${t}/${bad}" "${k}/a.pem" "${k}/${bad}.pem")"
    cmp -s "${k}/a.pem" "${t}/${bad}/etc/egress-ca.pem" || fail "${bad}: a set the pinned root did not sign replaced it: ${out}"
    ! grep -q '^CA_SHA256=' "${t}/${bad}/etc/agent.env" 2>/dev/null || fail "${bad}: the pin moved: ${out}"
    [[ "${out}" == *"not the pinned"* ]] || fail "${bad}: the refusal was not logged: ${out}"
  done

  # trust_ca puts each cert in the store as its own file, and removes the
  # files of a cert that left the set.
  (
    # shellcheck source=/dev/null
    source "${here}/routes.sh"
    export PF_CA_STORE="${t}/store"
    trust_ca "${k}/rotate.pem"
    [[ "$(find "${PF_CA_STORE}" -name 'pi-fortress-egress*.crt' | wc -l)" -eq 3 ]] || fail "trust_ca did not write one file per cert"
    cmp -s "${k}/a.pem" "${PF_CA_STORE}/pi-fortress-egress.crt" || fail "the first cert is not pi-fortress-egress.crt"
    trust_ca "${k}/b.pem"
    [[ "$(find "${PF_CA_STORE}" -name 'pi-fortress-egress*.crt' | wc -l)" -eq 1 ]] || fail "trust_ca kept a cert that left the set"
  ) || exit 1
else
  echo "agent routes_test: no openssl; rotation cases skipped"
fi

# provision.sh passes the pin on, and runs the first routes.sh as TOFU.
# shellcheck disable=SC2016
grep -qF 'CA_SHA256=${CA_SHA256}' "${here}/provision.sh" || fail "provision.sh does not write CA_SHA256 into agent.env"
grep -qxF 'PF_CA_TOFU=1 /usr/local/sbin/pi-fortress-agent-routes' "${here}/provision.sh" || fail "provision.sh does not record the pin on its first routes run"
echo "agent routes_test: ok"
