#!/bin/bash
# install.sh against a fake release: throwaway signing keys made here, a
# fake curl that serves files from a scratch directory, and a fake pf at
# vm/pi/pf that only echoes its arguments. Nothing touches the network or
# the release key of the repo. scripts/shell_test.sh runs it. It also runs
# alone.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "${here}"

fail() { echo "install_test: $*" >&2; exit 1; }

command -v ssh-keygen >/dev/null || fail "ssh-keygen is required"
command -v setsid >/dev/null || fail "setsid (util-linux) is required to run install.sh with no terminal"

t="$(mktemp -d)"
trap 'rm -rf "${t}"' EXIT

cat >"${t}/os-release" <<'EOF'
ID=ubuntu
VERSION_ID=24.04
VERSION_CODENAME=noble
EOF

ssh-keygen -q -t ed25519 -N '' -C release@pi-fortress -f "${t}/key"
ssh-keygen -q -t ed25519 -N '' -C someone-else -f "${t}/other"
pubkey="$(cut -d' ' -f1,2 "${t}/key.pub")"

sign() {
  rm -f "$2.sig"
  ssh-keygen -q -Y sign -f "$1" -n pi-fortress-dist "$2"
}

# release ROOT VER: pf-bundle-VER-<arch>.tar for both arches, each with
# its own .sig, and the signed SHA256SUMS over them, under ROOT/VER/.
# This is the layout that make release uploads and GitHub serves.
release() {
  local root="$1" ver="$2" arch d
  d="${root}/${ver}"
  mkdir -p "${d}"
  for arch in amd64 arm64; do
    rm -rf "${t}/tree"
    mkdir -p "${t}/tree/vm/pi"
    printf '#!/bin/sh\necho "fake pf %s %s $*"\n' "${arch}" "${ver}" >"${t}/tree/vm/pi/pf"
    chmod 0755 "${t}/tree/vm/pi/pf"
    tar -cf "${d}/pf-bundle-${ver}-${arch}.tar" -C "${t}/tree" vm
    sign "${t}/key" "${d}/pf-bundle-${ver}-${arch}.tar"
  done
  (cd "${d}" && sha256sum pf-bundle-*.tar >SHA256SUMS)
  sign "${t}/key" "${d}/SHA256SUMS"
}

good="${t}/good"
release "${good}" v1
release "${good}" v2

# The fake curl logs its arguments and copies BASE/<path> from
# PF_FAKE_ROOT/<path>. It fails like curl -f on a missing file.
base="https://pi-fortress-block.test/releases/download"
mkdir -p "${t}/bin"
cat >"${t}/bin/curl" <<EOF
#!/bin/bash
echo "\$*" >>"${t}/curl.log"
out="" url=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    *://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
src="\${PF_FAKE_ROOT}/\${url#"${base}/"}"
[[ "\${url}" == "${base}/"* && -f "\${src}" ]] || exit 22
cp "\${src}" "\${out}"
EOF
chmod +x "${t}/bin/curl"

# run ROOT ARGS...: install.sh with no terminal at all (setsid: no
# controlling tty, stdin from /dev/null), the fake curl first on PATH.
run() {
  local root="$1"
  shift
  rm -f "${t}/curl.log"
  setsid -w env PATH="${t}/bin:${PATH}" PF_FAKE_ROOT="${root}" PF_TEST_SKIP_ROOT=1 PF_TEST_UNAME_M=x86_64 \
    PF_TEST_OS_RELEASE="${t}/os-release" PF_SIGNER_PUBKEY="${pubkey}" "$@" </dev/null 2>&1
}

refuses() {
  local desc="$1" want="$2" out status
  shift 2
  out="$(run "$@")" && status=0 || status=$?
  [[ "${status}" -ne 0 ]] || fail "${desc}: expected a refusal, got exit 0: ${out}"
  [[ "${out}" == *"${want}"* ]] || fail "${desc}: expected '${want}' in the refusal, got: ${out}"
  [[ "${out}" != *"fake pf"* ]] || fail "${desc}: refused, but only after running the bundle's pf: ${out}"
}

proceeds() {
  local desc="$1" want="$2" out
  shift 2
  out="$(run "$@")" || fail "${desc}: refused: ${out}"
  [[ "${out}" == *"${want}"* ]] || fail "${desc}: expected '${want}', got: ${out}"
}

online=(env PF_RELEASE_URL="${base}" PF_VERSION=v2 bash install.sh)

proceeds "the right tag and arch" "fake pf amd64 v2 install -bundle " "${good}" "${online[@]}" -yes
log="$(<"${t}/curl.log")"
[[ "${log}" == *"SHA256SUMS.sig"* ]] || fail "did not fetch SHA256SUMS.sig: ${log}"
while IFS= read -r line; do
  for opt in "--proto =https" "--proto-redir =https" "--tlsv1.2" "--fail"; do
    [[ " ${line} " == *" ${opt} "* ]] || fail "curl ran without ${opt}: ${line}"
  done
done <<<"${log}"

# Each attack serves only files that the release key actually signed.
evil="${t}/wrong-arch"
cp -r "${good}" "${evil}"
cp "${good}/v2/pf-bundle-v2-arm64.tar" "${evil}/v2/pf-bundle-v2-amd64.tar"
cp "${good}/v2/pf-bundle-v2-arm64.tar.sig" "${evil}/v2/pf-bundle-v2-amd64.tar.sig"
refuses "the other arch's bundle under this arch's name" "does not match its SHA256SUMS entry" "${evil}" "${online[@]}" -yes

evil="${t}/old-tag"
cp -r "${good}" "${evil}"
cp "${good}/v1/pf-bundle-v1-amd64.tar" "${evil}/v2/pf-bundle-v2-amd64.tar"
cp "${good}/v1/pf-bundle-v1-amd64.tar.sig" "${evil}/v2/pf-bundle-v2-amd64.tar.sig"
cp "${good}/v1/SHA256SUMS" "${good}/v1/SHA256SUMS.sig" "${evil}/v2/"
refuses "an old tag's bundle and checksums under the new tag" "does not list pf-bundle-v2-amd64.tar" "${evil}" "${online[@]}" -yes

evil="${t}/old-bundle"
cp -r "${good}" "${evil}"
cp "${good}/v1/pf-bundle-v1-amd64.tar" "${evil}/v2/pf-bundle-v2-amd64.tar"
cp "${good}/v1/pf-bundle-v1-amd64.tar.sig" "${evil}/v2/pf-bundle-v2-amd64.tar.sig"
refuses "an old tag's bundle under the new tag's checksums" "does not match its SHA256SUMS entry" "${evil}" "${online[@]}" -yes

evil="${t}/missing"
cp -r "${good}" "${evil}"
grep -v amd64 "${good}/v2/SHA256SUMS" >"${evil}/v2/SHA256SUMS"
sign "${t}/key" "${evil}/v2/SHA256SUMS"
refuses "a SHA256SUMS that does not name the bundle" "does not list pf-bundle-v2-amd64.tar" "${evil}" "${online[@]}" -yes

evil="${t}/other-key"
cp -r "${good}" "${evil}"
sign "${t}/other" "${evil}/v2/SHA256SUMS"
refuses "a SHA256SUMS signed by another key" "SHA256SUMS signature verification failed" "${evil}" "${online[@]}" -yes

evil="${t}/no-sums"
cp -r "${good}" "${evil}"
rm "${evil}/v2/SHA256SUMS.sig"
refuses "a release with no SHA256SUMS.sig" "download failed" "${evil}" "${online[@]}" -yes

refuses "an http release URL" "must be an https:// URL" "${good}" \
  env PF_RELEASE_URL="http://pi-fortress-block.test/releases/download" PF_VERSION=v2 bash install.sh -yes
[[ ! -s "${t}/curl.log" ]] || fail "fetched over http before refusing it: $(<"${t}/curl.log")"
refuses "a file release URL" "must be an https:// URL" "${good}" \
  env PF_RELEASE_URL="file://${good}" PF_VERSION=v2 bash install.sh -yes

refuses "a PF_VERSION that is a path" "is not a release tag" "${good}" \
  env PF_RELEASE_URL="${base}" PF_VERSION=../v1 bash install.sh -yes

refuses "no terminal and no answers" "no terminal to answer" "${good}" "${online[@]}"
[[ ! -s "${t}/curl.log" ]] || fail "downloaded before refusing a run nobody can answer: $(<"${t}/curl.log")"
refuses "no terminal and only one answer" "no terminal to answer" "${good}" "${online[@]}" -wan eth0
proceeds "no terminal with -wan and -agent" "fake pf amd64 v2 install -bundle " "${good}" "${online[@]}" -wan eth0 -agent eth1
proceeds "no terminal with -agent=X --wan X" "-agent=eth1 --wan eth0" "${good}" "${online[@]}" -agent=eth1 --wan eth0

# Offline: the same binding, with the name taken from PF_BUNDLE.
proceeds "an offline bundle with its SHA256SUMS" "fake pf amd64 v2 install -bundle " "${good}" \
  env PF_BUNDLE="${good}/v2/pf-bundle-v2-amd64.tar" bash install.sh -yes
refuses "an offline bundle for the other arch" "is not named pf-bundle-<tag>-amd64.tar" "${good}" \
  env PF_BUNDLE="${good}/v2/pf-bundle-v2-arm64.tar" bash install.sh -yes
refuses "an offline bundle of another tag than PF_VERSION" "PF_VERSION=v1 but PF_BUNDLE" "${good}" \
  env PF_VERSION=v1 PF_BUNDLE="${good}/v2/pf-bundle-v2-amd64.tar" bash install.sh -yes
evil="${t}/offline-nosums"
mkdir -p "${evil}"
cp "${good}/v2/pf-bundle-v2-amd64.tar" "${good}/v2/pf-bundle-v2-amd64.tar.sig" "${evil}/"
refuses "an offline bundle with no SHA256SUMS" "no SHA256SUMS at" "${good}" \
  env PF_BUNDLE="${evil}/pf-bundle-v2-amd64.tar" bash install.sh -yes

echo "install_test: install.sh binds tag and arch, https only, no silent answers: clean"
