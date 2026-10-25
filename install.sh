#!/bin/bash
# pi-fortress gateway bootstrap (docs/gateway_install.md). On the Pi:
#
#   curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install.sh | sudo bash
#
# With no settings, it installs the newest release from GitHub. To pin
# a release: sudo PF_VERSION=v1.2.3 bash install.sh. To skip the
# questions: curl ... | sudo bash -s -- -wan eth0 -agent eth1.
# PF_RELEASE_URL names a different release server; PF_VERSION is then
# required.
#
# The questions go to /dev/tty, never to stdin. With no terminal, the
# install refuses unless -wan and -agent (or -yes) answer them.
#
# Offline / local bundle, no network fetch (SHA256SUMS and its .sig from
# the same release are next to it, or PF_SUMS names them):
#   sudo PF_BUNDLE=./pf-bundle-v1.2.3-arm64.tar bash install.sh
#
# This script only puts the signed bundle on the box and gives it to
# `pf install` (internal/install, internal/cli/install.go). After that,
# pf install does the OS/arch check, the interface wizard, apt packages,
# users, net.env.local and the swap-and-apply. This script does not.
# All arguments go directly to `pf install`.
set -euo pipefail

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

# answered ARGS...: the arguments answer the interface questions
# alone, as pf install parses them: -yes, or both -wan and
# -agent.
answered() {
  local wan="" agent="" a
  for a in "$@"; do
    case "${a}" in
      --) break ;;
      -yes | --yes | -yes=[1tT]* | --yes=[1tT]*) return 0 ;;
      -wan | --wan | -wan=?* | --wan=?*) wan=1 ;;
      -agent | --agent | -agent=?* | --agent=?*) agent=1 ;;
    esac
  done
  [[ -n "${wan}" && -n "${agent}" ]]
}

# valid_tag TAG: a release tag as make release names it, and nothing that
# a URL path or a file name could read as more than one segment.
valid_tag() {
  [[ "${#1}" -le 128 && "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ && "$1" != latest ]]
}

# sums_entry SUMS NAME: the sha256 that SUMS lists for NAME, one time for
# each line that names it exactly.
sums_entry() {
  awk -v n="$2" 'NF == 2 && ($2 == n || $2 == "*" n) && length($1) == 64 && $1 !~ /[^0-9a-f]/ { print $1 }' "$1"
}

PF_REPO_URL=https://github.com/praneos/pi-fortress

# latest_tag: the tag of the newest GitHub release. GitHub answers
# /releases/latest with a redirect to /releases/tag/<tag>. The caller
# checks the tag with valid_tag, and the signed SHA256SUMS binds the
# bundle to it. PF_TEST_LATEST_URL replaces the answer for
# scripts/shell_test.sh.
latest_tag() {
  local url
  url="${PF_TEST_LATEST_URL:-$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --location -o /dev/null -w '%{url_effective}' "${PF_REPO_URL}/releases/latest")}" || return 1
  [[ "${url}" == "${PF_REPO_URL}/releases/tag/"?* ]] || return 1
  printf '%s\n' "${url##*/releases/tag/}"
}

# The full script is one function, called on the last line. bash reads
# all of it before anything runs. Thus an incomplete download under
# curl | bash runs nothing.
main() {
  # PF_TEST_SKIP_ROOT lets scripts/shell_test.sh test the refusals below
  # without sudo. It is unset in all real use, where root is really required
  # (pf install checks it again independently in all cases).
  [[ "${EUID}" -eq 0 || -n "${PF_TEST_SKIP_ROOT:-}" ]] || fail "must run as root (sudo ... bash install.sh)"

  # --- arch --------------------------------------------------------------
  # PF_TEST_UNAME_M overrides `uname -m`, as PF_TEST_MODEL of apply.sh
  # replaces /proc/device-tree/model. Thus scripts/shell_test.sh tests the
  # refusal paths below without a second architecture or OS
  # available.
  case "${PF_TEST_UNAME_M:-$(uname -m)}" in
    aarch64 | arm64) ARCH=arm64 ;;
    x86_64 | amd64) ARCH=amd64 ;;
    *) fail "unsupported CPU architecture ${PF_TEST_UNAME_M:-$(uname -m)}; pi-fortress ships arm64 (Raspberry Pi) and amd64 (Debian/Ubuntu) builds only" ;;
  esac

  # --- OS ------------------------------------------------------------------
  # The /etc/os-release of Raspberry Pi OS is the same as that of Debian,
  # byte for byte. Thus arm64 also needs the device-tree model (the same
  # check as pf_host_guard of vm/pi/apply.sh). amd64 uses only os-release.
  # pf install (internal/install/target.go) makes exactly the same decision
  # again when it runs. Thus, if a bug here lets a box through, pf install
  # still refuses it before it downloads or writes anything.
  # PF_TEST_OS_RELEASE and PF_TEST_MODEL replace the two real files, for
  # the same reason as above.
  OS_RELEASE_FILE="${PF_TEST_OS_RELEASE:-/etc/os-release}"
  MODEL_FILE="${PF_TEST_MODEL:-/proc/device-tree/model}"
  [[ -r "${OS_RELEASE_FILE}" ]] || fail "no ${OS_RELEASE_FILE}; cannot tell what this box is running"
  # shellcheck source=/dev/null
  . "${OS_RELEASE_FILE}"
  MODEL=""
  [[ -r "${MODEL_FILE}" ]] && MODEL="$(tr -d '\0' <"${MODEL_FILE}" || true)"

  OS_LABEL=""
  case "${ARCH}" in
    arm64)
      if [[ "${MODEL}" == *"Raspberry Pi"* && "${ID:-}" == debian && ( "${VERSION_CODENAME:-}" == bookworm || "${VERSION_CODENAME:-}" == trixie ) ]]; then
        OS_LABEL="Raspberry Pi OS Lite 64-bit (${VERSION_CODENAME})"
      fi
      ;;
    amd64)
      if [[ "${ID:-}" == debian && ( "${VERSION_ID:-}" == 12 || "${VERSION_ID:-}" == 13 ) ]]; then
        OS_LABEL="Debian ${VERSION_ID} amd64"
      elif [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]]; then
        OS_LABEL="Ubuntu 24.04 amd64"
      fi
      ;;
  esac
  [[ -n "${OS_LABEL}" ]] || fail "unsupported target arch=${ARCH} id=${ID:-?} version=${VERSION_ID:-?} codename=${VERSION_CODENAME:-?} model=${MODEL:-none}; supported: Raspberry Pi OS Lite 64-bit bookworm/trixie on arm64, Debian 12/13 or Ubuntu 24.04 on amd64"
  echo "install.sh: target ${OS_LABEL} (${ARCH})"

  need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required and not on PATH"; }
  need ssh-keygen
  need sha256sum
  need tar

  # --- signer key ----------------------------------------------------------
  # The real key that is published now (docs/user_guide/verify.md,
  # docs/release.md "Signing": namespace pi-fortress-dist, principal
  # release@pi-fortress). It is embedded here, not left as a to-do, because
  # the repo already has it in allowed_signers form. PF_SIGNER_PUBKEY
  # overrides it for key rotation, with no edit to this file. Releases up
  # to v0.1.5 use the earlier key in verify.md; set PF_SIGNER_PUBKEY to it
  # to install one of them.
  PF_SIGNER_PUBKEY="${PF_SIGNER_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKVK/2pcp/J483O0Q/NvHVZr6jAR3uzMQfTabUh5B96R}"
  case "${PF_SIGNER_PUBKEY}" in
    "" | *PLACEHOLDER* | *TODO*)
      fail "PF_SIGNER_PUBKEY is unset or a placeholder; refusing to trust an unverifiable bundle. See https://pi-fortress.praneos.ai/verify/ for the real key."
      ;;
  esac

  # --- which bundle ---------------------------------------------------------
  # Four files from one release: the bundle, its .sig, SHA256SUMS and
  # SHA256SUMS.sig. The .sig of the bundle proves only that the release key
  # signed these bytes one time. The signed SHA256SUMS names them
  # pf-bundle-<tag>-<arch>.tar. Thus it binds them to the requested tag and
  # to the arch of this box.
  if [[ -n "${PF_BUNDLE:-}" ]]; then
    [[ -f "${PF_BUNDLE}" ]] || fail "PF_BUNDLE=${PF_BUNDLE} not found"
    NAME="$(basename -- "${PF_BUNDLE}")"
    case "${NAME}" in
      pf-bundle-?*-"${ARCH}".tar) ;;
      *) fail "PF_BUNDLE ${NAME} is not named pf-bundle-<tag>-${ARCH}.tar as published; the name, listed in the release's signed SHA256SUMS, is what binds a bundle to its tag and to this box's arch" ;;
    esac
    TAG="${NAME#pf-bundle-}"
    TAG="${TAG%-"${ARCH}".tar}"
    valid_tag "${TAG}" || fail "PF_BUNDLE ${NAME} does not carry a release tag"
    [[ -z "${PF_VERSION:-}" || "${PF_VERSION}" == "${TAG}" ]] || fail "PF_VERSION=${PF_VERSION} but PF_BUNDLE is ${NAME}; refusing a bundle of another release"
    SIG_SRC="${PF_SIG:-${PF_BUNDLE}.sig}"
    [[ -f "${SIG_SRC}" ]] || fail "no signature at ${SIG_SRC} (set PF_SIG to point at it)"
    SUMS_SRC="${PF_SUMS:-$(dirname -- "${PF_BUNDLE}")/SHA256SUMS}"
    [[ -f "${SUMS_SRC}" && -f "${SUMS_SRC}.sig" ]] || fail "no SHA256SUMS at ${SUMS_SRC} (or no ${SUMS_SRC}.sig); download both from the same release page as the bundle, or set PF_SUMS"
  else
    need curl
    # Exported: pf install keeps it in /etc/pi-fortress/release.url for
    # pf upgrade.
    export PF_RELEASE_URL="${PF_RELEASE_URL:-${PF_REPO_URL}/releases/download}"
    if [[ "${PF_RELEASE_URL}" != https://?* || "${PF_RELEASE_URL}" =~ [[:space:]] ]]; then
      fail "PF_RELEASE_URL must be an https:// URL (got ${PF_RELEASE_URL}); releases are fetched over https only"
    fi
    # The name of a release asset has its tag. Thus there is no fixed "latest"
    # path to build. GitHub serves only /releases/download/<tag>/<asset>.
    # With no PF_VERSION, the tag comes from GitHub, and only for the
    # GitHub release URL.
    if [[ -z "${PF_VERSION:-}" ]]; then
      [[ "${PF_RELEASE_URL%/}" == "${PF_REPO_URL}/releases/download" ]] ||
        fail "PF_VERSION is not set: with your own PF_RELEASE_URL, set PF_VERSION to a release tag, e.g. PF_VERSION=v0.1.0"
      PF_VERSION="$(latest_tag)" || fail "no published release found at ${PF_REPO_URL}/releases/latest. Set PF_VERSION to a tag from ${PF_REPO_URL}/releases, or use PF_BUNDLE for an offline install."
      echo "install.sh: newest release is ${PF_VERSION}"
    fi
    [[ "${PF_VERSION}" != latest ]] || fail "PF_VERSION=latest is not a release tag; leave PF_VERSION unset for the newest release"
    valid_tag "${PF_VERSION}" || fail "PF_VERSION=${PF_VERSION} is not a release tag (letters, digits and . _ + - only)"
    TAG="${PF_VERSION}"
    BASE="${PF_RELEASE_URL%/}/${TAG}"
    NAME="pf-bundle-${TAG}-${ARCH}.tar"
  fi

  # --- who answers the questions -------------------------------------------
  # pf install asks for the uplink and agent ports on /dev/tty. With no
  # terminal (a headless runner, cron, ssh without -t), nobody can answer.
  # If the script silently accepts the proposal, a new box can fence its
  # uplink. Thus refuse before the download.
  if ! answered "$@" && ! { : </dev/tty; } 2>/dev/null; then
    fail "no terminal to answer the interface questions on; pass -wan <uplink> -agent <agent port> (and -house <port> for a home network), or -yes to take the proposed ports, as arguments to install.sh (piped: curl ... | sudo bash -s -- -wan eth0 -agent eth1)"
  fi

  # --- get the bundle --------------------------------------------------------
  WORK="$(mktemp -d /tmp/pf-install.XXXXXX)"
  trap 'rm -rf "${WORK}"' EXIT
  SIGNERS="${WORK}/release-signers"
  printf 'release@pi-fortress namespaces="pi-fortress-dist" %s\n' "${PF_SIGNER_PUBKEY}" >"${SIGNERS}"
  TAR="${WORK}/pf-bundle.tar"
  SIG="${WORK}/pf-bundle.tar.sig"
  SUMS="${WORK}/SHA256SUMS"
  if [[ -n "${PF_BUNDLE:-}" ]]; then
    cp "${PF_BUNDLE}" "${TAR}"
    cp "${SIG_SRC}" "${SIG}"
    cp "${SUMS_SRC}" "${SUMS}"
    cp "${SUMS_SRC}.sig" "${SUMS}.sig"
    echo "install.sh: using local bundle ${PF_BUNDLE}"
  else
    # --proto-redir also: GitHub answers each asset with a redirect.
    get() {
      curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location "$1" -o "$2" ||
        fail "download failed: $1"
    }
    echo "install.sh: downloading ${BASE}/${NAME}"
    get "${BASE}/${NAME}" "${TAR}"
    get "${BASE}/${NAME}.sig" "${SIG}"
    get "${BASE}/SHA256SUMS" "${SUMS}"
    get "${BASE}/SHA256SUMS.sig" "${SUMS}.sig"
  fi

  # --- verify ----------------------------------------------------------------
  ssh-keygen -Y verify -f "${SIGNERS}" -I release@pi-fortress -n pi-fortress-dist -s "${SUMS}.sig" <"${SUMS}" >/dev/null 2>&1 \
    || fail "SHA256SUMS signature verification failed; refusing a checksum list the release key did not sign"
  mapfile -t WANT < <(sums_entry "${SUMS}" "${NAME}")
  [[ "${#WANT[@]}" -eq 1 ]] || fail "the signed SHA256SUMS does not list ${NAME} exactly once; refusing a bundle its release does not name (wrong tag or arch, or another release's SHA256SUMS)"
  HAVE="$(sha256sum <"${TAR}" | cut -d' ' -f1)"
  [[ "${HAVE}" == "${WANT[0]}" ]] || fail "${NAME} does not match its SHA256SUMS entry; refusing a bundle that is not the ${TAG} ${ARCH} release (another arch's or another tag's bundle under this name)"
  ssh-keygen -Y verify -f "${SIGNERS}" -I release@pi-fortress -n pi-fortress-dist -s "${SIG}" <"${TAR}" \
    || fail "signature verification failed; refusing to install an unverified bundle"
  echo "install.sh: signature verified (pi-fortress-dist): ${NAME} is release ${TAG} for ${ARCH}"

  # --- hand off to pf install --------------------------------------------
  BUNDLE_ROOT="${WORK}/extract"
  mkdir -p "${BUNDLE_ROOT}"
  # make release ships the binary only at vm/pi/pf (it omits bin/). A
  # make pi-bundle tar has both.
  PFBIN=""
  for _p in vm/pi/pf bin/pf; do
    if tar -xf "${TAR}" -C "${BUNDLE_ROOT}" "${_p}" 2>/dev/null; then
      PFBIN="${BUNDLE_ROOT}/${_p}"
      break
    fi
  done
  [[ -n "${PFBIN}" ]] || fail "bundle carries neither vm/pi/pf nor bin/pf; is this really a pf-bundle tar?"
  chmod 0755 "${PFBIN}"

  # stdin is /dev/null: pf install asks on /dev/tty. Under curl | bash,
  # stdin is this script.
  echo "install.sh: running pf install"
  "${PFBIN}" install -bundle "${TAR}" -sig "${SIG}" -signers "${SIGNERS}" "$@" </dev/null
}

main "$@"
