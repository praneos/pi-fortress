#!/usr/bin/env bash
# Reproducible release: pf binaries, SHA256SUMS, an SSH signature over it.
#
#   release.sh release                 build HEAD into RELEASE_DIR and sign
#   release.sh verify                  build REV twice in scratch worktrees, compare
#   release.sh check SUMS SIG SIGNERS  verify a downloaded set
#   release.sh lint [DIR]              release-lint every pf-bundle-*.tar in DIR (default RELEASE_DIR)
#   release.sh pi-bundle OUT SHA       make pi-bundle: the working tree's non-ignored files, for pi-ship
#   release.sh placeholders            refuse while an owner placeholder is unfilled (make docs-push runs it too)
#
# Artifacts are each regular file under the release directory. SHA256SUMS
# covers all of them. So later artifacts (appliance images and
# pf-bundle-*.tar, one per arch) only have to be in the directory before sums runs.
set -euo pipefail

NAMESPACE=pi-fortress-dist
PRINCIPAL=release@pi-fortress
ARCHES="amd64 arm64"
die() { echo "release: $*" >&2; exit 1; }

# What the owner fills on launch day (docs/release.md "Owner placeholders"):
# a finder reads the disclosure address, contact and challenge rules to
# make a report, and DOCS_URL is the address of the site. Both the release
# and the docs deploy refuse while one is left, because the site links
# directly to SECURITY.md and the challenge rules.
OWNER_PLACEHOLDERS='<(DISCLOSURE_EMAIL|CONTACT|WINDOW_START|WINDOW_END|APPLIANCE_URL|CANARY_SOURCE|DOCS_URL)>'
OWNER_FILES="SECURITY.md README.md docs/challenge_rules.md docs/hall_of_fame.md docs/INDEX.md docs/user_guide zensical.toml"
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) ||
	die "not in a git checkout: release.sh builds from what git tracks, so ignored files stay out"

version() {
	local tag
	if tag=$(git -C "$1" describe --tags --exact-match --match 'v*' 2>/dev/null); then
		echo "$tag"
	else
		echo "$(git -C "$1" describe --tags --always --abbrev=12 --match 'v*')-dev"
	fi
}

# preflight SRC: the inputs a rebuild has to share.
preflight() {
	local want have
	[ -z "$(git -C "$1" status --porcelain)" ] || die "$1 has uncommitted changes; commit or build a clean worktree"
	want=$(sed -n 's/^toolchain //p' "$1/go.mod")
	[ -n "$want" ] || die "go.mod has no toolchain line"
	have=$(cd "$1" && GOTOOLCHAIN=local go env GOVERSION)
	[ "$have" = "$want" ] || die "go is $have, go.mod pins $want"
}

# build SRC OUT: one pf per arch. It is a position-independent executable
# with no shared libraries. The kernel loads its code at a random address.
build() {
	local src=$1 out=$2 ver epoch arch
	preflight "$src"
	ver=$(version "$src")
	epoch=$(git -C "$src" log -1 --format=%ct)
	mkdir -p "$out"
	for arch in $ARCHES; do
		# -buildvcs=true: the stamp is commit hash, commit time and a
		# clean flag, all fixed by preflight. Backup manifests read it.
		(cd "$src" && env GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off GOWORK=off \
			GOEXPERIMENT= CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 \
			go build -buildmode=pie -trimpath -buildvcs=true \
			-ldflags "-s -w -buildid= -X pi-fortress/internal/cli.Version=$ver" \
			-o "$out/pf-linux-$arch" ./cmd/pf)
		chmod 0755 "$out/pf-linux-$arch"
		touch -d "@$epoch" "$out/pf-linux-$arch"
	done
}

# head_tree SRC DIR: the tracked tree at the HEAD of SRC, and nothing else,
# extracted into DIR. The git status in preflight cannot see an ignored
# file. So a bundle of the checkout itself shipped .cache/, build/ and all
# else that .gitignore hides, vm/policy/secrets.env included.
head_tree() {
	mkdir -p "$2"
	git -C "$1" archive --format=tar HEAD | tar -x -C "$2"
}

# work_tree SRC DIR: the make pi-bundle equivalent of head_tree. A desktop
# push ships uncommitted edits on purpose (its sha says -dirty). So it
# takes the working copy, but only of files that git tracks or would
# track: ignored files stay behind in the same way.
work_tree() {
	mkdir -p "$2"
	(cd "$1" && git ls-files -z --cached --others --exclude-standard |
		while IFS= read -r -d '' f; do
			if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
		done | tar --null --no-recursion -T - -cf -) | tar -x -C "$2"
}

# secretscan FILE...: nothing key-shaped in what is about to be signed
# (internal/secretscan). A bundle is an uncompressed tar, so the bytes of
# its files are scanned as they are.
secretscan() {
	(cd "$ROOT" && SECRETSCAN_FILES="$*" go test -count=1 -run TestArtifactsHoldNoSecrets ./internal/secretscan >/dev/null) ||
		die "something key-shaped in $*: SECRETSCAN_FILES=\"$*\" go test -v -run TestArtifactsHoldNoSecrets ./internal/secretscan"
}

# bundles SRC OUT VER: pf-bundle-VER-<arch>.tar for each arch, next to
# the binaries that build just wrote into OUT. It is built from the
# head_tree export of SRC, with the binary of the arch placed at vm/pi/pf.
# It is reproducible for the same reason as the binaries: the same tracked
# tree, the same version stamp (commit time, not wall clock), the same
# file order (ship.Build walks the tree in lexical order).
#
# PI_SEED is the PI_OWNED lists of the Makefile. The operator edits them
# in place under /opt/pi-fortress/vm/policy. So a release ships them as
# seeds, and the copy on the box wins on each upgrade. Without it, an
# upgrade reverts each block and revocation. So it is required here, and
# does not default to nothing.
bundles() {
	local src=$1 out=$2 ver=$3 epoch arch sha tree
	[ -n "${PI_SEED:-}" ] || die "PI_SEED is empty; run make release, which passes the Makefile's PI_OWNED lists"
	epoch=$(git -C "$src" log -1 --format=%ct)
	sha=$(git -C "$src" rev-parse --short HEAD)
	tree=$(mktemp -d "${TMPDIR:-/tmp}/pf-release-tree.XXXXXX")
	# shellcheck disable=SC2064
	trap "rm -rf '$tree'" EXIT
	head_tree "$src" "$tree"
	for arch in $ARCHES; do
		cp "$out/pf-linux-$arch" "$tree/vm/pi/pf"
		chmod 0755 "$tree/vm/pi/pf"
		(cd "$src" && env -u GOOS -u GOARCH GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off GOWORK=off CGO_ENABLED=0 \
			go run ./cmd/pf ship bundle -root "$tree" -o "$out/pf-bundle-$ver-$arch.tar" \
			-version "$epoch" -sha "$sha" \
			-keep "vm/policy/generated vm/policy/alert.url" -seed "$PI_SEED" \
			-omit "dist bin")
		rm -f "$tree/vm/pi/pf"
		touch -d "@$epoch" "$out/pf-bundle-$ver-$arch.tar"
		(cd "$src" && go run ./cmd/pf ship lint "$out/pf-bundle-$ver-$arch.tar") ||
			die "pf-bundle-$ver-$arch.tar fails release-lint"
		# install.sh runs the vm/pi/pf in the bundle. Without it, no release installs.
		case $'\n'"$(tar -tf "$out/pf-bundle-$ver-$arch.tar")"$'\n' in
		*$'\n'vm/pi/pf$'\n'*) ;;
		*) die "pf-bundle-$ver-$arch.tar has no vm/pi/pf, the binary install.sh runs" ;;
		esac
		secretscan "$out/pf-bundle-$ver-$arch.tar"
	done
	rm -rf "$tree"
	trap - EXIT
}

# pi_bundle OUT SHA: make pi-bundle. vm/pi/pf (make split-bin) is
# gitignored. So it is put into the staged tree by hand, as bundles
# puts the binary of each arch.
pi_bundle() {
	local out=${1:-} sha=${2:-} tree
	[ -n "$out" ] || die "usage: release.sh pi-bundle OUT SHA"
	[ -n "${PI_SEED:-}" ] || die "PI_SEED is empty; run make pi-bundle, which passes the Makefile's PI_OWNED lists"
	[ -x "$ROOT/vm/pi/pf" ] || die "no $ROOT/vm/pi/pf; make split-bin first"
	case $out in /*) ;; *) out=$PWD/$out ;; esac
	tree=$(mktemp -d "${TMPDIR:-/tmp}/pf-pi-bundle.XXXXXX")
	# shellcheck disable=SC2064
	trap "rm -rf '$tree'" EXIT
	work_tree "$ROOT" "$tree"
	install -m 0755 "$ROOT/vm/pi/pf" "$tree/vm/pi/pf"
	(cd "$ROOT" && env -u GOOS -u GOARCH CGO_ENABLED=0 \
		go run ./cmd/pf ship bundle -root "$tree" -o "$out" -sha "$sha" \
		-keep "vm/policy/generated vm/policy/alert.url" -seed "$PI_SEED" \
		-omit "dist bin")
	secretscan "$out"
}

# lint DIR: release-lint over each bundle already in DIR (default
# dist/<version>/), separate from a new release() run. For example, CI
# runs it separately, or against a directory that this script did not
# build itself.
lint() {
	local dir=${1:-${RELEASE_DIR:-}} f
	[ -n "$dir" ] || dir=$ROOT/dist/$(version "$ROOT")
	shopt -s nullglob
	local bundles=("$dir"/pf-bundle-*.tar)
	shopt -u nullglob
	[ ${#bundles[@]} -gt 0 ] || die "lint: no pf-bundle-*.tar in $dir"
	for f in "${bundles[@]}"; do
		go run ./cmd/pf ship lint "$f" || die "$f fails release-lint"
	done
	echo "release-lint: ${#bundles[@]} bundle(s) in $dir ok"
}

sums() {
	(cd "$1" && find . -type f ! -name 'SHA256SUMS*' ! -name allowed_signers -printf '%P\n' |
		LC_ALL=C sort | xargs -r sha256sum >SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
}

KEY=${SIGN_KEY:-$HOME/.ssh/pi_fortress_release}
KEY=${KEY/#\~/$HOME}

# signable: 0 to sign, 1 for a sanctioned unsigned build. It dies
# otherwise, before any build output exists.
signable() {
	if [ ! -r "$KEY" ]; then
		[ "${RELEASE_UNSIGNED:-}" = 1 ] || die "no signing key at $KEY (set SIGN_KEY, or RELEASE_UNSIGNED=1 for a local build)"
		return 1
	fi
	[ -r "$KEY.pub" ] || die "no public key at $KEY.pub"
	command -v ssh-keygen >/dev/null || die "ssh-keygen not found"
	# install.sh refuses a release that another key signed, so refuse it here.
	local pinned
	pinned=$(sed -n 's/.*PF_SIGNER_PUBKEY:-\(ssh-[^ ]* [A-Za-z0-9+\/=]*\)}.*/\1/p' "$ROOT/install.sh")
	[ -n "$pinned" ] && [ "$pinned" = "$(cut -d' ' -f1,2 "$KEY.pub")" ] ||
		die "$KEY.pub is not the key that install.sh pins as PF_SIGNER_PUBKEY (set SIGN_KEY)"
}

sign() {
	local dir=$1 key=$KEY
	rm -f "$dir/SHA256SUMS.sig"
	ssh-keygen -q -Y sign -f "$key" -n "$NAMESPACE" "$dir/SHA256SUMS"
	# install.sh and pf upgrade check the .sig of each bundle, and also
	# SHA256SUMS. SHA256SUMS must name pf-bundle-<tag>-<arch>.tar exactly.
	local b
	for b in "$dir"/pf-bundle-*.tar; do
		[ -e "$b" ] || continue
		rm -f "$b.sig"
		ssh-keygen -q -Y sign -f "$key" -n "$NAMESPACE" "$b"
		ssh-keygen -q -Y verify -f <(printf '%s namespaces="%s" %s\n' "$PRINCIPAL" "$NAMESPACE" "$(cut -d' ' -f1,2 "$key.pub")") \
			-I "$PRINCIPAL" -n "$NAMESPACE" -s "$b.sig" <"$b" >/dev/null || die "$b.sig does not verify"
	done
	printf '%s namespaces="%s" %s\n' "$PRINCIPAL" "$NAMESPACE" "$(cut -d' ' -f1,2 "$key.pub")" >"$dir/allowed_signers"
	check "$dir/SHA256SUMS" "$dir/SHA256SUMS.sig" "$dir/allowed_signers"
}

# placeholders: refuse while any owner placeholder is left. A listed
# path that is gone is also refused, so a rename cannot remove a file
# from the check without notice.
placeholders() {
	local f
	# shellcheck disable=SC2086
	for f in $OWNER_FILES; do
		[ -e "$ROOT/$f" ] || die "placeholders: $f is missing; update OWNER_FILES in scripts/release.sh"
	done
	# shellcheck disable=SC2086
	! (cd "$ROOT" && grep -rn -E "$OWNER_PLACEHOLDERS" -- $OWNER_FILES) >&2 ||
		die "an owner placeholder is still unfilled (docs/release.md); fill it in and commit"
}

# site_placeholders: the check for a docs deploy while the repo is not
# public. It covers only the site files. The site must then link nothing
# in the repo, so a link into the repo refuses and asks for the full check.
SITE_FILES="docs/user_guide zensical.toml"
site_placeholders() {
	# shellcheck disable=SC2086
	! (cd "$ROOT" && grep -rn -E "github\.com/[^/ ]+/pi-fortress(/(blob|tree)/|\"|\)|$)" -- $SITE_FILES) >&2 ||
		die "site-placeholders: the site links into the repo (above); run 'release.sh placeholders' instead"
	OWNER_FILES=$SITE_FILES placeholders
}

check() {
	local sums=${1:-} sig=${2:-} signers=${3:-}
	[ -n "$sums" ] && [ -n "$sig" ] || die "usage: make release-check SUMS=path/SHA256SUMS SIG=path/SHA256SUMS.sig SIGNERS=allowed_signers"
	[ -n "$signers" ] || die "SIGNERS: an allowed_signers file holding the key published in the README, not one fetched next to the download"
	command -v ssh-keygen >/dev/null || die "ssh-keygen not found"
	ssh-keygen -Y verify -f "$signers" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$sig" <"$sums" ||
		die "signature does not verify for $PRINCIPAL in namespace $NAMESPACE"
	(cd "$(dirname "$sums")" && sha256sum --strict --ignore-missing -c "$(basename "$sums")") ||
		die "checksum mismatch"
}

release() {
	local dir=${RELEASE_DIR:-} signed=1
	preflight "$ROOT"
	# The notice goes in the signed bundle. A <PLACEHOLDER> in it would
	# be signed and published as the terms.
	! grep -n -E '<[A-Z][A-Z_]+>' "$ROOT/EVALUATION_NOTICE.txt" >&2 ||
		die "EVALUATION_NOTICE.txt still has a placeholder; fill it in and commit"
	placeholders
	signable || signed=0
	[ -n "$dir" ] || dir=$ROOT/dist/$(version "$ROOT")
	[ ! -e "$dir" ] || [ -z "$(ls -A "$dir")" ] || die "$dir is not empty; remove it first"
	build "$ROOT" "$dir"
	# Nothing key-shaped goes in a binary that we sign (internal/secretscan).
	secretscan "$dir"/pf-linux-*
	install -m 0644 "$ROOT/EVALUATION_NOTICE.txt" "$dir/"
	[ "${APPLIANCE:-}" != 1 ] || VERSION=$(version "$ROOT") PF_APPLIANCE_IN_RELEASE=1 "$ROOT/scripts/appliance.sh" "$dir"
	bundles "$ROOT" "$dir" "$(version "$ROOT")"
	sums "$dir"
	if [ "$signed" = 1 ]; then
		sign "$dir"
	else
		echo "release: !!! UNSIGNED: no key at $KEY and RELEASE_UNSIGNED=1. Do not publish $dir." >&2
	fi
	echo "release: $dir"
	cat "$dir/SHA256SUMS"
}

verify() {
	local rev scratch n
	rev=$(git -C "$ROOT" rev-parse --verify "${REV:-HEAD}^{commit}")
	scratch=$(mktemp -d "${TMPDIR:-/tmp}/pf-release-verify.XXXXXX")
	# shellcheck disable=SC2064
	trap "for n in a b; do git -C '$ROOT' worktree remove --force '$scratch/'\$n/src 2>/dev/null; done; git -C '$ROOT' worktree prune; rm -rf '$scratch'" EXIT
	for n in a b; do
		git -C "$ROOT" worktree add -q --detach "$scratch/$n/src" "$rev"
	done
	# Separate caches, source paths, time zones and locales: anything that
	# the binaries get from the builder shows as a difference.
	(export GOCACHE=$scratch/a/cache GOPATH=$scratch/a/gopath GOMODCACHE=$scratch/a/gopath/pkg/mod TZ=UTC LC_ALL=C
		build "$scratch/a/src" "$scratch/a/out" && sums "$scratch/a/out")
	(export GOCACHE=$scratch/b/cache GOPATH=$scratch/b/gopath GOMODCACHE=$scratch/b/gopath/pkg/mod TZ=Pacific/Kiritimati LC_ALL=C.UTF-8
		build "$scratch/b/src" "$scratch/b/out" && sums "$scratch/b/out")
	if cmp -s "$scratch/a/out/SHA256SUMS" "$scratch/b/out/SHA256SUMS"; then
		echo "release-verify: $(version "$scratch/a/src") at ${rev:0:12}: identical"
		cat "$scratch/a/out/SHA256SUMS"
		return 0
	fi
	echo "release-verify: builds of ${rev:0:12} differ:" >&2
	diff "$scratch/a/out/SHA256SUMS" "$scratch/b/out/SHA256SUMS" | head -20 >&2
	exit 1
}

cmd=${1:-}
shift || true
case $cmd in
release) release ;;
verify) verify ;;
check) check "$@" ;;
lint) lint "$@" ;;
pi-bundle) pi_bundle "$@" ;;
version) version "$ROOT" ;;
placeholders) placeholders ;;
site-placeholders) site_placeholders ;;
*) die "usage: release.sh release|verify|version|placeholders|site-placeholders|check SUMS SIG SIGNERS|lint [DIR]|pi-bundle OUT SHA" ;;
esac
