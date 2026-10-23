# Release build

`make release` builds the public binaries. It makes checksums of them and signs the
checksums. The source is public (Apache-2.0). Thus, anyone can build a commit again
and get the same bytes. Code: `scripts/release.sh`.

## Targets

| Target | Does |
|---|---|
| `make release-gate` | `go mod verify`; `govulncheck` (pinned, fetched by `go run`, never linked) on `./...`; `internal/secretscan` over the tracked tree. Run it before you make a tag |
| `make release` | Refuses a dirty tree, an angle-bracket placeholder left in `EVALUATION_NOTICE.txt` (it ships in the bundle), or an unfilled owner placeholder (below). Builds HEAD into `dist/<version>/`. Refuses if `internal/secretscan` finds anything key-shaped in a binary. Builds one bundle per arch from a `git archive` export of HEAD. Thus, no gitignored file (`.cache/`, `build/`, a `vm/policy/secrets.env`) can go into a bundle. Refuses a bundle that `internal/secretscan` flags. Writes `SHA256SUMS`. Signs it and each bundle |
| `make release-verify [REV=HEAD]` | Checks out REV into two scratch worktrees. Builds each with its own GOCACHE, GOPATH, time zone and locale. Compares `SHA256SUMS` byte for byte. If they differ, fails and prints the different lines. Removes the worktrees |
| `make release-check SUMS=… SIG=… SIGNERS=…` | `ssh-keygen -Y verify`, then `sha256sum -c --strict --ignore-missing` beside SUMS |

## Owner placeholders

These stay in the tree until launch day. While one is left, `make release`
refuses (`release.sh placeholders`, which can also run alone). `make
docs-push` runs the same check. `release.sh site-placeholders` checks
only the site files (`docs/user_guide/`, `zensical.toml`) and also
refuses a link from the site into the repo, for a deploy while the repo
is not public:

| Placeholder | Where | Fill with |
|---|---|---|
| `<DISCLOSURE_EMAIL>` | `SECURITY.md`, `docs/challenge_rules.md` | the security mailbox |
| `<CONTACT>` | `README.md` | a contact, or delete the line |
| `<DOCS_URL>` | `zensical.toml` `site_url` | the address of the docs site, for example `https://<project>.pages.dev` or its own domain, no trailing slash |

The check covers the files in `OWNER_FILES` in `scripts/release.sh`:
`SECURITY.md`, `README.md`, `docs/challenge_rules.md`,
`docs/hall_of_fame.md`, `docs/INDEX.md`, all of `docs/user_guide/` and
`zensical.toml`. It also refuses the retired placeholders
`<WINDOW_START>`, `<WINDOW_END>`, `<APPLIANCE_URL>` and
`<CANARY_SOURCE>`, so that they cannot come back. If a path in its list no
longer exists, the check also fails. Thus, when you move a file, update
`OWNER_FILES`.

Version: an exact `v*` tag. If there is no tag, `git describe --tags --always --abbrev=12`
plus `-dev`. Untagged builds are permitted, and the version marks them. `pf version` prints the version
with the commit hash, commit time and a modified flag.

## Output

```
dist/<version>/
  pf-linux-amd64  pf-linux-arm64   static, mtime = commit time
  pf-bundle-<version>-<arch>.tar   what install.sh and pf upgrade fetch
  pf-bundle-<version>-<arch>.tar.sig  that bundle's own signature, namespace pi-fortress-dist
  EVALUATION_NOTICE.txt            the evaluation notice
  SHA256SUMS                       sha256sum format, sorted by name
  SHA256SUMS.sig                   ssh-keygen -Y sign, namespace pi-fortress-dist
  allowed_signers                  convenience copy; never trust it for verification
```

`SHA256SUMS` covers each file under the directory, with these exceptions:

- `SHA256SUMS*` itself. The sums cannot hash the file that contains them.
- The bundle `.sig` files. The release writes them after the sums, at signing.
- `allowed_signers`. This copy is a convenience, not evidence. If the sums
  covered it, this would suggest that the download can vouch for its own key.

Each bundle is the tracked tree at HEAD (a `git archive` export, never
the checkout itself). It has `pf` at `vm/pi/pf` and no `bin/`. `make
release` refuses a bundle if one of these is true:

- It fails `pf ship lint` or `internal/secretscan`.
- It has no `vm/pi/pf`, the binary that `install.sh` runs.

The lists of the operator (`PI_OWNED` in the Makefile) ship as seeds. Thus, an
upgraded box keeps its own copies (`gateway_install.md`, "Where the lists live").
`release.sh` refuses to build a bundle without that list. Thus, run it through
`make release`.

`install.sh` fetches one bundle, its own `.sig`, `SHA256SUMS`
and `SHA256SUMS.sig`. It installs the bundle only when the signed
`SHA256SUMS` lists its sha256 under exactly `pf-bundle-<tag>-<arch>.tar`.
The asset name binds a bundle to its tag and arch. Thus, keep the
name as it is. `pf upgrade -version` does the same. `make release`
also signs and verifies each bundle. Upload each `.sig` with its bundle,
and both `SHA256SUMS` files. `pf install` keeps the `PF_RELEASE_URL` that it installed
from in `/etc/pi-fortress/release.url`. `pf upgrade -version
<tag>` reads that file (`gateway_install.md`).

Appliance images (a build option, not part of a public release) join the release when `release.sh` writes them
into `dist/<version>/`. It does this between `build` and `sums`. `scripts/appliance.sh` writes them with `VBoxManage export`
as an OVA pair. `pf ship bundle` writes each bundle tar in lexical order, with the commit time as the mtime of each entry.

## Pinned inputs

- Toolchain: `toolchain` in `go.mod`, `GOTOOLCHAIN=local`. The build fails if `go env GOVERSION` is different.
- Modules: `-mod=vendor`, `GOPROXY=off`, `GOWORK=off`. Not `-mod=readonly`: that mode resolves from the module cache and can fetch. The supply-chain rule of the Makefile forbids fetches.
- Environment: `GOENV=off` (no user `go env -w`), `CGO_ENABLED=0`, `GOAMD64=v1`, `GOARM64=v8.0`, empty `GOEXPERIMENT`.
- Flags: `-buildmode=pie -trimpath -buildvcs=true -ldflags "-s -w -buildid= -X …cli.Version"`. VCS stamping stays on. It records only commit, commit time and a clean flag. Backup manifests read the revision.
- Source: a clean tree at one commit. If there are uncommitted or untracked files, the build refuses to run.

To build a published release again and compare it:

1. Check out its tag.
2. Run `make release-verify`.
3. Run `RELEASE_UNSIGNED=1 make release`.
4. Compare `dist/<version>/SHA256SUMS` with the published one.

Verified 2026-09-13: two worktree builds plus a third in a separate tree gave identical sums for amd64 and arm64.

## Signing

- Key: `SIGN_KEY` (default `~/.ssh/pi_fortress_release`), shared with the Pi ship flow in `signed_ship.md`.
- Namespace `pi-fortress-dist`. Pi ship bundles use `pi-fortress-release`. `ssh-keygen -Y verify` binds the namespace. Thus, one signature never verifies as the other. `allowed_signers` also carries `namespaces="pi-fortress-dist"`.
- Principal `release@pi-fortress`.
- No key: `make release` fails before it builds. `RELEASE_UNSIGNED=1` builds unsigned with a loud warning. Never publish that directory.

Key custody: use an `ed25519-sk` key on a hardware token that requires a touch
(`ssh-keygen -t ed25519-sk -O verify-required`). Thus, a stolen laptop cannot sign.
Keep a second, offline token enrolled as a backup signer. Publish the
`allowed_signers` line in two locations:

- In `docs/user_guide/verify.md` (and `install.sh`).
- In a second channel under separate control (the release page or a pinned post).

Thus, a swap of one copy does not swap the two copies.
When you rotate the key, publish the new line in the two channels. Sign it with the old key.

## Verifying a download

```
echo 'release@pi-fortress namespaces="pi-fortress-dist" <key from docs/user_guide/verify.md>' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I release@pi-fortress -n pi-fortress-dist \
  -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The two commands must pass. Take the key from `docs/user_guide/verify.md` or the second channel. Never take it
from the download directory.

## Docs site

`docs/user_guide/` is the public manual. [Zensical](https://zensical.org/)
builds it into a static site. A maintainer deploys the site manually to
Cloudflare Pages. Config: `zensical.toml` at the repo root. The Makefile pins
the Zensical version (`ZENSICAL_VERSION`). Thus, a build today and a build
next month render the same way.

```
make docs                              # build into build/docs/, fail on any warning
wrangler login                         # once per machine, opens a browser
DOCS_PROJECT=<project> make docs-push  # wrangler pages deploy, direct upload
```

`docs-push` first runs `release.sh placeholders` (above) and
`scripts/leak_check.sh`. If one of them fails, it stops. An agent never runs it. A maintainer logs in to Cloudflare and
pushes it. There is no GitHub integration. Each push is a manual
`wrangler pages deploy` from a built tree.

This is phase 1: one version, no history. Phase 2 plan:

1. A `mike` fork writes a local `gh-pages` branch without `--push`.
2. `docs-push` deploys the tree of that branch, not `build/docs/` directly.

This gives versioned docs and does not change the deploy step.
