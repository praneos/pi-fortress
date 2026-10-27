# Gateway install: a Pi, or a plain Debian/Ubuntu box

Pi Fortress has no binary releases yet. Release builds start at v1, when the project is stable. Until then, install from source at the latest stable tag: refer to [Install from source](#install-from-source) below and the README. A source install uses the same `install.sh`, `pf install` and `pf upgrade -bundle` that this page describes. The download paths (`install.sh` with no `PF_BUNDLE`, `pf upgrade -version`) apply from v1.

From v1, the releases are at <https://github.com/praneos/pi-fortress/releases>. Each release has:

- one bundle for each arch, `pf-bundle-<version>-<arch>.tar`, each with a `.sig`
- the signed `SHA256SUMS` (`release.md`)

`install.sh` fetches and verifies a bundle from there. Or, with `PF_BUNDLE`, it installs a bundle that is already on the box. `user_guide/pi_setup.md` gives the hardware and the cables.

## Supported targets

| Arch | OS |
|---|---|
| arm64 | Raspberry Pi OS Lite 64-bit, bookworm or trixie. Real hardware: `/proc/device-tree/model` must say Raspberry Pi. Reason: the `/etc/os-release` of Pi OS is byte-for-byte the same as that of Debian. |
| amd64 | Debian 12 or 13, or Ubuntu 24.04 |

`install.sh` refuses all other targets. `pf install` refuses them again (`internal/install/target.go`). Each prints the detected arch/OS. It does not guess.

## Install

```
# from v1, the newest release from GitHub:
curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install.sh | sudo bash
# from v1, one release tag, from the script of that tag:
V=v1.2.3
curl -fsSLO https://raw.githubusercontent.com/praneos/pi-fortress/$V/install.sh
sudo PF_VERSION=$V bash install.sh
# from v1, with the interfaces already known (no questions, no terminal needed):
curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install.sh | sudo bash -s -- -wan eth0 -agent eth1
# offline, from a bundle, its .sig, SHA256SUMS and SHA256SUMS.sig already on the box (also the source install):
sudo PF_BUNDLE=./pf-bundle-v1.2.3-arm64.tar bash install.sh
```

With no `PF_VERSION`, `install.sh` asks GitHub for the newest release tag (`/releases/latest`). The signed `SHA256SUMS` binds the bundle to that tag. `PF_RELEASE_URL` names a different release server; then `PF_VERSION` is necessary. A minimal image may not have `curl`: `sudo apt-get install -y curl`.

`pf install` refuses an agent or house port that carries your SSH session now (a VLAN on it included). The install gives that port a new address, so the session would stop part-way. Connect over the uplink, for example Wi-Fi.

`install.sh` downloads these files:

- `$PF_RELEASE_URL/$PF_VERSION/pf-bundle-$PF_VERSION-<arch>.tar`
- its `.sig`
- the `SHA256SUMS` and `SHA256SUMS.sig` of that release

This is exactly the GitHub `releases/download/<tag>/<asset>` layout.

With `PF_RELEASE_URL`, `PF_VERSION` is necessary. It must be a tag (letters, digits, `. _ + -`). The name of an asset contains its tag, so there is no fixed "latest" path.

`PF_RELEASE_URL` must be `https://`. `install.sh` refuses all other values before a download. curl runs with `--proto '=https' --proto-redir '=https' --tlsv1.2 --fail`, so a redirect to plain http also fails. There is no http override. The tests serve the release through a fake `curl`.

All arguments go directly to `pf install`. `install.sh` does these steps:

1. Refuses a run that is not as root, an unsupported arch, and an unsupported OS, as above. Each refusal has a clear message.
2. Refuses a run with no terminal, if its arguments do not answer the interface questions. This refusal comes before any download. `pf install` asks on `/dev/tty`. Without a terminal, only `-wan` and `-agent` together, or `-yes`, can answer. A piped run works (`curl ... | sudo bash -s -- -wan eth0 -agent eth1`). The script is one function, and its last line calls that function. Thus, a download that stops early runs nothing.
3. Verifies the release in this sequence:
   1. It verifies `SHA256SUMS` with `ssh-keygen -Y verify` against the `pi-fortress-dist` key that `docs/user_guide/verify.md` publishes. The script embeds this key as `PF_SIGNER_PUBKEY`. You can override it for key rotation, as in "publish the new line signed by the old key" in `release.md`.
   2. It requires that the sha256 of the bundle is the one that `SHA256SUMS` lists under exactly `pf-bundle-<tag>-<arch>.tar`. The tag is the requested tag. The arch is the arch of this box.
   3. It verifies the `.sig` of the bundle.

   The `.sig` alone proves only that the key signed those bytes one time. The name in the signed sums binds the bytes to the tag and arch. Thus, `install.sh` refuses an old signed bundle, or the bundle of the other arch, served under this name.

   An offline `PF_BUNDLE` takes the tag from its file name. This name must be `pf-bundle-<tag>-<arch>.tar` for this arch. It must also match `PF_VERSION`, if set. `SHA256SUMS` and its `.sig` must be next to the bundle or at `PF_SUMS`.
4. Extracts `vm/pi/pf` of the bundle from the verified tar. A `make release` bundle has no `bin/`. For an older `make pi-bundle` tar, the script falls back to `bin/pf`. Then it runs `pf install -bundle ... -sig ... -signers ...`. All steps after this point are Go (`internal/install`), not shell. The stdin of `pf install` is `/dev/null`.

**Limit:** this gives no rollback protection on a fresh box. A box with nothing installed has no version floor and no trusted clock. Thus, `install.sh` installs exactly the tag that it gets, signed and bound. It does this also if that tag is old and has known holes. Find the newest tag first: on the Releases page from v1, or with `git tag` for a source install. After the install, the floor refuses older bundles.

`pf install` runs as root and is idempotent. It does these steps:

1. Checks the OS/arch again. Copies the bundle and its `.sig` one time into the root-only `/var/lib/pi-fortress/install-work/`. Verifies that copy again against the signer file from install.sh. All later steps read the copy. They never read the `-bundle` path again. Thus, a file that changes after verification cannot be the file that `pf install` extracts or publishes.
2. Runs the interface wizard, before it writes anything (`ip -j link` / `route show default`):
   - It proposes the WAN from the default route, or it takes `-wan`.
   - It proposes the agent NIC from the other hardware ports. A hardware port has `link_type ether`, a `/sys/class/net/<if>/device` link, and no `bridge`, `tun_flags` or `master` entry there. Thus, the wizard never offers docker0, `br-*`, `virbr*`, veth, tun/tap, VLAN children, `vnet*`, macvtap, or a port that is already in a bridge or bond.
   - It makes the agent proposal against a pinned `-wan`.
   - With both `-wan` and `-agent`, it asks nothing.
   - With `-yes`, it prints the proposal and accepts it.
   - In all other cases, it asks on `/dev/tty`, never on stdin. Under `curl | sudo bash`, stdin is the script. An optional third prompt asks for the house NIC.
   - With no terminal, or at end of input at a prompt, it refuses and names `-wan`, `-agent` and `-yes`. It never gives a silent yes.
   - It refuses an uplink that is also the agent (or house) interface. This refusal comes before it writes the signer file, `net.env.local`, `gateway.role` or the floor.

   Then it keeps two files for `pf upgrade`:
   - The signer file, as `/etc/pi-fortress/release-signers`. This is not the `allowed_signers` of `signed_ship.md`. Refer to "Two signers, on purpose" below.
   - The `PF_RELEASE_URL` of the download, as `/etc/pi-fortress/release.url`. An offline `PF_BUNDLE` install has no URL. It does not change an existing `release.url`.

   Then it writes `/etc/pi-fortress/net.env.local` (`INT_IF`, `WAN_IF`). If it has a house NIC, it also writes `/etc/pi-fortress/house.env`: `HOUSE_IF` plus the `10.78.0.0/24` defaults that `house.env.example` ships. On a fresh box, it makes `/etc/pi-fortress`. The tool does these steps in place of the nmcli command and the copy-and-edit step of a manual setup. It upserts existing files. It does not truncate them. Thus, the other keys of an operator survive a second run.
3. Deletes `/etc/pi-fortress/lab` if it is present, because a release install is never a lab box. Writes `/etc/pi-fortress/gateway.role`. `apply.sh` refuses a host that is not a Raspberry Pi, a lab VM or the appliance, unless that file is there. Thus, this file lets a Debian or Ubuntu amd64 gateway apply, the first time and each later time.
4. Extracts the verified copy into a scratch tree under `/var/lib/pi-fortress/install-work/`. It uses `ship.Extract`: the same manifest and per-file check that `pf ship install` uses. The only purpose is to give `vm/pi/provision.sh` a real tree. provision.sh runs against this tree with `PF_ALLOW_ANY_HOST=1` and `PF_SHIP_APPLIES=1`. provision.sh handles these items:
   - the apt packages (`nftables dnsmasq wireguard wireguard-tools curl tcpdump iproute2 ca-certificates dnsutils conntrack usb-modeswitch logrotate rsync python3 chrony network-manager`)
   - the policy defaults. A list that the operator owns (`PI_OWNED` in the `Makefile`, for example `allow.domains`, `dns_types.allow`, `git_push.allow`) is written to `/etc/pi-fortress` only when it is absent. Thus a second run of provision.sh keeps the edits of the operator. The shipped lists (`core.hosts`, `doh.ips`, `doh.domains`, `key_prefixes.rules`) are replaced, as a ship replaces them. The operator lines of each are in its `.local` file (`core.hosts.local`, `doh.ips.local`, `doh.domains.local`, `key_prefixes.rules.local`), which provision.sh does not write.
   - the `pfship` user plus the ship units. The `pfship` user gets a key only when `/etc/pi-fortress/pfship.pub` is present (`signed_ship.md` Setup).

   provision.sh already does all of this idempotently. Thus, `pf install` uses it again, and does not add a second apt-get line. `PF_SHIP_APPLIES=1` makes provision.sh skip its own `pf apply`. Reason: the scratch tree is not the tree that will be live. The first apply is the one that `pf ship install` runs in step 5. apply.sh makes the `pf-broker`/`pf-engine`/... users itself, so `pf install` does not. `pf install` discards the scratch tree after provision.sh runs.
5. Puts the verified copy into a fresh incoming directory. Runs `pf ship install -namespace pi-fortress-dist -principal release@pi-fortress -pending-file ""` against it. The Installer of internal/ship then:
   - Does the real publish. There is no live `/opt/pi-fortress` yet, so its swap step is a plain rename, with no `.prev`.
   - Writes the version floor.
   - Runs `pf apply` and `pf doctor --post-upgrade`.

   The box has no `/vagrant`. Thus, `apply.sh` reads its policy, units and `pf` from the tree that it ships in, `/opt/pi-fortress`. That apply runs the version that the Installer just published. `-pending-file ""` skips the arm step of the confirm-or-revert timer. Reason: a first install has no previous tree to revert to.

You can run `pf install` again with the version that is already installed. Then it saves the answers of the wizard and applies again. It runs `pf apply` and `pf doctor --post-upgrade` of the live tree. It does not run `provision.sh`, and it does not publish again. Use this to finish a first install if its apply or doctor failed: fix the cause and run the same command again.

If the floor names a version that is not the version of the tree at `/opt/pi-fortress`, `pf install` refuses. The refusal tells you what to do instead: `pf upgrade -version`, or `pf rollback` when the floor version is the release before the version of the live tree. `pf install` refuses a bundle below the floor as a downgrade.

## Where the lists live

A `pf install` box has no `/vagrant`. `apply.sh` compiles from the tree that it runs in: `/opt/pi-fortress/vm/policy`. The TUI, `pf fetch`, `pf backup`/`pf restore` and `pf status` resolve the same directory. Thus, a block or a revocation from the operator goes where apply reads it. `base.PolicyDir` selects the directory in this sequence:

1. `/vagrant`, only when it holds `vm/pi/net.env` and `vm/policy`.
2. `/opt/pi-fortress`, only when it holds `vm/pi/net.env` and `vm/policy`.
3. Else, `/etc/pi-fortress`.

`PI_FORTRESS_POLICY` overrides this selection.

apply writes copies under `/etc/pi-fortress` (`core.hosts`, `allow.domains`, `git_push.allow`, ...). These copies are its output. They are not a place to edit. The installed `core.hosts` is the shipped one, with `core.hosts.local` appended under a marker line. The installed `key_prefixes.rules` is made in the same way from `key_prefixes.rules.local`. `pf compile` reads `doh.ips.local` and `doh.domains.local` next to the shipped DoH lists. The operator edits the local files.

All bundles ship the operator-editable lists as seeds. These are the `PI_OWNED` lists of the Makefile: `blacklist.*`, `never_block.*`, `direct_ip.allow`, `house.domains`, the `house_*` lists, `ssh_allow.ips`, `ntp_pass.ips`, `allow.domains`, `git_push.allow`, `dns_types.allow`, `core.hosts.local`, `key_prefixes.rules.local`, `doh.ips.local`, `doh.domains.local`, `sources.json`. If the box has its own copy of a list, `pf ship install` (and thus `pf upgrade`) carries that copy over the shipped one. It merges new feeds into `sources.json` (`fetch.MergeSeed`). The cost: a seeded list never takes an upstream change on a box that already has that list. `make release` refuses to build without the seed list.

The lists stay across a rollback in the same way as across an upgrade. These operations copy the lists of the live tree over the lists of `.prev` before they swap `.prev` back:

- `pf rollback`
- a dead-man revert
- the restore after a failed apply or a failed post-upgrade doctor

They also remove from `.prev` a list that the operator deleted. Thus, an edit or a revocation after the upgrade survives. If that copy fails, the rollback does not occur, and it says so. It does not go back to the older lists.

## Upgrade

Until v1, there is no release to download. A source install uses `-bundle` (README, "Update from source").

```
sudo pf upgrade -version v1.3.0       # from v1; base from PF_RELEASE_URL or /etc/pi-fortress/release.url
sudo pf upgrade -bundle ./pf-bundle-v1.3.0-arm64.tar -sig ./pf-bundle-v1.3.0-arm64.tar.sig   # SHA256SUMS(.sig) beside it, or -sums
sudo pf upgrade -confirm              # disarm the dead-man timer (pf ship confirm)
```

`pf upgrade` does these steps:

1. It builds `<base>/<version>/pf-bundle-<version>-<arch>.tar` (and `.sig`).
2. It downloads both, plus the `SHA256SUMS` and `SHA256SUMS.sig` of the release, over https only. The files go into a fresh root-only `/var/lib/pi-fortress/upgrade/<unique>/`.
3. It binds and verifies them against `release-signers` exactly as `install.sh` does. `VerifyRelease` checks `SHA256SUMS.sig`, one entry for `pf-bundle-<tag>-<arch>.tar`, its sha256, then the `.sig` of the bundle.

`-bundle` follows the `PF_BUNDLE` rule of `install.sh`:

- The name is `pf-bundle-<tag>-<arch>.tar` for this arch.
- The name matches `-version`, if given.
- `SHA256SUMS` and its `.sig` are next to the bundle or at `-sums`.

`pf upgrade` first copies all four files into the incoming directory. It checks and stages only the copies. A refusal comes before `pf ship install` runs.

Then it runs exactly `pf ship install -incoming <unique dir> -signers release-signers -namespace pi-fortress-dist -principal release@pi-fortress -dir /opt/pi-fortress`. It runs this command under `systemd-run --unit=pf-upgrade-<unique> --wait --collect`. If `systemd-run` is missing, it falls back to an inline run with a warning.

`pf upgrade` itself no longer stages, swaps or applies anything. The wrapped `pf ship install` call is the same command that a desktop ship push runs. Thus, an upgrade gets these items from it:

- the stage/swap (`renameat2` exchange)
- the floor
- `pf apply`
- `pf doctor --post-upgrade`, with rollback on failure
- the confirm-or-revert pending file
- the `releases/`+`state.version` bookkeeping

No code of `pf upgrade` duplicates these items (`internal/install/upgrade.go`, `internal/ship/install.go`).

There is no network wizard, and `provision.sh` does not run again. Reason: an upgrade changes code and policy defaults, not interfaces or apt packages. `-confirm` still execs `pf ship confirm`.

The OS hardening files are not only in `provision.sh`. They are in `vm/pi/lib/harden.sh`, and each full `pf apply` writes them again. Thus an upgraded box gets the files of the new release, the same as a fresh install:

- the sysctl file `/etc/sysctl.d/99-pi-fortress.conf`. apply sets its values at once, except `ip_forward`: apply enables forwarding only after it loads the ruleset.
- the unattended-upgrades config `/etc/apt/apt.conf.d/20auto-upgrades` and `52-pi-fortress-upgrades`. The origins in `52-pi-fortress-upgrades` follow `ID=` in `/etc/os-release`: on Ubuntu, the Ubuntu security pocket and the ESM security pockets; on Debian and Raspberry Pi OS, the Debian security origins and the Raspberry Pi origin.
- the key-only sshd drop-in `/etc/ssh/sshd_config.d/99-pi-fortress.conf` (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin no`). The same file sets `MaxAuthTries 5`, `LoginGraceTime 30`, `MaxStartups 10:30:60`, `ClientAliveInterval 120` and `ClientAliveCountMax 3`. It sets `AllowTcpForwarding local`: `ssh -J` (ProxyJump) through the gateway works, `ssh -R` does not. It turns off agent, Unix-socket, X11 and tunnel forwarding, `GatewayPorts`, `PermitUserEnvironment` and `Compression`. apply writes it only when a user under `/home` has a usable login key: `~/.ssh/authorized_keys` holds a key that `ssh-keygen -l` reads and that has no forced command, and the home, `.ssh` and the file are not writable by group or other (sshd ignores the key if they are). apply checks the new file with `sshd -t` before it reloads sshd. If `sshd -t` fails, apply puts back the old file (or none) and warns. With no usable key, apply changes nothing and warns that password login is on. Thus a box that had no key at install time turns password login off at the first apply after the operator adds a key. If `sshd -T` still shows `passwordauthentication yes` (a file that sorts before ours sets it), apply warns.

apply writes a file only when its content changes. apply installs no package. If `unattended-upgrades` is not installed, apply prints a warning. Install the package with `apt-get install unattended-upgrades`.

`pf doctor` has an `ssh` rung. It reads `/etc/ssh/sshd_config` and the files that it includes, and warns while sshd takes passwords. The rung does not need root. It is a best-effort parse: if it cannot read a file, or a `Match` block turns passwords on for some logins, it says that the result is inconclusive. `sudo sshd -T` gives the exact value.

### OS packages and reboots

`pf upgrade` does not update the OS packages. On a fresh install, `provision.sh` enables `unattended-upgrades`. It installs updates each day and does not reboot (`Automatic-Reboot "false"`). Thus a kernel or core library fix is not active until you reboot the gateway.

To install the OS updates at once, run `sudo apt update && sudo apt full-upgrade` after `sudo pf upgrade -confirm`. If you do not, the daily `unattended-upgrades` run installs the security updates. In both cases, reboot when the `reboot` rung of `pf doctor` is `warn` or `FAIL`.

`pf doctor` shows this on rung `reboot`:

- `warn`: `/var/run/reboot-required` is there. The rung shows its age and the packages from `/var/run/reboot-required.pkgs`. Each package that asks for a reboot writes the flag again, so the age is the time since the last request.
- `warn`: the running kernel is no longer installed, or a newer kernel of the same flavor is installed. The rung compares `uname -r` with the directories in `/lib/modules`. A kernel that is installed again with the same release string does not show here; the flag shows it.
- `FAIL`: the flag is older than 7 days.

Plan the reboot: `sudo reboot`. The agents have no gateway while it starts.

A Go daemon reads the system CA roots one time, when it starts. Thus `apply.sh` installs the apt hook `/etc/apt/apt.conf.d/60pi-fortress-ca`. After each dpkg run, it runs `/usr/local/lib/pi-fortress/ca-restart.sh`. When `/etc/ssl/certs/ca-certificates.crt` is different from the last run, the script restarts the running units of pf-broker, pf dns (`pi-fortress-dns-agent-go`, `pi-fortress-dns-stub@*`) and pf alert. The last hash is in `/var/lib/pi-fortress/ca-bundle.sha256` (mode 0600). The hook writes nothing to the terminal and never fails the apt run. The journal tag of a restart is `pi-fortress-ca`.

A broker start locks a sealed credential store again. Thus with a sealed store (`#pf-sealed` header in `secrets.env`, or a store that the script cannot read), the hook does not restart pf-broker. It restarts pf dns and pf alert, and writes the time to `/var/lib/pi-fortress/ca-restart-pending` (mode 0600). While that file is there, `pf doctor` warns on rung `ca`. When you can unlock, run `sudo systemctl restart pi-fortress-broker.service`, then `sudo pf unlock`. Each broker start (also the restart of a `pf apply`) removes the file (`ExecStartPost` in `pf-broker.service`).

## Install from source

This is the install path until v1. The README gives the commands. Build from the latest stable tag (`git tag -l 'v*' --sort=-v:refname | head -1`). First verify the tag with `git verify-tag` against the key in `user_guide/verify.md`. This flow uses the same `install.sh`, `pf install` and `pf upgrade -bundle` as a release. Only the signer is different: your own SSH key, given to `install.sh` as `PF_SIGNER_PUBKEY`. `pf install` keeps that key in `release-signers`. Thus each later `pf upgrade` accepts only bundles that your key signed.

`make release RELEASE_UNSIGNED=1` does these steps:

- It refuses a tree with uncommitted changes, and a Go that is not the `toolchain` of `go.mod` (`GOTOOLCHAIN=local`, so no download).
- It builds the bundles for arm64 and amd64 from a `git archive` of HEAD, into `dist/<version>/`. `<version>` is the tag of HEAD, or `git describe` plus `-dev` (for example `v0.1.3-31-ga40f790bc164-dev`). `scripts/release.sh version` prints it. The directory must be empty. To build the same commit again, remove it first.
- It writes `SHA256SUMS` and does not sign. `make release` signs only with the key that `install.sh` pins. Thus you sign with `ssh-keygen -Y sign -n pi-fortress-dist`, as the README shows. The principal is not in the signature. `install.sh` binds your key to `release@pi-fortress` when it writes the signer file.

The version floor of a bundle is the commit time of HEAD. Thus `pf upgrade` refuses a commit that is older than the installed one.

You can also run the same steps on the Pi itself, with Go 1.27.3 for arm64 installed there. Then there is no `scp`, and `PF_BUNDLE` is `dist/$V/pf-bundle-$V-arm64.tar`. The build is slower, and the signing key is on the box that it protects.

From v1, a box that you installed from a release trusts only the release key. To also accept your bundles, add a second line to `/etc/pi-fortress/release-signers`: `release@pi-fortress namespaces="pi-fortress-dist" <your public key>`. `ssh-keygen -Y verify` accepts a signature from each line.

## Two signers, on purpose

There are two different signer files:

- `/etc/pi-fortress/release-signers`: `pi-fortress-dist` namespace, principal `release@pi-fortress`, `release.md`.
- `/etc/pi-fortress/allowed_signers`: `pi-fortress-release` namespace, principal `release`, `signed_ship.md`.

`pf install`/`pf upgrade` never touch `allowed_signers`.

`ssh-keygen -Y verify` binds the namespace into the signature itself. Thus, a bundle signed for one namespace never verifies against the other.

Each key line in the two files must have the `namespaces=` option of its file: `namespaces="pi-fortress-dist"` in `release-signers`, `namespaces="pi-fortress-release"` in `allowed_signers`. A key on a line with no `namespaces=` option can sign in each namespace. Thus `pf` refuses the file before each verify, `pf install` does not save it, and `provision.sh` does not install it. The error names the file and the line, and tells you which `namespaces="..."` to add.

The use of two files is a policy choice. The public download key may be published anywhere and rotated in the open. It does not get the same trust as a `pfship` push key. A stolen push key would give unreviewed root on all Pis that trust it. A later decision can unify the two files. But that decision is for the owner of both flows. Do not make it here by default.

## Known gaps versus the ship-push path

`pf install` and `pf upgrade` do not stage, swap or apply anything themselves. Both put a verified bundle in a fresh incoming directory. Then both run `pf ship install -namespace pi-fortress-dist -principal release@pi-fortress` against it:

- `internal/install/shipexec.go` builds the args.
- `internal/install/upgrade.go` wraps the call under `systemd-run` for pf upgrade.
- `internal/install/install.go` runs the call directly for pf install. Reason: a first install has no dropped-SSH concern of its own.

That is the same code path that a desktop ship push runs. Thus, the gaps that this section listed before are now closed:

- `renameat2` exchange (`internal/ship/exchange.go`) instead of the two renames of `SwapTree`. `SwapTree` is removed. The swap of `internal/ship` already falls back to a plain rename when `/opt/pi-fortress` does not exist yet. A first install has this case.
- `fetch.MergeSeed` for `sources.json` instead of a plain recursive copy.
- `pf doctor --post-upgrade` with rollback on failure.
- The confirm-or-revert pending file. `pf install` skips it with `-pending-file ""`, because there is no `.prev` to revert to.
- `releases/` retention and the `state.version` gate.

Remaining:

- Nobody has tested `pf rollback` end to end after a `pf install`/`pf upgrade`. It was tested only after a desktop ship push. It swaps `.prev` back in. It needs no signature in either case.
- `pf install` extracts the verified copy two times. The first extraction goes into a scratch tree (`/var/lib/pi-fortress/install-work/`). This gives `vm/pi/provision.sh` a tree to run against. Then the independent extraction of `pf ship install` publishes the real tree. This is two tar passes on a box that does this one time. It is not a correctness issue.

## Open items

1. **Release URL on the box.** `pf install` keeps the `PF_RELEASE_URL` that install.sh downloaded from. It keeps it in `/etc/pi-fortress/release.url`, which `pf upgrade` reads. After an offline `PF_BUNDLE` install, put `https://github.com/praneos/pi-fortress/releases/download` in that file, or export `PF_RELEASE_URL`. Always pass `-version <tag>`.
2. **Bundle signatures.** `install.sh` and `pf upgrade` verify `SHA256SUMS.sig`, the entry of the bundle in it, and the `.sig` of the bundle. On an installed box, the version floor also refuses an older bundle. A manual `pf install -bundle` checks only the `.sig`, because its caller selected the file. `make release` signs each bundle and checks the signature. Upload each `pf-bundle-*.tar.sig` with its bundle, and `SHA256SUMS` with `SHA256SUMS.sig`. If not, nobody can install the bundle from a URL. `pf upgrade` accepts only an `https://` release URL. It follows no redirect to anything else.
3. The bundle layout is the full tree, with `pf` at `vm/pi/pf`. `make release` builds it from a `git archive` of HEAD, so no ignored file goes in. It omits `bin/`. It refuses a bundle without `vm/pi/pf`. `install.sh` runs that binary, or `bin/pf` from an older `make pi-bundle` tar. If the layout changes, two items must change with it: the extraction in `install.sh`, and the `vm/pi/provision.sh` call in `pf install`.
4. Test coverage: unit tests (`internal/install/*_test.go`), `bash -n`, `shellcheck`, the refusal cases for `install.sh` in `scripts/shell_test.sh`, and the `lifecycle` e2e group of the cloud lab (`cloud_lab.md`). A real Pi run of the same group is the last gate.

## Tests

- `internal/install`:
  - OS/arch detection against `/etc/os-release` fixtures (`target_test.go`).
  - Interface proposal against fake `ip -j` JSON (`iface_test.go`). Virtual interfaces, the sysfs hardware test against a fake `/sys/class/net`, and a pinned `-wan` are in `install_test.go`.
  - `pf install` itself with a throwaway signer (`install_test.go`):
    - It refuses a bad signature, an http release URL and an uplink-as-agent before it writes anything.
    - It refuses a downgrade.
    - It applies the same version again.
    - It runs provision before ship.
    - A `-bundle` that changes after verification never reaches `pf ship install`.
    - The wizard asks on its terminal. It refuses with no terminal, and it refuses at end of input.
  - `net.env.local`/`house.env` upsert, and refusal of an http `release.url` (`netenv_test.go`).
  - Upgrade URL building, and refusal of an http `PF_RELEASE_URL` and an http redirect (`upgrade_test.go`). Refusal of a path-shaped `-version` (`upgrade_bind_test.go`).
  - The `SHA256SUMS` binding against a fake release over `httptest` (`upgrade_bind_test.go`):
    - The right tag and arch pass.
    - These cases refuse and leave nothing behind:
      - the bundle of the other arch
      - the bundle of an old tag, with or without its own `SHA256SUMS`
      - a list that does not have the name, or that has it two times
      - a foreign-signed or missing `SHA256SUMS` or `.sig`
      - a foreign bundle `.sig`
    - `-bundle` gives the same results. It also stages a copy, not a link.
  - A signature-failure refusal against an `httptest` server that signs with the wrong key (`upgrade_test.go`). With `Wrap` faked: `doUpgrade` puts a verified bundle in a fresh incoming directory and gives `pf ship install` exactly `ShipInstallArgs`. It cleans the directory after. It never wraps on a bad signature (`upgrade_test.go`).
  - `ShipInstallArgs`, `NewIncomingDir` (fresh, 0700, different for each call) and `PlaceBundle` (`shipexec_test.go`).
- `internal/ship`: a bundle is signed under one namespace/principal. The Installer refuses it when its `Namespace`/`Principal` fields name a different one. The Installer accepts it when they match (`TestInstallNamespacePrincipal`, `install_test.go`). This mechanism keeps `pi-fortress-dist` and `pi-fortress-release` apart.
- `install.sh`:
  - `bash -n` and `shellcheck`, through `scripts/shell_test.sh`. That script globs all `.sh` files.
  - Behavioural cases in that same script: an unsupported architecture, an unsupported OS, and a missing `PF_RELEASE_URL` with no `PF_BUNDLE`. `PF_TEST_UNAME_M`, `PF_TEST_OS_RELEASE` and `PF_TEST_SKIP_ROOT` stand in for `uname -m`, `/etc/os-release` and root. `PF_TEST_GUARD_EUID` and `PF_TEST_GUARD_ROOT` of `vm/pi/lib/guard.sh` do the same for `apply_test.sh`, and the guard reads them only with `PF_TEST_HARNESS=guard`.
  - `scripts/install_test.sh` (`shell_test.sh` runs it). It builds two releases with throwaway keys. It serves them through a fake `curl`, under `setsid`, so there is no terminal. Results:
    - The right tag and arch install.
    - The script refuses these cases:
      - the bundle of the other arch
      - the bundle of an old tag, with or without its own `SHA256SUMS`
      - a `SHA256SUMS` that does not list the bundle
      - a `SHA256SUMS` signed by a different key
      - a missing `SHA256SUMS.sig`
      - an http or file URL
      - a path-shaped `PF_VERSION`
    - With no terminal, the script refuses a run with no answers, or with only `-wan`, before any download. `-wan` plus `-agent` installs.
    - The offline path installs with its `SHA256SUMS`. It refuses the name of the other arch, a `PF_VERSION` mismatch and a missing `SHA256SUMS`.
