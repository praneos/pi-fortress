# Installer: from rsync loop to a thing a stranger can install

Status: replaced by `docs/gateway_install.md`. `pf install` and `pf upgrade` exist now. But they use a bundle-per-arch design: `pf-bundle-<ver>-<arch>.tar` + `.sig`, with `Extract` from `internal/ship`. They do not use the original design of this file below (`go:embed`, `--agent-if`, `.deb`). Nothing implements that design. This file keeps it only as the earlier record. There are no binary releases before v1, so the download URLs below do not exist.

Read `gateway_install.md` first. It tells how a box gets installed today. Come back here for the tier-2 and tier-3 ideas (`.deb`, Pi image) that it does not cover yet.

One difference is important when you read the plan below. On an installed box, the lists of the operator are not in `/etc/pi-fortress`. They are in `/opt/pi-fortress/vm/policy`, the tree that apply compiles from. They ship as seeds, and the copy on the box overrides the seeds (`gateway_install.md`, "Where the lists live").

The rest of this document is the earlier plan. Nobody built it:

## Where we are

Today, a Pi gets Pi Fortress with these steps:

1. `make split-bin GOARCH=arm64`.
2. `rsync` the full repo to `/opt/pi-fortress`.
3. Symlink `/vagrant`.
4. Run `provision.sh` from the symlink.

Eighteen Go call sites and all shell scripts probe `/vagrant/...` first. They probe `/etc/pi-fortress` or `/usr/local/lib/pi-fortress` second. That is a dev loop, not a distribution. A second user needs the repo, Go 1.27, `make`, and this document.

The binary is already the easy part. `pf` is one file (`CGO_ENABLED=0`, `-buildmode=pie -trimpath -ldflags '-s -w'`). It links no shared library. It needs only the dynamic loader of the OS, which loads its code at a random address. The problem is everything *around* the binary. These files are in many locations:

- six systemd units
- `apply.sh` and `status.sh`, which `pf apply` / `pf status` exec
- the agent `setup.sh`
- the default policy files (`core.hosts`, `allow.domains`, `key_prefixes.rules`, `blacklist.*`, `never_block.*`, `doh.*`, `sources.json`)

## The one change that makes everything else simple

**Embed the surroundings in the binary.** Use `go:embed` to put those files into a package. Add `pf install`. Then the binary is its own installer:

- There is one file to copy.
- There is one command to run.
- The dev loop becomes only "build, scp, `pf install`".

`go:embed` cannot read files above the package directory. Thus, the files move to this tree:

```
assets/
  embed.go                  package assets; //go:embed units scripts policy agent
  units/*.service           from vm/pi/*.service
  scripts/apply.sh status.sh lib/netman.sh   apply.sh sources lib/netman.sh; ship it beside it
  policy/*                  defaults: core.hosts allow.domains key_prefixes.rules
                            blacklist.* never_block.* doh.* sources.json
  agent/setup.sh routes.sh
```

`vm/pi` keeps `net.env`, `provision.sh`, and the Vagrant-only parts. `provision.sh` becomes only "apt + pf install --lab". The paths in `Vagrantfile` and `vm/bin/*.sh` change. Nothing else in `vm/` changes.

### `pf install`

```
sudo pf install --agent-if eth0 --pi-ip 10.77.0.1/24 [--dns 9.9.9.9] [--lab] [--no-apt] [--no-nm]
```

These are the steps. Each step is idempotent:

1. `apt-get install nftables dnsmasq conntrack ca-certificates curl`, unless `--no-apt` is set. The `.deb` path already declared these packages.
2. Group `pf-fortress`, users `pf-broker` and `pf-engine`. This step moves out of `apply.sh`.
3. Directories: `/etc/pi-fortress`, `/usr/local/lib/pi-fortress`, `/var/lib/pi-fortress`, `/var/log/pi-fortress`.
4. Write the embedded units to `/etc/systemd/system/pi-fortress-*.service`. Write the scripts and agent files to `/usr/local/lib/pi-fortress`. Always overwrite these files, because they are code.
5. Write the embedded policy defaults to `/etc/pi-fortress` **only if they are absent**. These files are config, so the edits of the operator win. Print the defaults that this step skipped, so that drift is visible. `pf install --diff-policy` shows the embedded files against the installed files.
6. Write `/etc/pi-fortress/net.env` from the flags (`PI_IP`, `AGENT_NET`, `DNS_UPSTREAM`). `--lab` also writes the `VBOX_*`/`AGENT_IP` keys and touches `/etc/pi-fortress/lab`.
7. Unless `--no-nm` is set, run `nmcli con add type ethernet ifname <agent-if>
   con-name agent-net ipv4.method manual ipv4.addresses <pi-ip>
   ipv4.never-default yes ipv6.method disabled`. This is the manual nmcli step. The tool does it, not the human. Skip this step when a connection already owns that interface.
8. The `provision.sh` hardening that landed today moves here, as Go or as an embedded `harden.sh`. The guards stay the same. The hardening is:
   - sysctls
   - an sshd drop-in, guarded by `authorized_keys`
   - Bluetooth off
   - unattended-upgrades
9. `pf apply`. Then `systemctl enable --now` the units.
10. Print these items:
    - the detected interfaces
    - the CA fingerprint
    - the agent lines, with the two hashes filled in (getting_started §2). These lines fetch `setup.sh`, `sha256sum -c` it, and run it with `<pi-ip> <ca.pem sha256>`.

`pf uninstall [--purge]` does these steps:

- Stop and remove the units.
- `nft delete table inet fortress`.
- Restore `/etc/dnsmasq.conf` if we made a backup of it.
- Remove the apt hook `/etc/apt/apt.conf.d/60pi-fortress-ca` and `/var/lib/pi-fortress/ca-bundle.sha256`. If the hook stays, it does nothing when the script is gone.
- Remove `/usr/local/lib/pi-fortress`.

`--purge` also removes `/etc/pi-fortress`. This deletes the secrets and the CA. Thus, the command must say so. It must also require the flag two times or a typed confirmation. Without `--purge`, an uninstall/install round trip keeps all slots.

`pf version`: `-ldflags "-X pi-fortress/internal/cli.version=$(git
describe --tags --always)"`. `pf status` prints the version. `pf install` refuses a downgrade unless `--force` is set.

### Kill the `/vagrant` probes

After this change, the binary embeds the assets, and `pf install` writes `/etc/pi-fortress` and `/usr/local/lib/pi-fortress`. Then each `firstFile("/vagrant/...", ...)` becomes one fixed path. The lab VM runs the exact production layout, because its provisioner is `pf install --lab`. Delete the fallbacks in `www`, `admin`, `alert`, `observe`, `daemons.go`, `apply.sh`, `routes.sh`, `setup.sh`.

## Delivery: how the binary gets to the Pi

There are three tiers. Do the first two tiers. Do the third tier only when there is a second user.

### Tier 1: GitHub Release with a verifiable binary

`make release` cross-builds `pf-linux-arm64` (Pi) and `pf-linux-amd64` (lab, cloud). The build is reproducible: `-trimpath`, `CGO_ENABLED=0`, the Go version pinned in the `go.mod` `toolchain`, and no cgo. Thus, anyone can rebuild and get the same hash. Publish the binary, `SHA256SUMS`, and a signature.

For the signature, select one of these methods, not both:

- `ssh-keygen -Y sign -f ~/.ssh/pf_release -n pi-fortress SHA256SUMS` on the desktop. The Pi verifies with `ssh-keygen -Y verify` against an `allowed_signers` line that is fixed in `install.sh`. This needs zero new tools, because OpenSSH is on all Pis. Start with this method.
- GitHub artifact attestations: build in Actions, then `gh attestation
  verify pf-linux-arm64 --owner <org>`. There is no key to keep. But the Pi must have `gh`.

The bootstrap script is `install.sh`. It is in the repo, and the release serves it:
`curl -fsSL https://github.com/<org>/pi-fortress/releases/latest/download/install.sh | sudo bash -s -- --agent-if eth0`.

The script does these steps:

1. Download the binary, the sums, and the signature.
2. Verify them.
3. `install -m 0755` to `/usr/local/sbin/pf`.
4. `pf install "$@"`.

The trust anchor is GitHub over TLS, plus the pinned signer key in the script. All `curl | bash` installers have the same anchor. But our installer also verifies a signature after the TLS hop.

This also answers a finding from a hardening review:

- A sha256 from the same desktop that built the binary proves nothing.
- A signature from a key that never leaves the desktop is proof.
- The Pi can check that signature before `install` touches root.

### Tier 2: a `.deb`

The Pi runs Debian. A package gives us these items:

- dependency resolution
- atomic upgrade
- `conffiles` semantics for `/etc/pi-fortress`
- `apt remove`

Build the package with `nfpm` from `make deb`. `nfpm` is in Go and uses one YAML file. It needs no Debian toolchain, and it gives cross-arch builds at no cost:

```yaml
name: pi-fortress
arch: arm64            # and amd64
depends: [nftables, dnsmasq, conntrack, ca-certificates, curl]
contents:
  - src: bin/pf-linux-arm64
    dst: /usr/local/sbin/pf
scripts:
  postinstall: packaging/postinst   # pf install --no-apt --no-nm; needs net.env or it prints the install command and exits 0
  preremove:   packaging/prerm      # pf uninstall
```

All other files come out of the binary at postinst. Thus, the package list stays one line.

- To install, run `sudo apt install ./pi-fortress_*.deb`. Then, the first time, run `sudo pf install --agent-if eth0`. Postinst cannot guess the agent NIC.
- To upgrade, `apt install` the new `.deb`. Postinst runs `pf install` again with the existing `net.env`. Then the units restart.

`secrets.env` and the CA are never in the package.

An apt repository (`deb [signed-by=...] https://.../pi-fortress stable
main`) is one more `reprepro` or `aptly` step. Add it only when unattended-upgrades should carry Pi Fortress itself.

### Tier 3: a Pi image

A `pi-gen` stage bakes an image with these parts:

- Pi OS Lite
- the `.deb`
- a first-boot `pf install` that reads `/boot/firmware/pi-fortress.env`

The operator edits this one file on the SD card from any laptop, like the `custom.toml` of Imager. This is what "distribute" means for a non-technical buyer. Do not start tier 3 before tier 2 survives one real upgrade.

## Order of work

1. `assets/` + embed + `pf install` + `pf uninstall` + `pf version`. The Vagrant provisioner becomes `pf install --lab`. Delete the `/vagrant` probes. This is the largest part: two to three days. This time includes the move of the `provision.sh` hardening.
2. `make release`, `install.sh`, ssh signing, and a new Pi setup guide for this method. Half a day.
3. `nfpm` `.deb`, postinst/prerm. Half a day.
4. An `itest` SSH target, so that `make lab-test
   PI=pi-fortress.local` runs the canaries against the output of the installer. That is the acceptance test for all of the above.

## What not to do

- Do not ship the repo. Policy defaults are inputs to the binary. They are not a directory tree that the user maintains.
- Do not `curl | bash` without a signature check. We accept the HTTP `setup.sh` on the agent side only because the wire is a direct cable. The Pi installer runs as root on the enforcer.
- Do not port `apply.sh` to Go in the same change that embeds it. First embed it and ship. Then port the nft/dnsmasq templating when the cloud work needs a second platform in any case.
