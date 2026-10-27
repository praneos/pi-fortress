<p align="center"><img src="docs/user_guide/assets/logos/logo.svg" width="120" alt="Pi Fortress logo: a shield with the letter pi, over crossed swords"></p>

# Pi Fortress

Pi Fortress is a Raspberry Pi 5 between your AI coding agent and the internet.
It controls where the agent can connect. It keeps your API keys off the
machine of the agent.

> **Open evaluation.** One command starts the full system in a VM lab,
> with the same end-to-end tests that run on a real Pi 5. Use test keys,
> or keys with a spend limit, while you evaluate.

## Why

A prompt injection in a web page, a README or an MCP tool can make an
agent send your API key to a different location. The agent can disable
controls on its own machine. The agent cannot disable a separate box on
the network cable.

- **The agent never holds a real key.** It holds a placeholder. The Pi
  puts in the real key only for the service that owns that key.
- **The agent reaches only the hosts that it resolved through the Pi.**
  Raw IPs, its own encrypted DNS, IPv6 and QUIC all fail.
- **It does not stop normal work.** npm, docs and web fetch continue to work.
  The Pi blocks known-bad sites. It logs new origin servers for you to review.

The same Pi can also filter your home network. It blocks ads, trackers,
malware and phishing for each phone, laptop and TV. It decrypts nothing
there.

## Lock it down

Enable paranoid mode, and the agent can connect only to the sites on your
allowlist ([FAQ](docs/user_guide/faq.md)). How it compares with proxies,
vaults and sandboxes: [comparison](docs/user_guide/comparison.md). Each
attack that we tested, and its result: [risk model](docs/risk_model.md).

## Try it in a VM lab

The full setup runs as VMs on one Linux host with `/dev/kvm`: the Pi, a
home device, a desktop seat and agents. It has the same end-to-end tests
as a real Pi. You need 8 GB RAM and about 100 GB of disk. The bootstrap
installs KVM, libvirt and Vagrant, and makes its own networks on the
host. Thus, use a machine that you can give to the lab. A cloud VM is
best: Ubuntu 24.04, amd64, nested virtualization on. Run:

```
curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install-lab.sh | sudo bash
```

The script clones this repo and runs `vm/cloudlab/bootstrap.sh --up`.
From a clone that you already have, run that command with `sudo`.

Then follow [Getting started](docs/user_guide/getting_started.md) from
step 2. Details: [docs/cloud_lab.md](docs/cloud_lab.md).

## Install on a Pi 5

Pi Fortress has no binary releases yet. Release builds start at v1, when
the project is stable. Until then, build from the latest stable tag, as
below. The project signs each stable tag.

You need these items ([full list](docs/user_guide/pi_setup.md)):

- A Raspberry Pi 5 with Raspberry Pi OS Lite 64-bit.
- A USB Ethernet adapter.
- A machine for the agent. The only network path of this machine is the Pi.

Connect the Pi to its uplink (for example Wi-Fi), with SSH on. Then
[install from source](#install-from-source). The installer asks which
port is the uplink and which port is for the agent. It refuses to give
the agent the port of your SSH session. Then follow
[Getting started](docs/user_guide/getting_started.md).

Debian 12/13 or Ubuntu 24.04 on amd64 also works. Use the `amd64`
bundle there. Details: [docs/gateway_install.md](docs/gateway_install.md).

### Install from source

You build and sign the bundle on your desktop. Then the Pi verifies it
with your key. You need git, make, Go 1.27.3 (the `toolchain` line of
`go.mod`) and an SSH key.

On the desktop, get the source and find the newest stable tag:

```
git clone https://github.com/praneos/pi-fortress && cd pi-fortress
git tag -l 'v*' --sort=-v:refname | head -1
```

The newest stable tag now is `v0.1.7`. Verify the tag against the key
of the project, then check it out:

```
echo 'release@pi-fortress namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKVK/2pcp/J483O0Q/NvHVZr6jAR3uzMQfTabUh5B96R' > ~/pi-fortress.allowed_signers
git -c gpg.ssh.allowedSignersFile="$HOME/pi-fortress.allowed_signers" verify-tag v0.1.7
git checkout v0.1.7
```

`verify-tag` must print `Good "git" signature for release@pi-fortress`.
Keep the key file outside the clone: `make release` refuses a tree with
files that git does not track. The fingerprint of the key, and why you
take it from this page: [verify the source](docs/user_guide/verify.md).

Then build, sign and install. On a new Pi, run on the desktop:

```
make release RELEASE_UNSIGNED=1
V=$(scripts/release.sh version)
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n pi-fortress-dist dist/$V/SHA256SUMS dist/$V/pf-bundle-$V-arm64.tar
scp install.sh dist/$V/SHA256SUMS* dist/$V/pf-bundle-$V-arm64.tar* <user>@<pi>:
ssh -t <user>@<pi> "sudo PF_SIGNER_PUBKEY='$(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub)' PF_BUNDLE=pf-bundle-$V-arm64.tar bash install.sh"
```

`make release` builds only committed code, here the tag that you checked
out. The Pi trusts the bundle because your own key signed it. After this,
the Pi accepts only bundles that your key signed.

### Update from source

Get the new tags and find the newest stable tag. Verify it and check it
out, as above. Then build, sign and upgrade. In the clone, run:

```
git fetch --tags
git tag -l 'v*' --sort=-v:refname | head -1
git -c gpg.ssh.allowedSignersFile="$HOME/pi-fortress.allowed_signers" verify-tag <tag>
git checkout <tag>
make release RELEASE_UNSIGNED=1
V=$(scripts/release.sh version)
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n pi-fortress-dist dist/$V/SHA256SUMS dist/$V/pf-bundle-$V-arm64.tar
scp dist/$V/SHA256SUMS* dist/$V/pf-bundle-$V-arm64.tar* <user>@<pi>:
ssh -t <user>@<pi> "sudo pf upgrade -bundle pf-bundle-$V-arm64.tar -sig pf-bundle-$V-arm64.tar.sig"
```

Check the box, then run `sudo pf upgrade -confirm` on the Pi within 10
minutes. If not, the Pi rolls back. Details: [docs/gateway_install.md](docs/gateway_install.md#install-from-source).

`pf upgrade` does not update the OS packages. Run
`sudo apt update && sudo apt full-upgrade`, or let the daily
`unattended-upgrades` run install the security updates. Reboot when
`pf doctor` tells you to (rung `reboot`).

## Documentation

- [Getting started](docs/user_guide/getting_started.md): the first ten minutes
- [Pi setup](docs/user_guide/pi_setup.md): hardware, cabling, more agents
- [Home network](docs/user_guide/home_network.md): phones, laptops and TVs
- [Architecture](docs/user_guide/architecture.md): how a request flows and where keys live
- [FAQ](docs/user_guide/faq.md): what breaks, revoking a key, performance
- Everything else, including design docs: [docs/INDEX.md](docs/INDEX.md)

## Capture the key

Run your own gateway with a canary credential that you mint. Then find a
method that we can reproduce to get the canary off the Pi. A confirmed
bypass gets a row in the hall of fame. The challenge has no end date.
[Rules](docs/challenge_rules.md).

## Contributing and security

Issues and pull requests are welcome. Start with [AGENTS.md](AGENTS.md).
Report security issues privately. Never report them in a public issue: [SECURITY.md](SECURITY.md).

Contact: security@praneos.ai

## License

[Apache-2.0](LICENSE). Maintained by [Praneos Labs](https://github.com/praneos).
We provide it as is, without warranty. See also
[EVALUATION_NOTICE.txt](EVALUATION_NOTICE.txt).
