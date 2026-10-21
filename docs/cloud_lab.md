<!-- Build and test pi-fortress on cloud or local VMs, without a real Pi. -->
# Cloud lab

The cloud lab builds the full Pi Fortress setup from VMs on one machine:

- the Pi gateway
- a house device
- a desk seat
- one or more agents

It copies the real wiring. Thus, the same test suite that runs here can run against a real Pi later. One script controls the lab: `vm/cloudlab/lab.sh`.

Only the final check in this guide needs real Pi hardware. Everything else runs on one host, cloud or local.

## What you get

| VM | Plays | Lab address |
|---|---|---|
| `gw` | the Pi gateway (hostname `pi-fortress`) | `10.77.0.1` (agents), `10.79.0.1/30` (desk), `10.78.0.1` (house) |
| `agent`, `agent2` | agent VMs | `10.77.0.10`, `10.77.0.11` |
| `desk` | the desktop seat | `10.79.0.2` |
| `house` | the admin house device, plus two pool devices in network namespaces: `phone` (no reservation, accepts IPv6 router advertisements) and `iot` (hardcoded `8.8.8.8` resolver) | `10.78.0.20` from DHCP; `phone` and `iot` from the pool `.100-.199` |

```
 agent, agent2  --------------------- agent segment ---+
                                                        |
 desk           --------------------- desk segment ----+--- gw (the Pi)
                                                        |
 house          --------------------- house segment ---+
                                                        |
                                                       uplink -- internet
```

Each VM starts with a management link, so that Vagrant can configure it. When the setup is complete, `lab.sh` cuts that link on all VMs except `gw`. Then a client can reach the internet, or a VM on a different segment, only through the gateway. This is also true on a real Pi. `agent` and `agent2` share the agent segment, so they can reach each other directly. The gateway does not see that traffic. Agents on one segment are one trust tier.

This matches the real Pi closely:
- `gw` runs the real gateway install scripts.
- `desk` runs the real desk setup script.
- `house` gets its address from the DHCP of the Pi. Its `phone` and `iot` namespaces each own a NIC on the house bridge. Each namespace takes its own pool lease (`vm/cloudlab/guest/house-ns.sh`, `pf-house-ns@<name>.service`). To run a command as one of them: `vm/cloudlab/lab.sh ssh house sudo ip netns exec phone dig example.com`.
- The test suite reaches each client only by SSH through `gw`, never by a shortcut on the host.

## 1. Host

| Need | Minimum |
|---|---|
| Virtualization | `ls /dev/kvm` must work. Use a bare-metal machine, or a cloud VM type with nested virtualization on. |
| vCPU | 2 (4 is faster) |
| RAM | 8 GB (16 GB if VMs run out of memory) |
| Disk | 100 GB (60 GB with one agent VM). See the disk table below |
| OS | Ubuntu 24.04 (others may work) |
| Go | see `go.mod` for the version |

Check nested virtualization before you pay for anything.

The GCP NIC has an MTU of 1460. This is 40 bytes less than the usual LAN MTU of 1500. A guest that negotiates a bigger MSS on egress can blackhole if the path drops the PMTU ICMP. Thus, `sudo vm/cloudlab/lab.sh host` clamps TCP MSS to the PMTU of the path for each SYN that it forwards. This has no cost on a normal 1500-MTU host. It needs no GCP-specific flag.

| Cloud | What works | Example |
|---|---|---|
| GCP | Normal VMs can run nested VMs | `n2-standard-4` (4 vCPU, 16 GB), Spot. Cheapest good option |
| Azure | Most v3 and newer sizes support it | `D4s_v5`, Spot |
| AWS | Normal EC2 instances cannot. Only bare metal can | `c5.metal` or `m5zn.metal`, Spot. Much more expensive |
| Local | Any Linux box with `/dev/kvm` | Your desktop |

On AWS, the lab needs a `.metal` instance, because EC2 gives no nested virtualization on other instance types. Use Spot. Stop the instance when you are done.

### GCP Spot, step by step

**Desktop**, with `gcloud` installed and logged in:
```sh
gcloud config set project <project>
gcloud config set compute/zone <zone>

gcloud compute instances create pf-lab \
  --machine-type=n2-standard-4 \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP \
  --enable-nested-virtualization \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB --boot-disk-type=pd-balanced
```

Copy the repository to the host and log in:
```sh
gcloud compute config-ssh
rsync -a --exclude .vagrant ./ pf-lab.<zone>.<project>:~/pi_fortress/
gcloud compute ssh pf-lab
```

**Host**, first checks and setup:
```sh
ls /dev/kvm && grep -c vmx /proc/cpuinfo
cd ~/pi_fortress && sudo vm/cloudlab/bootstrap.sh
```

Log out and log in again for the group change. Then start the lab.

With Spot, GCP can take the VM back at any time. With `--instance-termination-action=STOP`, the disk survives. After a stop:
```sh
gcloud compute instances start pf-lab
```
Then, on the host, run `sudo vm/cloudlab/lab.sh host` and `vm/cloudlab/lab.sh up` again. Stop the VM yourself when you finish for the day. Delete it when the work is complete:
```sh
gcloud compute instances stop pf-lab
gcloud compute instances delete pf-lab
```

### Disk

| What | Space |
|---|---|
| Base VM image (box) | about 2 GB |
| Each lab VM disk, as it fills | 8 GB to 12 GB. Five VMs reach about 50 GB |
| Go toolchain and build cache | about 3 GB |
| Repository, logs, bundles | about 2 GB |

100 GB `pd-balanced` is comfortable and costs about 0.35 USD a day. 60 GB is enough with `PF_AGENT_COUNT=1`. The VM disks are in `/var/lib/libvirt/images`. `vm/cloudlab/lab.sh destroy` frees them.

Then configure the host with one command, from the repository root:

**Host**
```sh
sudo vm/cloudlab/bootstrap.sh
```

This command:

- installs KVM, libvirt, Go (the version in `go.mod`), Vagrant and the libvirt plugin
- adds you to the `libvirt` and `kvm` groups
- makes the lab networks

Then log out and log in again, so the new groups apply.

To do it manually instead:

**Host**
```sh
sudo apt-get update
sudo apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients libvirt-dev \
  dnsmasq-base ebtables ruby-dev build-essential pkg-config libxml2-dev libxslt1-dev zlib1g-dev \
  rsync git make curl gpg lsb-release
# Ubuntu 26.04 only: the interface driver is a separate package there.
# On 24.04 it is part of libvirt-daemon, and this package does not exist.
apt-cache show libvirt-daemon-driver-interface >/dev/null 2>&1 &&
  sudo apt-get install -y libvirt-daemon-driver-interface
sudo usermod -aG libvirt,kvm "$USER"
# log out and back in so the new groups take effect
curl -fsSL -o hashicorp.asc https://apt.releases.hashicorp.com/gpg
# exactly one key, D55C0D1AC78A8D8126CB631CFC9CA96ACA026560 (scripts/lab_deps.sh pins the same)
gpg --show-keys hashicorp.asc
sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg hashicorp.asc
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y vagrant
vagrant plugin install vagrant-libvirt
```

Install Go. Then clone the repo and `cd` into it. Run all commands below from the repo root.

### One command

On a new cloud VM, with no clone yet, `install-lab.sh` does the clone and then this command:
```sh
curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install-lab.sh | sudo bash
```
It checks for `/dev/kvm`, 8 GB RAM and the free disk. When you are logged in as root, it makes the user `pflab` to run the lab, because vagrant refuses root. Settings: `PF_LAB_USER`, `PF_LAB_DIR`, `PF_REPO`, `PF_REF` (the head of `install-lab.sh` lists them).

`sudo vm/cloudlab/bootstrap.sh --up` does all of the above and section 2 below in one run. It goes from a fresh host to a running, enrolled lab. It does these steps:

1. Installs the host packages and groups.
2. Re-execs the rest of the work as your own user, with the libvirt and kvm groups already active. It uses `sg`, so you do not need to log out and log in.
3. Starts the lab.
4. Enrols one agent through the real claim flow: `pf enroll mint` + `pf claim` on the gateway, then the printed claim command on the agent. This is the same path that `vm/itest/enroll_test.go` proves. If a step of this flow fails, it falls back to whatever the pre-seeded agent credentials already gave the agent.
5. Runs a fast e2e group (`policy`) as a smoke check.

The command is idempotent. You can run it again at any time, also after a host reboot. Plain `sudo vm/cloudlab/bootstrap.sh` (no `--up`) does only the host half. It prints the manual steps below, for users who want to run each step manually.

## 2. Bring the lab up

**Host**
```sh
sudo vm/cloudlab/lab.sh host
vm/cloudlab/lab.sh up
```

- `host` configures the virtual networks of the lab. Run it again after the host reboots.
- `up` builds the gateway binary. It makes `gw` first, then the other VMs. It writes an SSH config for all of them.
- The first run downloads a VM image and installs packages on each VM. Thus, it is slow. Later runs are fast.

Options (set as environment variables before `up`):

| Env | Default | Meaning |
|---|---|---|
| `PF_AGENT_COUNT` | `2` | number of agent VMs, 1 to 3 |
| `PF_BOX` | `debian/bookworm64` | base VM image |
| `PF_E2E_REBOOT` | unset | `1` lets the tests reboot `gw` and `desk` |
| `PF_E2E_DESTRUCTIVE` | unset | `1` runs the lab-only groups (`strip`, `secrets`, `setup`, `enroll`, `tui`) against `PF_TARGET=pi`. These groups seed secrets, truncate logs and enroll the agent again. Use it only for a fresh Pi with nothing to keep. For the length of the run, it also lends the Pi the `pf-core-echo.test` fixture: `touch /etc/pi-fortress/lab`, the `pf-core-echo.test *` line in `core.hosts`, and `pf apply --local`. Thus, the `secrets` group and the two `enroll` subtests that read the echo run on hardware, and do not skip. Nothing opens: the broker synthesises the echo in process, and `192.0.2.0/24` is already carved out of the agent gate on every box. The teardown copies the baseline back from `/var/lib/pi-fortress/e2e-echo`, applies again and `cmp`s each file. The teardown runs also when tests fail. The next run recovers a run that was killed. Without `PF_E2E_DESTRUCTIVE`, the suite does not lend this fixture to a real Pi, and those subtests skip as before. The suite still makes small changes on a real Pi. Section 5 lists them |

Quick check:

**Host**
```sh
vm/cloudlab/lab.sh status
vm/cloudlab/lab.sh ssh pi sudo pf doctor
vm/cloudlab/lab.sh ssh agent "curl -sS -o /dev/null -w '%{http_code}\n' https://example.com"
vm/cloudlab/lab.sh ssh desk ip route show default
```
Expected results:

- `pf doctor` passes.
- The curl prints `200`.
- The desk route goes through the gateway.

## 3. Run the tests

**Host**
```sh
vm/cloudlab/lab.sh test
vm/cloudlab/lab.sh test -v -run 'TestLab/(drops|house|desk)'
PF_E2E_REBOOT=1 vm/cloudlab/lab.sh test -v -run 'TestLab/ops'
```
`lab.sh` passes all arguments after `test` directly to `go test`.

| Group | Runs on | Checks |
|---|---|---|
| `policy` | agent, gateway | The agent reaches the gateway. Allowed names and HTTPS work. The gateway sinkholes a blocklisted canary name. |
| `drops` | agent | The gateway drops direct-IP and DNS-over-HTTPS connections. |
| `fakeip` | agent, gateway | With `AGENT_DNS=fakeip` (the default), the agent gets answers from the pool, and HTTPS works through the pool. The gateway refuses an SNI that is not the mapped name. It drops the real address. |
| `strip` | agent, gateway | The fence strips a fake token from a header, a body and a URL, and logs each strip. Lab only. |
| `secrets` | agent, gateway | The fence substitutes a placeholder on the `pf-core-echo.test` core host, and refuses or strips it on other hosts. OAuth refresh capture, WebSocket frame scrub, hourly budget. Lab only. |
| `setup` | agent, gateway | The gateway serves `setup.sh` and `ca.pem` on port 80. `setup.sh` enrols the agent. It refuses a CA with no sha256. Lab only. |
| `agent-vm` | agent | The agent has no checkout and no Guest Additions. Its clock follows the gateway. It has only the sudo that it was provisioned with. |
| `enroll` | agent, gateway | The documented setup lines. `pf enroll mint`, the claim code (six characters, five minutes, one use), and substitution until the slot is deleted. Lab only. |
| `dns-segments` | gateway, agent | The Go resolver serves each segment from `dns.json`, writes log rows and fills `resolved_v4`. |
| `house` | house | DHCP lease, DNS, blocklists, SSH only from the admin device |
| `house-devices` | house (`phone`, `iot`) | Pool lease and DNS option. No SSH from the pool. The setup page and the desk are unreachable. The gateway drops QUIC. No IPv6 route. The gateway refuses a hardcoded resolver in less than 2s. The test disconnects the house cable for 30s and then connects it again. |
| `seg-dhcp` | gateway, house | A temporary `DHCP=on` segment on a VLAN of the house cable gives a lease and a reservation. Cloud lab only. |
| `desk` | desk | Desk setup and lock (no forwarding, survives a reboot). Default route and internet through the gateway. SSH to the gateway and agents, and nothing else to the agents. Only the resolver of the gateway: the gateway sinkholes a listed name and logs it in `dns-desk.jsonl`, and refuses a different resolver. The gateway drops and logs a blocklisted address and an unresolved 443 address. A `PARANOID=on` desk resolves only its allowlist (skipped unless armed). No SSH to the house device. |
| `uplink` | gateway | The gateway drops IPv6 on the uplink. ARP answers only for the interface in the request. An untrusted uplink closes SSH and ping. |
| `tui` | gateway | `sudo pf tui` on a real pty paints the menu and each view. Lab only. |
| `ops` | gateway, agent | feeds fail safely, log rotation, no extra network listener, reboot |
| `lifecycle` | gateway | Ships a bundle N-1, then N. The post-upgrade doctor passes. `pf rollback` returns to N-1. The `/etc/pi-fortress` state stays intact, and a list edit made after N stays. A bundle rigged to break DNS reverts on its own. An unconfirmed upgrade reverts after the dead-man deadline. `pf ship confirm` clears the pending state. |

Tests that reboot a VM run only with `PF_E2E_REBOOT=1`. Run `ops` last, because its reboot test restarts `gw`. `lifecycle` runs only with `PF_E2E_LIFECYCLE=1`. It ships bundles and rolls the gateway back. Thus, it is a release gate, not part of a normal run:
```sh
PF_E2E_LIFECYCLE=1 vm/cloudlab/lab.sh test -v -run 'TestLab/lifecycle' -timeout 20m
```
The same group runs against a real Pi with `PF_TARGET=pi PF_E2E_LIFECYCLE=1 make e2e RUN=TestLab/lifecycle`. The arch of the bundle follows the target: amd64 in the lab, arm64 on the Pi.

`make cloudlab-up`, `make cloudlab-test` and so on run the matching `lab.sh` command with no extra arguments.

## 4. Daily loop

| Task | Command |
|---|---|
| Rebuild after a change to Go code, and apply again on the gateway | `vm/cloudlab/lab.sh sync` |
| Run one test group | `vm/cloudlab/lab.sh test -v -run TestLab/house` |
| Open a shell in a VM (`pi`, `agent`, `agent2`, `house`, `desk`) | `vm/cloudlab/lab.sh ssh desk` |
| Run the setup again on one client | `vm/cloudlab/lab.sh provision desk lab-net` |
| Stop the VMs, keep the disks | `vm/cloudlab/lab.sh down` |
| Start again after `down` or a host reboot | `sudo vm/cloudlab/lab.sh host && vm/cloudlab/lab.sh up` |
| Start from zero | `vm/cloudlab/lab.sh destroy && vm/cloudlab/lab.sh up` |
| Ship a real signed upgrade to the gateway VM, the way a Pi gets one | `vm/cloudlab/lab.sh ship` |
| Snapshot all lab VMs | `vm/cloudlab/lab.sh snapshot before-upgrade` |
| Roll all lab VMs back to a snapshot | `vm/cloudlab/lab.sh restore before-upgrade` |
| List the snapshots of this lab | `vm/cloudlab/lab.sh snapshots` |

`lab.sh ship` does these steps:

1. Builds the amd64 bundle (`make pi-bundle GOARCH=amd64`).
2. Signs it with a lab-only key, generated under `.vagrant/lab-keys`. It never uses `~/.ssh/pi_fortress_release`.
3. Makes the gateway VM trust that key (`/etc/pi-fortress/allowed_signers`, namespace `pi-fortress-release`).
4. Gives the gateway VM a `pfship` user and key.
5. Uploads through `pfship`, exactly like `make pi-ship`.
6. Waits for a row in `ship.jsonl` (`docs/signed_ship.md`).

`lab.sh sync` (rsync plus `pf apply`) stays the fast inner loop for ordinary development. Use `ship` to test the same upgrade path that the Pi gets, also with the `lifecycle` e2e group.

`lab.sh snapshot`/`restore`/`snapshots` are `virsh snapshot-create-as` / `snapshot-revert` / `snapshot-list` across all lab VMs. Their names have the prefix `pflab-`, so they show as the snapshots of this lab. This rolls the full developer lab back to a point in time. It is not the rollback of the product. `lab.sh ship` plus `pf rollback` on the gateway tests that rollback.

## 5. Running the same tests against a real Pi

When your real Pi is ready, you can run this same suite from your desktop. The suite reaches the agent only through the Pi. For the Pi, refer to [pi_setup.md](user_guide/pi_setup.md). To enrol a credential and claim it on an agent, refer to [getting_started.md](user_guide/getting_started.md).

**Desktop**

1. Write an SSH config, for example `~/.ssh/pf-e2e.config`:
   ```
   Host pi
     HostName <pi-address>
     User <pi-admin-user>

   Host agent
     HostName 10.77.0.10
     User vagrant
     IdentityFile <path-to-agent-private-key>
     IdentitiesOnly yes
     ProxyJump pi
     StrictHostKeyChecking no
     UserKnownHostsFile /dev/null
   ```
   `ssh -F` does not read your normal `~/.ssh/config`. Thus, copy into this file each special key line that you need for the Pi.

2. Run:
   ```sh
   PF_TARGET=pi PF_SSH_CONFIG=~/.ssh/pf-e2e.config make e2e V=1
   PF_TARGET=pi PF_SSH_CONFIG=~/.ssh/pf-e2e.config PF_E2E_REBOOT=1 make e2e V=1 RUN=TestLab/ops
   ```
   `RUN` selects the groups to run, the same as `go test -run`.

Needs:
- The Pi admin user has passwordless sudo, or an allowlist of the commands that the suite runs. The suite checks `sudo -n true` first. With `PF_TARGET=pi`, a refusal is not fatal:
  - The subtests that need no sudo still run.
  - Each subtest that sudo refuses skips, and names the command that it wanted.
  - At the end of the run, the suite logs how many groups thinned out.

  The signed ship setup in [pi_setup.md](user_guide/pi_setup.md) removes passwordless sudo. Thus, after that setup, expect this type of run.
- `PF_REQUIRE_SUDO=1` restores the hard failure. `PF_REQUIRE_SUDO=0` allows the skips on all targets. The default is on for the `vagrant` and `cloudlab` targets. Both of these labs provision passwordless sudo, so a refusal there means that the lab is broken.
- `/vagrant` on the Pi points at the repo copy. The first-time step in [pi_setup.md](user_guide/pi_setup.md) creates it. The feeds test uses it.

What the suite changes on a real Pi without `PF_E2E_DESTRUCTIVE`:

| Change | Undo |
|---|---|
| One forced log rotation (`ops`) | none needed |
| A short-term copy of generated config files in `/tmp/pf-gen` (`ops`) | removed at the end |
| Some addresses cleared from the resolved sets (`drops`, `house`) | they come back at the next lookup |
| Bursts of DNS queries from the agent in the logs, and one `dns_tunnel` alert (`ops`) | none needed |
| Back-dated monitor day files, and one `pf monitor` tick. The tick prunes day files older than seven UTC days, as the daemon does (`ops`) | the test files are removed at the end |
| `pf observe once` runs. This updates the state of observe (`policy`, `ops`) | none needed |
| On the agent VM: its own output lock (`agent_lock`) is lifted for a few seconds for each probe that must reach the Pi. IPv6 is on, link-local only, on its cable for one probe (`drops`, `policy`) | restored after each probe. If the run is killed, a deadman on the agent restores it two minutes later |
| On the agent VM: the clock is set one hour ahead, so that the clock unit brings it back (`agent-vm`) | the unit sets it back |
| A reboot, only with `PF_E2E_REBOOT=1` | none needed |

In addition to the lab-only groups (`strip`, `secrets`, `setup`, `enroll`, `tui`) and the echo fixture above, `PF_E2E_DESTRUCTIVE=1` adds these changes:

| Change | Undo |
|---|---|
| Retired keys written into `net.env.local` and `house.env`. `pf apply --local` refuses each (`ops`) | the files are put back from a copy |
| The agent resolver stopped in the middle of a flood (`ops`) | started again, also on failure |
| `pf apply --local`, to check that resolved addresses survive the reload (`dns-segments`) | none needed |
| A DHCP lease renewed on the house client, the house DHCP daemon reloaded and the logs rotated (`house`) | none needed |
| The lab seed replaces the `secrets.env` of the broker (`secrets`) | The suite restores it from a root-only copy in `/var/lib/pi-fortress/itest-secrets`, compares it byte for byte, then deletes the copy. A failed restore fails the run and keeps the copy |

## 6. What still needs real hardware

| Item | Why a VM cannot show it |
|---|---|
| The seat console and TUI on the screen of the Pi, and in a real terminal | needs a real screen, keyboard and terminal |
| A phone on Wi-Fi, and the house Wi-Fi access point | needs real radio hardware |
| The real network cable and VLANs of the desktop | needs the real NIC and cable |
| Claude Code with a real account and a hardware security key | needs real accounts and keys |
| Anything that depends on days that pass, or Pi-class latency and load | the lab does not run that long, and the VMs are not a Pi 5 |

## Limits

| Item | Status |
|---|---|
| A first run on a new host OS | Most likely to need a fix: the bridged NICs, VLAN tags through the bridges, and NIC order in the base image |
| The test groups | Written. Your first `lab.sh test` run is the proof for your host |
| The listener check in `ops` | Assumes that `pf` listens on TCP only on ports 22, 53, 80 and 8080 |

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| No virtualization support | Use bare metal, or a cloud instance type with nested virtualization on. |
| `vagrant up` fails on a network option | Run `vagrant plugin list` and make sure that `vagrant-libvirt` is installed. |
| A client cannot reach the gateway, or `gw` has no internet | Run `sudo vm/cloudlab/lab.sh host` again. Some cloud networks block outbound DNS to public resolvers. |
| Docker is installed on the host | `sudo iptables -S FORWARD \| grep pf` must show three ACCEPT rules. If not, run `sudo vm/cloudlab/lab.sh host` again. |
| `lab.sh ssh agent` hangs | The gateway is down, or its last apply failed. Run `lab.sh ssh pi sudo pf doctor`. |
| Vagrant cannot reach a client | Run `lab.sh uncut`, wait a minute, retry, then `lab.sh cut`. |
| Wrong network interface selected, or the house VM never gets its address | The guest setup selects interfaces by MAC address. Compare with `ip -br link` inside the VM. |

## Teardown

**Host**
```sh
vm/cloudlab/lab.sh destroy
sudo vm/cloudlab/lab.sh host-clean
```

## See also

- [pi_setup.md](user_guide/pi_setup.md): the setup of a real Pi
- [home_network.md](user_guide/home_network.md): the filtered home network behind the Pi
- [public_wifi.md](user_guide/public_wifi.md): the uplink of the Pi on a network that you do not control
- [getting_started.md](user_guide/getting_started.md): how to enrol and claim a credential
- [architecture.md](user_guide/architecture.md): how a request flows through the gateway
