# Lab and operator manual; the landing page is README.md

Four VirtualBox VMs (pi, agent, house and desk), or a real Pi 5. The enforcement is in `pi-fortress`. In the lab, nothing changes the firewall, DNS, or routes of the Ubuntu host. On the real Pi, the desktop traffic also goes out through the fence. There, `vm/desk/setup.sh` does change the routes and nftables of the desktop.

The full topology, with house and desk, also runs as VMs on one cloud KVM host. It has an automated test suite. Refer to `cloud_lab.md`.

Rules for an AI agent that drives the cloud lab:

- Use `lab.sh` for all operations that touch a client. Before raw `vagrant` on a client, run `lab.sh uncut`. After it, run `lab.sh cut`.
- Never add host routes, bridge addresses or firewall rules to make a test pass. The tests check the isolation between desk, house and agents.
- Only `lab.sh host` and `host-clean` need sudo on the host.
- The safe-host rules of AGENTS.md apply. Block tests use `192.0.2.1` and `pi-fortress-block.test`. Feed hostnames get only `dig`.
- `make e2e` runs against the target that `PF_SSH_CONFIG` names. Check `PF_SSH_CONFIG` before a reboot run.

```
lab:  agent (10.77.0.10) --intnet agent-net--> pi-fortress (10.77.0.1) --VBox NAT--> internet

real: one cable, desktop NIC to Pi eth0, both unaddressed trunks carrying tags
      agent VMs .10 .11 .12 + Docker macvlan .128/25 --VLAN 20--> eth0.20  10.77.0.1    --> uplink
      desktop host <nic>.79 10.79.0.2                 --VLAN 79--> eth0.79  10.79.0.1/30 --> uplink
      house AP on a USB adapter                                    eth1     10.78.0.1    --> uplink
```

The policy has these parts:

- **default-allow HTTPS dests**
- a blocklist
- observe logs
- a secrets fence on agent HTTPS

The house segment is in `apply.sh`. It has its own interface behind an AP. It is filter only, with no CA. Its settings are in `user_guide/home_network.md`.

All other segments are plain. Each plain segment is a data file under `/etc/pi-fortress/segments.d/`. Thus, a second AP or an SSID-per-VLAN is a file, not a code change. A VLAN on the cable of the house port gets no `ADMIN`, `SSH_TO` or agent network (`checkHouseCable` in `internal/render/config.go`).

A plain segment is strict by default. The gateway treats it as a machine that an agent may have escaped to. A plain segment gets:

- NAT to the uplink, and isolation from all other segments.
- DNS only through the Pi, with the lists of the agent, key-shape refusal and address-only answers.
- QUIC, DoT and DoH dropped.
- New connections on any port only to addresses that its own resolver gave.
- Local addresses dropped.
- The strict ports of the house.

By default, it gets no CA, no inspection, and no credential substitution. The `desk-inspect` group of the e2e suite sets `INSPECT=on` and installs the CA on the desk for its run. Then it sets both back. The keys are in `vm/pi/segments.d/desk.env.example`.

Below, `<nic>` is the wired NIC of the desktop that carries the trunk to the Pi. It is `PARENT` for `vm/desk/setup.sh`. If `PARENT` is not set, it is `enp6s0`.

Run all commands below from the repo root, unless the text says otherwise.

## Useful commands

### Daily loop

Lab (VMs):

```
./vm/bin/up.sh          # start VMs (first run downloads the box)
./vm/bin/apply.sh       # feeds + nft/dnsmasq + observer + secrets fence + agent CA
make test               # shell-test + go test + apply-test + lab-test + appliance-test (lab skips if VMs are down)
make lab-test V=1       # VM suite only, verbose subtests (against the pf the VM has installed, so apply.sh first after a Go change)
make apply-test         # render the nft ruleset with and without a house segment, diff against the golden
make fuzz FUZZTIME=15   # HTTP parsers, scanners, secrets loader
make audit              # go mod verify + govulncheck against vuln.go.dev; run it weekly or on any dependency bump
./vm/bin/observe.sh once
./vm/bin/alerts.sh show
./vm/bin/status.sh
```

Real Pi:

- `PI_IP` is the address that you use to reach the Pi, not `10.77.0.1`. After the VLAN cutover, it is the desk segment address `10.79.0.1`. Before the cutover, it is the Wi-Fi address of the Pi on your LAN.
- `PI_USER` is your login on the Pi.

```
PI_IP=10.79.0.1 make pi-ship            # build arm64, sign, upload to pfship; the Pi verifies and runs pf apply
PI_IP=10.79.0.1 make pi-provision       # first time: users, units, packages
PI_IP=10.79.0.1 make pi-ssh
make agent-up                           # agent VMs bridged onto VLAN 20 (AGENT_BRIDGE=<nic>.20)
AGENT_COUNT=3 make agent-up             # agent, agent2, agent3 at 10.77.0.10 .11 .12
AGENT_COUNT=3 make agent-destroy
```

Do **not** `destroy` between these commands. `apply` is a reload, not a rebuild. On an agent VM, `/vagrant` is a one-way rsync share, not the read-write vboxsf share. Edits in the VM do not come back.

Desktop host: run these commands one time for each machine, in this sequence. Test between each command:

```
sudo vm/desk/setup.sh net       # trunk <nic>, <nic>.20 address-less, <nic>.79 10.79.0.2/30
sudo vm/desk/setup.sh default   # move the default route to 10.79.0.1
sudo vm/desk/setup.sh lock      # no forwarding, nothing in or out on <nic> or <nic>.20
sudo vm/desk/setup.sh status
```

Run `lock` last. Its forward drop cuts all containers that are still on the default docker bridge. This includes the sandbox that an agent may be in.

`lock` also refuses a host with a second way out. `status` lists such a way out under "uplinks". A second way out is one of these:

- a default route (in any table, v4 or v6, the VPN 0/1 pair included) that is not via `DESK_GW` on the desk VLAN
- a wireless interface that is up and not rfkill-blocked
- a different hardware-backed NIC with carrier and an IPv4 route

These rules apply to the check:

- Docker, libvirt, VirtualBox host-only and overlay devices do not count, unless a real port is enslaved below them.
- Of the VLANs on the trunk, only `<nic>.20` and `<nic>.79` are exempt.
- tailscale0 and wg* count only with a default route.

`vm/desk/setup.sh uplinks` runs only the check. Disable the radio between `default` and `lock`: `nmcli radio wifi off`, or `sudo rfkill block wifi`. Both survive a reboot. `ip link set down` does not. Also disable Wi-Fi in the BIOS permanently.

`pf-desk-lock.service` runs the check again two minutes after each boot (`pf-desk-uplink-check`). At that time, NetworkManager has started the connections that it autoconnects. The check only gives a warning:

- It logs a finding at crit priority (`journalctl -b -u pf-desk-uplink-check`).
- `status` shows the finding under "uplinks at boot".
- It blocks nothing. Reason: a boot check that cut egress could stop the only working uplink of a desk.

The lock is `PartOf=nftables.service`, and `nftables.service` wants it. Thus, `systemctl restart nftables` flushes the ruleset and loads `pf_desk_lock` again.

A development box that keeps Wi-Fi as a fallback locks with `sudo PF_DESK_ALLOW_SECOND_UPLINK=1 vm/desk/setup.sh lock`. This gives a loud warning. With `PF_LAB=1`, the check reports and continues. The check does not count the management NIC of the cloud lab. `/etc/pf-lab.env` names this NIC.

The way back from any step is `sudo pf-desk-restore` or `sudo vm/desk/setup.sh restore`. The two commands do the same restore. `net` and `lock` install `pf-desk-restore`. It needs no repo and no DNS. The restore:

- undoes `default` and `lock`
- keeps the VLAN profiles
- restores the Wi-Fi uplink

### Secrets (on the Pi)

You can mint from your workstation. Then the tokens do not go into a shell argument:

1. Copy the access token (`sk-ant-oat01-...`) and the refresh token (`sk-ant-ort01-...`) as two lines.
2. Pipe the clipboard in. Use `pbpaste` on macOS. Use `wl-paste` or `xclip -o -selection clipboard` on Linux. `<user>` is your login on the Pi:

```
pbpaste | ssh <user>@<pi> sudo pf enroll mint --kind CLAUDE --stdin
```

On the Pi, paste the two lines after the mint command, then push Ctrl-D:

```
sudo pf enroll mint --kind CLAUDE --stdin
sudo pf enroll list
sudo pf enroll peek --slot <slot>
sudo pf enroll delete --slot <slot>
```

The live values are in `/etc/pi-fortress/broker/`:

- `secrets.env`: mode 0600, owned by the broker.
- `secrets.disabled`: the quarantine sidecar.

The gateway copies nothing to the agent.

To enrol the agent with a claim code:

1. Run `sudo pf tui`.
2. Go to Agent network → Keys.
3. Select the slot.
4. Push `c`.

The screen shows an eight-character code. The code is valid for five minutes and works one time. The screen also shows three lines to paste in the agent VM. The hash is the hash of the claim script. The Pi calculates it:

```
h=<sha256>
f=$(mktemp) && curl -fsSo "$f" http://<pi>/claim/<CODE> &&
echo "$h  $f" | sha256sum -c && sh "$f"
```

These lines run `setup.sh` (CA, DNS pin, output lock). They write `~/.claude/.credentials.json` and `~/.pi-fortress/env.sh`, with placeholders only. On a slot:

- `x` quarantines the slot. The broker stops the injection immediately.
- `R` restores the slot.
- When a slot is in quarantine for seven days or more, the next apply purges it.

### Management

Use `sudo pf tui`, over ssh or at the seat. There is no HTTP console. Nothing listens on the network for management. The TUI has these screens:

- status
- house devices and reservations
- house and agent lists
- feed toggles
- slots (list, claim, quarantine, delete)
- logs
- `house.env`
- apply and fetch, with streamed output
- reboot and shutdown

Devices lists each device per segment, with its query, flow and blocked counts. Enter shows its top names, top destinations and blocked events.

The Blocked tab of Activity is the blocked-contact table, newest first: time, threat, source device, destination. Under the table, there is a bar row for each segment. The bar row shows the blocked count per day for the last seven local days, over the queries and flows counts.

Both screens read `observe.json` again every 5 s. Thus, they are late by a maximum of one observe flush.

### Observe (what the agent actually hit)

```
./vm/bin/observe.sh once     # snapshot DNS + dest flows, print
./vm/bin/observe.sh show     # last snapshot, no poll
./vm/bin/observe.sh reset    # new session (skips old dns.jsonl; does not kill live TCP)
```

On the Pi the files are:

- `/var/lib/pi-fortress/observe/observe.json`
- `/var/log/pi-fortress/observe.jsonl`

The gateway never terminates the traffic of a plain segment. Thus, observe keeps its first-seen destinations instead:

- Observe writes one `"kind":"dest"` row in `observe.jsonl` the first time that the segment reaches a name (or a bare address) on a port.
- Observe keeps the destination for 30 days after the last contact. It writes no second row in that time.
- `pf observe` and the New destinations tab of the TUI show it.

The query names of a plain segment get the `dns_key` check of the agent and the stricter `dns_tunnel` checks. For these checks, one of these is enough:

- one TXT or NULL question with a left label of 16 or more characters
- three long-label names in a minute

### Alerts (token strip)

A strip is silent, unless something watches. The jsonl file is the log. The alerter is a sidecar, so egress filtering does not wait for a webhook.

```
./vm/bin/alerts.sh show      # last strip event
./vm/bin/alerts.sh follow    # terminal bell + notify-send on the host
```

Phone:

1. Copy `vm/policy/alert.url.example` to `vm/policy/alert.url`.
2. Put one ntfy/Slack/Discord URL in it.
3. Run `./vm/bin/apply.sh`.

The POST has only `host` / `where` / `rule`. It never has the token.

### Unknown destinations

Unknown HTTPS still goes to the real internet. The broker logs a sample (`host` / `method` / `path`, no body) to `/var/log/pi-fortress/unknown.jsonl` on the Pi. No data about it leaves the box.

Related documents:

- TLS engine vs credential broker: `docs/privilege_split.md`.
- Real Pi 5: hardware and cables in `user_guide/pi_setup.md`, install in `docs/gateway_install.md`, the dev ship loop in `docs/signed_ship.md`.

```
vagrant ssh pi -c 'sudo tail /var/log/pi-fortress/unknown.jsonl'
```

Edit `vm/policy/allow.domains`. Its seed is `core.hosts` + Claude harvest. `example.com` is intentionally not on that list, because it is the canary. Claude telemetry (Datadog) is on the list, so a real session stays quiet.

### Shells

```
vagrant ssh pi
vagrant ssh agent      # the provisioner's account: passwordless sudo
make agent-shell       # the account the agent's work runs under
```

The agent VM has two accounts:

- `vagrant`: Vagrant and the test suite use this account. It has sudo, because they need it.
- `agent`: the agent itself runs here (Claude Code, a claimed credential, a checkout). By default, it has no sudo. The well-known password of vagrant is locked, so `agent` cannot borrow the sudo of vagrant.

Root in the guest gets nothing on the network, because the gateway controls the network. But root is where a hypervisor escape starts. If the work needs root (package installs, docker, the devops jobs that a cloud VM is rented for), say so when you make the VM:

```
make agent-up AGENT_SUDO=1          # a new VM; the cloud lab reads the same variable
make agent-provision AGENT_SUDO=1   # an existing one; without the variable it takes sudo away again
```

Agent enroll, for a dedicated box or to do the VM CA again from the Pi. Read the two hashes on the Pi, never on the agent (`sudo sha256sum /var/lib/pi-fortress/www/setup.sh /var/lib/pi-fortress/www/ca.pem`):

```
curl -fsSo /tmp/pf-setup.sh http://<pi>/setup.sh
echo '<SETUP_SHA>  /tmp/pf-setup.sh' | sha256sum -c && sudo bash /tmp/pf-setup.sh <pi> <CA_SHA>
```

The Pi serves `setup.sh` and `ca.pem` only on the agent NIC (port 80). The first argument is the Pi address. `setup.sh` never guesses it from a default route. The second argument is the sha256 of the CA. `setup.sh` refuses a CA fetched without it, or a CA that does not match it. A claim code carries both hashes.

`setup.sh` then does these steps:

1. Installs the egress filtering CA.
2. Pins DNS.
3. Disables IPv6/Wi-Fi, if present.
4. Loads the `agent_lock` nft table. This table has policy drop on output. Only DNS, the CA server, and ping to the Pi leave the box. TCP 443 and TCP 22 to any address also leave the box. All of this traffic leaves only on the cable to the Pi. A oneshot loads the table again before the network on each boot. The table needs `nftables` installed off-box.
5. Checks `https://example.com`.

The same script runs on Ubuntu/Debian, Fedora/RHEL/Rocky/Alma/Amazon Linux, Arch, and openSUSE. The CA tools are different. `curl|bash` is the same. NixOS and Alpine do not use this path. Install `curl` and `ca-certificates` *before* the box is on the Pi. If not, HTTPS to distro mirrors will fail TLS inspection.
Throwaway CA check (docker, not the host): `make distro-test`

The lab VM (`vm/agent/provision.sh`) also pins the CA:

- Its first provisioning records the sha256 of the `ca.pem` that it fetches. It records it as `CA_SHA256` in `/etc/pi-fortress/agent.env`. Or it takes `PF_CA_SHA256=<CA_SHA>` from the environment.
- `routes.sh` fetches `ca.pem` again at each boot. It refuses a `ca.pem` that does not match. It keeps the CA that is already trusted.
- The exception is a rotation with `pf engine ca` ([fence.md](fence.md) §5.2f). `routes.sh` takes a set that the pinned CA signed, and pins that set.

When the CA of the Pi changes without a rotation (for example, a new `pf engine -init-ca`), do one of these:

- Set `CA_SHA256` in that file to the new hash.
- Delete the line and provision again (`make agent-provision`). This records the CA that it then fetches.

A VM provisioned before the pin existed continues to fetch without a pin, until you provision it again. It gives a warning at each boot.

Inside **agent** (traffic must go through the Pi):

```
dig example.com
curl -I --max-time 10 https://example.com
dig pi-fortress-block.test          # expect 0.0.0.0
curl --max-time 5 https://192.0.2.1 # expect timeout
```

Inside **pi** (sudo):

```
sudo pf apply
sudo pf status
sudo pf observe once
sudo nft list set inet fortress blacklist_v4 | head
sudo tail -n 50 /var/log/pi-fortress/dns.jsonl
```

### Policy

```
./vm/bin/fetch.sh       # host-side feed fetch only (apply also fetches)
./vm/bin/apply.sh       # compile local canaries + generated - never_block
```

Edit, then apply. No VM rebuild is necessary:

- `vm/policy/blacklist.ips` / `blacklist.domains`: local canaries and extra drops. Pi-owned: `make pi-ship` seeds them one time and never overwrites them
- `vm/policy/never_block.*`: never drop these entries from feeds (includes Mullvad), even if a feed contains them. Agent side only. The house list does not read it. Pi-owned
- `vm/policy/shared_parents.domains`: shared parents (`github.io`, `herokuapp.com`, `co.uk`). A feed entry that is one of them, or a parent of one, does not compile. The block lists of the operator do not read it. Shipped. Each ship overwrites it
- `vm/policy/house_default.domains`: shipped house-segment defaults (YouTube, chess.com, SoundCloud and their CDNs). Each ship overwrites it. You cannot edit it in the TUI. To unblock one, use `house_never_block.domains`
- `vm/policy/house.domains` / `house_never_block.domains`: the house-segment sinkhole extras and exceptions of the operator. An exception can also disable a shipped default. The house list ignores `never_block.domains`. Pi-owned
- `vm/policy/doh.ips` / `doh.domains`: public resolvers. They are for the DNS pin, so the agent cannot use DoH/DoT around the Pi. never_block cannot override them. Shipped. Each ship overwrites them
- `vm/policy/doh.ips.local` / `doh.domains.local`: the resolvers of the operator, added to the shipped lists. Pi-owned
- `vm/policy/core.hosts`: `host KIND[:Header,...]...`. The credential targets for each kind. Only those kinds apply on that name. A name matches exactly. `*.name` matches all subdomains. One label, `_`, a bare `*`, a `*` after the first `*.`, an empty label, a label over 63 bytes, a host over 253 bytes and a non-ASCII host are refused with a warning, and the line is skipped. A placeholder goes only into `Authorization`, `X-Api-Key` and the headers that a line names after its kind (`docs/fence.md` §5.2). Shipped. Each ship overwrites it
- `vm/policy/core.hosts.local`: the `core.hosts` lines of the operator, added to the shipped lines. apply installs both as `/etc/pi-fortress/core.hosts`. `pf enroll mint --header` writes here. Pi-owned
- `vm/policy/allow.domains`: known dests. They are not logged to `unknown.jsonl`
- `vm/policy/key_prefixes.rules.local`: the rules of the operator, added to the shipped rules. apply installs both as `/etc/pi-fortress/key_prefixes.rules`. pf compile refuses a rule that does not compile or has no literal prefix. Pi-owned
- `vm/policy/key_prefixes.rules`: `name regexp [KIND]`. Shipped. Each ship overwrites it.
  - Start each rule with a literal prefix (`ghp_`, `AKIA`). The broker does not start with a rule that has no prefix.
  - Write a body length as a minimum (`{36,}`), with no closing `\b`. Then a longer key is stripped whole.
  - A leading `\b` means "not after a word byte, unless it ends an escape such as `\n` or `%20`". Use it for prefixes that occur inside words.
  - `(?-i:...)` makes part of a rule case-sensitive.
  - One name may head several lines (`vm/policy/key_prefixes.md`).
  - A rule tagged with a kind does not run on a core host that applies that kind. Thus, the fence never redacts the credential that it just substituted. All other rules run everywhere (`pf broker -strip-core`, default on)
- `vm/policy/key_prefixes.md`: live-token prefixes to detect later
- `vm/policy/sources.json`: feed URLs. `"enabled": false` (or `e` in Feeds of the TUI) disables a feed. `"segment": "house"` sends a feed only to the house list. `"min_ip_prefix"` (default 12) is the widest prefix that an IP feed can add; pf compile drops a wider one. Pi-owned: a signed ship keeps the copy of the Pi and appends only the feeds that are new in git. `"seeded"` holds the ids already offered. Thus, a disabled or deleted feed stays disabled or deleted
- `vm/policy/generated/`: last fetch (gitignored)
- Pi only: `/etc/pi-fortress/broker/secrets.env` (slotted; mint with `sudo pf enroll`)

Block tests use only `192.0.2.1` and `pi-fortress-block.test`. Check a listed hostname from a fetched feed with `dig` to the Pi, never with curl.

### Lifecycle

```
./vm/bin/halt.sh        # stop VMs, keep disks
vagrant up              # start again (or ./vm/bin/up.sh)
vagrant provision pi    # re-run bootstrap on existing pi VM
./vm/bin/destroy.sh     # delete VMs; next up.sh re-imports
```

`destroy` is only for a broken box or a Vagrantfile change that needs a clean import. Policy changes never need it.

## Lab caveats

- On a real Pi, the host changes. `vm/desk/setup.sh` changes the nftables, IP forwarding and DNS of the host. This is on purpose: it stops the desktop as a way around the Pi. In the lab, nothing on the host changes
- The Vagrant NAT NIC of the agent is there for `vagrant ssh`. It must not originate web or DNS traffic. In both modes, that NIC is cut (`--cableconnected1 off`) after ssh on the sanctioned path is proved. When bridged, that path goes through the Pi. In the lab, it goes through the host-only management NIC. Reason: the NAT path runs in host userspace and bypasses host netfilter. Reach the VMs at `10.77.0.10` and up from a segment whose file names `SSH_TO`

README.md and `docs/risk_model.md` §7 give the limits of the fence, and what it intentionally does not do.
