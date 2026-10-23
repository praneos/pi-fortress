<!-- End-to-end guide: flash a Pi 5, wire it as the agent gateway, install pf, bring agents up. -->
# Set up a Raspberry Pi 5 gateway

This page sets up a Raspberry Pi 5 as a gateway. It starts with a blank SD card. It ends with a working gateway with an agent behind it.

- For the home network (house segment), refer to [home_network.md](home_network.md).
- For a gateway on Wi-Fi that you do not control, refer to [public_wifi.md](public_wifi.md).
- To enrol a credential and claim it on the agent, refer to [getting_started.md](getting_started.md) steps 3-4.

This page stops when the agent can reach the internet through the gateway.

## 1. What you need

| Item | Notes |
|---|---|
| Raspberry Pi 5, 4 GB or more | You need 8 GB only if the Pi also serves all the devices of a house |
| Official 27 W USB-C power supply | A weaker supply limits the USB current. Then a USB Ethernet adapter flaps: it drops and connects again, many times |
| microSD card, 32 GB A2, or an NVMe HAT (an SSD add-on board for the Pi) | |
| USB 3 gigabit Ethernet adapter (RTL8153 or RTL8156 chipset) | Necessary when the onboard port is the uplink. Refer to step 3 |
| Cable from your ISP router to the Pi | The uplink: your connection to the internet |
| Cable from the Pi to the agent machine | The agent segment: the network of the agent |
| A desktop or laptop | To connect to the Pi with SSH |

The agent machine is a Linux machine or VM. Its only network path is the gateway. Install `curl` and `ca-certificates` on it before you put it behind the gateway. If you do not, its package manager fails TLS (HTTPS encryption) checks. It fails until it trusts the certificate authority (CA) of the gateway.

## 2. Flash and first boot

**Desktop:**
```
sudo apt install -y rpi-imager
```
Start `rpi-imager`. Select Raspberry Pi 5 → Raspberry Pi OS (other) → Lite (64-bit). In the customisation settings:

- Set a hostname, your username, and a strong password.
- Do not configure Wi-Fi.
- Set your timezone.
- Enable SSH with public-key login only.

Then:

1. Write the card.
2. Connect the Pi to your ISP router through the onboard Ethernet port.
3. Keep all USB adapters disconnected.
4. Start the Pi.

Then, from the desktop:
```
ssh <user>@<pi-hostname>.local
```
This command uses mDNS. mDNS resolves `.local` hostnames on your local network without a DNS server. If the name does not resolve, find the address of the Pi on the lease page of your router. Then, on the Pi:

**Pi:**
```
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y --no-install-recommends nftables dnsmasq curl tcpdump iproute2 ca-certificates dnsutils conntrack rsync
sudo rfkill block wifi bluetooth   # skip this line for a Wi-Fi uplink, step 3 option B
echo nf_conntrack | sudo tee /etc/modules-load.d/pi-fortress.conf
sudo modprobe nf_conntrack
sudo reboot
```
`nftables` is the Linux firewall that Pi Fortress uses to filter and route traffic. The commands above install it. You do not configure it directly. The later steps and `pf apply` configure it for you.

Steps 3 to 5 run `pf`. Thus, install `pf` first, with step 6. The `pf` installer proposes the uplink and agent ports itself. Steps 3 to 5 explain these choices and how to change them.

## 3. Choose the uplink

"Uplink" and "agent link" are roles. They are not fixed physical ports:

- `WAN_IF` is the interface that has the default route (your path to the internet).
- `INT_IF` is the interface that has the agent address (`PI_IP`, below).

You can pin each of them, and not use detection. Use the table in step 4.

**Option A: wired uplink, USB adapter for the agent (recommended).**

1. Connect the USB gigabit adapter.
2. Find its name with `ip -br link` (for example `eth1`).
3. Configure it as the agent network:

**Pi:**
```
sudo nmcli con add type ethernet ifname <nic> con-name agent-net ipv4.method manual ipv4.addresses 10.77.0.1/24 ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
sudo nmcli con up agent-net
ip -4 -o addr show to 10.77.0.1
```
`ipv4.never-default yes` keeps the ISP link as the only default route.

**Option B: Wi-Fi uplink, onboard Ethernet to the agent.** You do not need a USB adapter. But the Wi-Fi throughput is lower, and Wi-Fi can drop silently. Do not run `rfkill block wifi` in step 2. Your SSH session uses the onboard port. Thus, start Wi-Fi first, from that same session:

**Pi:**
```
sudo rfkill unblock wifi
sudo nmcli dev wifi connect "<ssid>" password "<password>" ifname wlan0
ip -4 -br addr show wlan0
```
From the desktop, connect with SSH to that Wi-Fi address. Then, in that new session, change the onboard port into the agent network:

**Pi:**
```
sudo nmcli con mod "Wired connection 1" connection.autoconnect no
sudo nmcli con add type ethernet ifname eth0 con-name agent-net ipv4.method manual ipv4.addresses 10.77.0.1/24 ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
sudo nmcli con up agent-net
ip -4 route show default
```
Make sure that the default route goes through `wlan0`. Then move the Ethernet cable of the Pi from the router to the agent machine. Or move it to the desktop that hosts the agent VMs.

!!! note
    If you do not control the Wi-Fi network (for example, in a cafe or hotel), read [public_wifi.md](public_wifi.md) before you continue.

## 4. Agent network values

These are the network defaults. Each software update writes them again. To keep a value across updates, put it in `/etc/pi-fortress/net.env.local` on the Pi. Put only the keys that you want to override in this file. `sudo pf tui`, **System → Settings**, writes this file for you for these keys:

- The DNS keys.
- `UNTRUSTED_UPLINK`.
- `AGENT_DNS`.
- `FAKEIP_NET`.
- The connection limits.

The TUI refuses a value that the gateway cannot use.

!!! warning
    Do not use a different agent subnet for `AGENT_NET`. The setup script and lock rules of the agent depend on these exact values.

| Key | Meaning | Default |
|---|---|---|
| `AGENT_NET` | Address range of the agent segment, in CIDR notation. CIDR notation is an IP range plus a `/prefix` that shows how many addresses the range covers | `10.77.0.0/24` |
| `PI_IP` | Address of the gateway on the agent segment | `10.77.0.1` |
| `AGENT_IP` | Static address of the first agent | `10.77.0.10` |
| `INT_IF` | Interface on the agent side. Keep it empty to detect it from `PI_IP` | empty |
| `WAN_IF` | Uplink interface. Keep it empty to detect it from the default route | empty |
| `DNS_UPSTREAM` | The resolver to which the gateway forwards queries | `9.9.9.9` |
| `DOT_AUTH_NAME`, `DOT_IPS` | Upstream for DNS over TLS (DoT: DNS queries on an encrypted connection). Set the two keys or neither. For example, `dns.quad9.net` with `9.9.9.9 149.112.112.112`. Or a Control D profile `<id>.dns.controld.com`, with the addresses that `dig +short` gives for it. Set them in `net.env.local`. When they are set, the agent, the home network, and the Pi itself all use this upstream. Then the gateway drops plain DNS that leaves the Pi. | empty |
| `AGENT_DNS` | How the gateway answers DNS queries from the agent. `forward` sends the query to the upstream resolver and gives the real address. `fakeip` never sends the query. Each name gets a stand-in address from `FAKEIP_NET`. The gateway resolves the real name itself only when the agent connects to it over HTTPS. Thus a DNS query alone cannot carry data out. With `fakeip`, SSH from the agent to an allowed host must use the IP address of the host, not its name. `fakeip` works with the WebFetch tool of Claude Code and with the common HTTP clients. Some agent tools use an SSRF-guard library that refuses private and reserved addresses. Such a tool refuses all stand-in addresses, so pin `forward` for it. After a switch from `fakeip`, agents keep old answers for up to a minute. After a switch from `forward`, agents keep old answers until their cache time ends. | `fakeip` |
| `FAKEIP_NET` | The private address range from which `fakeip` gives stand-in addresses. Use CIDR notation, from `/16` to `/24`. It must not overlap a network that the gateway is on. | `198.18.0.0/16` |
| `SLOT_WARN_REQUESTS` | Number of requests in one hour, per credential slot, before you get one alert. `0` disables it. | `3000` |
| `SLOT_STOP_REQUESTS` | Number of requests in one hour, per credential slot, before the gateway disables that slot. `0` disables it. This is the shipped setting. | `0` |
| `SLOT_WARN_UPLOAD_MB` | Uploaded megabytes in one hour, per credential slot, before you get one alert. `0` disables it. | `500` |
| `SLOT_STOP_UPLOAD_MB` | Uploaded megabytes in one hour, per credential slot, before the gateway disables that slot. `0` disables it. This is the shipped setting. | `0` |
| `AGENT_CONN_PER_IP` | Number of open connections that one agent address can hold to the gateway at the same time. Above this number, the gateway refuses and logs new connections. It never stops connections that are already open. `0` disables it. | `128` |
| `AGENT_NEW_PER_IP` | Number of new connections in one second that one agent address can open. The format is `RATE/BURST`: the steady rate, and how many connections the address can open at the same time before the rate applies. `0` disables it. | `50/200` |
| `AGENT_CONN_TOTAL` | Number of open connections that the full agent network can hold at the same time, for all of its addresses. `0` disables it. | `4096` |
| `HOUSE_CONN_PER_IP`, `HOUSE_NEW_PER_IP`, `HOUSE_CONN_TOTAL` | The same three limits for each device on the home network and for the full home network. A phone or a laptop stays well below them. A torrent client or a busy file server can need more. | `1024`, `100/500`, `32768` |
| `HOUSE_NEW_TOTAL` | Number of new connections in one second that the full home network can open, for all of its devices or addresses. The format is `RATE/BURST`. Each closed connection keeps its slot in the table for 30 seconds. Thus this limit stops many devices together from filling the table. A household with several phones, laptops, and a TV that load pages at the same time stays below it. `0` disables it. The gateway refuses a value below 100 a second. | `1000/5000` |
| `SEG_CONN_PER_IP`, `SEG_NEW_PER_IP`, `SEG_CONN_TOTAL` | The same three limits for each plain network that you add in step 8. The total is per network. They are the same as the limits of the agent network, because the agents run on the desktop on the desk network. A desktop browser with hundreds of open tabs can go above 128 connections. If pages start to fail, increase the per-device number for that network. | `128`, `50/200`, `4096` |
| `SEG_NEW_TOTAL` | Number of new connections in one second that each plain network from step 8 can open as a whole, for all of its addresses. The format is `RATE/BURST`. Like `HOUSE_NEW_TOTAL`, it stops one network from filling the table with closed connections. It is the same as the new-connection total of the agent network. That total is fixed at `300/600`. A desk with one or two computers stays below it. The file of a network can set `NEW_TOTAL` to override it. `0` disables it. The gateway refuses a value below 100 a second. | `300/600` |

### Connection limits

Each connection through the gateway uses a slot in one table. The Pi shares this table between all its networks and its own connections, SSH also. The connection limits above stop one device from filling the table. For example, a faulty agent or a home device can open connections in a loop. The gateway refuses these connections, and all other traffic continues to work. The blocked events of that device show a refused connection as `conn_limit`.

The gateway refuses a limit value that it cannot use:

- Below 16 connections per device.
- Below 64 per network.
- Below 5 new connections a second.

These values break a usual web page. They do not stop abuse.

### Spending limits per credential

The gateway counts what each credential slot uses in the last hour:

- The number of requests into which it put a live credential.
- The megabytes of request body that went out with these requests.

An agent can be persuaded to run in a loop, or to upload your repository to a different location. Such an agent shows a number far above the number for your own work.

- A **warn** sends you one alert. It changes nothing.
- A **stop** disables the slot. This is the same as `x` in **Agent network → Keys**. The agent gets the same refusal as for all disabled credentials. After you examine the problem, restore the slot with `R`. A restore also clears the hour. Thus the next request does not trigger the same limit again.

!!! note
    The two stops are off by default. This is intentional. A limit that fires on a false positive stops a working session. Only you know the normal rate of your agent. Run the gateway for one week and read the warnings. Then set the stop above that level. An apply refuses a stop that is below its own warning. Reason: that stop disables the slot before the warning tells you.

The counters are in memory. Thus a restart of the gateway starts the hour again. **Agent network → Keys** shows the last hour of each slot next to its last use.

### Headers a credential may go in

The gateway writes a live credential only into `Authorization` and `X-Api-Key`. It does this only for the hosts to which `core.hosts` binds the kind of the credential. This covers all the kinds that come with the gateway. A placeholder in a different header, for example `User-Agent` or `Referer`, makes the gateway refuse the full request. Reason: a provider logs these headers and can show them back.

If a provider wants its key in a different header:

1. Bind the kind to the host of the provider in `core.hosts.local`.
2. Name the header when you mint.

The two files are in `/opt/pi-fortress/vm/policy/`. `core.hosts.local` is your file. An upgrade replaces `core.hosts` next to it, and keeps `core.hosts.local`. (`pf apply` builds `/etc/pi-fortress/core.hosts` from the two files. Do not edit it.)

```
echo 'gitlab.com GITLAB_TOKEN' | sudo tee -a /opt/pi-fortress/vm/policy/core.hosts.local
sudo pf enroll mint --kind GITLAB_TOKEN --stdin --header PRIVATE-TOKEN
sudo pf apply
```

`--stdin` reads the token from standard input. Paste the token, push Enter, then push Ctrl-D. The token does not go into a shell argument or the shell history. Then mint adds `gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN` to `core.hosts.local` for each host that has the kind. If no host has the kind yet, mint refuses. You can never name these headers: `User-Agent`, `Referer`, `Origin`, `Host`, `Via`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `Content-*`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer` and `Proxy-*`. `pf apply` refuses a line that tries to name one.

## 5. Cable the agent

**Direct cable.** Connect a cable directly from the agent port of the Pi to the network card of the agent machine. Or bridge the network card of a VM onto that port (step 7).

**Give each agent a static address.** The agent network has no DHCP. This is intentional:

- The gateway drops all traffic from outside `AGENT_NET`.
- SSH into the agent network opens only to fixed addresses.

The first agent is `10.77.0.10/24` (`AGENT_IP`). Its gateway and DNS are `10.77.0.1`. More agents use `.11`, `.12`, and so on. On an agent with NetworkManager, run these commands. `<nic>` is the port with the cable to the Pi.

**Agent:**
```
sudo nmcli con add type ethernet ifname <nic> con-name pf-agent ipv4.method manual ipv4.addresses 10.77.0.10/24 ipv4.gateway 10.77.0.1 ipv4.dns 10.77.0.1 ipv6.method disabled connection.autoconnect yes
sudo nmcli con up pf-agent
ping -c 1 10.77.0.1
```
Without NetworkManager, set the same address, gateway, and DNS in the network settings of the distribution. The ping must answer before you can run `setup.sh` on the agent. Agents on the VLAN 20 trunk below get their addresses in the same way.

**One VLAN trunk for agent and desk traffic.** A VLAN (virtual LAN) uses tags to divide one physical cable into several separate networks. If the desktop also needs its own network through the Pi, use one cable. Divide it with 802.1Q tags (the VLAN tag standard):

- VLAN 20 for the agent segment.
- VLAN 79 as a plain segment for the desktop itself. This segment gets NAT, isolation, and the DNS and connection filters of step 8. TLS inspection and the credential fence are an option for this segment ([step 8](#the-credential-fence-on-the-desk)). NAT (network address translation) lets several devices share one address.

The commands below use `eth0` as the agent port of the Pi, as in option B of step 3. With option A, use the name of the USB adapter. Apply refuses a VLAN on the uplink.

On the Pi, add a segment file. Step 8 below explains the keys:

**Pi:**
```
sudo install -d -m 0755 /etc/pi-fortress/segments.d
sudo nano /etc/pi-fortress/segments.d/desk.env
```
```
IF=eth0.79
NET=10.79.0.0/30
IP=10.79.0.1
ADMIN=yes
```
Then move the agent address onto the VLAN. `nmcli` cannot change the type of a profile. Thus, delete the profile and add it again:
```
sudo nmcli con delete agent-net
sudo nmcli con add type vlan con-name agent-net ifname eth0.20 dev eth0 id 20 ipv4.method manual ipv4.addresses 10.77.0.1/24 ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
sudo nmcli con up agent-net
sudo pf apply --local
```
`pf apply` builds a trunk profile on the parent interface and starts the desk VLAN. You can connect with SSH into the desktop from an admin laptop on the house network. To do this, also add `SSH_FROM=<laptop address>` to the file (step 8).

!!! note
    At this point, each device that is still on the untagged cable loses its connection to the Pi. This is expected.

On the desktop side, this split needs three changes:

1. Tag the network card of the desktop into the two VLANs.
2. Move the default route of the desktop onto the desk VLAN.
3. Stop the desktop from forwarding traffic between the VLANs.

The last change is important. A desktop that forwards traffic can carry the traffic of an agent around the Pi. The desk setup script does all three changes. The script is in the desk folder of the source, which is published with the public release. On the desktop, clone the release tag that you installed (`git clone --depth 1 --branch <tag> https://github.com/praneos/pi-fortress`). Run the script from that folder. `<nic>` is the card of the desktop with the cable to the Pi. Test between the steps:

**Desktop:**
```
sudo PARENT=<nic> ./setup.sh net       # tag <nic>: VLAN 20 with no address, VLAN 79 at 10.79.0.2/30
sudo PARENT=<nic> ./setup.sh default   # move the default route to the Pi, 10.79.0.1
sudo PARENT=<nic> ./setup.sh lock      # no forwarding; nothing in or out on <nic> or VLAN 20
sudo PARENT=<nic> ./setup.sh status
```
Run `lock` last. Its forward drop also cuts all containers that are still on the default Docker bridge. This includes a sandbox in which an agent can run. To go back from any step, run `sudo pf-desk-restore`:

- `net` and `lock` install this command.
- It needs no clone and no DNS.
- It undoes `default` and `lock`, keeps the VLAN profiles, and starts the Wi-Fi uplink again.

The only uplink of the desktop must be the Pi. Disable Wi-Fi in the BIOS or remove the Wi-Fi card. Disconnect all other network cables. Traffic that leaves on a different path goes around all the rules on the Pi. Thus the lock step refuses a desktop that still has one of these paths:

- A different default route. The full tunnel or exit node of a VPN is such a route.
- Wi-Fi that is on.
- A different wired port with a route.

The lock step names each path, with the command that closes it. The `uplinks` step of the desk setup script does the same check by itself. Its `status` step includes the check. `PF_DESK_ALLOW_SECOND_UPLINK=1` makes lock continue anyway. It is for a development machine that keeps Wi-Fi as a fallback. A desk that you rely on should not need it.

The desk lock does the same check again two minutes after each boot. At that time it only warns (`journalctl -b -u pf-desk-uplink-check`, and the `status` of the desk setup script under "uplinks at boot"). To disable Wi-Fi, use `nmcli radio wifi off` or `sudo rfkill block wifi`. The command `ip link set … down` does not stay in effect after a reboot.

## 6. Install and update `pf`

A key that never touches the Pi signs each release. Connect to the Pi with SSH over its uplink (for example Wi-Fi, set in Raspberry Pi Imager). Then, on the Pi:
```
curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install.sh | sudo bash
```
From your desktop, the same command in one line: `ssh -t <user>@<pi> 'curl -fsSL https://raw.githubusercontent.com/praneos/pi-fortress/main/install.sh | sudo bash'`.

The command installs the newest release. To install one release, run `sudo PF_VERSION=v1.2.3 bash install.sh` with the script of that tag. A minimal image may not have `curl`: `sudo apt-get install -y curl`.

!!! warning "Do not connect through the agent port"
    The install gives the agent port a new address. If your SSH session uses that port, the session stops part-way. Thus `pf install` refuses an agent or house port that carries your SSH session.
`install.sh` does these steps:

1. It checks the Pi model and the OS.
2. It downloads the bundle.
3. It verifies the signature of the bundle.
4. It runs `pf install`. `pf install` proposes the uplink and agent ports and asks you to confirm them.

If you already know the ports, add `-wan eth0 -agent eth1` to the last line. You can safely run the command again. If `pf install` stops at its apply or health check, correct the cause. Then run the same command again. It applies the installed version again.

To update, give the tag. `pf install` kept the `PF_RELEASE_URL` above in `/etc/pi-fortress/release.url`. After an offline `PF_BUNDLE` install, write the URL into that file yourself first.
```
sudo pf upgrade -version v1.3.0
sudo pf upgrade -confirm
```
If an upgrade fails its own health check, it rolls back immediately. If an upgrade passes, it reverts automatically after ten minutes, unless you confirm it. Thus an upgrade that disconnects you undoes itself.

`sudo pf rollback` goes back one version manually, to the release before this one. You cannot go back further. If rollback cannot run because a different apply is running, it tells you. It then exits non-zero and keeps the pending upgrade armed. Run it again.

A rollback does not change the block lists and the other lists that you edit. An upgrade also does not change them. Thus a rollback does not undo an edit or a removal that you made after the upgrade. Always give a tag: `latest` does not match the release download paths.

`pf version` on the Pi shows the version that runs now.

## 7. Bring agents up

**A physical agent machine:** connect it to the agent port with a cable. Give it its address (step 5). Then go to the last paragraph of this step.

**Agent VMs on the desktop:**

1. Make a Linux VM in a hypervisor of your choice.
2. Install `curl` and `ca-certificates` in the VM while it still has its own path out.
3. Give the VM only one network card. Bridge it onto the desktop interface that connects to the agent port of the Pi:
    - On a direct cable, this is the card.
    - On a trunk, this is the VLAN 20 child without an address (`<nic>.20`).
4. Remove all NAT cards and second cards from the VM. Such a card is a path around the Pi.
5. In the VM, set the static address from step 5.

More agents use consecutive addresses from `AGENT_IP`: `10.77.0.10`, `.11`, `.12`. (Contributors can build the same VMs with the Vagrant lab. Its manual is published with the source.)

Then, on each agent, continue with [getting_started.md](getting_started.md) steps 2 to 4:

1. Run `setup.sh` of the agent against the gateway.
2. Check the block-test canaries.
3. Enrol and claim a credential.

## 8. Add another plain network

A plain segment is a separate network that the gateway serves, for example the desk. The gateway assumes that a machine on a plain segment can be compromised. Thus the segment gets almost the same rules as the agent network. By default, it gets no TLS inspection:

- It resolves names through the gateway, with the block lists of the agent network. The gateway refuses DNS to all other servers. It drops DNS over TLS, the known DNS-over-HTTPS servers, and QUIC.
- A new connection on any port or protocol, or a ping, goes only to an address that the DNS of the segment gave recently.
- No local addresses: the segment cannot reach the LAN of the uplink, the admin page of the router, or other private ranges, on all ports.
- The ports are the strict set of the house (web, the encrypted mail and push ports, time, ping), unless `EGRESS` sets a different value. With `strict`, outgoing SSH goes only to the addresses in `ssh_allow.ips`.
- The shared IP blacklist applies. The segment is isolated from the agents, the house, and other segments.

Without `INSPECT=on`, a plain segment does not get:

- TLS inspection.
- A check of the site name that a connection sends.
- Credential substitution.

Thus keep live credentials off a desk, or turn on [the credential fence on the desk](#the-credential-fence-on-the-desk).

To add a segment, put a file in `/etc/pi-fortress/segments.d/`. Give the file the name of the segment. These names are not permitted:

- `house`, `agent`, `pi`, or `broker`.
- Two names that are different only by `-` and `_`.

**Pi:**
```
sudo nano /etc/pi-fortress/segments.d/<name>.env
```

| Key | Required | Meaning |
|---|---|---|
| `IF` | yes | Interface. For an 802.1Q VLAN child, use `parent.id` |
| `NET` | yes | Address range of the segment, in CIDR notation |
| `IP` | yes | Address of the gateway in `NET` |
| `ADMIN` | no, default `no` | `yes` opens rate-limited SSH to the gateway from this segment. Apply refuses it on the cable of the house port (below) |
| `SSH_TO` | no | An address or range in `AGENT_NET` that this segment can reach on TCP 22. Apply refuses it on the cable of the house port (below) |
| `BLOCK_DIRECT_IP` | no, default `on` | `off` stops the drop of new connections to an address that the DNS of this segment did not give recently. Set it to `off` only for software that connects to addresses that it got from a different source. An example is the relays of a mesh VPN |
| `EGRESS` | no, default `strict` | `strict` allows web, the encrypted mail and push ports, time, and ping. It drops other ports. `audit` logs what `strict` would drop, but lets it through. Use `audit` for one day first. `open` allows all ports |
| `ALLOW_PORTS` | no | More ports for `strict`, for example `"tcp:5000-5002 udp:3478"`. Use plain decimal. Apply refuses a leading zero or `+` |
| `SSH_FROM` | no | One address that can open SSH into this segment, for example your admin laptop on the house network. The segment can never open a connection back to it. This SSH path is not reachable from the uplink or the agent network. Apply refuses the address of an agent. The SSH connection arrives only on the house interface or on the interface of a different plain segment. It never arrives on the WireGuard tunnel. When `WG_IF` is set, the house can still reach it |
| `CONN_PER_IP`, `NEW_PER_IP`, `CONN_TOTAL`, `NEW_TOTAL` | no, default the `SEG_` values from step 4: `128`, `50/200`, `4096`, `300/600` | The connection limits of this network, one key at a time. `0` disables one limit |
| `DNS_TYPES` | no | The DNS of the segment answers only with addresses. It refuses names that have the shape of a key, as the agent network does. List the record types that the software of the segment needs, for example `"SRV TXT MX"`. Chat, single sign-on, or mail clients can query these types |
| `DHCP` | no, default `off` | `on` makes the gateway lease addresses on this segment, from `DHCP_START` to `DHCP_END`. Each device gets `IP` as its router and DNS server, and a 12-hour lease. The house gets the same service. Use it for devices that cannot use a static address, for example IoT devices on a VLAN per SSID. It is permitted on the cable of the house port. The access point must not run its own DHCP on that SSID (in AP mode, it does not) |
| `DHCP_START`, `DHCP_END` | with `DHCP=on` | The first and the last address to lease, in `NET`. Apply refuses a range that includes `IP`, or the network or broadcast address of `NET`. It also refuses a range that goes backwards. Set the two keys or neither |
| Reservations | no | This is not a key. It is a file: `/etc/pi-fortress/dhcp.<name>.hosts`. It has one `mac,ip,name` line per device. The name is optional. `#` starts a comment. The format is the same as `house.hosts`. Each device always gets its address, in the `DHCP_START`–`DHCP_END` range or outside it. Apply refuses a malformed MAC, an address outside `NET`, `IP` itself, and the network or broadcast address of `NET`. It also refuses a MAC or address that is in the file two times, and all reservations while `DHCP` is off. `pf backup` includes the file, as it includes `house.hosts` |
| `INSPECT` | no, default `off` | `on` gives this segment the credential fence of the agent network. All TCP 443 of the segment goes to the engine and the broker. The machines of the segment must trust the gateway CA first. Apply refuses it on the cable of the house port, and with `BLOCK_DIRECT_IP=off`. With `ADMIN=yes`, apply warns. Refer to [the credential fence on the desk](#the-credential-fence-on-the-desk) |
| `PARANOID` | no, default `off` | `on` makes the DNS of the segment answer only the names in `/etc/pi-fortress/allow.<name>.domains`. The file has one name per line, and each name includes its subdomains. All other names get the blocked answer. This key is separate from `PARANOID` of the agent network. When apply first sees the segment, it makes this file with the Anthropic names. Thus Claude Code continues to work. Apply refuses `on` while the file is missing or empty, or with `BLOCK_DIRECT_IP=off` |

**Pi:**
```
sudo pf apply --local
```
The name must match `^[a-z][a-z0-9_-]{0,15}$`. Apply refuses a bad name, key, or address. It also refuses an interface or network that overlaps `INT_IF`, `WAN_IF` or another segment. It also refuses a segment on a VLAN of the uplink, for example `eth0.30` when `WAN_IF=eth0`. It tells you the file and the line.

The uplink can itself be a VLAN, for example an ISP VLAN such as `WAN_IF=eth0.35`. Then all of its cable belongs to the uplink. Apply then also refuses a segment, `INT_IF`, or `HOUSE_IF` in these locations:

- On a sibling VLAN of the uplink (`eth0.30`).
- Untagged on its parent (`eth0`).

Correct the file and apply again.

A segment can also be a VLAN on the house port. Use one VLAN per SSID of a Wi-Fi access point that tags each SSID. For example, use `IF=eth1.30` for an IoT network next to `HOUSE_IF=eth1`. These tags are only as strong as the access point. A device on any SSID, or a compromised access point, can tag its traffic into any VLAN on that cable. Thus, for a segment that shares the cable of the house port, apply:

- Refuses `ADMIN=yes` and `SSH_TO`.
- Refuses the agent network on that cable completely.
- Warns on each apply that the segment is only as isolated as the access point or switch.

`SSH_FROM` is still permitted. `DHCP=on` is also permitted, because most IoT devices need it. The [VLAN tutorial](tutorials/02-vlan-segments.md) has the example and the reasons.

When the segment exists, `sudo pf tui` has a menu entry for it. The entry has the same Devices, Filtering, Activity, and Settings as the other networks:

- **Filtering** shows the lists of the agent network, read-only. A segment resolves with these lists.
- In **Settings**, Enter changes the value of `ADMIN`, `BLOCK_DIRECT_IP`, `PARANOID`, and `DHCP`. For `SSH_TO`, Enter asks for a value.
- Enter on one end of the DHCP range asks for the two ends, because apply refuses one end without the other. Thus set the range before you set `DHCP` to on.
- The TUI refuses a value that apply would refuse. It then does not change the file.
- With `DHCP` on, the row below it gives the name of the reservations file. You edit this file manually.
- `A` runs the `apply --local` that makes the change take effect.
- When you set `ADMIN` to off, the TUI asks you first. Reason: your session often comes in through that same segment.
- The TUI shows `IF`, `NET`, and `IP`, but you cannot edit them there. To move a segment, you must also change the machine at the other end of the cable. Thus a move stays an edit to the file and a reboot.
- **Activity** has a **New destinations** tab. It shows each destination that a device on the segment reached for the first time. The name comes from the DNS of the segment. A query that has a key, or that looks like a DNS tunnel, makes an alert, as on the agent network.

To remove a segment, delete its file and apply:

**Pi:**
```
sudo rm /etc/pi-fortress/segments.d/<name>.env
sudo pf apply --local
```
Apply then:

- Removes the firewall rules and the DHCP server of the segment.
- Deletes the `seg-<name>` NetworkManager profile that it made. Thus the interface releases the address of the segment.
- Prints one `pruned NetworkManager profile` line for each profile.

When you move a segment to a different `IF`, apply does the same to the old profile before it makes the new profile. It does not change other connections.

A segment that was untagged on its own port, for example `IF=eth2`, leaves an inert `pf-parked-eth2` profile on that port. This profile has no address, no DHCP, and no route. Thus the Pi never asks the device on that port for an address or a default route. Apply tells you this in one line. Apply removes the profile again when a segment, the house, or the agent network uses that port. Apply removes a VLAN child, for example `eth1.30`, completely. The allowlist and reservations files of the segment, next to `segments.d`, are your files. They stay until you delete them.

One exception prevents a lockout. An SSH session into the Pi can come through the profile that apply would delete. For example, you remove or move the desk while you are logged in over the desk. Then apply keeps that profile, prints a warning, and still succeeds. The firewall rules of the segment have already changed. Thus:

1. Keep the session open.
2. Get access in a different way (the house admin device, or a keyboard on the Pi).
3. Remove the profile manually with `sudo nmcli con delete seg-<name>` and `sudo pf apply --local`.

The [FAQ](faq.md) ("What breaks on the desk?") lists what a strict desk breaks, and the key that repairs each problem.

### The credential fence on the desk

With `INSPECT=on` in the file of the desk, the desk gets the fence of the agent network. All HTTPS of the desk goes through the engine and the broker. The tools on the desk hold placeholders. The gateway puts in the real key only for the service of that key, and it removes live keys in known formats. Thus an agent that escapes to the desk finds no real keys there.

The Pi must run a release that has the `INSPECT` key. An older release refuses the key with `unknown key 'INSPECT'` and changes nothing. If you see that, update `pf` first ([step 6](#6-install-and-update-pf)).

1. Copy the certificate of the gateway CA to a file that your user can read on the Pi. Copy only the certificate. The key of the CA stays on the Pi. `-t` gives `sudo` a terminal, so that it can ask for your password. Write down the sha256 that the command shows.

    **Desktop:**
    ```
    ssh -t <user>@10.79.0.1 'sudo install -m 0644 /var/lib/pi-fortress/engine/ca-cert.pem /tmp/pf-ca.pem && sha256sum /tmp/pf-ca.pem'
    ```
    Do not use `ssh <user>@10.79.0.1 sudo cat ... > pf-ca.pem`. Without a terminal, `sudo` cannot ask for the password. The command then fails and leaves an empty file.

2. Copy the file to the desktop. Then remove the copy on the Pi. The copy belongs to root, thus the removal needs `sudo`.

    **Desktop:**
    ```
    scp <user>@10.79.0.1:/tmp/pf-ca.pem ~/pf-ca.pem
    ssh -t <user>@10.79.0.1 sudo rm /tmp/pf-ca.pem
    sha256sum ~/pf-ca.pem
    ```
    The sha256 must be the same as in step 1. The file must start with `-----BEGIN CERTIFICATE-----`.

3. Install the certificate on the desktop. Use the desk setup script from the source, and the sha256 from step 1. Run it with `sudo` from your own user, not from a root shell. If not, Chrome does not get the certificate. For Chrome and Chromium, first install `certutil` (`sudo apt install libnss3-tools`).

    **Desktop:**
    ```
    sudo ./setup.sh ca ~/pf-ca.pem <sha256>   # in the desk folder of the source
    ```
    The step refuses a file that holds a private key, a certificate that is not a CA, and a wrong sha256. Each line of its output tells you one location:

    | Output line | Meaning |
    |---|---|
    | `system store: /usr/local/share/ca-certificates/pi-fortress-desk.crt` | Go, curl, git, and the Python `ssl` module trust the gateway CA |
    | `environment: /etc/profile.d/... (shells), /etc/environment.d/... (desktop apps)` | `NODE_EXTRA_CA_CERTS` for Node. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `PIP_CERT` for Python `requests`, `httpx`, and `pip`. Log out and log in again to get them |
    | `Chrome and Chromium: added to ~/.pki/nssdb` | Chrome and Chromium trust the gateway CA. Restart the browser |
    | `Chrome and Chromium: install libnss3-tools (certutil) and run this again` | Chrome and Chromium do not trust the CA yet. Install `libnss3-tools`, and run step 3 again. The step is safe to run again |
    | `Firefox: policy /etc/firefox/policies/policies.json` | Firefox trusts the gateway CA after a restart |
    | `Firefox: ... has other policies` | You already have a Firefox policy file. Add `/etc/pi-fortress/desk-ca.pem` to `Certificates.Install` in that file |
    | `Java and tools with their own roots need the CA in their own store` | Import `/etc/pi-fortress/desk-ca.pem` into each such store manually |

    The certificate has no effect until you set `INSPECT=on` in the next step. To remove all of it, run `sudo ./setup.sh ca-remove` in the desk folder of the source.

4. Turn on the fence. Do step 3 first: without the CA, all HTTPS from the desk fails.

    **Pi:**
    ```
    sudo sed -i '/^INSPECT=/d' /etc/pi-fortress/segments.d/desk.env && echo INSPECT=on | sudo tee -a /etc/pi-fortress/segments.d/desk.env
    sudo pf apply --local
    ```
    Then, on the desktop, make sure that HTTPS goes through the gateway. The output must show `issuer: CN=pi-fortress`:

    **Desktop:**
    ```
    curl -sv -o /dev/null https://example.com 2>&1 | grep issuer
    ```

5. Enrol each key on the gateway ([getting started](getting_started.md), step 3). The claim code of step 4 there is for an agent, because it also runs the setup of the agent. On the desk, put the placeholder `pf_<slot>_<KIND>` (`sudo pf enroll list`) in the tool, in the place of the real key. Examples:

    - An environment variable: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`.
    - git: `https://x-access-token:pf_<slot>_GITHUB_TOKEN@github.com` in `~/.git-credentials`.
    - A Claude subscription: copy `~/.claude/.credentials.json` from an agent that claimed the slot. The file holds only placeholders.

6. Delete the real keys from the desk. Revoke each key that was on the desk before, and enrol a new one.

To turn the fence off:

**Pi:**
```
sudo sed -i 's/^INSPECT=on/INSPECT=off/' /etc/pi-fortress/segments.d/desk.env && sudo pf apply --local
```
To remove the CA from the desktop, run `sudo ./setup.sh ca-remove`.

Know these points:

- With `ADMIN=yes` on the desk, apply warns. The SSH key of the desk for the Pi can read all real keys on the Pi. Protect that key with a hardware key (`ssh-keygen -t ed25519-sk`) or a passphrase.
- `pf-desk-restore` restores the route of the desktop. It does not restore its keys. When the Pi is down, the placeholders do not work. Use a different device for an urgent login.
- The fence logs of the desk include the host, the method, the path, and the header names of unknown servers. They never include bodies or header values.
- The paranoid mode and the fake-IP of the agent network do not apply to the desk. The desk uses its own `PARANOID` key.
- For what breaks, refer to the [FAQ](faq.md#desk-tls-inspection).

## 9. Check it works

| Where | Command | Good result |
|---|---|---|
| Agent | `dig example.com` | Resolves |
| Agent | `curl -I --max-time 10 https://example.com` | `200`, no certificate warning |
| Agent | `dig pi-fortress-block.test` | `0.0.0.0`, the blocklist canary |
| Agent | `curl --max-time 5 https://192.0.2.1` | Times out, direct IP denied |
| Agent | `curl --max-time 5 https://1.1.1.1` | Times out, DoH resolver pinned out |
| Pi | `sudo pf status` | Interfaces, rules and services all up |
| Pi | `sudo pf observe once` | Shows the recent DNS and connections of the agent |
| Pi | `ss -lntup \| grep -E ':(53\|80\|8080) '` | Each binds a gateway address such as `10.77.0.1`, never `0.0.0.0` |

!!! warning
    The bootstrap that installs the certificate authority on the agent uses plain HTTP, because the agent does not trust the gateway yet. Thus, use a direct cable or an isolated VLAN for that link. Never use a shared switch. A different device on the same broadcast domain can serve a forged certificate. A broadcast domain is the set of devices that can see the raw traffic of each other.

## 10. Daily loop

Policy changes and list changes need only a new apply, not a software update:

**Pi:**
```
sudo pf apply --local
sudo pf observe once
sudo pf monitor show -n 5
```

A new version of `pf` itself comes as an update from us.

`sudo pf tui` does the same things with menus:

- Select a network.
- Use Left and Right to move between its sections.
- Use Tab to move between its lists or logs.

The TUI highlights the current section and tab. Right from the last section goes to the first section. Left from the first section goes back to the menu.

| Menu | Sections |
|---|---|
| Overview | "All good" or what needs attention, then devices and blocks today per network |
| Agent network | Devices · Filtering · Activity · Settings · Keys (slots, claim codes, quarantine) |
| Home network | Devices · Filtering · Activity · Settings |
| each segment you added | Devices · Filtering · Activity · Settings |
| System | Health · Settings (the Pi's own DNS, untrusted uplink, agent DNS mode and fake-IP range, connection limits) · Feeds · Admin log · Actions |

The TUI saves an edit immediately. The edit takes effect at the next apply. The footer shows this until you push `A`. `A` runs the apply that the edit needs. It shows the output on System → Actions.

## 11. Seat

You can use the Pi with a keyboard and screen instead of SSH. To do this, add `consoleblank=600` to the single line in `/boot/firmware/cmdline.txt`. Then the screen does not go blank during use. Log in and run:

**Pi:**
```
sudo pf tui
```
`q` closes the TUI. When you log out, the seat locks.

## 12. Do not

!!! warning
    - Do not give the agent interface of the Pi a gateway or DNS server, or name it in a blocklist or allow list. (The agent machines do use the Pi as their gateway and DNS, step 5.)
    - Do not manage the gateway from the agent side. From the agent side, only DNS (53), the certificate server (80), the gateway engine (8080), and ping reach the Pi. The gateway drops all other traffic.
    - Do not put the certificate-authority bootstrap of the agent on a shared switch.
    - Do not leave the Pi where other persons can take it. The SD card holds the live credentials and the gateway CA key. They are not encrypted, unless you seal the store (`pf enroll seal`, refer to the [FAQ](faq.md)). If the card is lost, revoke and re-enrol each credential, replace the gateway CA, and run `setup.sh` again on each agent.

## 13. Troubleshooting

| Symptom | Check |
|---|---|
| `no interface holds PI_IP` or `no default route, so WAN_IF is empty` | You did not do step 3, or the uplink cable is down |
| `pf missing` | There is no `pf` binary on the Pi. Run `install.sh` again (step 6) |
| Agent cannot reach the gateway | The agent needs a static address in `10.77.0.0/24`, with `10.77.0.1` as gateway and DNS (step 5). On the Pi, `ip -4 -o addr show to 10.77.0.1` must show the agent port |
| VLAN child loses its address after reboot | A different profile took the parent interface back. Check with `nmcli -t -f NAME,FILENAME con show`. Then run `sudo pf apply --local` again |
| Untagged frames get dropped after a VLAN split | This is expected: the parent interface is trunk-only now. Bridge VMs onto the tagged child, not the parent |
| Desktop cannot reach the Pi after the VLAN split | Make sure that the desktop has its desk VLAN address. Then ping the desk address of the Pi, and check `sudo pf status` on the Pi |
| Segment file is refused | `pf apply` names the file and the line. Correct the name pattern, the `ADMIN` value, or an overlapping `NET`/`IF`. Then apply again |
| Every lookup on one network gets `REFUSED`, the others work | The lists of that network did not load when `pf dns` started. Thus only that network answers nothing. `sudo pf apply --local` names the file that does not load. Correct it and apply again |
| Desk `setup.sh lock` refuses with `SECOND UPLINK` | The desktop has a different path out (step 5). Close each path that the message names. Then run lock again |
| A desk app or site fails while the Pi is fine | Refer to the [FAQ](faq.md), "What breaks on the desk?" |
| `sudo: a terminal is required to read the password` when you copy the CA | `ssh host sudo ...` gives `sudo` no terminal. Use `ssh -t`, as in [the credential fence on the desk](#the-credential-fence-on-the-desk), step 1. The failed command leaves an empty `pf-ca.pem`: do not use it |
| `rm: cannot remove '/tmp/pf-ca.pem': Operation not permitted` | The copy belongs to root. Use `ssh -t <user>@10.79.0.1 sudo rm /tmp/pf-ca.pem` |
| `setup.sh ca` refuses: `holds a private key` | You copied `ca.pem`, which holds the CA key. Delete that copy now. Copy `ca-cert.pem` |
| `setup.sh ca` refuses: `does not match the sha256` or `must hold one certificate` | The copy is not complete, or it is a different file. Do steps 1 and 2 again |
| `unknown key 'INSPECT'` from apply | The Pi runs an older release. Update `pf` (step 6). Nothing changed on the Pi |
| All HTTPS on the desk fails after `INSPECT=on` | The desk does not trust the gateway CA. Do step 3 of the desk fence, then log out and log in again. To get HTTPS back immediately, set `INSPECT=off` and apply |
| One tool fails TLS after `INSPECT=on`, the browser works | The tool has its own certificate store. For Node, open a new login session, so that it gets `NODE_EXTRA_CA_CERTS`. For Java, import `/etc/pi-fortress/desk-ca.pem` into its store. An app that pins its certificate cannot work through the fence |
| Chrome shows a certificate error, Firefox works | Chrome did not get the CA. Install `libnss3-tools`, and run `setup.sh ca` again with `sudo` from your own user. Then restart Chrome |
