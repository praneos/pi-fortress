<!-- How to run Pi Fortress for the first time: a Pi 5, a gateway VM or a lab, enrol a credential, watch it work. -->
# Getting started

You can run Pi Fortress on a Pi, on a Debian or Ubuntu VM, or in a lab. All ways use the same binary and the same policy files. The only difference is how difficult it is for the agent to escape.

| Way | Description | How to start | Escape requires |
|---|---|---|---|
| Pi 5 | A Raspberry Pi 5 on the cable between the agent machine and your uplink. Full steps: [pi_setup.md](pi_setup.md) | Build `pf` from the latest stable tag and install it with `install.sh`: [pi_setup.md](pi_setup.md), step 6. | Physical access |
| Gateway VM | A Debian or Ubuntu VM next to the agent VM. The two VMs share a virtual network. No other machine is on that network: [below](#gateway-on-a-debian-or-ubuntu-vm) | Build `pf` from the latest stable tag and install it with `install.sh`, as on the Pi. | A hypervisor break |
| Cloud lab, for testers and contributors | The Pi, a home device, a desktop seat and agents, all as VMs on one Linux host with KVM, in the cloud or local. It runs the same end-to-end tests as a real Pi | One command from a clone of the source, with the cloud lab guide (`docs/cloud_lab.md`) | A hypervisor break |
| Vagrant lab, for testers and contributors | Two VirtualBox VMs on a laptop: a gateway VM and an agent VM. An internal network connects them | From a clone of the source, with the lab manual (`docs/lab.md`) | A hypervisor break. The VirtualBox NAT adapter is the virtual router that gives a VM internet access. The hypervisor disconnects this adapter when `vagrant ssh` works without it. The path for `vagrant ssh` is through the Pi, with `AGENT_BRIDGE` set, or through a host-only management network interface (`vboxnet0`, `192.168.56.0/24` by default) |

!!! note "Open evaluation"
    The fastest way to evaluate Pi Fortress is the cloud lab: one command, no hardware. Use test keys, or keys with a spend limit, while you evaluate.

Pi Fortress has no binary releases yet. Release builds start at v1, when the project is stable. Until then, you build `pf` from the latest stable tag. The project signs each stable tag ([Verify the source](verify.md)). You sign the bundle with your own SSH key. `install.sh` does these steps:

1. It examines the machine.
2. It verifies the bundle against your key.
3. It starts `pf install`.

## Prerequisites

**Pi 5:**

- A Pi 5 (4 GB is sufficient).
- The official 27 W USB-C power supply.
- A 32 GB A2 microSD card, or an NVMe HAT (an SSD add-on board for the Pi).
- Raspberry Pi OS Lite 64-bit.
- A USB 3 gigabit Ethernet adapter (RTL8153 or RTL8156 chipset), if the onboard port is your uplink.
- A cable from the agent machine to the agent port of the Pi.

**Gateway VM:** an amd64 host that can run two VMs. For the gateway VM: Debian 12 or 13, or Ubuntu 24.04.

**Cloud lab:** a Linux host with `/dev/kvm` (bare metal, or a cloud VM with nested virtualisation), 8 GB RAM and approximately 100 GB of disk. The lab installs KVM, libvirt and Vagrant. It also makes its own networks on the host. Thus, use a machine that you can dedicate to the lab.

**Vagrant lab:** a Linux host with VirtualBox and Vagrant. The lab uses a `bento/debian-12` box. It does not change the firewall, DNS, or routes of your host.

**Agent side, all ways:** a Linux machine or VM. Its only network path must be the gateway.

- The enrolment script supports Ubuntu/Debian, Fedora/RHEL/Rocky/Alma/Amazon Linux, Arch, and openSUSE.
- It does not support NixOS or Alpine.
- Install `curl` and `ca-certificates` on the agent machine **before** you put it behind the gateway. If you do not, its package mirrors fail TLS inspection until the agent trusts the gateway CA. TLS is the encryption of HTTPS. CA means certificate authority.

## Gateway on a Debian or Ubuntu VM

`install.sh` also installs on Debian 12 or 13, or Ubuntu 24.04, on amd64. Thus the gateway can be a VM next to the agent VM, instead of a Pi.

- Give the gateway VM two network cards:
    - One card with internet access (NAT or bridged). This card becomes the uplink.
    - One card on a virtual network. Only the gateway VM and the agent VM are on this network. The network has no host address, no DHCP and no NAT. VirtualBox calls this an internal network. In libvirt, it is an isolated network with no IP.
- Give the agent VM one network card, on the same virtual network. First install `curl` and `ca-certificates` in the agent VM, while it still has a path out. Then remove all other cards.
- On the gateway VM, install as on the Pi ([pi_setup.md](pi_setup.md), step 6). You can give the names of the two cards: `-wan <uplink> -agent <isolated>`.

Then do the steps below. Follow the steps for the **Pi**. To escape, the agent then needs a hypervisor break, as in the labs.

## The first ten minutes

Steps with the mark **lab** apply to the two labs. Steps with the mark **Pi** apply to a Pi, or to a gateway VM that you installed with `install.sh`. All steps below assume that `pf` is already installed on the gateway.

### 1. Bring the gateway up

**Pi:**

1. Flash the card and install `pf` from the latest stable tag ([pi_setup.md](pi_setup.md), steps 2 and 6).
2. The installer proposes the uplink port and the agent port. It asks you to confirm them. Steps 3 to 5 in that page explain these choices and how to change them.
3. Make sure that the Pi answers `sudo pf status`.
4. Connect the agent machine to the agent port with a cable. Or bridge an agent VM onto the agent port (step 7 in that page).
5. Give the agent its address, as follows.

**Give the agent a static address.** The agent network has no DHCP. This is intentional:

- The gateway drops all traffic from outside `10.77.0.0/24`.
- SSH into the agent network is open only to fixed addresses.

The first agent is `10.77.0.10/24`. Its gateway and DNS server is `10.77.0.1`. More agents use `.11`, `.12` and so on. On an agent with NetworkManager, `<nic>` is the port that connects to the gateway:
```
sudo nmcli con add type ethernet ifname <nic> con-name pf-agent ipv4.method manual ipv4.addresses 10.77.0.10/24 ipv4.gateway 10.77.0.1 ipv4.dns 10.77.0.1 ipv6.method disabled connection.autoconnect yes
sudo nmcli con up pf-agent
ping -c 1 10.77.0.1
```
If the agent does not have NetworkManager, set the same address, gateway and DNS in the network settings of the distribution. The ping must answer before step 2.

**Lab:** follow the cloud lab guide or the lab manual (published with the source). At the end, the gateway and the agent VM are on an internal network. They have no other route out. The address of the agent is already set.

After you have a Pi, a change to a policy or a list needs a reload, not a rebuild: `sudo pf apply --local`. For more information, refer to [pi_setup.md](pi_setup.md), "Daily loop".

### 2. Put the agent behind the gateway and prove it

First, read the two hashes on the gateway itself, at its console or over SSH. Never read them from the agent:
```
sudo sha256sum /var/lib/pi-fortress/www/setup.sh /var/lib/pi-fortress/www/ca.pem
```
Then run these commands on the agent. `<SETUP_SHA>` and `<CA_SHA>` are the two hashes.

- **Lab:** use `vagrant ssh agent`, or `lab.sh ssh agent` in the cloud lab.
- **Pi:** use the agent machine.

The lab VM also has a separate `agent` account for the work of the agent. This account has no `sudo` access, unless the VM was made with `AGENT_SUDO=1`.
```
curl -fsSo /tmp/pf-setup.sh http://10.77.0.1/setup.sh
echo '<SETUP_SHA>  /tmp/pf-setup.sh' | sha256sum -c && sudo bash /tmp/pf-setup.sh 10.77.0.1 <CA_SHA>
dig example.com                       # resolves
curl -I --max-time 10 https://example.com   # 200, through the gateway's TLS
dig pi-fortress-block.test            # 0.0.0.0: the blocklist canary
curl --max-time 5 https://192.0.2.1   # times out: direct IP denied
curl --max-time 5 https://1.1.1.1     # times out: DoH resolver pinned out
```
`setup.sh` does these steps:

1. It installs the gateway CA. The CA is the credential that lets the gateway examine encrypted HTTPS traffic.
2. It pins DNS to the gateway.
3. It disables IPv6 and Wi-Fi, if they are present.
4. It locks the machine. Only DNS, the CA server, and ping to the gateway can go out. TCP ports 443 and 22 can go out only on the agent network. Traffic to the internet goes through the gateway. Traffic to a different agent on the same segment goes directly to that agent.
5. It examines `https://pf-open-echo.test/` to prove that inspection works. The gateway itself answers this echo endpoint.

The last check above fails because the gateway also pins out DoH. DoH (DNS over HTTPS) sends DNS queries inside HTTPS.

!!! warning
    The script and the CA come over plain HTTP, because the agent does not trust the gateway yet. The hashes make this safe. The hashes come from the gateway over a channel that the agent network cannot touch. Thus a second machine on the agent network that answers for the gateway address cannot replace the script or the CA. `sha256sum -c` refuses a replaced script. `setup.sh` refuses a CA that does not agree with `<CA_SHA>`. But keep this path a direct cable or the internal network of the lab. Never use a shared switch.

### 3. Enrol a credential

The gateway mints (makes) the live credential values. The agent never mints them. Each credential gets a 16-hex **slot** ID. The agent sees only a placeholder in the format `pf_<slot>_<KIND>`.

**Lab:** run `vagrant ssh pi` (cloud lab: `lab.sh ssh pi`). Then run the mint command. Paste the access token and the refresh token on two lines, then push Ctrl-D:
```
sudo pf enroll mint --kind CLAUDE --stdin
sudo pf enroll list
```
**Pi:** run this from your workstation. The tokens do not go in a shell argument.

- Put the access token on line one and the refresh token on line two.
- `pbpaste` is for macOS. On Linux, use `wl-paste` or `xclip -o -selection clipboard`.
```
pbpaste | ssh <user>@<pi> sudo pf enroll mint --kind CLAUDE --stdin
```
These are the kinds at this time:

- `CLAUDE_OAT`/`CLAUDE_ORT`. You mint them together, as `--kind CLAUDE`.
- `ANTHROPIC_API_KEY`
- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `XAI_API_KEY`
- `CANARY`. This is a tripwire credential. By default, it is bound to no host. The capture-the-key rules are published with the public release.

A slot expires after 90 days, unless you give `--expires 30d`, an RFC 3339 time (for example `2027-01-31T00:00:00Z`), or `none`. In the last seven days, the gateway sends a daily warning to your alert webhook. To extend a slot, run `sudo pf enroll renew --slot <slot> --expires 90d`. The live values stay in `/etc/pi-fortress/broker/secrets.env` on the gateway, with mode 0600. The broker user owns this file.

### 4. Hand the agent a placeholder with a claim code

1. On the gateway, run `sudo pf tui`. This is a text menu in the terminal.
2. Open **Agent network → Keys**.
3. Select the slot.
4. Press `c`.

You get a code of eight characters. The code is valid for five minutes, and you can use it one time only. You also get three lines. Paste all three lines on the agent:
```
h=<the claim script's sha256, computed by the gateway>
f=$(mktemp) && curl -fsSo "$f" http://10.77.0.1/claim/<CODE> &&
echo "$h  $f" | sha256sum -c && sh "$f"
```
The hash is the reason for the extra lines:

- The claim script comes over plain HTTP. It runs only if it is the script that the gateway serves.
- The claim script contains the hashes of `setup.sh` and the CA. Thus a claim does not need you to read the hashes as in step 2.
- If `sha256sum` reports `FAILED`, a different machine answered for the gateway address. The code is then used. Find the cause before you make a new code.

The claim script writes `~/.claude/.credentials.json` and `~/.pi-fortress/env.sh`. These files contain only placeholders. Claude Code now starts with a credential that is a real credential only behind this gateway.

### 5. Watch a placeholder leave and a substituted request arrive

**Lab only.** The lab gateway runs a core echo at `https://pf-core-echo.test/`. This echo reports what it received. A real Pi does not serve it. From the agent, with a slot that you minted, run:
```
curl -sS -H 'Authorization: Bearer pf_<slot>_CLAUDE_OAT' https://pf-core-echo.test/
```
The reply contains `"substituted": true`. This shows that the placeholder left the agent and the live value arrived at the origin server.

The gateway refuses a request in these conditions:

- The slot does not exist.
- The placeholder goes to a host that must not carry that kind.

The response is a `503` with `Retry-After: 60`. The body does not give the cause. The gateway does not forward the request.

On a Pi, you can see the same result indirectly. Run the agent against `api.anthropic.com`. Then look at the "last used" column in **Agent network → Keys**.

### 6. See a stripped token alert

From the agent, send a live-looking token to a non-core host. All gateways serve `pf-open-echo.test`, in the lab and on the Pi:
```
curl -sS -H 'Authorization: Bearer sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' https://pf-open-echo.test/
```
The reply reports `"stripped": true`. The gateway removed the token before the request continued.

On the gateway (in the lab, after `vagrant ssh pi`), run:
```
sudo pf alert show
sudo pf alert watch
```
To also get an alert on your phone:

1. Put an ntfy, Slack, or Discord webhook URL in `/etc/pi-fortress/alert.url`.
2. Run `sudo pf apply --local`.

The webhook carries the host, the location, and the rule. It never carries the token. It sends a maximum of 30 alerts in one hour, plus a maximum of 30 more about keys and credentials. If there are more alerts, one message at the end of the hour gives the number and the kind of the alerts that it held back. `pf alert show` still has all of them.

On a Pi, the same webhook also gets a message when memory or CPU pressure is high, and one at each boot, which also tells if the boot before ended without a clean shutdown. Refer to [Pressure alerts and the hardware watchdog](pi_setup.md#pressure-alerts-and-the-hardware-watchdog).

The webhook also gets a digest of the blocked requests to listed destinations, a maximum of one each 30 minutes. Ad and tracker blocks on the house segment do not cause a digest. Refer to [Block digest](pi_setup.md#block-digest).

### 7. Look at what the agent actually hit

```
sudo pf observe once               # on the gateway
sudo tail -n 50 /var/log/pi-fortress/dns.jsonl
```
The gateway does not block unknown origin servers. It only logs them. Each unknown origin server gets a line in `/var/log/pi-fortress/unknown.jsonl`. The line has:

- The host, method, path, and header names.
- A shortened `User-Agent` and `Content-Type`.
- The `Authorization` scheme, without its credential.
- The cookie names, without their values.

The gateway does not log other header values or bodies. Thus you can see where a new tool went, but you do not see what it sent.

## Revoking

To revoke a slot, use one of these methods on the gateway:

- Run `sudo pf enroll delete --slot <slot>[,<slot>...]`.
- In the TUI, press `x` on the slot to quarantine it immediately. Press `R` to restore it.

A quarantined slot is eligible for purge after seven days. The next full `pf apply` purges it. `pf apply --local` does not purge. No timer does this. Thus a machine where you never run a full `pf apply` keeps the row. You do not need to search the agent disks for anything.
