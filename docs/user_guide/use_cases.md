<!-- Five concrete ways to use Pi Fortress, each with setup, what it protects and what it does not. -->
# Use cases

Each scenario below has three parts:

- The setup.
- What the gateway protects.
- What the gateway does not protect.

The "protects" part never adds new rules. It applies the rules in [architecture.md](architecture.md) to that setup.

## 1. A solo developer running Claude Code, Cursor or Codex with live keys

**Setup:**

- Put the agent in a VM or a machine behind the gateway.
- Mint your Claude tokens or API key on the gateway: `sudo pf enroll mint --kind CLAUDE ...`
- Make a claim code and run the one-line command on the agent. It writes `~/.claude/.credentials.json` with a placeholder, not a live credential.

**Protects:**

- The agent never has a live token. A hijacked session, a malicious dependency, or a stolen VM image cannot take your subscription or key to a different location.
- If a token in a known format goes to a different host, the gateway strips it and sends you a notification.
- GitHub tokens get the same protection for `github.com` and `api.github.com`.
- One command revokes a credential.

**Does not:**

- Stop the agent when it calls `api.anthropic.com` with your own credential. You must still monitor the spend and the quota.
- Stop the agent when it sends the contents of your repo to the vendor inside a prompt.
- Work with a tool that uses only HTTP/2, or that pins its own certificate. Claude Code works because it negotiates HTTP/1.1, the older and simpler version of HTTP.

## 2. A small team sharing one gateway

**Setup:**

- One Pi, with a number of agent machines on the agent segment: `10.77.0.10`, `.11`, `.12`, or a Docker macvlan range. Macvlan gives each container its own network address, as a separate machine has.
- One credential slot for each person and each credential. Each slot gets its own claim code.
- The management screen (TUI), under Agent network → Keys, shows the last use of each slot.

**Protects:**

- No agent machine has the live key of a team member.
- A leaked laptop or VM image contains only placeholders.
- When you quarantine one slot, the credential of that person stops. The credentials of other persons do not change.
- The gateway logs the unknown origin servers of all team members in one log.

**Does not:**

- Isolate team members from each other. All agent machines share one network segment. Thus they are one trust tier. A placeholder is a capability for its kind. A process on the segment that learns the placeholder can spend against that slot until you delete the slot. Thus, treat a placeholder like a key on a short leash. Delete slots when people leave.

## 3. Running untrusted skills, plugins or MCP servers

**Setup:**

- Run the agent, and each skill or MCP server that it loads, inside the agent VM, behind the gateway.
- Give that VM only placeholders.
- Keep the desktop outside.

**Protects:**

- The gateway exists for this case: a skill with its own, independent network access.
- The skill can open its own connections (sockets). But all of these connections go through the gateway:
    - There is no live key to steal.
    - The gateway refuses direct IPs and DoH (DNS over HTTPS).
    - The gateway sinkholes blocklisted hosts.
- The gateway logs new origin servers. Thus you can see when the skill connects to a new location.

**Does not:**

- Stop a malicious skill when it calls the approved APIs with your placeholder. The gateway replaces the placeholder with the live credential. Thus a bad skill can still spend your quota and send data to the vendor.
- Read what a skill receives inside `br`- or `zstd`-compressed responses from an origin server.
- Stop a large upload before it starts. The broker streams a body larger than 1 MiB, or a chunked body. It does not buffer it.
    - The broker still strips live-looking tokens while the body goes through.
    - A placeholder in the body stops the upload.
    - But the request headers are already at the origin server at that time.

## 4. A family network behind the same box

**Setup:**

- A second Ethernet adapter on the Pi (`eth1`, `10.78.0.1`). A cable connects it to a Wi-Fi router in access-point mode.
- The Pi runs DHCP (it gives addresses to house devices) and DNS for that network.
- The Pi applies the same malware and phishing feeds, plus a sinkhole list for the house only.

- Optional: the house goes out through a WireGuard VPN, with a kill switch. If the tunnel stops, the house has no internet. Thus no traffic leaks.

**Protects:**

- Phones and laptops get the malware and phishing feeds, a DNS pin, and drops for DoH, DoT and QUIC. Thus a phishing link resolves to nothing. The gateway also drops the VPN app of a device.
- By default, only web ports and other encrypted ports can go out. The gateway examines each connection by site name. Thus an app cannot go around the filter with a direct connection to an address. [Home network](home_network.md) lists the settings that open more.
- The house cannot reach the agent segment or the desktop. The agent segment and the desktop cannot reach the house. The only exception is the one admin device that you reserve. This device can use SSH to the gateway and the agent. It can also use SSH into the desktop, if you name it in the `SSH_FROM` of the desk.
- A phone with its own private DNS provider does not resolve, unless you enable `HOUSE_PRIVATE_DNS` for your own endpoint. In that case, the gateway still examines its HTTPS by site name.

**Does not:**

- Examine house TLS. The house segment has no CA, no credential fence, and no log for each request.
- Act as a parental-control product. It is a filter, not a proxy. It has no schedules and no rules for each device.

## 5. A red-team lab

**Setup:**

- Make a lab yourself: use the cloud lab guide (one command on a Linux host with KVM) or the VirtualBox lab manual. Both are published with the source.
- The gateway VM has a lab marker. This marker enables two echo services. The gateway itself answers the two services:
    - The core echo (`pf-core-echo.test`).
    - The open echo (`pf-open-echo.test`).
- Canaries: `192.0.2.1` (direct IP), `pi-fortress-block.test` (sinkhole), and `example.com` (unknown, allowed).

**What you get:**

- The end-to-end suite of the project. It runs against the cloud lab. It is published with the source.
- Three logs to monitor: `strip.jsonl`, `unknown.jsonl` and `use.jsonl`. They show each refusal, strip and use.
- Each substitution failure returns identical bytes. Thus your tests examine the fence and its parser, not differences in the error message.
- The attack surfaces of interest:
    - The HTTP/1.1 wire parser in the credential path.
    - Encoding tricks.
    - All methods that get a placeholder to an origin server without the placeholder ever becoming live.

**Limits:**

- The lab is a set of VMs on one host. Thus hypervisor escape is out of scope for the lab itself.
- Report findings privately: by email to security@praneos.ai, or with GitHub private vulnerability reporting (the **Security** tab of the repo). Do not open a public issue. After the public release, a bypass also counts for the capture-the-key challenge.
