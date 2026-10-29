# Risk model — Pi Fortress

This document has the problem (§1), the risk model (§2.1), the hostile uplink
(§2.2), and the non-goals (§7). The section numbers are stable. Other docs
refer to them. The fence is in `docs/fence.md`.

## 1. Problem

Prompt injection can make a coding agent on a developer machine fetch a page
and then POST secrets to some location. Host sandboxes (Claude Code, Codex,
Cursor) enforce their rules on the same kernel that the agent already runs
on. Attackers have bypassed these sandboxes.

The useful split:

| Plane | Where | Trust |
|---|---|---|
| Suspect | Agent VM | Hostile |
| Enforce | Pi Fortress VM (later a Pi 5) | Higher |
| Human | Host desktop | Filtered as a possible escape. Inspected only with `INSPECT=on`. |

**The uplink is a role, not a port.** The masquerade rule uses the interface
that holds the default route. This interface is `WAN_IF`, and `pf render`
detects it. The rules never use a literal `eth0` or `wlan0` in nft, in policy
routing, or in a unit. If you replace a cable uplink with a Wi-Fi uplink, a
name changes. You do not get a second copy of the rules. `pf render` also
detects `INT_IF`: it is the interface that holds `PI_IP`. If the detection
does not give what you want, `net.env` can pin `INT_IF` and `WAN_IF`.
`HOUSE_IF` is not detected. You set its name in `house.env`.

A VLAN child of the uplink (`WAN_IF`) is refused as `INT_IF`, `HOUSE_IF`, or
a segment. Reason: tagged frames from any other device on the wire of the
uplink would go into it. If `WAN_IF` is itself a VLAN (an ISP VLAN), the same
applies to its siblings and to its untagged parent. The full cable belongs to
the uplink.

A VLAN on the cable of the house port is permitted, for example a VLAN for
each SSID on a consumer AP. But it gets only house trust: a client of the AP,
or the AP itself, can tag frames into it. Apply refuses `ADMIN=yes` and
`SSH_TO` on such a segment, and `INT_IF` on that cable. Apply warns that the
isolation of such a segment is only as good as the AP.

A plain segment can serve DHCP (`DHCP=on`). This adds one more listener on
the Pi:

- It listens on UDP 67, only on the interface of that segment.
- A DHCP-only dnsmasq that is bound to that interface answers (`port=0`, no
  DNS).
- It runs in the sandbox of the house unit, with one capability,
  `CAP_NET_BIND_SERVICE`. On dnsmasq older than 2.91, for example Debian
  12, dnsmasq keeps `CAP_NET_ADMIN` too, because it does not start its
  DHCP server without it. Each DHCP instance has its own account
  (`pf-dhcp-<name>`, `pf-dhcp-house` for the house). An instance can
  write only its own lease file and log.

The Pi lets in the `0.0.0.0` source of a client with no lease on that port,
and nowhere else. Forwarded traffic is still pinned to the `NET` of the
segment. This is the DHCP surface of the house, one time for each segment
that asks for it.

The daemons that parse bytes from the network have no `CAP_NET_ADMIN`.
`pf dns` has only `CAP_NET_BIND_SERVICE`, and `pf observe` has no
capability. One small daemon, `pf netgate`, holds `CAP_NET_ADMIN` for
them. It takes only fixed binary messages, on one socket for each client,
and checks the uid and gid of each peer: a write of public IPv4 addresses
to a resolver gate set, the verdicts of the house SNI queue, and a request
for the conntrack table (`privilege_split.md`). One `pf dns` process
serves the agent, the house and each plain segment. Thus code that runs
in it can still put a public IPv4 address in each gate set that
`dns.json` names, for each of these segments, and decide the SNI verdict
of a queued house packet, as its answers can. It cannot change the
ruleset, a route, a link or a bridge, or write any other set. When `pf netgate` is
down, `pf dns` answers SERVFAIL to each name that needs a set write, the
kernel drops the queued house packets, and the flow rows of observe stop.

The Pi is the NTP server of the house and of each plain segment. chrony
listens on UDP 123 when the Pi has a house or a plain segment:

- Its `allow` lines name only the house network and the plain segment
  networks. Input accepts UDP 123 only to the address of the Pi on those
  interfaces. The uplink and the agent network get no NTP.
- nat prerouting sends each NTP packet of the house and of a segment to
  the Pi, whatever its destination. Thus NTP, which can carry hidden data
  in its timestamps and extension fields, never leaves those networks.
  Under strict, NTS key exchange (TCP 4460) does not leave either.
- The one exception is a plain segment with `NTP=pass`, for a device that
  needs NTS end to end. Its NTP and NTS go out, but only to the addresses
  in `ntp_pass.ips` (well-known public time servers, only in address space
  that their operator holds; not a cloud provider's shared pool, so
  `time.windows.com` is not listed). Thus the hidden-data
  path of that segment is open to those servers only. NTP to each other
  address still goes to the Pi. The default is `NTP=redirect`.
- chrony has a rate limit for each client address, no command port on the
  network, and no `local` line. Thus it serves only a clock that it
  synchronized over NTS.

chrony is C code that this project does not own. The lab has an opt-in
black-box fuzz of it (`PF_E2E_FUZZ_NTP=1`, the `ntp-fuzz` group in
[cloud_lab.md](cloud_lab.md)).

In the VirtualBox lab, Pi Fortress does not change the host firewall, DNS, or
default route. On a real Pi, the desktop goes out through the Pi as a plain
segment (`segments.d/<name>.env`). Pi Fortress treats the desktop as a
machine that an agent can have escaped to. The desktop gets:

- DNS only through the Pi, with the lists of the agent, the key-shape
  refusal, and address-only answers.
- Drops for QUIC, DoT, and the DoH addresses.
- A resolved-address gate on each new flow: TCP and UDP (except port 53),
  ping, and every other IP protocol (GRE, ESP, SCTP, ICMP other than echo),
  whatever `EGRESS` says. `BLOCK_DIRECT_IP=off` removes this gate.
- Drops for local addresses on every port.
- Strict ports by default (`EGRESS`, `ALLOW_PORTS`). Thus SSH goes out only
  to `ssh_allow.ips`, unless the segment opens port 22 itself.
- `SSH_FROM`, which lets one address SSH in. The connection must arrive only
  on the house interface or on the interface of a different plain segment. It
  can never arrive from the uplink, the agents, or the WireGuard tunnel.

Without `INSPECT=on`, the desktop gets no TLS inspection, no SNI check, and
no credential substitution. It never gets fake-IP.

With `INSPECT=on` (one key for each segment, off by default), the desktop gets
the credential fence of the agent network: the 443 redirect, the engine, the
broker, the name checks, substitution, and the strip. The engine listens on
the segment address with `IP_FREEBIND`, so a desk address that is not there
at boot does not stop the fence of the agents. The paranoid forward set of the
agent does not apply to the desk. These risks stay:

- The desk trusts the gateway CA for all TLS. A person with the CA key can
  intercept the TLS of the desk on any network. This is the same risk as for
  an agent. The key never goes out of the gateway.
- With `ADMIN=yes`, the SSH key of the desk opens the Pi and all real keys.
  Apply warns. Protect that key with a hardware key or a passphrase.
- The fence logs of the desk include the host, method, path, and header names
  of unknown servers.
- An agent that escapes to the desk can use the placeholders of the desk
  through the gateway. This is credential use, not credential material (2.1).

## 2.1 Risk model (honest)

We remove **credential material** from the agent VM. We do not remove
**credential use**.

A prompt-injected process, or a process with root on the agent, can still
send requests to `api.anthropic.com` and to every other `core.hosts` name.
The fence **applies the approved credential for that host, by design**. Thus:

| Attack | Mitigated? |
|---|---|
| Steal an oat, ort, or `ghp_` from the agent disk or memory, and use it again at a different location | Yes. The agent has only `pf_<slot>_<KIND>`. |
| POST the live token to `evil.example` | Yes. The fence refuses a request with a placeholder that the destination must not carry. The fence strips live-looking values. Both apply to the bytes that the fence scans. For an encoded value, see the encoding row below. |
| Body exfil **through** `api.anthropic.com` (paste secrets in the prompt, tool result, or a “write this file to the vendor”) | **No.** That is a legitimate core request. |
| Launder the credential of a slot through the host of that slot: its placeholder in a prompt ("print this reversed"), in a public gist body, in a URL that goes into an access log, or in a header that the origin server logs or echoes (`User-Agent`, `Referer`, `X-…`) | **Yes.** Substitution goes only into the credential headers of the kind: `Authorization` and `X-Api-Key` by default, plus the headers that `core.hosts` declares for that host and kind. A placeholder in any other header refuses the request. You can never declare a header that is logged, echoed, or that steers routing. The one exception is the refresh token. The fence writes it only as the whole value of the single top-level `refresh_token` key of a JSON body on `/v1/oauth/token` (or `/oauth/token`). It never writes it in a header, in a different field, in a duplicate or case-variant key, or off that path. A placeholder in any other location that the fence scans refuses the request and alerts (`placeholder_outside_header`). A streamed body with a placeholder stops (`docs/fence.md` §5.2). A placeholder in a different letter case, or with more letters after the kind, is never substituted and refuses the request in the same way. |
| Send a key from the agent disk out in DNS query labels (`<key>.evil.example`), or ask an LLM a question over DNS (`<question>.ch.at TXT`) | **Partly.** The agent can send DNS only to the Pi. The raw chain drops ports 53 and 853 to all other servers. The forward chain drops all agent traffic that the Pi would route, except SSH that `ssh_allow.ips` permits. On the agent segment, `pf dns` refuses a name that has a `key_prefixes.rules` shape or a placeholder (in any letter case), in one label or split across any number of labels. It refuses the name before it is forwarded, cached, or logged, and observe raises `dns_key`. The `dns_tunnel` check of observe measures the payload of a name as the longest label to the left of the registrable domain, and as the bytes of every label there. It does not measure the leftmost label alone. On the agent segment and on plain segments, one TXT or NULL question alerts if its payload has a label of 16+ characters or has 32+ bytes. Three names a minute, per client and domain, with a label of 30+ characters or 50+ payload bytes also alert. On the house segment, an alert needs one of these, per client and domain in one minute: twenty or more names with that average label or payload size, 120 or more distinct names, or twenty or more queries with half or more of them TXT or NULL. Tunnel-shaped queries (TXT, NULL, or any label of 16+) log from a reserved budget for each source. Thus a flood of short names cannot buy them silence. Each row goes into a bucket by its own timestamp. Thus a restart does not replay the rows into false alerts. In fake-IP mode, an address asked as a name (`192.0.2.1.`) gets the answer NXDOMAIN, and it never gets a pool address. The key-shape refusal also tries the last label alone. It also lets a run continue into a last label that is not TLD-shaped. **Not detected:** (1) a payload under those thresholds, for example labels under 30 characters and under 50 bytes a name, fewer than three such names a minute per client and domain on the agent segment or a plain segment (twenty on the house segment), names spread across many registrable domains, or A queries at a slow pace; (2) a TXT question split into short labels with a total under 32 bytes; (3) `.arpa` names; (4) a key with a tail of letters only, split into a TLD-shaped last label. That last name goes only to the servers of the TLD, never to a zone that the attacker holds. Above 20 queries/s per source in each log class (burst 100), the queries still get answers, but they are only counted, not logged. The agent segment is also address-only. The Pi answers every type other than A with an empty answer and never forwards it (except a `dns_types.allow` pair). AAAA, HTTPS and SVCB are always answered empty, on every segment, also when `dns_types.allow` or `DNS_TYPES` lists them. An A answer gets to the agent as a maximum of 16 A records under the queried name, with no CNAME, authority, or additional records. This stops answers that come back (TXT text, CNAME targets as free text). It also limits what one lookup can bring in to 16 addresses, 64 bytes. `AGENT_DNS=fakeip`, the default, closes the lookup itself. The Pi answers every agent A query from a reserved pool and never forwards it. The broker resolves a name only when the agent opens TLS to it, after the SNI matched the name, the key-shape, blocklist, and paranoid checks (`fence.md`, Fake-IP). A name that the attacker selects still costs one upstream lookup for each TLS handshake, and the lookup is logged. A plain segment such as the desk also gets the same key-shape refusal, tunnel alerts, and address-only answers. Only the `dns_types.allow` pairs of the agent and its own `DNS_TYPES` widen these answers, and never for AAAA, HTTPS or SVCB. A plain segment gets no fake-IP, because fake-IP needs the fence. If `AGENT_DNS=forward` is pinned, exfil in query names is open again: an encoded key in an A query still gets to the authoritative server of the zone. Paranoid mode closes it in both modes: the Pi answers a name outside the forward set locally and never forwards it. The own `PARANOID=on` of a plain segment does the same there, against its `allow.<name>.domains`. |
| DNS-rebind a public name to a private, reserved, loopback, or CGNAT address, to reach the services of the Pi or a LAN device (router admin, a NAS) | **Mitigated.** Agent segment: with the default `AGENT_DNS=fakeip`, the resolved address never gets to the agent. The broker checks every address that it dials against `dest.Allowed` (`internal/broker/fakeip.go` `dialName`). It dials the address that it checked and never resolves again. Thus there is no TOCTOU. House segment: the forward chain drops `@reserved_v4`, whatever the resolver said. Every segment: `pf dns` never adds a private, loopback, link-local, CGNAT, multicast, or unspecified address from an upstream answer to the gate set (`internal/gateset` `Public`), and `pf netgate`, which does the write, refuses such an address from any source. The answer still gets to the client. But on a plain segment such as the desk, a rebound name meets the directip gate as a direct dial, on any port. The same rule catches a public name that points to a LAN host (split horizon). The agent gate passes only the pool, `192.0.2.0/24`, `PI_IP` and `direct_ip.allow`. An address in `direct_ip.allow` still goes to the engine and the broker, as each agent connection on 443 does, and the broker refuses a private, reserved or LAN address (`dest.Allowed`). Thus a LAN or home address stays unreachable from an agent, by design. `pf dns` refuses a hosts line with an address inside `FAKEIP_NET` when it loads its files. A plain segment also drops `@reserved_v4` on every port, as the house segment does. Thus neither a rebind nor a typed LAN address gets to the LAN of the uplink. |
| Reach a home line of the attacker (a home server, a dynamic DNS name, a residential proxy) through a public name that resolves to it, to send data out or get commands | **Detected** (audit mode, the default), **refused** with `EYEBALL=refuse`. The broker looks up each address that it dials for the agent network in the table of eyeball networks that `pf fetch` builds. It looks up the address after `dest.Allowed` and before the dial. A hit writes an `eyeball_network` row with the name, the address and the ASN, and alerts one time for each name and ASN (`fence.md`, Eyeball networks). **Not caught:** (1) a server in a cloud, hosting or CDN network, which is the usual case and is what the agent reaches each day; (2) an ISP that no feed calls an eyeball network, or that bgp.tools calls a content network; (3) an address that no feed maps to an ASN; (4) an exempt name or ASN in `eyeball.allow`; (5) IPv6, because the broker dials IPv4 only; (6) a time with no table, or a table older than 30 days: the check then fails open and logs that one time. The check is a detector on top of the fence, not a gate. |
| Use all of the Max quota, or run up API spend | **No**, by default. Inject does not limit the rate. Per-slot hourly warnings alert on unusual spend. `SLOT_STOP_REQUESTS`/`SLOT_STOP_UPLOAD_MB` can disable a slot after it passes them, after the fact. Both stops are off by default. The operator can delete the slot at the seat or in the TUI. |
| Use a placeholder guessed from 64 bits of slot ID toward core | Residual. 16 hex is not 7 characters. Treat a leaked placeholder as a stolen capability for that kind. The fence refuses a wrong guess. Every refusal reads the same, thus a guess gets no feedback. |
| Send a live token of a different kind to a core host (an OpenAI key in a Claude prompt toward `api.anthropic.com`) | **Mitigated.** A core host substitutes only the kinds that are listed for that name. Every prefix rule tagged with a different kind runs there and strips. This applies to buffered bodies and to streamed bodies (over 1 MiB, or chunked) (`pf broker -strip-core`, on by default). Both paths cut a match at 4096 characters: the fence strips the head of a longer token and forwards its tail. Disable stripping only for a tool that must legitimately send the key of a different provider to a core host. A rule with no kind is not a residual. `compile` skips a rule only when the rule *has* a kind that the host substitutes. Thus an untagged rule also strips on a core host. |
| Send a token out in the *name* of a header (`ghp_…: 1`) or in the request method (`ghp_… / HTTP/1.1`), not in a value | **Yes.** The fence cannot rewrite a name or a method, because each gives the request its meaning. Thus it refuses the request and alerts (`key_in_header_name`, `key_in_method`) when a field name or the method holds a placeholder, any live value (also one of a kind that the host injects), or a `key_prefixes.rules` match. A key in an unknown format is not caught in a name or a method, as in a value. In paranoid mode, such a key can go only to an allowlisted host. |
| Encode a placeholder or a live value that the agent holds, and send it to a host that the agent may reach: base64, a custom encoding, or a value split across fields | Residual. The fence scans the literal bytes, a gzip or deflate body after the decode, the decoded user:password of `Authorization: Basic`, the percent-decoded request target (`encoded_url_token`), and the JSON strings of a buffered body after the unescape of `\uXXXX` and `\/` (`encoded_body_token`). It does not decode other encodings: base64 outside `Authorization: Basic` passes. A placeholder works only through the Pi, from the agent segment. Thus a placeholder that goes out encoded gives nothing to a different network. A live key on the agent is the risk of the operator. Paranoid mode limits the hosts that it can go to. |
| Use a DoH server, or any HTTPS API, on a name that is not blocked as a covert channel: resolve names past the Pi, or send data out | Residual. The Pi sees the TLS name and the size of the request, not the DNS question or the data. The fence scans a body for keys and placeholders only. Paranoid mode limits the agent to the allowlisted hosts. |
| Move the agent clock with a false `Date` header from a device that answers for the Pi on the agent segment, so that an expired or not-yet-valid certificate passes | Residual. The agent sets its clock from the `Date` header of the Pi, and that header has no signature. After the first sync of a boot, one poll cannot step the clock more than 24 hours: the agent logs one line and changes nothing. A larger step needs two polls, 10 to 30 minutes apart, that give the same offset within 5 seconds. Thus a host suspend of more than a day recovers at the next poll. The first sync of each boot takes any step, because a new VM or a box with a flat clock battery can start days or years off. The state files are in `/run`, so a reboot also recovers the clock. Thus a device that wins the first sync of a boot can set any time, a device that wins one poll can move the clock up to 24 hours, and a device that wins two polls in a row can set any time. Such a device can also answer the CA and DNS of the Pi, so the clock adds little to what it can already do. |
| Read the placeholders of a different slot from the claim handoff | Residual. `GET /claim/<code>` on port 80 of the Pi is plain HTTP. A root agent that ARP-spoofs the Pi on the agent VLAN can read the script that a different agent redeems. It can also read the placeholders in that script, and these are capabilities. Integrity holds: the pasted command checks the script against a hash copied from the Pi. The script checks `setup.sh` in the same way. `setup.sh` then checks `ca.pem` against a hash that the script gives. Confidentiality does not hold. Today: use one agent per VLAN, or claim before other agents run. |

An alert is not a guarantee of delivery. The webhook takes a maximum of 30
posts an hour for ordinary rows. Separately, it takes a maximum of 30 posts
an hour for credential and key rows. Above that, a row goes only to the log,
the console, and `alert.last`. One post at the end of the hour gives the
number of rows that were held back. The cap and the debounce never hold back
a canary row. If the queue is full of canary posts, a new canary post removes
the oldest one. The summary counts that post. When
`pf alert run` restarts, it does not send again the posts that are still in
the queue. But the rows stay in the logs. `pf alert show` gives the last row
(`docs/fence.md` §5.3).

Token theft is the common attack. Revocation is one `enroll delete` on the
Pi. You do not have to search every agent disk. This still has value. But it
is not an airgap, not a DLP of the conversation, and not a spend cap. Do not
build a product on the assumptions that we did not make.

## 2.2 Hostile uplink

The uplink can be public Wi-Fi. There, a neighbor can scan the Pi and answer
its ARP and DNS. The defense of the Pi itself is the `input` chain and two
kernel settings:

- Default drop.
- IPv6 dropped in both directions on `WAN_IF`.
- ARP answered only for the address of the interface that gets the query
  (`arp_ignore=1`, `arp_announce=2`).

`UNTRUSTED_UPLINK=1` also closes SSH and ping on the uplink. It also stops
outgoing mDNS and LLMNR. Apply refuses this setting unless a house admin or
an `ADMIN=yes` segment can still reach the Pi. This does not cover plain DNS,
traffic metadata, or captive portals. For details and checks, refer to
`user_guide/public_wifi.md`.

The blocklist download is the one process of the Pi that reads feed bodies
from the internet. It runs as `pf-feeds` with no capability. It can reach
loopback (the resolver stub) and public addresses through the uplink; no
private, shared or link-local address, thus no service of the Pi on a
segment address and no host on the LAN of the uplink. A public address of
the Pi itself on the uplink stays open to it (`privilege_split.md`). Root
imports only list lines that pass a strict check, and one bad line stops
the import of all lists. Thus a hostile feed server or uplink can change
which names and addresses the lists block, within the size caps,
`never_block` and `core.hosts`. It cannot add a firewall rule.


## 7. Non-goals

- Do not edit host nftables, IP forwarding, or DNS in the VirtualBox lab. On
  a real Pi, `vm/desk/setup.sh` is the one exception: the operator runs it,
  and it locks the desktop to the Pi.
- Do not default-deny.
- Do not send data about unknown destinations out of the gateway.
- Do not fork Gondolin.
- Do not inspect TLS on the human desktop by default. The gateway inspects
  agent TCP 443 with a CA. The key of this CA never goes out of the gateway.
  The agent segment trusts the certificate of this CA. A desk trusts it only
  when the operator sets `INSPECT=on` and runs `setup.sh ca`. The house never
  installs it.
- Do not parse LLM provider traffic.
- Do not speak HTTP/2. The engine offers only `http/1.1` through ALPN.
  Clients that list `h2` and `http/1.1` negotiate down. h2-only clients fail
  the TLS handshake with a `no_application_protocol` alert, and the engine
  logs `alpn_h2_only refused`. For the reason and the trigger to examine this
  again, refer to `docs/http2.md`.
- Do not use Raspberry Pi OS ARM in VirtualBox.
- Do not make the Pi into a full house router. The Pi routes only the house
  segment and the plain segments of `segments.d`. The house segment is a
  second interface behind a dumb AP. It is filtered, not inspected
  (`user_guide/home_network.md`). No hostapd, no schedules.
