<!-- Short answers to the questions people ask first about Pi Fortress. -->
# FAQ

**Does it see my traffic?**
Yes on the agent segment. On the desk and house segments, it does not decrypt traffic. It sees the DNS names that the devices look up, and the addresses that they connect to.

On the agent segment, the gateway:

- Terminates TLS.
- Parses the request.
- Lets the broker read headers and bodies, so that the broker can substitute or strip credentials.

The gateway logs:

- Strip events: the host, the location, and the rule. It never logs the token.
- A sample of unknown origin servers: the host, method, path, header names, a shortened `User-Agent` and `Content-Type`, the `Authorization` scheme without its credential, and the cookie names without their values. It logs no other header value, and it never logs bodies.
- DNS queries.

The gateway does no TLS inspection on the house segment. On the desk, TLS inspection is off until you turn on [the desk fence](#desk-tls-inspection). Then these logs also include the desk.

**Where are my keys?**
On the gateway. Never on the agent.

The keys are in `/etc/pi-fortress/broker/secrets.env` on the gateway. The file has mode 0600. Only the broker user can read it. The agent never gets a copy of a live credential. It has only placeholders such as `pf_<16hex>_<KIND>`.

You can also encrypt the file at rest with `pf enroll seal`. After that, run `pf unlock` one time after each broker start. The decryption key is only in the memory of the broker. Thus, after each of these events, you must run `pf unlock` again:

- A reboot.
- A full `pf apply`.
- A software update.

The seal operation is also one of these events, because it leaves the store locked. Run `pf unlock` immediately after you seal the store. If you do not, the broker refuses all requests that use a credential.

`pf enroll seal` refuses to seal if a comment or other clear-text line looks like a credential. An example is an old token in the line `# old=ghp_…`. The command gives the line numbers, so that you can delete those lines.

The seal operation does not erase the old unencrypted copy. Flash storage keeps freed blocks. Thus an image of the SD card can still show a value that the store held before the seal, or while the store was unsealed. If you lose the card, or if someone steals it, revoke the affected credentials with the provider. Do not rely on the seal to protect them.

**What breaks?**
A short, specific list. Most common dev tools work correctly.

- Clients that pin their own certificate. They do not trust the gateway CA.
- Clients that use only HTTP/2. The gateway offers only `http/1.1`. Thus an `h2`-only client gets a `no_application_protocol` alert.
- HTTP/3. The gateway drops UDP 443.
- Software that needs IPv6. IPv6 is off on the agent. The gateway denies IPv6, because the gateway is IPv4 only. An IPv6-only uplink does not work.
- Software that needs a direct IP connection or its own resolver.
- Responses with `br` or `zstd` compression to a request without a substituted credential. They pass through, but the gateway does not scan them.
- A response in an encoding other than gzip to a request that had a substituted credential. The gateway refuses it with `502`, because the gateway cannot scrub it. The gateway asks only for gzip. Thus this occurs only with a server that ignores `Accept-Encoding`. This is rare.

Claude Code, the Anthropic SDK, Go `net/http`, curl, git, npm, pip and `gh` all negotiate HTTP/1.1. They work correctly.

**How does git over HTTPS get a credential?**
Automatically, through a placeholder in `~/.git-credentials`.

When you claim a slot that has a `GITHUB_TOKEN`, the claim:

- Writes `~/.git-credentials` (mode 0600) with one line for each host that has the `GITHUB_TOKEN` kind in `core.hosts`, for example `https://x-access-token:pf_<slot>_GITHUB_TOKEN@github.com`. It replaces only the existing lines for those hosts.
- Runs `git config --global credential.helper store`. Exception: if you already have a helper, the claim does not change it. The script then prints the command to change to the `store` helper.

git sends the placeholder as Basic auth. The gateway decodes it and replaces it with the live token. The gateway does this only for requests to `github.com`.

To do this setup manually, first run `. ~/.pi-fortress/env.sh`. Then run:
```
git config --global credential.helper store
printf 'https://x-access-token:%s@github.com\n' "$GITHUB_TOKEN" >> ~/.git-credentials && chmod 600 ~/.git-credentials
```

**Why does `git push` get a 503?**
Because the repo is not in `git_push.allow`.

A push over HTTPS goes only to a repo that this file lists as `<host> <owner>/<repo>`. `<owner>/*` covers all repos one level below the owner. It does not cover deeper levels. The shipped file is empty. Thus the gateway refuses all pushes until you add a line and run `sudo pf apply`. This does not affect clone and fetch.

Each refusal writes a `refused:git_push_not_allowed` row in `strip.jsonl`, with the repo name. The list controls only the push protocol of git. A token can still write through the REST or GraphQL API of a provider. A gist is one path segment, so you cannot list it. The gateway always refuses a git push to a gist.

The gateway drops an SSH push, unless the server address is in `ssh_allow.ips`. This is a separate list.

**Can a compromised agent still spend my quota or leak data through the API?**
Yes.

The gateway is designed to approve a request to `api.anthropic.com` that has your placeholder. The gateway stops the live credential from going out. It does not examine your prompts for secrets.

Hourly limits for each slot can send you an alert, or disable the slot. They do this when a credential suddenly spends much more than usual ([pi_setup.md](pi_setup.md), "Spending limits per credential"). Monitor the "last used" column. If something looks wrong, delete the slot.

**How do I revoke?**
Run one command on the gateway, or quarantine it from the TUI.

On the gateway, run `sudo pf enroll delete --slot <slot>[,<slot>...]`. Or, in `sudo pf tui`, press `x` on the slot. This quarantines the slot immediately. `R` restores the slot. The gateway purges a quarantined slot at the first full `pf apply` after seven days.

You do not need to do anything on an agent disk, because no agent disk ever had the live credential.

**How do I add a new provider host?**
Add a line to `core.hosts.local`, then run `pf apply`.

Add `host KIND...` to `/opt/pi-fortress/vm/policy/core.hosts.local`. This file is next to the shipped `core.hosts`. An upgrade replaces `core.hosts`, but it keeps `core.hosts.local`. Lines for the same host add together.

- A bare name matches only that exact name.
- `*.name` covers all subdomains.
- A line with no kinds allows the name as an authority. The gateway does not inject anything for that name.

A new *kind* does not need a change to the minting command, because that command accepts all names in capitals. But a new kind needs a token pattern in `key_prefixes.rules`, so that the broker can strip the token elsewhere. The pattern must start with a literal prefix, for example `ghp_`. The broker does not start with a pattern that has no prefix.

**My tool sends its key in a header other than `Authorization`. Why is the request refused?**
The broker replaces a placeholder only in `Authorization` and `X-Api-Key`, unless you declare a different header for that host and kind.

If the placeholder is in a different location, the broker refuses the full request. Reason: headers such as `User-Agent` and `Referer` go into the logs of the provider. It is possible to read these headers back.

To declare the header, run `sudo pf enroll mint --kind KIND --header PRIVATE-TOKEN ...`. Or write `gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN` in `core.hosts.local` yourself. Then run `sudo pf apply`. You can never declare a header that is logged, that is echoed, or that controls routing.

Do not put documentation hosts or blob hosts in `core.hosts`. Put them in `allow.domains`. When paranoid mode is off, the only effect of `allow.domains` is that the gateway does not log these hosts as unknown. In paranoid mode, `allow.domains` is the allowlist.

**Does it work on a Mac?**
Not natively.

The gateway is a Linux box (Pi 5 or a Debian VM). The enrolment script is for Linux distributions.

A Mac works correctly as the human seat. Mint credentials from the Mac over ssh (`pbpaste | ssh ... pf enroll mint --stdin`). Run the agent in a Linux VM, or on a box that has a cable to the gateway.

**Is it open source?**
Yes, under Apache-2.0.

The source and the build are public. Each release is signed and reproducible: if you build a tag again, you get the same bytes. The project is open for evaluation. Use test keys, or keys with a spend limit, while you evaluate.

**Why a Raspberry Pi?**
It is a cheap, separate machine that you put between your agents and the internet.

It can be on the cable between the agent machines and the uplink. For the Pi tier, the escape condition is physical access to the Pi.

If you have no Pi, the same binary also runs in a VM on your laptop. For that tier, the escape condition is a hypervisor break.

**What about NixOS or Alpine agents?**
The setup script does not support them. But you can configure them manually.

The enrolment script knows only the CA tools of these distributions:

- Ubuntu/Debian.
- Fedora and its family.
- Arch.
- openSUSE.

The enforcement on the network side does not depend on what the agent runs. But on NixOS or Alpine, you must install the CA certificate and the DNS pin yourself.

**Can I run several agents?**
Yes.

Put several agent machines or VMs on the agent segment, at `10.77.0.10`, `.11`, `.12`. There is also a reserved Docker macvlan range. The agents share one segment. They are one trust tier.

**What is the performance cost?**
Not measured yet. There are no published numbers.

Known costs:

- No HTTP/2 multiplexing.
- Two TLS terminations.
- The gateway inflates gzip responses. Optionally, it compresses them again. If the broker runs hot, `-recompress=false` disables the second compression.

`pf monitor` samples CPU, memory and temperature every five minutes. Use it to check the cost yourself.

**What happens on a gateway reboot or power cut?**
All services restart. The policy applies again automatically.

If the credential store is sealed, nothing that needs a credential works until someone runs `pf unlock`. These tell you about it:

- The TUI.
- `pf doctor`.
- One webhook for each broker start.

A full `pf apply` or a software update also restarts the broker. Thus each of these also asks for the passphrase again.

`pf apply --local` restarts the broker only if something that the fence reads has changed:

- The blocklist (a feed edit or a blacklist edit).
- The allowlist.
- The git push allowlist.
- The core hosts (`core.hosts.local`) or the token patterns (`key_prefixes.rules`).
- Paranoid mode.
- The network settings of the gateway.

A change only to the house segment does not lock the store again. The nightly feed refresh also does not lock it again.

**Does the house or desk segment get the credential fence?**
The house: no. The desk: yes, when you set `INSPECT=on` in its segment file.

Pi Fortress assumes that an agent can escape to the desk. Thus the desk always gets rules that are almost the same as the agent network rules. On the desk, `pf dns`:

- Answers on the segment address, with the block lists of the agent.
- Refuses names that look like a key.
- Answers only with addresses.

The gateway rejects DNS queries to all other servers. A new connection on any port, or a ping, can go only to an address that this resolver gave. The gateway drops QUIC, DNS over TLS, the known DoH servers, and all local addresses. Only the same strict set of ports as the house segment is open.

The desk also uses the IP blacklist, because the blacklist is a packet filter set for all segments. Without `INSPECT=on`, the desk does not have these:

- The CA.
- TLS inspection.
- The site-name check.
- Credential substitution.

**The desk fence.** With `INSPECT=on`, the desk gets the same protection as the agent VMs. The tools on the desk hold only placeholders. The gateway puts in the real key only for the service of that key, and it removes live keys in known formats. Thus an agent that escapes to the desk finds no real keys there either. The desk must trust the gateway CA first (`setup.sh ca`). For the steps, refer to [Pi setup, step 8](pi_setup.md#the-credential-fence-on-the-desk).
{ #desk-tls-inspection }

The paranoid mode and the fake-IP of the agent network do not apply to the desk.

You set paranoid mode for each network. To hold the desk to its own allowlist, put `PARANOID=on` in its segment file. This works whether or not the agent network is in paranoid mode.

The house segment gets the malware and phishing feeds, a DNS pin, and drops for DoH, DoT, and QUIC. It also has no CA and no inspection.

**How do I hold the agent to an allowlist?**
Enable paranoid mode.
{ #paranoid-mode }

1. Operate for one week with paranoid mode off.
2. Examine `pf observe once` and `unknown.jsonl` to see what your sessions reach.
3. Put those names in the allowlist, in `sudo pf tui`, **Agent network → Filtering → Paranoid allowlist**. Each name covers its subdomains. The core hosts are always allowed.
4. Add `PARANOID=1` to `/etc/pi-fortress/net.env.local`. Do not use `net.env`, because each update replaces it.
5. Run `sudo pf apply`.

All other names then get the blocked answer. The gateway refuses a connection to one of these names. To disable paranoid mode, set `PARANOID=0` and apply again. A desk or other plain network has its own switch: `PARANOID=on` in its segment file ([pi_setup.md](pi_setup.md), step 8).

**What breaks on the desk?**
Some things that a normal home network allows. Each item has a fix in the file of the desk, `/etc/pi-fortress/segments.d/<name>.env` ([pi_setup.md](pi_setup.md), step 8). After the fix, run `sudo pf apply --local`.

| What breaks | Why | Fix |
|---|---|---|
| HTTP/3 | The gateway drops UDP 443 | No action is necessary. Browsers then use HTTPS over TCP |
| An app on a port other than web, encrypted mail, push and time. Examples: a game, the direct media of a call app, a service on an unusual port | `EGRESS` is `strict` | Set `EGRESS=audit` for one day. Read `sudo journalctl -k -g <name>-audit` on the Pi. Then list the ports in `ALLOW_PORTS` and set `strict` again |
| A printer, a NAS, the admin page of the router, all other devices on your local network | The desk can never reach local addresses, on any port, whatever the `EGRESS` value | Use those devices from the house network |
| Pages that fail in a browser with hundreds of open tabs | The limit is 128 open connections for each device | `CONN_PER_IP=512` |
| Teams, XMPP or mail autodiscover, some single sign-on and VPN clients | They query SRV or TXT records. The desk DNS answers only with addresses | `DNS_TYPES="SRV TXT"`. Add `MX` if a mail client needs it |
| `ping 1.1.1.1`, or other traffic to a bare address | The desk can reach only the addresses that the desk DNS gave | Use a name |
| The secure DNS of a browser, or a local DNS proxy such as ctrld | Its DNS queries go to a different server. Thus the desk cannot reach the addresses that it resolves | Disable it, so that the desktop uses the DNS of the Pi |
| Software that connects to addresses that it got in a different way, for example the Tailscale relays | Same as above | `BLOCK_DIRECT_IP=off`. This removes that protection for all of the desk |
| With `INSPECT=on`: an app that pins its own certificate, for example some banking, VPN, and update clients | The app does not trust the gateway CA | Use the app on a different device, or set `INSPECT=off` |
| With `INSPECT=on`: a client that uses only HTTP/2, for example a gRPC client | The engine speaks only `http/1.1` | Same as above |
| With `INSPECT=on`: Java, or a different tool with its own certificate store | The tool does not read the system store | Import `/etc/pi-fortress/desk-ca.pem` into the store of the tool |
| With `INSPECT=on`: a WebSocket or a download that stays open for more than one hour | The gateway closes each connection after one hour | No action is necessary. Most clients connect again automatically |
| A VPN over GRE or IPsec (ESP), or a different protocol that is not TCP or UDP, to a bare address | The same check applies to all protocols, not only TCP and UDP. Also, `strict` lets out only some TCP and UDP ports, and ping | Use the server name, or `BLOCK_DIRECT_IP=off`. For GRE or ESP, also set `EGRESS=open` |
| `git push` over SSH | With `strict`, SSH goes out only to `ssh_allow.ips` | Add the host addresses there, or push over HTTPS |
| Software that needs IPv6 | The desk is IPv4 only, like all networks on the gateway | None |

**How is management done?**
With a terminal tool, `pf tui`. Run it over ssh or at the seat.

There is no web console. No management service listens on the network. The policy is in plain text files. `pf apply` applies them. There are two groups of files:

- The lists (blocklists, `never_block`, `ssh_allow.ips` and similar lists) are in `/opt/pi-fortress/vm/policy/`. `pf apply` compiles from these files. The TUI and `pf fetch` edit them.
- The settings, such as `net.env.local` and `house.env`, are in `/etc/pi-fortress`.

The Devices and Activity sections of the TUI show this data for each device:

- What the device looked up and contacted.
- Which contacts the gateway blocked, and which threat feed blocked each one.

**What is a claim code?**
A one-time code that puts a placeholder on the agent. You do not copy a file.

It is a six-character code that the TUI issues for one slot. It is valid for five minutes. You can use it only one time.

The agent redeems the code with the three lines that the TUI shows. These lines fetch `http://10.77.0.1/claim/<CODE>`. They run the fetched file only if its sha256 matches the sha256 that the gateway calculated. The script then checks `setup.sh` and the CA in the same way.

The gateway adds each issue and each redeem to a ledger, on a best-effort basis. If an append fails, the gateway ignores the failure. The failure does not block the issue or the redeem. Thus, use the ledger as a record for review. It is not proof that nothing occurred.

**How do I know what a new tool talked to?**
Check `pf observe once` and `unknown.jsonl` on the gateway.

`pf observe once` shows DNS queries and the flows to each origin server. `unknown.jsonl` logs a sample of each origin server that is not on the allow list or the core list. The gateway does not block unknown origin servers. It logs them for review.

**How do I report a bypass?**
Privately: by email to security@praneos.ai, or with GitHub private vulnerability reporting (the **Security** tab of the repo, then **Report a vulnerability**). Do not open a public issue.

After the public release, a confirmed fence bypass also counts for the capture-the-key challenge.

A useful report gives:

- The layer (resolver gate, engine, broker, agent lockdown).
- The exact request.
- The log lines from `strip.jsonl` or `unknown.jsonl`.

You can safely use the canaries `192.0.2.1`, `pi-fortress-block.test` and `pf-open-echo.test` in a report. Do not test against hosts that you do not own.
