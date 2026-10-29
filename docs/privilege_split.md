# Engine / broker split

**Both sides use Go.** The Python code is gone. The lab `make test` is the
gate. There is no dual inject.

In the tree: `internal/httpwire` (no `net/http`), `internal/preamble`
(`PFB1`), `internal/corepolicy`.

Related: `docs/risk_model.md` §2.1 (risk model), `docs/fence.md` §5.2 (fence).

## 0. The insight

The old Python addon was one process with two jobs. The two jobs had opposite
trust profiles:

| Job | Trust | Holds |
|---|---|---|
| Parse hostile ClientHello + HTTP from the agent | Untrusted bytes | — |
| Apply approved oat/ort | Trusted | `secrets.env`, CA key |

These two jobs must not share an address space. OpenSSH did this split
decades ago (a child that faces the network vs a privileged monitor).

```
agent ──TLS──► [ENGINE] :8080
                  holds: CA key, leaf cache
                  knows: nothing about kinds, hosts, tokens, DoH
                  does:  orig_dst, ClientHello peek, mint leaf, TLS
                         terminate, unix splice of *agent-facing* plaintext
                  │
                  ▼
           /run/pi-fortress/broker/broker.sock   pf-broker:pf-fence 0660
                  │
                  ▼
               [BROKER]  Go
                  holds: secrets.env, core.hosts, allow.domains
                  does:  httpwire, corepolicy, inject/strip,
                         echo, doh-403, hashes, harvest, origin TLS
```

The engine terminates TLS and moves bytes. It does **not** parse HTTP. It
does **not** dial the origin server. The broker is the TLS client to
`orig_dst` (`ServerName=SNI`). Live tokens exist only in the broker and on
the origin hop. The plaintext on the agent side has placeholders in and
placeholders out. The broker rewrites the data before the splice back.

The broker pre-dials the origin server to decrease the latency of each
request. It pre-dials immediately when a preamble passes the SSRF and source
checks. It never pre-dials for echo fixtures. Thus the origin TLS handshake
occurs at the same time as the parse of the first client request, not after
it. The broker also keeps that connection alive, to use it again for more
requests on the same client connection. It does this only when both of these
are true:

- The previous response reached its framed end.
- Neither side sent `Connection: close`.

The broker still verifies the origin certificate against the SNI on each
dial. Reuse is limited to one client connection. The broker never shares a
kept connection across clients or SNIs.

An attacker can compromise the engine with a malformed ClientHello. The
attacker then gets the CA private key and a stream of placeholders. **Only**
the agent VM trusts this CA. The attacker does not get `sk-ant-oat01-`.

“Splice both ways” does not mean engine↔origin. With that reading, live
tokens would go through the engine on the way to Anthropic. That reading is
wrong. **The engine never speaks to the internet.** nft already fail-closes
the agent forward path. The engine is a local TLS terminator.

## 1. Why this beats a goproxy MITM

| goproxy design | After the split |
|---|---|
| Fake CONNECT + `dumbResponseWriter` | Gone. No goproxy. |
| Dial orig_dst vs SNI | The engine puts orig_dst in the preamble. The broker dials. One Go function, unit-tested, no listener. |
| Header canonicalization | Gone. Go never sees HTTP. |
| HTTP/2 | The engine ALPN offers only `http/1.1`, until the broker gets h2 support. |
| Dual parity table | Deleted. One broker package (`internal/broker`). |
| 1 GB box / RSA leaves | The engine mints **ECDSA P-256** leaves. The RSA CA can stay. |

Both processes use Go (`CGO_ENABLED=0`, `GOARCH=arm64` later). The split is
about privilege, not language. The engine parses hostile bytes. The broker
holds live credentials. The broker can move to the cloud later (unix → mTLS).

## 2. Locks

- Do not put `core.hosts`, kinds, or `secrets.env` in the engine. The
  engine reads `key_prefixes.rules` for the SNI key-shape check. It keeps
  only the compiled shapes, not the kind column.
- Do not dial the origin server from the engine.
- If the broker socket is absent or refuses the connection, **close** the
  agent connection after the handshake. Never pass through. Never buffer and
  retry.
- Leaves: ECDSA P-256, cached. Do not sign with RSA for each request.
- Use one preamble format: **`PFB1` + uint16 length + JSON**, one time for
  each connection. No Echo bool: the broker decides TEST-NET from OrigDst.
  No PROXY v2. No second dialect.
- `/etc/pi-fortress/fence` has `split` only. Apply writes this file. Never
  put a second process on `:8080`.
- A third user, `pf-sidecar`, runs alert and monitor. These are file tailers
  with no capabilities. The state directories stay owned by root. `apply.sh`
  gives the sidecar exactly the files that the sidecar rewrites
  (`alert.offset`, `alert-notice.offset`, `alert.last`). `alert.service`
  can write these three files and its `StateDirectory`,
  `/var/lib/pi-fortress/alert` (the pressure and digest state). The digest
  state has the full names of the blocks, so it is `0600`.
  `alert.url` (the webhook URL) is `root:pf-sidecar 0640`, in
  `/etc/pi-fortress` and in the policy tree. Only `alert.service` gets the
  `pf-sidecar` group (`SupplementaryGroups`). monitor runs as the same user
  without that group, so it does not read `alert.url`.
- A fourth user, `pf-observe`, runs observe. It has no capability. The
  conntrack dump needs `CAP_NET_ADMIN`, so `pf netgate` (below) runs it
  for observe. It reads the query logs and `strip.jsonl` through
  `pf-fortress`, and the DHCP lease files through `pf-leases`. The `systemd-journal` group gives it read
  access to the full system journal. Of the journal, observe reads only
  the kernel log.
  It owns `/var/lib/pi-fortress/observe` (its ledger and checkpoints),
  `observe.jsonl` and `notice.jsonl`. `observe.service` can write only
  these paths and `/var/log/pi-fortress`, and in that directory only the
  files that it owns. The other state under `/var/lib/pi-fortress` is
  read-only to both. `/var/lib/pi-fortress/www` is not visible to them
  (see the www item below). There is no console
  daemon. For management, use `sudo pf tui`. This is a terminal program. Its only
  privilege is the sudo of the operator.
- www writes to exactly one directory:
  `/var/lib/pi-fortress/www/claims-redeemed` (`root:pf-fortress 2770`,
  `SupplementaryGroups=pf-fortress`, `ReadWritePaths` for that path only).
  In this directory, www makes a marker for each spent claim code and
  appends to the ledger. It only reads the claims in
  `/var/lib/pi-fortress/www/claims` (`root:pf-fortress 2750`), so it cannot
  create or change a claim. `/etc/pi-fortress/broker` stays in
  `InaccessiblePaths`.
- The engine and www read no log, no observe state, no webhook URL and no
  house reservation. Thus both units also list these paths in
  `InaccessiblePaths`: `/var/log/pi-fortress`,
  `/var/lib/pi-fortress/observe`, `/etc/pi-fortress/alert.url` and
  `/etc/pi-fortress/house.hosts`. The two files are optional (`-`),
  because a box with no webhook or no house does not have them.
- The claims and the ledger have the live claim codes. Their group is
  `pf-fortress`, and almost all daemons are in it. Thus each other daemon
  unit (engine, broker, sidecars, observe, DNS, DHCP, netgate) lists
  `/var/lib/pi-fortress/www` in `InaccessiblePaths`. Only root and www can
  read a code. apply makes the directory before it starts the first unit,
  because systemd ignores an optional path that is missing at the start.
- `pf netgate` (`netgate.service`) is the one daemon that holds
  `CAP_NET_ADMIN` for pf dns and observe. Both parse bytes from the
  network, and neither has the capability. With it, code that runs in a
  process can change the ruleset, a route, a link or a bridge. netgate
  does three fixed jobs, and nothing else:
  - GATE, for the agent resolver: add public IPv4 addresses to a resolver
    gate set (`resolved_v4`, `resolved_house_v4`, `resolved_<name>_v4`),
    or restart their timeout. It writes only a set that `dns.json` names,
    only addresses that pass the public check of the resolver
    (`internal/gateset`), at most 64 in one request, and at most 200
    requests each second (burst 400) for each gate set. Thus a flood of
    names on one segment cannot use the writes of a different segment. At
    most 16 `nft` processes run at one time, for all sets together. The
    write is the same `nft` command that pf dns ran before, with a 3 s
    timeout.
  - SNI, for the agent resolver: netgate binds the NFQUEUE of the house
    SNI check while pf dns is connected, and relays each queued packet to
    pf dns. It reads only the id, the mark and the length of the packet,
    and copies the payload. pf dns sends back the verdict and a code for
    the SNI bits. netgate sets only these bits of the mark that the kernel
    gave. A verdict for a packet that waits for none has no effect. A
    packet that waits more than 15 s is dropped. An NFQUEUE socket cannot
    go to pf dns as a file descriptor: the kernel checks the capability of
    the sender of each verdict.
  - CT, for observe: run `conntrack -L -o extended` (fixed arguments, at
    most one each 2 s, 5 s, 48 MiB) and stream the output back.

  netgate runs as `pf-netgate` (group `nogroup`), with `CAP_NET_ADMIN` as
  its only capability, only `AF_UNIX` and `AF_NETLINK`, and the sandbox and
  system-call filter of pf dns (plus `@chown`). It reads `dns.json` at
  start, for the table, the sets and the queues. apply restarts it after it
  writes `dns.json`, before pf dns. It reads no log and no state.

  Its sockets are in its `RuntimeDirectory`, `/run/pi-fortress-netgate`
  (`0755`): `dns.sock` (`pf-netgate:pf-dnsgate 0660`) and `ct.sock`
  (`pf-netgate:pf-ctgate 0660`). Each is `SOCK_SEQPACKET`, with fixed
  binary messages. netgate also checks the uid and the primary gid of each
  peer (`SO_PEERCRED`): `pf-dns` with `pf-dnsgate` on `dns.sock`, and
  `pf-observe` with `pf-fortress` on `ct.sock`. A message that is not
  valid closes the connection. Each refusal is logged, at most one line
  each second.

  Each client fails closed. When netgate is down, a GATE fails and pf dns
  answers SERVFAIL. No socket binds the SNI queue, so the kernel drops its
  packets. observe gets no conntrack table, so the flow and volume rows
  stop, and observe says so in the journal. netgate restarts at once
  (`Restart=always`), and pf dns and observe have `Wants=` and `After=`
  on it. When the account of observe or the group `pf-ctgate` is missing,
  netgate logs the reason and starts without `ct.sock`. Then only the
  conntrack table stops, not the gate set writes and the SNI queue.

  Limits: netgate holds `CAP_NET_ADMIN`, so code that runs in netgate has
  full control of the network. Its input is fixed messages from two
  accounts and the netlink attributes of the kernel. It uses only the
  standard library and two small packages of this tree
  (`internal/netgate/imports_test.go`). pf dns still decides what goes into
  a gate set and the SNI verdict of a queued house packet. One pf dns
  process serves the agent, the house and each plain segment. Thus code
  that runs in it can open a public IPv4 address in each gate set that
  `dns.json` names, so to each of these segments, as its answers can. It cannot flush or change the ruleset, add a route, a link
  or a bridge, or write a set that is not a resolver set.
- The feed refresh (`fetch.service`, `pf apply --refresh`), the signed ship
  (`ship.service`) and the ship dead-man (`ship-deadman.service`) stay root.
  apply loads nft, sets sysctls, adds the daemon accounts and writes `/etc`.
  Each unit has a sandbox: `ProtectSystem=strict` with only the paths that
  apply writes, a capability bounding set, `SystemCallFilter=@system-service`
  (without the calls of the item below), `NoNewPrivileges` and memory and
  task caps. A filtered call fails with `EPERM`. `fetch.service` lists
  `/etc/pi-fortress/broker`, `/var/lib/pi-fortress/engine` and
  `/var/lib/pi-fortress/www` in `InaccessiblePaths`, because a `--local`
  apply does not use them. Its bounding set has no `CAP_SYS_PTRACE` and no
  `CAP_SYS_ADMIN`: the refresh finds the admin SSH sessions by port 22,
  not by process, and it does not set the kernel sysctls of
  `lib/harden.sh`. `fetch.service` opens no IP socket
  (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`) and has
  `ProtectProc=invisible`. The sandbox of a root unit that writes `/etc`
  and talks to systemd limits the effect of a mistake. It is not a
  security boundary. Thus the refresh does not download a feed: the unit
  of the next item does that.
- `pi-fortress-feeds.service` downloads the feeds. It runs `pf fetch` as
  `pf-feeds`, with no capability and `NoNewPrivileges`. It can use only
  `lo` and the uplink (`RestrictNetworkInterfaces`, from a drop-in that
  apply writes) and only `AF_INET` and `AF_INET6`. It can reach loopback
  (the resolver stub on `127.0.0.1:53`) and public addresses through the
  uplink. `IPAddressDeny` takes out `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`, link-local and
  multicast; `IPAddressAllow=localhost` keeps loopback open. Thus it
  cannot reach a segment gateway address of the Pi (the engine, www, the
  resolvers, sshd), a client, or a host on the LAN of the uplink. A public
  address of the Pi itself on the uplink goes through `lo`, and stays
  open to it. When `/etc/resolv.conf` names a resolver that is not
  loopback (the router of the uplink, from DHCP), the drop-in opens that
  one address, so that the feed names resolve. Of
  `/var/lib/pi-fortress`, it sees only `feeds-in`: the copies of
  `sources.json` and the `never_block` lists that root puts there. It
  writes only `/var/lib/pi-fortress-feeds` (`0700`): the lists of the run
  and the last good copies. `pf feeds run` (root: apply, the timer, the
  TUI) starts the unit, then examines each line of each list. It imports
  the lists into `generated/` only when all lines pass. One bad line
  stops the import, and the lists stay as they were. `pf fetch` as root
  exits 2.
- Each unit with a system-call filter also removes asynchronous I/O
  (`@aio`, with io_uring), the kernel keyring (`@keyring`) and
  `userfaultfd` from its allowed set, and allows only native calls
  (`SystemCallArchitectures=native`). No pf unit, and no tool that a unit
  forks, uses these calls.
- `wg-alert.service` runs as root, for `wg show`, with `CAP_NET_ADMIN` as
  its only capability. It has the sandbox of the other root units, and its
  system-call filter also removes `@privileged`. `ProtectSystem=strict`
  makes the file system read-only for it, and `ReadWritePaths` has only
  `/var/lib/pi-fortress/wg.last`. Each DHCP dnsmasq (`dns-house.service`,
  `dhcp@.service`) can write only its own lease file under
  `/var/lib/pi-fortress` and `/var/log/pi-fortress`. apply makes each of
  these files before it starts the unit.
- `update-check.service` (`pf alert updates`) runs as `pf-sidecar`, the
  one user other than root that can read `alert.url`, with no capability.
  `ReadWritePaths` has only `/var/lib/pi-fortress/updates.last`. It does
  not set `ProtectKernelModules=yes`, because that hides `/lib/modules`
  and the check compares the running kernel with the installed ones. With
  no capability, it cannot load a module.
- The broker serves one source prefix. The unit reads `AGENT_NET` from
  `net.env` for `-agent-net`. With this flag, the broker refuses with 403 a
  preamble with a source outside that prefix. It does this before it parses
  a request. A house client behind a misrouted redirect never sees a slot.
- The daemons run as these unix users:
  - `pf-engine`: the engine. It has the CA key. It cannot open
    `secrets.env`.
  - `pf-broker`: the broker. It owns `secrets.env` `0600`.
  - `pf-sidecar`: alert and monitor.
  - `pf-observe`: observe.
  - `pf-dns`: `pf dns`, the agent resolver and the DoT stubs. Its one
    capability is `CAP_NET_BIND_SERVICE`. pf netgate writes the gate sets
    and binds the SNI queue for it. The agent resolver runs with the
    primary group `pf-dnsgate`. The stubs run with `pf-fortress`, so they
    cannot use netgate. It has no `CAP_NET_RAW`. It pins each new socket
    to its interface (`SO_BINDTODEVICE`) before the bind, and Linux 5.7
    and later allow that with no capability.
  - `pf-netgate`: pf netgate, in the group `nogroup`. Its one capability
    is `CAP_NET_ADMIN`.
  - `pf-dhcp-<name>`: each DHCP dnsmasq, in the group `nogroup`. Its
    capability is `CAP_NET_BIND_SERVICE` (port 67). It has no
    `CAP_NET_ADMIN`: its conf has `dhcp-broadcast`, so dnsmasq sends the
    reply to a client that has no address yet as broadcast, and writes
    no ARP entry for it. On dnsmasq older than 2.91, for example Debian
    12, dnsmasq keeps `CAP_NET_ADMIN`: before 2.91, dnsmasq does not start
    its DHCP server without it. On such a box, apply gives it back with
    the drop-in `net-admin.conf` of each DHCP unit. It has no
    `CAP_NET_RAW`: its conf has `no-ping`, so dnsmasq sends no ICMP echo
    to an address before it offers that address. The pin of the DHCP
    socket to its interface needs no capability (Linux 5.7 and later).
  - www has a dynamic user (`DynamicUser=yes`).
- There are seven groups:
  - `pf-fortress` has all pf daemons, for the files that they share (logs,
    state, the claims directories). The DHCP accounts and `pf-netgate` are
    not in it. Of the daemons, only www gets a path to the claims
    directories (`InaccessiblePaths` above).
  - `pf-fence` has the engine and the broker, and nobody else. It exists to
    gate the broker socket.
  - `pf-fakeip` has the broker only. It is the group of the fake-IP journal
    that `pf dns` writes.
  - `pf-leases` has `pf-observe` only. It is the group of the DHCP lease
    files (`pf-dhcp-<name>:pf-leases 0640`). They have the MAC and the
    name of each client. Apart from the dnsmasq that writes each file,
    only observe reads them. The reservations in `house.hosts` (`0644`,
    for dnsmasq and observe) and the observe rows also have client names.
    The engine and www do not see these files (`InaccessiblePaths` above).
  - `pf-sidecar` has no member account. Only `alert.service` gets it,
    through `SupplementaryGroups`. It is the group of `alert.url`.
  - `pf-dnsgate` has no member account. It is the primary group of the
    agent resolver (`Group=` in `dns-agent-go.service`) and the group of
    `dns.sock` of netgate. netgate gets it as a supplementary group, only
    to give it to that socket.
  - `pf-ctgate` has no member account. Only `observe.service` and
    `netgate.service` get it, through `SupplementaryGroups`. It is the
    group of `ct.sock` of netgate.

  The broker runs `Group=pf-fence`, with `pf-fortress` as a supplementary
  group. The engine is the other way round. `/run/pi-fortress` is
  `root:pf-fence 0750` (a tmpfiles line plus apply). The `RuntimeDirectory`
  of the broker below it is `pf-broker:pf-fence 0750`. The socket is `0660`.
  A sidecar in `pf-fortress` cannot traverse the first directory. Thus it
  cannot write a preamble to the broker. `/run/pi-fortress/apply.lock` is in
  that same root-only directory.
- The broker owns `/etc/pi-fortress/broker` (`pf-broker:pf-fortress 0750`).
  This directory has `secrets.env` `0600`, its flock file, the quarantine
  sidecar `secrets.disabled` (`0640`), and the expiry sidecar
  `secrets.expires` (`0640`).

  Root writes `secrets.disabled` for the `slot.disable` verb and for the `x`
  key of the TUI. The broker also writes it, for a stop threshold of the
  per-slot budget (docs/fence.md 5.2d). For this reason, the `ReadWritePaths`
  of the unit covers this directory, and `@chown` is back in its syscall
  filter. Both writers use the same flock and the same tmp+rename as a
  harvest rewrite. They never truncate in place.

  All other units list the directory in `InaccessiblePaths`, together with
  `/var/lib/pi-fortress/engine` (`pf-engine 0700`, `ca.pem` `0600`). Only
  `ca-cert.pem` is `0644`, and it is copied out for www.
- The strip, unknown, and use logs are `pf-broker:pf-fortress 0640`.
  `observe/observe.json`, `observe.jsonl` and `notice.jsonl` are
  `pf-observe:pf-fortress 0640` (observe runs `User=pf-observe`,
  `Group=pf-fortress`, `UMask=0027`).
- Both units run with:
  - An empty capability set.
  - `@system-service` seccomp, without `@aio`, `@keyring` and
    `userfaultfd`.
  - W^X memory.
  - Private `/dev` and `/proc`.
  - Pinned address families (engine: unix + inet only).

  `SO_ORIGINAL_DST` is a plain `getsockopt` and needs no capability. Never
  add `CAP_NET_ADMIN` to the engine: that is nft write access.
- nft does not change: TCP 443 redirect to `:8080`, UDP 443 drop, IPv6 off,
  forward policy drop. An engine crash does not cause a 443 leak.
- The risk model in `docs/risk_model.md` §2.1 still holds. The split does not
  stop core use or quota burn. It stops the engine from *being* the token
  store.

v2 (not v1): the engine asks the broker to mint leaves. The engine holds only
ephemeral per-host keys. Then all long-lived secrets are in one process. Do
not do this until v1 is boring.

## 3. Sequence (do not skip)

1. `httpwire` + `PFB1` preamble + `corepolicy` table tests. No sockets.
   (in tree.)
2. `secrets` + `fence` + dest/SSRF against `testdata/streams`.
   (in tree: `go test ./...`)
3. `pf broker` unix socket, dest deny, TLS verify, echo.
   (in tree: `go test ./internal/broker`)
4. `pf engine` — origdst, hello, ECDSA leaves, splice, fail-closed.
   (in tree: `go test ./internal/engine`)
5. Engine spliced to the live broker. Wire table:
   `TestLiveBrokerSecretsTable`. The VM `secrets` group (`vm/itest`) is green on split.
6. `fence=split` only. If the binary fails or the start fails, apply exits.
   Do not leave `:8080` empty. Do not start Python. The broker writes
   `/var/log/pi-fortress/{strip,unknown}.jsonl` (`src=split`). It answers DoH HTTP with `403 dns_pin`.

Do not start step 3 until step 1 runs the Host-spoof fixture in milliseconds
without Vagrant. This fixture is the case that we recently closed in Python.

## 4. Testability (the actual prize)

Broker fixtures: a preamble + raw HTTP bytes on disk. Each case of the `secrets`
and `strip` groups (`vm/itest`) becomes one file. Host-spoof is one file.
`go test` on the host, no engine.

Engine tests: a dummy broker that echoes. The tests check that the preamble
is correct, that the splice holds, and that the engine fails closed if the
socket is missing.

The security-critical path (inject/strip/harvest) has **zero networking**.

## 5. Operations

| Unit | User | Binds | Reads |
|---|---|---|---|
| `pi-fortress-broker` | `pf broker` | `/run/pi-fortress/broker/broker.sock` | `/etc/pi-fortress/broker/secrets.env`, policy |
| `pi-fortress-engine` | `pf engine` | `PI_IP:8080` (`net.env`) | CA pem, `key_prefixes.rules`, not secrets |

The engine unit has `Wants=` for the broker, not `Requires=`. A broker
bounce occurs at each harvest restart. During a bounce, the engine stays up
and fails closed on the socket. It does not take 443 down with the broker.

`./vm/bin/apply.sh` runs `make split-bin` when `go` is on the host. If the
engine, the broker, or the CA is missing, apply exits.

Cloud later: a change from the unix socket to an mTLS hop is a transport
change, not a redesign. The credential authority is already a process
boundary.

## 6. What we reject from the goproxy design

- goproxy as the product (CONNECT inspection + credential application in-process)
- Dual `apply_placeholders` in Go
- Compiling on the Pi
- `go-vhost`, goproxy’s baked-in CA
- Engine language as a security argument

Keep these from that design: static Go binary, orig_dst not `DNS(SNI)`,
HTTP/2 off, IPv6 off. The CA comes from `pf engine -init-ca`.

## 7. Implementation order vs other work

Canaries, encoding DLP, and HDMI are **broker** features. Do not implement
them twice.

This file is the TLS-architecture spec.
