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
- A fourth user, `pf-observe`, runs observe. Its only capability is
  `CAP_NET_ADMIN` (ambient), for the conntrack netlink dump. It reads the
  query logs and `strip.jsonl` through `pf-fortress`, and the DHCP lease
  files through `pf-leases`. The `systemd-journal` group gives it read
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
  `pf-fortress`, and all daemons are in it. Thus each other daemon unit
  (engine, broker, sidecars, observe, DNS, DHCP) lists
  `/var/lib/pi-fortress/www` in `InaccessiblePaths`. Only root and www can
  read a code. apply makes the directory before it starts the first unit,
  because systemd ignores an optional path that is missing at the start.
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
  `lib/harden.sh`.
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
  - `pf-dns`: `pf dns`, the agent resolver and the DoT stubs. Its
    capabilities are `CAP_NET_BIND_SERVICE` and, for the agent resolver
    only, `CAP_NET_ADMIN` (the nft fork that feeds `resolved_v4`, and the
    SNI queue). It has no `CAP_NET_RAW`. It pins each new socket to its
    interface (`SO_BINDTODEVICE`) before the bind, and Linux 5.7 and
    later allow that with no capability.
  - `pf-dhcp-<name>`: each DHCP dnsmasq, in the group `nogroup`.
  - www has a dynamic user (`DynamicUser=yes`).
- There are five groups:
  - `pf-fortress` has all pf daemons, for the files that they share (logs,
    state, the claims directories). The DHCP accounts are not in it. Of
    the daemons, only www gets a path to the claims directories
    (`InaccessiblePaths` above).
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
