# Flows — what actually happens to a request

These sequence diagrams show real behaviour: how requests flow, how
they are rewritten, and how they are blocked. The conventions are the
same as in [architecture.md](architecture.md):

- Red is a drop or a refusal.
- Amber is observation or review.
- Labels name the real code.

For the concepts, refer to
[../user_guide/tutorials/](../user_guide/tutorials/README.md).

## Flow A — allowed request, credential injected (the happy path)

The agent connects to an approved core host. The placeholder leaves the
agent. The live credential goes to the origin server. The response comes
back scrubbed.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent VM (hostile)
    participant R as Pi resolver<br/>(pf dns)
    participant N as nftables<br/>(prerouting chains)
    participant E as pf engine :8080<br/>(TLS terminator)
    participant B as pf broker<br/>(HTTP fence)
    participant O as Origin<br/>(api.anthropic.com)

    A->>R: A? api.anthropic.com (DNS pinned to Pi)
    R-->>A: 203.0.113.7 + adds to nft set resolved_v4 (element lives 2h,<br/>the answer, cached or handed out, never outlives it)
    A->>N: TCP 443 → 203.0.113.7, TLS ClientHello<br/>(SNI=api.anthropic.com, ALPN)
    N->>N: raw: not in blacklist_v4 ✓<br/>resolver gate: new conn, IP ∈ resolved_v4 ✓
    N->>E: REDIRECT to :8080 (orig dst via SO_ORIGINAL_DST)
    E->>E: internal/peekconn: read + replay hello<br/>internal/hello: SNI ok · ALPN http/1.1 ok
    E->>E: internal/ca: mint leaf cert for SNI (Pi CA)
    E->>B: unix socket + PFB1 preamble<br/>(conn id, orig dst, SNI, ALPN)
    B->>B: source ∈ agent-net? (else 403) · httpwire framing checks
    B->>B: internal/corepolicy: core host + kind CLAUDE_OAT allowed<br/>→ internal/fence INJECTS live OAT over placeholder
    B->>O: TLS dial (pf-broker output rule: tcp/443 only)
    O-->>B: 200 response
    B->>B: internal/fence scrub: live literals → placeholders
    B-->>E: rewritten response
    E-->>A: response over leg-① TLS — agent never saw the live token
```

## Flow B — blocked: three layers, all fail closed

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant R as Pi resolver
    participant N as nftables
    participant J as kernel journal → pf observe

    rect rgb(255, 235, 235)
    Note over A,R: ① Name on the blocklist — sinkhole
    A->>R: A? malware.example
    R-->>A: 0.0.0.0 (address=/name/0.0.0.0 — never went upstream)
    end

    rect rgb(255, 235, 235)
    Note over A,N: ② Client that skips DNS — direct IP
    A->>N: TCP 443 → 192.0.2.1 (canary, TEST-NET)
    N->>N: prerouting: blacklist_v4 interval match → DROP
    Note over N: silent timeout, not RST — the prober learns nothing
    end

    rect rgb(255, 235, 235)
    Note over A,N: ③ Structural escapes — no route exists
    A->>N: UDP 443 (QUIC) · TCP 853 (DoT) · TCP 8443<br/>TCP 22 · 51820 (WireGuard) · IPv6
    N-->>A: DROP (raw prerouting, then forward chain)
    end

    N->>J: nft drop log line (prefix + address — never a token)
```

## Flow C — DoH escape attempt, caught by signature

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant N as nftables
    participant B as pf broker
    participant D as internal/doh

    A->>A: resolve own DoH endpoint (fails if known — doh.domains sinkholed)
    alt resolver answered (unknown DoH front)
        A->>N: POST https://some-host/dns-query?dns=… (tcp/443)
        N->>B: resolver gate ok → redirected into fence
        B->>D: path /dns-query · content-type application/dns-message
        D-->>A: 403
    else known resolver IP
        A->>N: TCP 443 → doh.ips entry
        N-->>A: DROP (never_block cannot reopen these)
    end
    Note over A,N: even a successful lookup yields an IP the resolver gate<br/>will not pass 443 to — the escape fails twice over
```

## Flow D — OAuth refresh: harvest + scrub

This is the only flow in which the response carries new credentials.
The agent never sees them.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant B as pf broker
    participant S as slot store<br/>(internal/secrets)
    participant C as platform.claude.com

    A->>B: POST /oauth/token<br/>credential: pf_<16hex>_CLAUDE_ORT
    B->>B: harvestAllowed? path normalized<br/>SNI+Host agree on core host with CLAUDE_ORT ✓
    B->>B: bindRefreshSlot: slot bound from the credential<br/>actually carried (bearer or JSON body)
    B->>S: acquire per-slot refresh lock (before upstream write)
    alt slot busy
        B-->>A: 429 refresh_busy
    else lock acquired
        B->>B: inject live ORT over placeholder
        B->>C: POST /oauth/token (live ORT)
        C-->>B: 200 JSON {access_token, refresh_token}
        alt not JSON or unparsable 200
            B-->>A: 502 — a live pair forwarded unread is never allowed
        else parses
            B->>S: HarvestHeld → upsert new OAT/ORT (never mints rows)
            B->>B: withMinted overlays the new values onto the scrub set
            B->>B: rewrite.go: scrub live literals → placeholders
            B-->>A: response shows placeholders only
            Note over A,S: agent keeps using pf_…, and the live pair<br/>now lives on the Pi, sealed at rest
        end
    end
```

## Flow E — unknown destination: default allow + review log

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant N as nftables
    participant B as pf broker
    participant U as unknown.jsonl

    A->>N: TCP 443 → some-new-docs-site.com
    N->>B: resolver gate ok → allowed (default is allow) → redirect
    B->>B: not a core host → NO injection<br/>internal/fence strips any live-looking credential
    B->>U: sample row, rate-limited per client and host<br/>(names and sizes, no hashes)
    Note over U: adoption over lockdown — the operator reviews<br/>the log, not every request, and it never leaves the box
```

## Flow F — the agent tries to leave (negative space)

This flow shows all that is not in flows A–E. One diagram is
sufficient, because the behaviour is always the same: **drop, log, move
on**.

```mermaid
flowchart LR
    A["agent process"]
    subgraph TRIES["Escape attempts"]
        T1["unset HTTPS_PROXY,<br/>dial origin directly"]
        T2["use DoT 853 / DoQ"]
        T3["QUIC / HTTP-3"]
        T4["git over SSH, ssh anywhere"]
        T5["WireGuard tunnel out"]
        T6["IPv6 destination"]
        T7["hardcoded IP:443<br/>(never resolved)"]
        T8["h2-only or<br/>cert-pinned client"]
    end
    subgraph FATE["Outcome"]
        X1["FENCED — proxy vars are irrelevant:<br/>nft redirects tcp/443 at the router"]
        X2["DROP — 853 closed; 53 only to Pi"]
        X3["DROP — udp/443"]
        X4["DROP — 22 closed unless ssh_allow.ips names it"]
        X5["DROP — 51820; a tunnel is not an exception"]
        X6["no route — disable_ipv6=1 + nft drop"]
        X7["DROP — resolver gate: not in resolved_v4"]
        X8["TLS refused — ALPN http/1.1 only;<br/>no_application_protocol alert"]
    end
    A --> TRIES
    T1 --> X1
    T2 --> X2
    T3 --> X3
    T4 --> X4
    T5 --> X5
    T6 --> X6
    T7 --> X7
    T8 --> X8
    X1 --> L["unknown.jsonl / strip log<br/>→ alert + review log"]
    X7 --> L2["nft drop log → pf observe<br/>(blocked events)"]
```

Caveat, for the lab only: if `AGENT_BRIDGE` is not set, the VirtualBox
NAT adapter is a userspace path around all of these controls. The
default Vagrant lab is a development topology. It is not an isolation
tier.

## Flow G — a plain segment (the desk)

The gateway filters a plain segment (`segments.d/<name>.env`) as a
machine to which an agent possibly escaped. But the gateway never
terminates it: there is no engine, no broker, and no credential.

NAME below is the file name of the segment. Its resolver feeds
`resolved_NAME_v4` and nothing else. The diagram does not show
SSH_FROM, the one way in.

```mermaid
flowchart LR
    D["desk host"]
    subgraph RAW["filter_prerouting (raw)"]
        R1["IPv6 · blacklist_v4 · dns_bypass_v4<br/>UDP 443 · 853 → DROP"]
    end
    subgraph GATE["resolver_gate (-150)"]
        G1["new TCP/UDP (not 53), ping<br/>or any other protocol (GRE, ESP, ICMP)<br/>to an address not in resolved_NAME_v4<br/>→ DROP NAME-directip<br/>(BLOCK_DIRECT_IP=off removes it)"]
    end
    subgraph FWD["forward"]
        F1["isolation from agents (SSH_TO only),<br/>house and other segments"]
        F2["53 elsewhere → reject<br/>reserved_v4 → DROP NAME-local"]
        F3["TCP 22 to ssh_allow_v4 → accept"]
        F4["seg_NAME_egress:<br/>strict ports + ALLOW_PORTS<br/>(audit logs, open skips)"]
    end
    DNS["pf dns segment: agent lists,<br/>key-shape refusal, address-only<br/>(+ DNS_TYPES), PARANOID=on allowlist"]
    WAN(("uplink, NAT"))
    D -->|"DNS to the Pi"| DNS
    DNS -.->|"answers feed"| G1
    D --> R1 --> G1 --> F1 --> F2 --> F3 --> WAN
    F2 --> F4 --> WAN
    G1 -.-> OBS["pf observe: first-seen dest rows,<br/>dns_key, dns_tunnel"]
```
