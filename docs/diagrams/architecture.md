# Architecture — how the code and modules fit together

The system has:

- One binary (`cmd/pf` + `internal/cli`).
- Two enforcement tiers (engine + broker).
- One policy pipeline (fetch → compile → render → apply).
- One management plane with no network listener.

The labels name the real files. The code itself is the authoritative
table.

## 1. The whole system on one page

```mermaid
flowchart TB
    subgraph CLI["cmd/pf + internal/cli — one binary, many verbs"]
        APPLY["pf apply<br/>(fetch → compile → render → install)"]
        ENGINE["pf engine :8080"]
        BROKER["pf broker"]
        DNSD["pf dns"]
        ENROLL["pf enroll · unlock<br/>mint · seal · unseal"]
        TUI["pf tui"]
        OBS["pf observe · monitor<br/>alert"]
        WWW["pf www :80"]
        DOCTOR["pf doctor · status<br/>backup · restore"]
    end

    subgraph POLICY["Policy pipeline"]
        FETCH["internal/fetch<br/>blocklist feeds"]
        PCOMP["internal/policycompile<br/>merge − never_block"]
        RENDER["internal/render<br/>net.env + house.env + segments.d<br/>→ nftables.conf"]
        APPLYSH["vm/pi/apply.sh<br/>install nft · dnsmasq · units"]
        NFT[("nftables ruleset<br/>forward · input · output")]
    end

    subgraph DATAPATH["Per-connection data path (agent traffic)"]
        direction LR
        subgraph ENG["internal/engine — TLS terminator (user pf-engine)"]
            PEEK["internal/peekconn<br/>ClientHello peek + replay"]
            HELLO["internal/hello<br/>SNI · ALPN"]
            CA["internal/ca<br/>per-SNI leaf certs"]
            ORIGDST["internal/origdst<br/>SO_ORIGINAL_DST"]
        end
        PREAMBLE["internal/preamble<br/>PFB1 frame: conn id · orig dst · SNI · prints"]
        subgraph BRK["internal/broker — HTTP fence (user pf-broker)"]
            HW["internal/httpwire<br/>strict HTTP/1.1 framing"]
            FENCE["internal/fence<br/>keep · inject · strip"]
            HARVEST["harvest.go<br/>OAuth refresh capture"]
            REWRITE["rewrite.go<br/>scrubPairs → placeholder"]
            DOH["internal/doh<br/>DoH request signature"]
        end
        SECRETS["internal/secrets<br/>slot store · sealed at rest"]
    end

    subgraph DNS["DNS plane"]
        DNSMASQ["dnsmasq<br/>DHCP only: house, DHCP=on segments"]
        GODNS["internal/dnsd<br/>per-segment policy:<br/>agent · house · plain segments"]
        DNSLOG["internal/dnslog<br/>shared query-log format"]
        BLOCKLIST["internal/blocklist<br/>address=/name/ parser"]
    end

    subgraph MGMT["Management & observation (no network listeners)"]
        ADMIN["internal/admin<br/>verb table · apply lock · atomic writes"]
        AUDIT["internal/audit<br/>JSONL per mutating verb"]
        JSONL["internal/jsonl<br/>strip · use · unknown writers"]
        TAILER["internal/tailer"]
        ALERT["internal/alert<br/>webhook (never the token)"]
        OBSERVE["internal/observe<br/>DNS + conntrack ledger"]
        MON["internal/monitor<br/>box + proc stats"]
    end

    SHARED["internal/base · internal/dest<br/>internal/corepolicy · internal/blocklist"]

    APPLY --> FETCH --> PCOMP --> RENDER --> APPLYSH --> NFT
    NFT -.->|redirect :8080| ENGINE
    ENGINE --> PEEK --> HELLO --> CA
    ORIGDST --> ENGINE
    ENGINE -->|unix sock + PFB1| PREAMBLE --> BROKER
    BROKER --> HW --> FENCE
    FENCE -->|"live value"| SECRETS
    FENCE --> DOH
    HARVEST --> SECRETS
    FENCE --> REWRITE
    DOH --> JSONL
    REWRITE --> JSONL
    DNSMASQ -.-> DNSLOG
    GODNS --> DNSLOG
    BLOCKLIST --> GODNS
    PCOMP --> BLOCKLIST
    DNSLOG -.-> OBSERVE
    JSONL --> TAILER
    TAILER --> ALERT
    TUI --> ADMIN --> AUDIT
    ADMIN --> APPLY
    ENROLL --> SECRETS
    OBS --> OBSERVE
    OBS --> MON
    SHARED -.-> FENCE
    SHARED -.-> PCOMP
```

## 2. The two-process privilege split

The engine sees ciphertext and ClientHello messages. The broker sees
plaintext and live credentials. The two must not share a process
(`docs/privilege_split.md`):

```mermaid
flowchart LR
    subgraph ENGPROC["pf engine — user pf-engine"]
        E1["accept :8080 (redirected)"]
        E2["peek ClientHello"]
        E3["mint leaf (internal/ca)"]
    end
    SOCK[("unix socket<br/>/run/pi-fortress/broker/broker.sock<br/>0660 pf-broker:pf-fence")]
    subgraph BRKPROC["pf broker — user pf-broker"]
        B1["read PFB1 preamble"]
        B2["HTTP fence (internal/fence)"]
        B3[("secrets.env 0600<br/>/etc/pi-fortress/broker/")]
    end
    AGENT["agent VM"] -->|"TLS w/ leaf"| E1
    E1 --> E2 --> E3 --> SOCK
    SOCK --> B1 --> B2
    B2 --> B3
    B2 -->|"dial tcp/443 only (nft output rule)"| NET(("internet"))
```

The group `pf-fence` controls access to the socket. Each other daemon
unit lists the broker directory in `InaccessiblePaths`. Only root can reach
the admin socket (`/run/pi-fortress/broker/admin.sock`, 0600,
pf-broker). The full model of the TUI is "the operator's sudo".

## 3. The policy pipeline (config → running fence)

```mermaid
flowchart LR
    subgraph INPUTS["Inputs"]
        SRC["vm/policy/sources.json<br/>feed URLs"]
        LOCAL["vm/policy/*<br/>blacklist · never_block · doh<br/>core.hosts · key_prefixes.rules"]
        ENV["vm/pi/net.env · house.env<br/>segments.d/*.env"]
    end
    FETCH["pf fetch as pf-feeds<br/>pi-fortress-feeds.service<br/>unreachable feed → STALE from cache<br/>pf feeds run (root) checks each line → generated/"]
    COMP["pf compile<br/>internal/policycompile<br/>local + generated − never_block"]
    REND["pf render<br/>internal/render<br/>refuses overlap · detects WAN_IF"]
    APPL["pf apply → vm/pi/apply.sh<br/>apply lock · restarts only what changed"]
    LIVE[("live: nft sets · dnsmasq conf<br/>pf dns · NetworkManager · units")]

    SRC --> FETCH --> COMP
    LOCAL --> COMP
    ENV --> REND
    COMP --> REND
    REND --> APPL --> LIVE
```

A refusal at any step leaves the previous ruleset loaded. A golden file
pins the no-house render. Thus a drift makes a test fail, not a device.

## 4. Where a decision is made (layer stack)

This diagram shows, in order, each module that answers the question
"may this connection exist?":

```mermaid
flowchart TB
    A["nft prerouting<br/>blacklist_v4 drop (before redirect)"] --> B
    B["nft resolver_gate + forward<br/>isolation pairs · resolver gate<br/>resolved_v4 · direct_ip.allow"] -->|"443 only"| C
    B -->|"everything else"| DROP1["policy drop"]
    C["internal/hello + engine<br/>SNI present & allowed · ALPN http/1.1"] --> D
    C -->|"empty/blocked SNI · h2-only"| DROP2["TLS refused / alert"]
    D["internal/fence via broker<br/>kind + SNI/Host agree (corepolicy)"] -->|"inject"| E["live credential toward core host"]
    D -->|"off-kind / unknown host"| F["strip live-looking values<br/>+ unknown.jsonl (review log)"]
    D -->|"doom path: /dns-query"| G["internal/doh → 403"]
```

Tutorials 03–06 explain each layer in detail.
