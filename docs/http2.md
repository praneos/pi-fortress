# HTTP/2 support for Pi Fortress

## Decision: HTTP/1.1 only

Pi Fortress uses HTTP/1.1 on both hops:

- The engine offers only `http/1.1` to the agent.
- The broker also offers only `http/1.1` when it dials an origin server.

All default agent clients that are important here work with this. Each
client either advertises `http/1.1` together with `h2` and negotiates down
cleanly, or uses h1 already. These clients are:

- Claude Code on the Node global `fetch`/undici.
- The anthropic SDK on httpx.
- Go `net/http`.
- curl, git, npm, pip, and gh.

The cost is the performance of multiplexing. The gain is no new module, and
no new parser that faces the attacker in the credential path.

Also, a configuration flag cannot enable h2. The full request and response
path of the broker is a hand-written HTTP/1.1 wire parser
(`internal/httpwire`). This parser does not import `net/http`, by design. It
has no framing, no HPACK, and no multiplexing. `docs/privilege_split.md` and
`docs/risk_model.md` §7 record the same decision: `http/1.1` only, until the
broker gets h2 support.

## What the engine does today

`internal/engine/engine.go` builds the `tls.Config` for the agent side with
these settings:

- `NextProtos: []string{"http/1.1"}`
- `MinVersion: tls.VersionTLS12`
- Session tickets disabled.

`internal/broker/upstream.go` also pins the TLS client for the origin side to
`http/1.1`.

`internal/hello` sets `Hello.H2Only` when a ClientHello has an ALPN extension
that lists neither `http/1.1` nor `http/1.0`. The engine then logs
`alpn_h2_only refused: engine speaks http/1.1 only sni=<sni> src=<addr>`.
This is a log line, not a branch. Control continues to the same h1-only
configuration, and the handshake decides the result.

- A client that offers both `h2` and `http/1.1` gets `http/1.1`. The client
  never sees a difference.
- A true h2-only client has no protocol in common with the engine. Thus the
  Go TLS server sends a fatal `no_application_protocol` alert, the handshake
  fails, and the engine logs the handshake error.

The alert is the clearest signal that the client can get. Thus the engine
does not close early. `TestH2OnlyLog` in `internal/engine/engine_test.go`
tests both the log line and the failed dial. Pi Fortress does not support
h2-only clients and prior-knowledge clients, by design.

## Reopen trigger

Build HTTP/2 when one of these occurs:

- A named client that we must support ships a default ALPN that offers `h2`
  without `http/1.1`. This is a hard failure, not a fallback.
- A measured latency or throughput regression on Claude Code traffic comes
  from the lack of multiplexing.

Monitor the first condition with the `alpn_h2_only` log count.

The near-term item to monitor is Claude Code on Node 26 or later. There,
undici v8 enables h2 by default. This alone does not start the trigger,
because undici still lists h1. But it is the signal to start.

When the trigger occurs, the path is an h2 server in the broker, with an h1
downgrade to the origin server. There are two options:

- The unencrypted HTTP/2 of the standard library (`net/http` `Protocols`
  with `UnencryptedHTTP2`). This adds no new modules.
- `golang.org/x/net/http2` `ServeConn`. `golang.org/x/net` is already in
  `go.mod`. This adds a new package from that module.

Most of the work is h2spec, fuzzing, and flow control on the HPACK decode,
fence, re-encode adapter.

## Why the other options were rejected

A hand-written framer and HPACK would keep the zero-dependency style. But
they would add two to three thousand lines of parser to the credential path.
This parser is security-critical and faces the attacker. It would also
implement again the algorithms that the Go team already fuzzes.

A different option is to pass h2 straight through for non-core hosts, and to
force h1 per SNI only for core hosts. This option is cheap and it works. But
it makes each unknown destination that can use h2 into a blind tunnel:

- The broker would not strip foreign live tokens.
- The broker would not catch DoH over h2.
- The unknown-destination log would stop for exactly the traffic that the
  fence exists to monitor.
