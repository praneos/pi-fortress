# Tutorials — the networking behind Pi Fortress

These tutorials are a plain-language refresher on each core networking concept that Pi Fortress uses. They are for all readers who want to know how Pi Fortress works inside. The order of the files is the order in which a packet meets the concepts. Each file first explains the concept. Then it shows exactly where and how Pi Fortress uses it.

| # | File | Concept |
|---|---|---|
| 1 | [01-ip-routing-nat.md](01-ip-routing-nat.md) | Addresses, subnets, private ranges, gateways, routing, NAT/MASQUERADE, conntrack |
| 2 | [02-vlan-segments.md](02-vlan-segments.md) | VLANs, trunk ports, segment isolation, why one cable carries the agent and desk networks |
| 3 | [03-dns-sinkhole-doh.md](03-dns-sinkhole-doh.md) | DNS resolution, caching, DoH/DoT, sinkholing, the resolver gate |
| 4 | [04-tls-interception.md](04-tls-interception.md) | TLS handshake, ClientHello/SNI/ALPN, CA + per-site leaf certs, transparent proxying |
| 5 | [05-nftables-packet-path.md](05-nftables-packet-path.md) | nftables hooks, sets, redirect, SO_ORIGINAL_DST, fail-closed design |
| 6 | [06-http-fence-oauth.md](06-http-fence-oauth.md) | HTTP/1.1 framing & smuggling, the credential fence, placeholder slots, OAuth harvest/scrub |

## Reading order

Are you new to networking? Read 1 → 6 in order. Each file builds on the file before it.

Do you want to learn about only one subsystem? Go directly to that file. Each file names the other tutorials that it assumes you already read.

## Staying safe while you experiment

If you try these steps on your own gateway, obey these rules:

- Test only against well-known safe hosts: `example.com`, Google, Cloudflare.
- For all traffic that the gateway must block, do not use a real target. Use these two canaries:
  - `192.0.2.1` (RFC 5737 TEST-NET).
  - `pi-fortress-block.test` (RFC 2606).
- Never curl, ping, or otherwise connect to a host from a blocklist feed. Treat it as untrusted. Do not try to confirm that it is live.
