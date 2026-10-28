# Fence — Pi Fortress

This document describes the secrets fence and the functions that depend on
it:

- the single refusal
- sealed credentials
- strip alerts
- content encoding
- WebSocket
- unknown destinations
- enrolment

The section numbers are stable. Other docs refer to them. For the risk
model, refer to `docs/risk_model.md`. For the operator view of policy files,
blocklists, and `pf tui`, refer to `docs/lab.md`.

## 5.2 Secrets fence

The fence does egress filtering on agent HTTPS:

- It inspects outgoing headers and bodies.
- It enforces redaction policies.
- It applies approved credentials for each host schema.

The agent has only `pf_<slot>_<KIND>`. The real values are on the Pi
(`/etc/pi-fortress/broker/secrets.env`, mode 0600, owned by the broker, not
in git). Each secret has a slot. `sudo pf enroll mint --kind CLAUDE ...`
allots a new 16-hex slot. The oat and the ort share this slot. The fence does
not substitute an unslotted `pf_CLAUDE_OAT`.

Placeholders have the format `pf_<16hex>_<KIND>`. The fence substitutes
only this exact spelling (the hex can be in either case). The slot ID is the
secret part, and an origin can change the letter case back or remove a
letter. Thus the fence also finds a placeholder with the prefix or the kind in
a different letter case (`PF_…`, `pf_<16hex>_claude_oat`), or with more
letters, digits or `_` after the kind (`pf_<16hex>_CLAUDE_OATx`). It never
substitutes such a variant. It refuses it in each location where it refuses a
placeholder: a header value or name, the method, the URL, a buffered body
(`slot_unknown` in a credential header) and a streamed body. `pf dns` and
the SNI check refuse it in a name.

`pf engine` terminates agent TLS on TCP 443 (nft redirect `:8080`). `pf
broker` applies approved credentials and enforces redaction. The two must not
share a process (`docs/privilege_split.md`).

The fence applies a credential by **kind + TLS name**, not to "any core
host". `vm/policy/core.hosts` lists `host KIND…` (`*` = lab echo). A name
matches exactly, unless it is written as `*.name`. `*.name` matches the name
and each subdomain of it. `pf compile` and `pf apply` refuse some host forms:
a host with one label (`localhost`), a host with `_`, a bare `*`, a `*` after
the first `*.` (`*.*.example.com`), a host with an empty label
(`..example.com`), a label over 63 bytes, a host over 253 bytes, and a
non-ASCII host. They print a warning,
skip that line, and change nothing else. For a non-ASCII host, the warning
gives the `xn--` form to write. `*` as a kind (the lab echo) is not
changed. A Claude placeholder
becomes live only toward Anthropic/Claude names. A GitHub placeholder becomes
live only toward GitHub.

The SNI is mandatory and must be a valid host name. The Host must match that
SNI, or be a subdomain of it. Thus Host `api.anthropic.com` with SNI
`evil.example` does not inject. A subdomain Host whose own `core.hosts`
line grants other kinds or headers than the line of the SNI does not
inject either. For an off-core host and for a kind mismatch,
the fence refuses the request with one response that does not give the cause
(§5.2b). The fence strips live-looking values in the bytes that it scans
(see "What the fence scans" below).

Substitution is **header-only**. The fence substitutes only into the
credential headers of the kind:

- `Authorization`, for every kind. This includes Bearer, and the decoded
  user:password of Basic (thus git over HTTPS).
- `X-Api-Key`, for every kind.
- Each header that a `core.hosts` line declares for that host and kind, as
  `host KIND:Header[,Header...]` (`gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN`).

Names are case-insensitive.

A placeholder of an allowed kind in any other header refuses the whole
request (`placeholder_outside_header`, with `where` naming the header). The
fence writes nothing into the request. Examples are `User-Agent`, `Referer`,
`Cookie`, and any `X-` header that is not declared. Reason: these headers go
into access logs and come back in audit APIs (the GitHub API returns
`user_agent`). There, they get past the literal scrub.

You can never declare these headers: `User-Agent`, `Referer`, `Origin`,
`Cookie`, `Set-Cookie`, `Host`, `Via`, `Forwarded`, `X-Forwarded-*`,
`X-Real-IP`, `Content-*`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
`Upgrade`, `TE`, `Trailer` and `Proxy-*`. `pf apply` refuses such a line and names the file and the
line. `pf enroll mint --header` also refuses it.

The lines for one host add up, for kinds and for headers. The operator puts
their own lines in `core.hosts.local`, next to `core.hosts`. An upgrade
replaces `core.hosts` and keeps the local file. Apply installs the two files
as one `/etc/pi-fortress/core.hosts`, with the local part below a marker
line.

A placeholder in `Host`, `Connection` or `Upgrade` refuses the request, as in
any other non-credential header. The fence never substitutes into these three
headers, and it never changes them. The authority decision, the blocklist and
paranoid mode read the `Host`, and the origin server routes the request by
it. Thus a live value or a token-prefix match in `Host` refuses the request
(`live_in_host`, an alert), also a live value of a kind that the host
injects. The broker does this check before its own rules on the `Host`
(the target rules, the blocklist, paranoid mode, git push). Thus a live
value always gives `live_in_host`, also when it makes a label longer than
63 bytes. The broker reads `Connection` and `Upgrade` to decide on a WebSocket
(§5.3c) before the fence runs, and the origin server switches the protocol by
them. Thus a live value or a token-prefix match in `Connection` or `Upgrade`
refuses the request (`live_in_connection`, an alert), also a live value of a
kind that the host injects. The origin server reads these three headers and
each field name without letter case. Thus the fence finds a live value there
in any letter case. The row names the header as the agent wrote it.

The fence writes a credential into one body only: the body of the refresh
token, `CLAUDE_ORT` on `/v1/oauth/token` or `/oauth/token`. This body is
always buffered. The refresh token goes there and nowhere else. It goes only
as the whole string value of the one top-level `refresh_token` key of the
body. It never goes:

- in a header,
- in a different field,
- in a second or case-variant `refresh_token`, or
- off the refresh path.

A placeholder of an allowed kind in any other location that the fence scans
refuses the request (`placeholder_outside_header`, an alert). Examples are
the URL and any other buffered body. A placeholder in a streamed body stops
the copy (`placeholder_in_streamed_body`, §5.2b). Data in a body or a URL can
come back past the literal scrub. Examples are a model that is asked to print
its prompt in reverse, a public gist, and an access log. Stripping does not
change. It runs over the URL, every header except `Host`, `Connection` and
`Upgrade`, and the body.

What the fence scans:

- The literal bytes of the method, the request target, each header name and
  value, and the body.
- A gzip or deflate body, after the decode, and the optional fields of each
  gzip member header (§5.3b).
- The decoded user:password of `Authorization: Basic`.
- The request target after the fence decodes all percent escapes.
- Each JSON string (key or value) of a buffered JSON body that holds an
  escape (`\uXXXX`, `\/`), after the unescape. A body is JSON when its
  `Content-Type` names JSON or when it parses as JSON. A string that holds
  JSON text with escapes gets the unescape again, up to four rounds.

A placeholder in a decoded form refuses the request, as in the literal
bytes. A live value or a token-prefix match that only a decoded form shows
also refuses the request (`encoded_body_token`, `encoded_url_token`),
because the fence cannot strip it in place. A literal match in a string
that also holds an escape strips as before. The fence does not decode other
encodings: base64 outside `Authorization: Basic`, a custom encoding, or a
value split across fields. A placeholder or a live value in such an
encoding passes. `docs/risk_model.md` §2.1 gives this
residual.

A live-looking value matches a `vm/policy/key_prefixes.rules` shape. The
match is the prefix, then the charset of the key, to at least the length of
the rule, and on to the first byte outside the charset. Thus the fence strips
the whole key, and does not miss it, if the key is longer than the minimum or
is glued to the next word.

A match that is longer than 16 KiB is not one key. The fence strips it on to
the end of its run of token bytes (letters, digits, `_`, `-` and `.`). A
streamed body holds at most 16 KiB of a match that is not complete. At that
limit, the fence strips the part that it holds, and then the rest of the run
as it comes. Thus a streamed body and a buffered body strip the same bytes.

A distinctive prefix (`ghp_`, `sk-ant-`, `glpat-`) matches at any position.
A prefix that sits inside ordinary words (`sk-`, `AIza`, `npm_`) needs one of
these before it:

- the start of the text,
- a non-word byte, or
- the end of an escape (`\n`, `\uXXXX`, `%20`).

The fence keeps the escape and strips the token. Thus a key at the start of a
JSON line, or after `%20` in a query, does not get past. The rules are in
`vm/policy/key_prefixes.md`.

The gateway drops UDP 443, so HTTP/3 cannot skip the fence. The gateway drops
blacklisted destinations in prerouting, *before* the redirect. Thus the
canary `192.0.2.1` still times out.

`CANARY` is the challenge kind (`docs/challenge_rules.md`). You mint it like
any other kind: `pf enroll mint --kind CANARY --stdin`. A `*` line does
not cover it, so the lab echo never reflects it. The shipped `core.hosts`
binds it nowhere. Thus the fence refuses every use of the placeholder and
strips every live value.

The broker writes each such event to the strip log, with `"threat":"canary"`
as the last field. These events are a strip, `kind_not_allowed_for_sni`,
`slot_unknown`, and a placeholder in a streamed body. Every refusal is
`alert`, and it does not use the once-per-cause alert of other kinds.
`observe` turns the rows into `canary` events, and the webhook summary starts
with `CANARY`.

A commented line in `core.hosts` shows how to make substitution attackable.
It binds the kind to a throwaway provider key with a 5 USD cap, as a line in
`core.hosts.local`. A canarytokens.org AWS key fits only extraction: SigV4
signs with the placeholder, so AWS rejects it.

Claude subscription: the identity on the wire *is* the Bearer /
`x-api-key`. The oat is opaque (not a JWT). `/v1/messages` has **no** user_id
header. The slot ID is the placeholder itself: `pf_<16hex>_CLAUDE_OAT` /
`_CLAUDE_ORT` (same hex). Two Max logins get two slots. Harvest and the
refresh lock are per slot.

- Inference injects the live oat.
- Refresh (`POST /oauth/token` on `platform.claude.com` /
  `console.anthropic.com`, both core) injects the live ort, captures the new
  oat/ort, and rewrites the response to placeholders.

Do not also `/login` that same ort on the host.

The tests use two names:

- `pf-core-echo.test`: substitute + fake `/v1/oauth/token`.
- `pf-open-echo.test`: no substitute / strip live-looking tokens.

DNS for those names is TEST-NET (`192.0.2.2` / `.3`), not the Pi IP. With
the Pi IP, the engine hairpins to its own :443 and the TLS handshake dies.
The broker answers these names itself. There is no connection to an
untrusted or production API.

The core echo reflects the **live** token back and harvests fake oauth tokens
into the slot. Thus it runs only with `-lab-echo`. `apply.sh` sets this flag
(through `/etc/pi-fortress/broker.env`) only if `/etc/pi-fortress/lab`
exists. The Vagrant provisioner creates that marker, and a shipped Pi has
none. Without the marker, the core echo is a 403 and its DNS entry is not
written.

The one exception is a run of the e2e suite with `PF_E2E_DESTRUCTIVE=1`
(docs/cloud_lab.md). This run:

1. Writes the marker for the length of the run. Thus the `secrets` and
   `enroll` groups can prove refresh capture and frame scrubbing on hardware.
2. Records the baseline under `/var/lib/pi-fortress/e2e-echo`.
3. Removes the marker again in a teardown that `cmp`s every file it touched.

The open echo stays on in all places. `setup.sh` uses it to prove TLS
inspection.

With `-lab-echo`, the core echo also answers a **wss handshake**, on the one
path `/ws`. It has no origin server to switch protocols with. Thus it holds
its own RFC 6455 peer on a `net.Pipe` (`internal/broker/echows.go`). The
handshake, the `101`, both frame pumps, and the scrub are the code that a
real `wss://` connection runs. The peer only reflects. It never scrubs, never
substitutes, and calculates nothing but `Sec-WebSocket-Accept`.

Thus the frames that the agent reads back are the frames that the fence put
on the uplink. This is the only way to see 5.3c from outside the Pi. The
broker refuses these exactly as before: any other path, the open echo, and
the core echo off the lab. The response is 501, or the 403 that the core echo
already answers off the lab.

Harvest runs on `/oauth/token` and `/v1/oauth/token`. It runs only when the
SNI and the Host agree on a core host that has `CLAUDE_ORT`. The broker
forwards the target as the agent wrote it. Thus the match uses those bytes,
and the path must be exactly one of the two paths:

- The authority of an absolute-form target of any scheme is dropped. (The
  broker refuses such a target before the fence runs anyway.)
- A query after `?` is permitted.
- A fragment, a percent escape, a dot segment, a run of `/` or a case
  variant in the path makes the target not a refresh path. An origin can
  route such a target to a different handler.

The refresh token is substituted only on a refresh path. Thus the same test
decides both. The fence refuses a refresh token on any other target. It
never substitutes that token with the harvest disarmed. Thus no pair is
minted that the response scrub has not heard of.

The broker binds the request to one slot, from the refresh credential that
the request actually carries. This credential is a live bearer, or the
`refresh_token` value, read strictly: one key, spelled once, in no other
case. The broker refuses a request before it writes anything upstream if:

- the request carries an ORT in any other shape, or
- the body of the request is not `application/json`.

For a placeholder, the refusal is the one refusal of the fence. For a live
value, the refusal is the 403.

The broker reads the first `Content-Type` to decide on `application/json`.
A request to a refresh path with a second `Content-Type` field, or with a
list of media types in one field (`a/b, c/d`), gets the one refusal of the
fence (`repeated_content_type`, an alert, §5.2b). RFC 9110 lets a recipient
join repeated fields into one list, so the two forms are the same. A comma
in a quoted parameter value does not make a list. The other readers of
`Content-Type` (the JSON body scan above, the DoH check) read each field and
each list item. Thus a request that is not a refresh can repeat it.

The broker acquires that slot **before** the write to the origin server. It
holds the slot until it has stored the rewritten response. A second refresh
of the same slot in that window gets `429 refresh_busy`, not a race. A
200 must be JSON. The broker reads a 200 strictly: one top-level
object, `access_token` and `refresh_token` each spelled exactly once and in
no other case, each value a string with no escape. A 200 must have a valid
`access_token`. It may omit `refresh_token`, but a `refresh_token` that is
present must be valid. For all other 200s, the agent gets a 502. After the
scrub, the broker scans the token response (status reason, field names and
values, body) with `key_prefixes.rules`. A match is a 502 for every status.
The broker stores no token from a status other than 200. Such an answer
gets a 502 when its body has an `access_token` or a `refresh_token` key
(at any depth, in any letter case) or, in a body that is not JSON, one of
these names. Thus the broker does not forward a pair that it did not store
and cannot scrub. An error answer with no such key goes to the agent.
Harvest refreshes
only the rows of a slot that already exists (`upsert` never mints). If any
other origin server returns `access_token`, it is data.

The HTTP layer of the broker (`internal/httpwire`, no `net/http`) is strict
where the fence rewrites by name. It rejects a repeated `Host`,
`Authorization`, or `Cookie` with a `400`. Reason: the fence rewrites the
first one, and the origin server must see exactly what the fence saw. The
fence refuses a repeat of each other header that it writes a credential into
for the host: `X-Api-Key`, and each header that the `core.hosts` line of the
host declares (`repeated_credential_header`, an alert, §5.2b). The name
matches in any letter case. A host that gets no credential has no such
header, so these headers can repeat toward it.

The broker forwards only an origin-form target (`/...`), or `*` with
`OPTIONS`. Reasons:

- The fence, the blocklist, and paranoid mode decide on the SNI and the
  `Host`.
- An origin server that follows RFC 9112 §3.2.2 routes an absolute-form
  target by its own authority.
- Thus `GET https://other.example/` with the Host of a core name would carry
  the credential of that name to a vhost that nobody judged.

The broker also refuses `CONNECT`, an HTTP/1.1 request with no `Host`
field, and a `Host` that is not a host and an optional port (RFC 9110
§7.2: a DNS name, an IPv4 literal, or a bracketed IPv6 literal; a port of
1 to 65535). The blocklist walks the labels of the `Host`, so it must see
a clean name. A `Host` port must be the port that the broker dialled: the
fence, the blocklist, and paranoid mode decide on the name only, and an
origin server can route by the port. A `Host` with no port goes out. The
result is `400`, and a strip row with `where=target` and the rule
`request_target`, `connect`, `no_host`, `bad_host`, or
`host_port_mismatch`. A `Host` that holds a live value or a token-prefix
match gets `live_in_host` before these rules.

The broker skips every 1xx response, up to a bounded number. A 101 is an
error, because nothing asked to upgrade. Thus a `103 Early Hints` cannot be
taken as the final response and desync keep-alive.

The broker checks the framing:

- `Content-Length` with `Transfer-Encoding` is smuggling.
- The broker refuses a `Transfer-Encoding` other than a single `chunked`.
- The broker refuses a repeated `Content-Length` in a request. In a
  response, it refuses repeated values that are not identical.
- The broker caps the header line and the header count before allocation.

If there are too many interim responses, the agent gets a 502. Bytes can
stay on the origin connection after a framed response ended:

- If the response is still buffered, these bytes are also a 502, because
  nothing has reached the agent yet.
- If the response is streaming, the body is already out. The leftover bytes
  then cost only the connection. The broker discards that connection and
  never uses it again.

The broker does not check a close-delimited HTTP/1.0 body for leftover bytes
at all. That connection ends in either case.

The fence does not scan trailers or chunk extensions. The broker reads each
trailer field after the last chunk of a body, checks that it has the shape
of a header field, and then discards it. A chunk extension (the text after
`;` on a chunk size line) is discarded in the same way. A trailer field
with a bad shape, or a control byte in a chunk extension, ends the request.
No trailer field and no chunk extension goes to the origin server or to the
agent. The broker also drops the `Trailer` header, which announces trailer
fields, in the request and in the response. Thus a placeholder or a live
value in a trailer field or a chunk extension does not leave the Pi, and it
writes no refusal and no strip row. The `Trailer` header itself is a
request header: the fence reads it before the broker drops it. A
placeholder there refuses the request, as in any other non-credential
header.

The broker also base64-decodes an `Authorization` value with the scheme
`Basic` (any case, with spaces or tabs before the token), padded or not. The
`user:password` goes through the same scan as any header value: the same
substitution, strip rules, refusal causes, and log rows (`where=header`, no
extra field). The broker re-encodes a changed credential with padding. An
unchanged credential leaves byte-identical. The broker still scans the raw
value. Thus a token that is not base64 is handled as before. There is one
decode and no nested encodings. If a value would grow past the 8 KiB line
cap, the result is a 502, and the broker never forwards it. This is how git
over HTTPS carries a placeholder: its credential helper sends
`x-access-token:<placeholder>` as Basic.

The broker scans origin responses for every live value: in the status reason,
in header names and values, and in the body. It buffers a response that has a
`Content-Length` of 1 MiB or less. It streams all other responses (chunked to
an HTTP/1.1 client). The broker rewrites a match to the placeholder and logs a
strip event with `where=response`. The broker cannot rewrite a header name,
because the name gives the field its meaning. Thus a live value or a
placeholder (in any letter case) in a header name gets a 502 and the same
strip event, and no byte of that response goes to the client. This also applies to the 101 of a WebSocket switch. A strip
event means that the origin server reflected a credential. Treat it as an
incident, not a redaction. The lab echoes are not origin servers. The broker answers
them itself, and the core echo reflects the live token back by design (above).

CA path: `generated/egress-ca.pem` in the policy directory
(`vm/policy/generated/egress-ca.pem` in a source tree). It is installed only
on the agent. During a CA rotation it holds more than one certificate
(§5.2f).

**The domain block list is enforced twice.** dnsmasq sinkholes a listed name
for any client that asks the Pi. A client that does not ask (`curl
--resolve`, `/etc/hosts`, an SDK with a pinned address) gets to the engine
with a well-formed SNI. Thus:

- The engine refuses a listed SNI before it mints a leaf.
- The broker refuses a listed `Host` or SNI with a 403 and a `blocklist`
  strip event.

Both read the same compiled `blocked-domains.conf` as the resolver
(`internal/blocklist`). This is a label walk, so the size of the list has no
cost for each connection. There is one list and one compile. The broker
verifies the origin certificate against the SNI. Thus, on a dedicated origin
server, a client cannot name an unlisted host to reach a listed one. On a
shared CDN edge that permits fronting, the `Host` check is the remaining
line.

Each domain list (for example `blacklist.domains`, `never_block.domains`,
`allow.domains` and the house lists) refuses a non-ASCII name. `pf compile`
and `pf apply` print a warning, skip that line, and give the `xn--` form to
write. An IPv4 address or range on a domain block list of the agent blocks
as it does on `blacklist.ips` (an nft `/32` or the range), not as a name. A
private or reserved address, or a range wider than `/8`, does not compile.
Each line of an operator list that does not compile, or that a shield
removes, gets a warning from `pf compile` and `pf apply`. The warning gives
the file and the reason.

**A blocked name resolves to `0.0.0.0`.** The resolver answers a listed
name with `NOERROR` and one A record, `0.0.0.0`, with a TTL of 0. It does
not answer `NXDOMAIN`. Each other record type of that name gets an empty
`NOERROR` answer. A name outside the allowlist in paranoid mode gets the
same answers. The DNS log marks each of these rows `blocked`. Reasons:

- This is the dnsmasq sinkhole form. The compiled lists use it, and a
  fixture that points a name to a real address uses the same path.
- The answer is final. A stub resolver does not try its search domains or
  a second resolver after it, as it can do after `NXDOMAIN`.

Thus a client gets a failed connection, not a failed lookup. For example,
`curl` reports "Connection refused" and not "Could not resolve host". An
agent that retries on a connection failure also retries a blocked name. On
Linux, a client that dials `0.0.0.0` connects to its own host. Thus a
service that listens on the agent itself can get that connection.

**The key-shape check of `pf dns` also applies to the SNI.** The broker dials
the origin with the SNI of the agent, and the origin can log it. A name that
the agent resolves has passed `pf dns`. But the agent can open TLS to that
address with any SNI. Thus, in both DNS modes and on all listeners:

- The engine refuses an SNI with a `key_prefixes.rules` shape or a
  placeholder before it mints a leaf. It logs `sni key_shape refused` with
  the source and destination, not the SNI. The engine reads the rules from
  `-rules` and refuses to start without them.
- The broker refuses the same SNI before any dial, with a 403 and a
  `sni_key_shape` strip event that is always marked `alert`. The row holds
  the rule and the zone, not the SNI. For a fake-IP pool address, the cause
  is `fakeip_key_shape` (Fake-IP, below).

**A listed name blocks its whole subtree, and that is accepted.** The
resolver, the engine, and the broker all match in the same way as the dnsmasq
`address=/name/`: a listed name covers itself and every name under it. The
walk goes label by label and knows nothing of the Public Suffix List. Thus it
cannot tell a registrable domain from a shared parent that hosts the sites of
other people. If a list names such a parent (`herokuapp.com`, `github.io`,
`blogspot.com`), every tenant under it is blocked, not only the one bad
`x.herokuapp.com` that the list meant. Pi Fortress takes this side on
purpose: it over-blocks a subtree, and does not under-block.

**A feed entry at a shared parent does not compile.** The shipped
`shared_parents.domains` names shared parents: code and site hosts,
application platforms, blog and site builders, dynamic DNS zones and the
usual public suffixes with two labels (`co.uk`). `pf compile` drops a feed
entry that is a name of that list or a parent of one (`github.io`, `io`).
This applies to the agent feeds and to the two house feed lists. An entry
under a listed name (`bad.github.io`) compiles. The summary of `pf compile`
names the entries that it dropped. The list applies only to the fetched
feeds: a name that the operator writes in `blacklist.domains` or
`house.domains` compiles as written. Each ship replaces the list. A shared
parent that the list does not name still blocks its subtree.

The guard is curation: `blacklist.domains` is Pi-owned, and `make pi-ship`
never overwrites it. The escape hatch is `never_block.domains`. It drops
every compiled entry at or under a name that it lists. An IPv4 address on
it shields as on `never_block.ips`: it drops each address or range entry
that holds the address. The escape hatch is as
coarse as the hazard. To open `myapp.herokuapp.com` again under a listed
`herokuapp.com`, the shield must name `herokuapp.com` itself. Reason: a
shield below a listed parent leaves the entry of the parent in place. A
shield on the parent also drops any entry that the feeds carried for a bad
tenant under it.

**core.hosts is a shield of its own, and it is not coarse.** An entry that
would block a host that `core.hosts` or `core.hosts.local` binds
credentials to does not compile: the host itself, a parent of it, or a name
under a `*.` entry. A feed line for `anthropic.com` must not cut the agent
off from the service that holds its credentials. An entry under an exact
core host stays, because it does not block the host. A core host that is
an IPv4 address drops each address or range entry that holds it.

**An IP feed adds no prefix wider than `/12`.** One feed line with a `/8`
would drop 16M addresses. `pf compile` drops a feed prefix that is wider
than `min_ip_prefix` of `sources.json` (8 to 32, default 12), and its
summary names the prefixes that it dropped. The widest entries of the
shipped feeds are `/12`, in Spamhaus DROP. Thus the default keeps all of
them. `blacklist.ips` of the operator accepts a prefix up to `/8`.

Full Public Suffix List handling is not planned. It adds complexity for a
corner case that `shared_parents.domains`, curation and `never_block`
already cover. Examine this again if a shipped feed lists a shared parent
that `shared_parents.domains` does not name, or if a legitimate tenant needs a
narrower carve-out than `never_block` gives. The house list works in the same
way, with `house_never_block.domains` as its shield.

**A destination must have come from the resolver.** Behind the name check
there is an address gate:

- `pf dns` (`internal/dnsd`) puts every A answer that it gives to the agent
  segment into `resolved_v4` (`flags timeout`, 2 h). A cache hit does not
  write the set again. Thus pf dns cuts the TTL of a cached answer to the
  time that its elements have left in the set.
- One answer puts at most 16 addresses into the set on an address-only
  segment (the 16 that the client gets), and at most 64 on a segment that
  gets the full answer. Each resolved set has `size 65535`. When a set is full, the
  kernel refuses the add. pf dns logs the error and answers SERVFAIL, and
  the set gets space again as its elements expire.
- `chain resolver_gate` drops a *new* TCP 443 connection from the agent
  segment to any address outside that set, `PI_IP`, the TEST-NET-1 canaries,
  and the `direct_ip.allow` of the operator.

The chain is at prerouting priority -150:

- After conntrack. Thus `ct state new` holds, and a `pf apply` does not cut
  live flows.
- Before dstnat. Thus the destination is still the origin server, not the
  engine.

The load does flush the set. Apply carries the elements over the load, with
what is left of each timeout (`pf nftsets save|restore`, `internal/nftsets`).
Without this, a client that answers from its own DNS cache never asks again.
The gate then drops its *new* connections until that cache expires. This gate
is what makes an IP-literal SNI fail too. The name check cannot see an
IP-literal SNI.

An element does not name the DNS name that gave it. Thus, when the DNS
policy of the operator changes (an operator block list, an allowlist,
`PARANOID`, a key rule), apply cannot remove only the addresses of the
names that the new policy blocks. Apply keeps a fingerprint of the
operator policy of each resolved set
(`/var/lib/pi-fortress/resolved-policy.state`). When it changes, apply
stops `pf dns`, flushes that set, and then starts `pf dns` on the new
policy (`pf nftsets policy`). A set whose policy did not change keeps its
elements. The feeds are not in the fingerprint. Thus a feed refresh does
not flush the sets, and a name that a feed adds keeps the addresses that
it already has in a set until they expire (2 h). An operator change
flushes at once.

The house segment has the same gate on 80 and 443, from its own
`resolved_house_v4`. With `HOUSE_BLOCK_HTTP=on`, the gate covers only 443.
One shared set would let a name resolved on one segment open an address on
the other. For the same reason, the house gate exempts
`house_direct_ip.allow` (set `house_direct_ip_v4`), never the list of the
agent. Under the default `HOUSE_EGRESS=strict`, it checks each new 443 flow
by its TLS name (the house SNI check). Under a different egress mode, it
checks only a 443 miss by its TLS name and does not drop it.

The house SNI check passes a flow when its name resolves through the house,
is not blocked, and the flow address is one that the name resolves to now,
one that the name resolved to through the house in the last 24 hours, or is
in the same /24 as one that it resolves to now. The /24 lets a CDN that
rotates its addresses through. The 24 hours let a device that opens a flow
with an expired answer after a long idle through, also when the CDN has moved
the name to a different range. A flow with Encrypted Client Hello (ECH) shows only the outer name
of the provider: it passes to a resolved address of that name or into the
ranges of `vm/policy/house_ech.ips`, whatever the inner name, and never by
the /24. A ClientHello that does not parse, or that has an extension type
two times, does not pass.
`direct_ip.allow` ships empty: nothing that an agent runs has needed it.

A plain segment (`segments.d/<name>.env`, the desk) has the gate from its own
`resolved_<name>_v4` on every new flow, not only 443. This includes TCP and
UDP (except port 53), ping, and every other IP protocol (GRE, ESP, SCTP, ICMP
other than echo), whatever `EGRESS` says. Reason: Pi Fortress treats a plain
segment as a machine that an agent can have escaped to. A plain segment has
no `direct_ip.allow` carve-out. `BLOCK_DIRECT_IP=off` in its file removes the
gate. Without `INSPECT=on`, a plain segment gets no TLS inspection, no name
check, and no substitution. The gate, its resolver, and its drops are all
that it has. With `INSPECT=on`, its TCP 443 goes to the engine on the segment
address (`-inspect-listen`), and the broker serves its subnet (`-fence-net`).
The paranoid forward set of the agent never applies to it, and the broker
refuses a fake-IP pool address from it (`fakeip_segment`).

**Fake-IP (`AGENT_DNS=fakeip`, the default. Claude Code's WebFetch and the
common HTTP stacks dial the pool).** In forward mode, every name that the agent looks up goes out of the
Pi as a query, before the fence has seen a connection. Thus a lookup alone is
a channel out (`<secret>.evil.example`), and an answer is a channel back in.

In fakeip mode, `pf dns` runs its checks on every agent A query: key shape
first, then class, the AAAA/HTTPS/SVCB filter, address-only, the sinkhole and
fixtures, no-dot and bogus-priv, and paranoid. If the query passes, `pf dns`
answers with an address from `FAKEIP_NET` (default `198.18.0.0/16`). There is
one name for each address, and the TTL is 60 s. `pf dns` forwards no A
query: no upstream, no cache, no `resolved_v4` write. A type that
`dns_types.allow` permits still goes upstream. AAAA, HTTPS and SVCB never
go upstream: an entry for them in `dns_types.allow` has no effect.

Each assignment is a line in `/var/lib/pi-fortress/dns/fakeip.journal`
(`internal/fakeip`), written before the answer. A name keeps its address
across restarts. A full pool uses the least recent address again. The gate
admits the pool where it admitted `resolved_v4`.

The engine gives the pool address to the broker as OrigDst. The broker then:

1. Refuses (403 `fakeip`) an empty SNI, a key-shaped SNI, or an IP-literal
   SNI. The key-shape check is the check of `pf dns`, and it runs first.
   Thus no strip row holds the key.
2. Maps the address back through the journal. It refuses (403 `fakeip`) an
   unmapped address, or an SNI that is not the mapped name.
3. Runs the blocklist and paranoid checks.
4. Only then resolves the name itself (`-resolver`: `DNS_FORWARD`, the
   upstream with DoT off, the stub on `127.0.0.1` with DoT on).
5. Dials an answer that passes `dest.Allowed`.

The address blocklist moves to the output chain on the `pf-broker` uid,
because the packets of the agent no longer carry a real address. The journal
is `pf-dns:pf-fakeip 0640` in a setgid `2750` directory. `pf-fakeip` holds
the broker alone.

What fake-IP closes: DNS as a silent channel in both directions. A lookup no
longer goes out of the Pi, and nothing but a pool address comes back. The
exception is a type that the operator permits in `dns_types.allow`. That
exception is never AAAA, HTTPS or SVCB.

What fake-IP does not close: a TLS connection to a name that the attacker
selects still makes the Pi resolve that name upstream, one time for each
name. But that lookup now:

- Is logged. `dns.jsonl` has the assignment, and the strip log of the broker
  has any refusal.
- Is key-checked twice: pf dns checks the query, and the broker checks the
  SNI.
- Costs a full TLS handshake through the fence for each name, not a UDP
  packet.

Also, paranoid mode still refuses any name outside the forward set before the
lookup.

SSH to `ssh_allow.ips` hosts works by address only, by design. The list holds
addresses and no names (`pf compile` skips a hostname line). Thus pf dns has
no name that it could answer with a real address. To learn which names go to
the list, pf dns would have to resolve every name upstream. That is the
lookup that fakeip exists to remove.

A name resolves to a pool address. TCP 22 is never redirected to the broker.
The forward chain answers the SYN with a reset. (For that, the raw TCP 22
drop skips the pool, and nothing else.) Thus `ssh host.example` on the agent
fails at once with "connection refused" against a `198.18.x.y` address. Use
the address, or a `~/.ssh/config` `Host` alias with `HostName <address>`.

To switch modes, set `AGENT_DNS=` in `net.env.local` (`forward` pins real
answers) and run `pf apply`. `pf apply` restarts `pf dns` and the broker.
Agents keep the answers that they already cached until their TTL ends: 60 s
for a pool answer, and up to the TTL of the upstream for a real answer. Until
then, connections to those addresses fail at the gate.

**Eyeball networks (`eyeball_network`, `EYEBALL=audit`, the default).**
`dest.Allowed` refuses private, reserved and LAN addresses. A public name can
still resolve to the home line of an attacker: a dynamic DNS name, a
residential proxy, or a home server for exfil or control. The agent reaches
cloud, hosting and CDN networks on a normal day. A home or mobile line is
rare, and it has the shape of those channels.

The broker looks up each address that it dials for the agent network in a
table of eyeball networks (`internal/eyeball`). The lookup is after
`dest.Allowed` and before the dial. In fakeip mode, the broker looks up each
address that the name resolved to. In forward mode, it looks up the address
that the agent dialed. A segment with `INSPECT=on` does not get the check.

| `EYEBALL` | A hit |
|---|---|
| `audit` | The broker dials. It writes a refusal row with `where` `audit`. |
| `refuse` | The broker does not dial that address. In fakeip mode it dials the next address of the name that is not a hit. If no address is left, the agent gets the 502 of a name with no dialable address, and the row has `where` `resolve`. In forward mode, the agent gets the 403 `ssrf` of `dest.Allowed`, and the row has `where` `preamble`. |
| `off` | No check. |

The row has `cause` `eyeball_network`, `host` (the name), `sni`, `dest_ip`
(the address), and `kind` (the ASN, for example `AS64496`). It alerts one
time for each name and ASN while the broker runs. The next rows for that
pair go only to the log. Thus a second home server does not hide behind the
first one.

The table: `pf fetch` builds `generated/eyeball.table` from the `eyeball`
section of `sources.json`. `pf apply` installs it as
`/etc/pi-fortress/eyeball.table`.

- The ranges feed maps each announced IPv4 range to its ASN (iptoasn.com,
  public domain).
- An ASN feed says which ASNs are eyeball networks: the class Eyeball of
  bgp.tools, its `dsl` and `mobile` tags, and the type Cable/DSL/ISP of
  PeeringDB.
- An ASN is in the table when an ASN feed includes it and no feed excludes
  it. bgp.tools class Content excludes. Thus a host of servers that calls
  itself an ISP in PeeringDB stays out.
- An unknown ASN is not in the table, so it is never a hit.

Each feed has its own last-good copy, as a blocklist feed has. The table
has the time of its oldest data. The broker loads the table again when the
file changes, with no restart. The check fails open:

- With no table, the check is off.
- With a table older than 30 days, the check is off.
- With a file that does not parse, the broker keeps the last good table.

The broker logs each change of that state one time (`pf broker: eyeball
...`).

A false hit is possible. Some CDNs put cache servers inside the network of
an ISP (Google Global Cache, Akamai, Netflix Open Connect). Such a server
has an address of the ISP, so a name that the CDN sends there is a hit.
Exempt that name.

`eyeball.allow` in the policy directory exempts a destination. One entry is
on each line: a name, which also exempts the names below it, or an ASN
(`AS64496`). On the Pi, edit `/opt/pi-fortress/vm/policy/eyeball.allow` and
run `pf apply`. The broker reads the list again when it changes.

What the check does not catch: a server in a cloud or hosting network, an
ISP that no feed lists, IPv6, and the time when the check fails open. It is
a detector on top of the fence, not a gate (`docs/risk_model.md` §2.1).

### 5.2b One wall, not a taxonomy

Substitution can fail for these reasons:

- The slot is unknown.
- The slot is disabled.
- The slot is expired (§5.2e).
- The slot holds no value.
- The store is sealed and locked (§5.2c).
- The destination may not carry that kind.
- The placeholder is in a location where the fence does not substitute.
- A field name holds a placeholder, a live value, or a token-prefix match
  (`key_in_header_name`). The fence cannot rewrite a name, because the name
  gives the field its meaning.
- The request method holds a placeholder, a live value, or a token-prefix
  match (`key_in_method`). The fence cannot rewrite a method, because the
  method gives the request its meaning.
- The percent-decoded request target holds a live value or a token-prefix
  match that the raw target does not show, or the target does not decode to
  a stable form in a few rounds (`encoded_url_token`). The raw bytes are
  different, so the fence cannot strip the value in place.
- The `Host` holds a live value or a token-prefix match (`live_in_host`).
  The origin server routes the request by its `Host`, so a strip there
  sends the request to a name that the fence did not judge.
- A `Connection` or an `Upgrade` holds a live value or a token-prefix match
  (`live_in_connection`). The broker decided on a WebSocket from these
  headers, so a strip there makes the origin server do a different thing.
- A header that the fence writes a credential into for the host occurs more
  than one time (`repeated_credential_header`). The origin server can read
  either field, and thus a value that the fence did not decide on.
- A request to a refresh path has more than one `Content-Type` field, or a
  list of media types in one field (`repeated_content_type`). The origin
  server can read a media type that the broker did not decide on.

For all of them, the agent gets one response, byte for byte: a 503 with
`Retry-After: 60` and a body that names no cause. The broker refuses the
request and does not forward it.

The agent is the adversary. Thus a taxonomy contradicts the design. Distinct
codes give away, in this order:

1. The state of the gateway.
2. Which slots exist and which are quarantined.
3. The inventory.
4. The SNI-to-kind policy. An agent could probe this policy host by host,
   and then aim at the weakest approved destination.

A dev-mode detail flag is not a solution. It gives two response paths, and
the production path is the untested one. Forwarding is also not a solution.
The 401 of the origin server would say what the fence does not say. It would
also give the slot ID and kind to a destination that the agent selected.

The detail is not deleted. It only goes to a different place. The broker
writes each cause to the strip log as `substitution_refused`, with the cause,
slot, kind, and SNI. `kind_not_allowed_for_sni`,
`placeholder_outside_header`, `placeholder_in_ws` (5.3c),
`encoded_body_token`, `key_in_header_name`, `key_in_method`,
`encoded_url_token`, `live_in_host`, `live_in_connection`,
`repeated_credential_header`, and `repeated_content_type` are always marked
`alert`. Each other cause is marked `alert` one time for each broker start.
These eleven are not an operational fault to fix. They show the fence
catching a credential aimed where it may not go. This is the signature of a compromised or badly broken
agent. A `live_in_host` row has the SNI as its `host`, so the live value goes
to no log and no webhook. The broker writes some rows before the fence runs:
the target rules, the blocklist, the paranoid deny and a refused git push.
A `Host` that holds a live value or a token-prefix match refuses as
`live_in_host` before each of these. When only the lowercase form of the
`Host` matches a token rule, each of these rows also has the SNI as its
`host`. A refresh response that the broker refuses (the
harvest cannot read the new pair, an answer other than a 200 has a token
field, or a token shape stays after the scrub)
writes `harvest_leftover` with the slot. It is always marked `alert`.

The broker does not read a streamed body (over 1 MiB, or chunked) before the
head goes to the origin server. Thus the broker cannot refuse a placeholder
in that body up front. The fence substitutes into no streamed body. Thus any
placeholder that the copy would forward stops the copy:

- The broker drops the origin connection in the middle of the body.
- The agent gets the same single refusal.
- The log says `placeholder_in_streamed_body`.

### 5.2c Sealed credentials at rest

`secrets.env` can be encrypted at rest:

- `sudo pf enroll seal` takes a passphrase.
- `sudo pf unlock` enters the passphrase, one time for each broker start. The
  broker holds the key in its memory and nowhere else. Thus each of these
  asks for the passphrase again: a reboot, a full `pf apply` (or `--local`
  when a fence input changed), and a signed ship.
- `pf enroll unseal` puts the file back in the clear.

Sealing is off by default. Nothing changes for an operator who does not want
a human in the reboot path.

Sealing buys protection against exactly two threats: the SD card is pulled
and imaged, or the gateway is carried off. Root on a running gateway can
still read the key out of the memory of the broker. What sealing protects is
the powered-off state. The plaintext file already had protection against a
non-root local read (0600, `pf-broker:pf-fortress`, the privilege split). It
also had protection against a backup: it is not in the backup format at all.
The key comes from a human. Reason: a gateway that could derive its own key
gives the key to whoever holds the card.

What sealing does not buy: sealing rewrites and renames the file. The
plaintext that it replaced stays in freed flash blocks, journals, and any
snapshot. If a value was ever in the clear on that card, an image of the card
has it. Today every store starts clear, because `pf enroll mint` refuses a
sealed store. Thus to mint again, you must do `unseal`, mint, `seal`. This
writes the clear file again. The fix is to mint into a sealed, unlocked store
through the broker, and never write plaintext. Until then, the guidance for
the operator is: if the card is lost, revoke the credentials with their
provider.

**The file is sealed or it is not.** A plaintext value on a *slotted* row
under a sealed header is a silent downgrade. Anything with write access could
do it. Thus it is a fault that fails the whole store shut. A return to
plaintext is an explicit whole-file rewrite. It is not a state that a file
can drift into.

A row with a key that is not a slot is skipped, as it always was, sealed or
not. It names no slot, so no substitution would reach it in either case.
`enroll seal` is the guard on that side. It refuses to seal at all while any
unslotted value is still in the file. It tells you to run `enroll migrate`
first.

`enroll seal` also refuses while a line that it would copy in the clear holds
something credential-shaped. Such lines are a comment, a line with no `=`,
and the note after a value. Credential-shaped means a leak-scan match, or a
run of 20 or more token bytes. An example is a rotated `# old=ghp_...` that
was kept for reference. The error names the line numbers and never the text.
Remove the lines and seal again. A value followed by ` # note` seals as
`loadFile` reads it: the value alone. The note moves to a comment line above.

```
#pf-sealed v1 scrypt N=32768 r=8 p=1 salt=<b64> canary=<b64>
# an operator note, kept
a1b2c3d4e5f67890_GITHUB_TOKEN=#pf1.<b64>
b0b1b2b3b4b5b6b7_CLAUDE_ORT=
```

The inventory stays in the clear on purpose: slot IDs, kinds, and empty
state. A slot ID is not a secret. The agent already holds it in the
placeholder. These work on a locked store: `enroll list`, `enroll delete`,
`enroll purge`, the TUI Keys view, and every `slot.*` verb. None of them has
to read or write a value. They use only lines and the sidecar.

`enroll mint` is not in that set. It is refused, and not left to fail at the
rewrite. To write a row into a sealed file, you must seal the row. After
`pf unlock`, the broker holds the key. `pf enroll` is a different process
that builds its own store, and it never gets the key. Thus no amount of
unlocking makes a CLI mint possible. `enroll mint` therefore fails before it
reads a token from stdin, draws a slot ID, or writes a paste file. The error
names the round trip that does work:

```
secrets: store is locked: a mint has to seal the row it writes and the key is held
by the broker, not by pf enroll. Unseal, mint, then seal again:
sudo pf enroll unseal; sudo pf enroll mint ...; sudo pf enroll seal; sudo pf unlock.
```

A slot minted with no value is also refused. The creation of the slot writes
no secret, and it could be let through for that reason. But a store that
takes one shape of mint and refuses another is a rule that the operator must
remember. The operator must remember it at the moment when they are least
able to.

The substitution and the OAuth harvest of the broker need values. Thus they
also refuse when the store is locked. `enroll peek` needs values, and it asks
for the passphrase. `enroll migrate` also needs values. But it runs on every
`pf apply` and must never stop for a prompt. Thus on a sealed store it prints
`sealed store: nothing to migrate` and exits clean. An unslotted plaintext
value under a sealed header is the fault that fails the whole store shut. It
is not something to migrate.

A sealed value starts with `#`, and this is load-bearing. Every reader that
is older than sealing reads `#` as a comment. Thus an older build reads the
slot as present and empty, and refuses. Bare base64 would have passed
`ValidLive` and been injected into live traffic as a token. A build that does
understand sealing must refuse a `#pf-sealed` version that it does not know.
It must not fall through to the values.

Thus each of these leaves the inventory readable, with every value empty:

- a sealed slot
- an unknown version
- a plaintext value
- a ciphertext that does not open

§5.2b answers these with the one refusal. If you remove the header, nothing
is downgraded. Both directions fail shut.

The KDF is scrypt (`x/crypto`, no `x/sys` beneath it), not PBKDF2. Reason:
the threat is offline cracking of a stolen card, and PBKDF2 is GPU-friendly.
The cipher is AES-256-GCM, with the env key of the slot as associated data.
Thus a ciphertext moved to the line of a different slot fails to open. It
does not make that slot answer with the credential of a different slot.

The unlock channel is a second broker socket,
`/run/pi-fortress/broker/admin.sock`, mode 0600, owned by `pf-broker`. It is
never the socket that the engine dials, because that one terminates untrusted
agent TLS. Root connects, because root bypasses DAC. The fence cannot open it
at all. The passphrase comes from `/dev/tty` with the echo off, never from
stdin. Thus it cannot go into a shell history or the environment of a unit.
The audit log records that an unlock was attempted, by whom, and whether it
worked. It never records what was typed.

**The cost, stated plainly.** Every broker start needs a human before any
workflow with credentials runs. After a power cut at 03:00, and equally after
an apply at noon, anything that needs a credential gets the §5.2b refusal
until someone unlocks. These surfaces show that gap:

- the TUI title bar and the Keys view
- a `pf doctor` rung
- one webhook for each operational cause for each broker start

The webhook goes one time, because a sealed store refuses everything
that an agent retries. The destination deny is the exception, and it always
posts.

### 5.2d Per-slot hourly budget

Everything above decides *whether* a credential may go to a destination.
Nothing above limits *how much* of it goes. A prompt-injected or looping
agent can carry a legitimate placeholder to a legitimate host at line rate.
The fence substitutes into every request of that agent. The budget is the
missing limit.

For each slot, the broker keeps a sliding hour of two values:

- the requests that it substituted into
- the request-body bytes that reached the origin server

The window is sixty one-minute buckets, not a list of timestamps. Thus an
agent cannot grow the heap of the broker with requests. The store bounds the
set of slots, because the fence substitutes only for a slot that it found
there. The window is in memory and starts empty after a restart. These values
are a rate. A rate that is loaded again from disk after an outage is a rate
that nobody measured. At start, the broker writes the limits to its journal.
The time of that line is the time when the count of the hour started again.

The bytes are the length that the request was framed with, after
substitution. Thus the count is what the provider received.

- A chunked body announces no length. The broker counts it as it copies it.
- If a copy aborts, the broker counts the abandoned fixed-length body whole.
  This is the size that the agent asked the fence to send.
- A request refused before substitution counts nothing, because nothing went
  out.

There are two thresholds for each window, both per slot. `0` sets each one
off. They are in `vm/pi/net.env`, and `apply.sh` passes them to the broker as
flags:

| Key | Default | What |
|---|---|---|
| `SLOT_WARN_REQUESTS` | 3000 | requests an hour before one operator row |
| `SLOT_STOP_REQUESTS` | 0 (off) | requests an hour before the slot is quarantined |
| `SLOT_WARN_UPLOAD_MB` | 500 | uploaded body MB an hour before one operator row |
| `SLOT_STOP_UPLOAD_MB` | 0 (off) | uploaded body MB an hour before the slot is quarantined |

Both stops ship off. A hard stop that fires on a false positive kills a
working session. Only the operator knows the honest rate of their agent. Read
the warn rows for a week. Then set the stop above what you saw. `apply`
refuses a stop below its own warn. Such a stop would quarantine the slot
before the alert that gives the operator a chance to look at it.

A warn writes one row for each crossing. It arms again when the window goes
back under the line, or after an hour if it never does. Thus a window that
stays above a warn costs one alert an hour, not one for each request.

A stop quarantines the slot through `secrets.disabled`. This is the sidecar
that the `x` key of the Keys view and the `slot.disable` verb already write.
There is one quarantine in this tree. The broker serves the request that
crossed the line. The next request that carries that placeholder meets the
§5.2b refusal, because the next snapshot marks the slot disabled and gives it
no value. `R` restores the slot, and the restore drops the window of that
slot. Without this, the
first request after the restore would cross the same still-full hour and
quarantine the slot again. If the broker could not apply a stop, its row says
so. It does not report a stop that did not occur.

The row goes to `strip.jsonl` with `threat: "slot_budget"`. Thus it gets to
`pf alert`, the webhook, and the TUI Activity view through the paths that
§5.3 already describes:

```json
{"t":"...","host":"api.anthropic.com","where":"requests",
 "rule":"slot_budget_warn:<slot>","client_ip":"10.77.0.10",
 "threat":"slot_budget","slot":"<slot>","count":3000,"limit":3000}
```

`where` is `requests` or `upload_bytes`. It names the unit of `count` and
`limit`. `rule` is `slot_budget_warn`, `slot_budget_stop`, or
`slot_budget_stop_failed`, each with the slot as a suffix. Thus two slots
that cross against one host are two alerts, not one.

The hour itself is only in the memory of the broker. Thus the `BUDGET` verb
on the admin socket of the broker reads it back: one line of slot, requests,
and bytes for each slot. `internal/admin` folds that into the `slots` verb.
The Keys view shows it as a "last hour" column. A `?` there means that the
broker did not answer. This is not the same fact as a slot that spent
nothing. `pf enroll list` reads the store on disk and does not show it.

### 5.2e Slot expiry

`enroll mint` takes `--expires`. The value is a duration from now, such as
`30d` (parseDays syntax), or an RFC3339 instant. Without the flag, a new slot
gets `90d` (`enroll.DefaultExpiry`). `--expires none` mints
a slot that never expires. The `CANARY` of the challenge uses it. Slots
minted before the default keep no deadline until someone renews them.

The deadline is in its own sidecar, `secrets.expires`, next to `secrets.env`.
This file is `pf-broker:pf-fortress 0640`, with one `<slot> <unix-ts>` per
line. It uses the same read-modify-write under lock as `secrets.disabled`.
The deadline is never inside `secrets.env` itself. Thus neither the plaintext
schema nor the sealed schema of `secrets.env` changes. A row minted before
this file existed, or minted with `--expires none`, keeps working with no
entry that names it.

After the deadline, the fence treats the slot exactly like a disabled one
(§5.2b):

- The row and its placeholder stay in `enroll list`.
- `Live` snapshots empty.
- The one wall of substitution answers the same 503, with a cause of its own,
  `slot_expired`, next to `slot_disabled` in the strip log.

`enroll list` shows the RFC3339 deadline or `-`. `enroll renew --slot <id>
--expires 30d|RFC3339|none` moves or clears the deadline. This is the one way
that a deadline changes after mint.

Harvest never touches this file. A refresh that captures a new oat/ort
rewrites only `secrets.env`. Thus a refresh cannot silently extend the life
of a slot. The bind of harvest excludes the refresh token of an
already-expired slot, in the same way as for a disabled slot
(`internal/broker/harvest.go` `bindRefreshSlot`).

On disk, the deadline is whole unix seconds. Every `Snapshot` decides again
whether "now" is past the deadline, in the same way as for `Busy`. Thus a
slot expires when the clock crosses the deadline, with no write to any file
in that window.

The broker checks deadlines every hour (`internal/broker/expiry.go`). While a
slot has seven days or less left, the broker writes a `slot_expiry` row to
`strip.jsonl` one time a day. In this row, `rule` is `slot_expiring:<slot>`,
`where` is the kinds, and `count` is the days left. The broker writes one
`slot_expired:<slot>` row when the deadline passes. `pf alert` posts both,
with the `renew` command. A restart forgets which warnings went out. This
costs a maximum of one repeated row. The broker writes an expired row only
within a day of the deadline. Thus it does not announce again a slot that is
already stale.

### 5.2f Egress CA rotation

The engine signs each leaf with one root, `/var/lib/pi-fortress/engine/ca.pem`.
Agents trust the certificates in the `ca.pem` that www serves
(`http://PI_IP/ca.pem`). `pf engine ca` changes the root in two steps with an
overlap. Thus no agent loses HTTPS when the root changes.

| Step | The engine signs with | The served `ca.pem` holds |
|---|---|---|
| before | the current root | the current root |
| `sudo pf engine ca rotate` | the current root | current root, next root, link |
| `sudo pf engine ca promote` | the next root, which is now current | current root, old root, link |
| `sudo pf engine ca retire` | the current root | the current root |

The link is a CA certificate with the key of the newest root, signed by the
root before it. An agent adds a new root only through a link that a root it
already trusts signed (see "The agent check" below).

Each step holds the apply lock and writes the files beside `ca.pem`:
`ca-next.pem` (cert and key, `0600`), `ca-link.pem`, `ca-old.pem`, and the
trust set `ca-trust.pem`. Then it runs `pf apply`. apply copies the trust set
to www, to `/etc/pi-fortress/egress-ca.pem` and to `generated/egress-ca.pem`,
and restarts the engine. `-apply=false` does not run apply. Without a rotation,
the trust set is the same bytes as `ca-cert.pem`. Thus a pin of the CA does not
change when you upgrade.

`sudo pf engine ca status` shows each root with its fingerprint and end date,
the sha256 of the trust set, and the next step. The `ca root` rung of
`sudo pf doctor` shows the same. It warns when the current root expires in
less than 90 days.

**Procedure.**

1. Run `sudo pf engine ca rotate`.
2. On each lab agent VM, run `sudo systemctl restart pi-fortress-agent-routes`,
   or reboot the VM. `routes.sh` fetches the new set, checks it, puts each
   certificate in the system store, and records the new pin. Its log says
   `is a CA set that the pinned CA signed; taking it`. The VM must have the
   `routes.sh` of this release and `openssl`.
3. On each box that you enrolled with `setup.sh`, run `setup.sh` again with
   the trust set sha256 from `pf engine ca status`. `setup.sh` does not fetch
   the CA again by itself.
4. Run `sudo pf engine ca promote`. The engine restarts and signs with the new
   root.
5. On each desk with `INSPECT=on`, copy `ca-cert.pem` again and run
   `setup.sh ca` (pi_setup.md). The desk trusts one root. Thus HTTPS through
   the desk fails from step 4 until this step.
6. When no agent needs the old root, run `sudo pf engine ca retire`. An agent
   removes the old root from its store at its next `routes.sh` run.

`retire` before `promote` stops a rotation: it removes the next root and the
link, and the engine continues with the current root. An agent that took the
set of `rotate` accepts the set after this `retire`, because that set keeps the
first root of the pinned set (see "The agent check" below).

**The agent check.** A VM pins the sha256 of the set that it trusts
(`CA_SHA256` in `agent.env`, lab.md). When the fetched set has a different
hash, `routes.sh` (`ca_extends`) takes it only when each certificate in it is
one of these:

- A certificate in the pinned set.
- A link: a CA certificate that a certificate in the pinned set signed.
- A root with the key of such a link.

Also, the fetched set must keep one of these roots of the pinned set:

- The newest root: the root with the latest `notBefore`. When two roots have
  the same `notBefore`, the root that comes first in the pinned set is the
  newest.
- The first root of the pinned set. The Pi puts the current root first.

Thus a device that answers for the Pi on the agent cable can copy the real set
and add a root of its own, but the box refuses that set: no trusted root signed
a link to that key.

The second rule has these results:

- `retire` after `promote` removes the old root. The set keeps the newest
  root. A box accepts it, also when it did not fetch after `promote`.
- `retire` before `promote` removes the next root. The set keeps the first
  root of the set of `rotate`. A box that fetched before `promote` accepts it.
- A box that fetched after `promote` has the new root first. It refuses a set
  that holds only the old root, and keeps its pin. If the box took that set,
  it would not trust the root that the engine signs with, and it could not
  take the next set of the Pi.

A VM that did not fetch between `rotate` and `retire` keeps the old root and
refuses the new set. Set its pin again (lab.md).

`routes.sh` refuses a `ca.pem` that is larger than 64 KiB or that has more than
8 certificates. Then it keeps the CA that it already trusts. A rotation serves
3 certificates.

A root that has expired cannot sign a link that agents accept. Rotate before
the end date. `pf doctor` warns 90 days before it.

### 5.3 Strip alerts

A strip is the incident: the agent already had the secret. The jsonl file is
the log. Alert is a consumer. Do not send an HTTP POST from the request path
of the broker. This stalls TLS.

| Path | What |
|---|---|
| `/var/log/pi-fortress/strip.jsonl` | One line for each match: `host`, `where`, `rule`, `t`, and `client_ip` when the preamble carried a source. Refusals add `ev`, `sni`, `cause`, `slot`, `kind`, and `alert` when the broker marks them. An `eyeball_network` row also adds `dest_ip`. A §5.2d budget crossing adds `threat`, `slot`, `count`, `limit`. A §5.2e expiry row adds `threat` and `slot`, and `host` is `-`. An expiring row also adds `count`. A name that the engine refused because the blocklist has it is a refusal with `cause` and `threat` `sni_blocked` and `where` `sni`. It never has `alert`, and one client and name give at most one such row each minute. |
| `pf alert` (`internal/alert`) | Tails the jsonl file and `notice.jsonl`. Writes the last event. Optional webhook. |
| `./vm/bin/alerts.sh follow` | Host terminal bell + `notify-send`. |
| `vm/policy/alert.url` | One URL: ntfy / Slack / Discord. |

The payload never includes the token. In every field, control, newline, and
bidi characters are replaced with `?`. Then the field is escaped for Slack
(`&<>`, mrkdwn off) or Discord (markdown backslash-escaped, no mentions).
Rows with the same `(threat, rule, where, host)` are debounced for 10s, on
the webhook only. The debounce does not apply to a canary row.

The webhook takes a maximum of 30 posts an hour for ordinary rows.
Separately, it takes a maximum of 30 posts an hour for credential and key
rows: `secret:` strips, alerting refusals, `dns_key`, `volume`
(`internal/alert` `webhookCap`). Above that, a row goes to the log, the
console, and `alert.last`, but not to the webhook. When the hour rolls, one
post says how many rows were held back, and of which kind. The cap and the
debounce never hold back a canary row. If the queue is full of canary posts,
a new canary post removes the oldest one. The summary counts that post. The broker still forwards the request after redaction.
Fail-closed is a later personality, not the default.

Every row is recorded locally (console, `alert.last`) and checkpointed
immediately after it is read. Its post waits in a bounded in-memory queue.
While the webhook refuses, the post is retried a maximum of one time every
30 s. Thus a webhook that fails or hangs never holds up the record. When
`pf alert run` restarts, it does not send again the posts that are still in
the queue. The rows stay in the logs. `pf alert show` gives the last row.

The summary at the end of a capped hour names both budgets ("at most 30
ordinary posts and 30 credential or key posts an hour"). The text comes from
the one constant that both budgets use. Thus the text cannot drift from the
cap.

Before the log gets to the alerter, the writer of the broker also bounds it.
The ordinary strip and refusal rows of a client draw on 5 a second, 600 at
one time (`internal/jsonl` `StripRowRate`, `StripRowBurst`). The canary and
the refusals marked to alert are outside that budget. Above that budget, the
broker still strips or refuses a request. But it drops the row and counts
it. A maximum of one time a minute, one `strip_suppressed` row for each
client says how many. `pf alert` posts that row as `LOG BUDGET <client>: <n>
strip or refusal rows not logged, ...`. This is a count of rows that are
missing, never a strip. `pf alert` debounces it for each client, not on its
`*` host.

The broker buffers and decodes a request body with a non-identity
`Content-Encoding` before the scan runs. This is the same buffered body that
a plaintext body gets. The broker never encodes it again:

- After a clean decode, the broker forwards the original compressed bytes
  unchanged.
- After a hit, the broker refuses the whole request.

Refer to 5.3b.

### 5.3b Content encoding

The broker offers `Accept-Encoding: gzip` and nothing else to the origin
server, whatever the agent asked for. Thus the uplink leg stays compressed,
with a coding that the standard library can undo.

The broker inflates a gzip response on the Pi, and scans and scrubs it as
plaintext. Then the broker does one of these:

- It gzips the response again at `BestSpeed`, with a flush for each scrubbed
  chunk, when the agent had accepted gzip (`pf broker -recompress`, default
  on).
- It forwards the response as identity.

Nothing after a framed body is used again: a close-delimited origin body ends
the upstream connection. Inflation has a cap (`Broker.MaxDecoded`, 64 MiB).
Thus a compression bomb ends the response, not the process.

The origin server can send a different coding anyway (br, zstd, deflate). The
broker logs it as `encoded:<coding>`, and the scrub cannot see inside it. A
live value can only come back in the reply to a request that carried one.
Thus the broker refuses that reply with a 502 (`ErrOpaque`) in these cases:

- The request had a credential substituted into it.
- The request is a token harvest.

The broker forwards any other reply in such a coding as opaque data.

This is the standard shape of a filtering proxy (Envoy decompressor plus
compressor, then re-encode). The CPU cost is on the Pi. Inflate is cheap.
The second deflate is the expensive half. Thus, if `pf status` shows the
broker hot, `-recompress=false` drops the deflate.

The request side does not encode again. Thus it does not need the compressor
of the response side. A request body can carry a non-identity
`Content-Encoding`: gzip, its `x-gzip` alias, `deflate`, or the two stacked
(`gzip, deflate`, with the most recently applied coding undone first). The
broker buffers such a body. The body must fit the ordinary body buffer, or the
broker refuses it unscanned. The broker decodes gzip and `x-gzip` with
`compress/gzip`, and `deflate` with `compress/zlib`. A decoded body has a cap
of 8 MiB (`maxDecodedBody` in `internal/fence`). This cap protects against a
decompression bomb.

The decoded bytes get exactly what a buffered plaintext body gets: the
token-prefix scan and the placeholder-outside-header rule (5.2b). A clean
decode changes nothing: the original compressed bytes go out. A hit refuses
the whole request. The broker does not edit compressed bytes in place,
because nothing on this path is ever encoded again.

The gzip header of each member goes to the origin with the body. Thus the
optional header fields (FEXTRA, FNAME, FCOMMENT) get the same scan as the
decoded bytes, one field at a time. A hit there refuses the request in the
same way.

These all refuse in the same way, `encoded_body_unscannable`:

- More than two layers.
- A coding that stdlib does not undo (br, zstd, compress).
- Bytes that do not decode.
- A decoded size that is more than the cap.
- A body that cannot be buffered for its `Content-Encoding` (over the buffer
  limit, or forced to stream).

A live value or token-prefix match found after the decode is
`encoded_body_token`. `encoded_body_token` alerts every time, the same as
`kind_not_allowed_for_sni`, `placeholder_outside_header`,
`key_in_header_name`, `key_in_method`, `encoded_url_token`, `live_in_host`,
and `live_in_connection` (5.2b).
`encoded_body_unscannable` alerts one time for each broker run, like a sealed
store. Reason: the broker refuses every request of a harmless client that
compresses its uploads with zstd. An alert on each one would fill the hourly
cap of the webhook before a real strip arrived. The log keeps every
occurrence.

### 5.3c WebSocket

`wss://` goes through the fence. `ws://` does not exist here: port 80 is
dropped at the network layer, and nothing about that changed.

A handshake that the broker recognises has all of these:

- a `GET` with no body
- exactly one `Upgrade: websocket`
- an `upgrade` token in `Connection`
- a `Sec-WebSocket-Key` that is not empty
- `Sec-WebSocket-Version: 13`

The broker does not decode the key or check its length. It does not look at
the HTTP version. Thus an HTTP/1.0 upgrade passes. The fence needs the
handshake to know that frames follow. It does not need to hold the origin
server to RFC 6455.

The broker forwards the handshake to the origin server with its
`Sec-WebSocket-Extensions` offer removed. Thus `permessage-deflate` cannot be
negotiated, and every frame stays readable. If an origin server accepts an
extension anyway, the broker ends the connection. The broker sends nothing of
that response to the agent, and it logs the extension. Any other
`Upgrade` is still a 501. A live value or a token-prefix match in the
`Connection` of a handshake refuses the request (`live_in_connection`, 5.2b).
The broker sends the 501 before the fence runs. A live value or a
token-prefix match in the `Connection` or the `Upgrade` of such a request
writes the same `live_in_connection` row, an alert. The agent still gets the
501.

The broker relays the `101` of the origin server to the agent as it arrived.
One exception applies: the broker changes a live credential that the origin
server reflected into a header back to its placeholder. The broker never
calculates or compares its `Sec-WebSocket-Accept`. Reason: the key that it
answers belongs to the agent, and the fence has no stake in that proof.

After the `101`, the broker parses frames in both directions:

- Client frames must be masked. The broker unmasks them and scans them for
  credentials, with the same primitive as the request body path. This
  applies to text and binary alike, because a token is ASCII in both. Then
  the broker masks them again with a new key.
- Server frames must not be masked. The broker forwards them byte for byte,
  unless the fence substituted a credential into the handshake.

In that case, the origin server holds a live value that it can reflect into
any frame. Thus the broker scrubs its frames in the same way as a response
body, and changes every live value back to its placeholder:

- One scrub for each data message, carried across its fragments.
- The message is fragmented again as it is read. RFC 6455 5.4 allows this
  when no extension is in play.
- Control payloads are scrubbed whole.

Each hit is a strip row with `where=ws_origin`. If the rewrite would grow a
control frame past 125 bytes, the session ends.

The broker reassembles a data message from its fragments and scans it one
time. Thus it still catches a token split across a fragment boundary that
the agent selected. The boundary that the scan does **not** cross is the
message. Two messages are two scans. A token split across two messages gets
to the origin server in the pieces that the agent selected, for a receiver
that joins them to put the token back together. That is a residual and not a
miss. To buy it, the broker would have to hold back the tail of every message
until the next one arrives. But the socket is allowed to send nothing more
for an hour. The overlap carry of the HTTP body path works only because a
body has an end that the fence can wait for.
`TestEchoWebSocketCatchesASplitFragmentAndNotASplitMessage` pins both halves.

Control frames get the same scrub: a ping or pong payload whole, and a close
reason after its two-byte status code. Reason: 125 bytes that the agent picks
is room for a token.

These end the session:

- RSV bits.
- Reserved opcodes.
- Fragmented or oversized control frames (before or after the scrub).
- Agent-to-origin messages past `Broker.MaxMessage` (5 MiB, fragments
  summed, 1009).
- A placeholder in an agent-to-origin message, ping, pong or close reason
  (1008). Refer to the end of this section.

A message that would take the broker past its byte budget ends the session
with 1013. The broker streams origin-to-agent messages, with a bound of
16 MiB.

A strip inside a frame is a strip event with `where=ws`. Open and close are
one line each on `unknown.jsonl` (`where=ws_open` / `ws_close`). The
`ws_close` line has the byte counts `ws_sent` and `ws_recv`. Reason: the strip
log is the incident channel, and a websocket open is not an incident.

Substitution does **not** occur inside frames. A frame is opaque application
data, with no field that the fence owns. A rewrite of a placeholder into a
live token there would give the agent a credential that it never held. The
fence could not scrub that credential back out of the reply.

Thus the broker refuses a placeholder in a frame from the agent. It does not
strip it. The scan runs on the reassembled message, so a placeholder split
across fragments is also found. It also runs on each ping, pong and close
payload. When the scan finds a placeholder:

- The broker does not forward that frame.
- The origin server gets a close with 1001, the same close as for size. Thus
  the origin server cannot tell that the fence found a placeholder.
- The agent gets a close with 1008 (policy violation).
- The strip log gets a `substitution_refused` row with
  `cause=placeholder_in_ws`, `where=ws`, the slot and the kind. It is always
  marked `alert`, the same as `placeholder_outside_header` (5.2b).

A placeholder that goes out as written gives the slot ID and the kind to the
origin server. Data in a frame can also come back past the literal scrub, as
data in a body can. Live values and token-prefix matches are still stripped,
as before.

This also applies to a placeholder that the agent got from the origin
server. After a substitution, the broker writes a reflected live value back
to the agent as its placeholder. If the agent then sends that text back in a
frame, the broker closes the session.

`Idle` becomes the gap between frames. Traffic in either direction resets it.
The lifetime ceiling, not `Idle`, bounds a subscription that legitimately
sends nothing upstream. Refer to 5.3d.

One test reads all of this back from outside the Pi: the `secrets` group's
`a websocket frame is scrubbed on its way out` (`vm/itest/secrets_test.go`),
against the peer of the core echo (5.2). The agent side is
`openssl s_client`. It gets a handshake and two frames that are built in Go and handed
over as base64 (`vm/itest/wsecho.go`). The agent segment has no websocket
client installed. The websocket client of curl is experimental and off in the
Debian build, and it gives nothing back to write a frame on.

### 5.3d Deadlines: idle and lifetime

There are two separate limits, deliberately not one. One limit for both is
what broke here before. A single absolute `SetDeadline` had to be both, and a
download that did exactly its job died at thirty seconds.

**Idle (`-idle` on `pf engine`, 30 s default).** The gap between bytes, not
a fixed moment. The broker has no flag for it, and always uses 30 s.
The splice of the engine and the legs of the broker both refresh it on
progress. Progress in **either** direction refreshes it. This is the part
that matters for a one-way stream.

- The engine resets the read and the write deadline of both legs on any byte
  that either copy goroutine moves.
- The websocket relay of the broker does the same with its `touch`.

A subscription or an SSE feed can push downstream for an hour while the agent
says nothing upstream. This connection does its job, and it is not cut for
silence. The engine and the HTTP legs of the broker set read and write
deadlines apart, never through `SetDeadline`. The websocket relay sets one
deadline on both legs, but a frame in either direction refreshes it. The
relay runs both directions over one connection. Thus a
blanket deadline set for one direction silently becomes the deadline of the
other.

Two places keep an absolute deadline on purpose. These are not the ceiling:

- The `-handshake` of the engine (10 s) covers the ClientHello.
- The broker holds one over the preamble and each request head.

Thus a client that dribbles one header byte in each idle period is still the
slow loris that it is, and it gets nothing free.

**Lifetime ceiling (`engine.MaxLifetime`, 1 h, fixed).** The ceiling on age.
It is measured from `accept`, and it covers the whole relay, not one request.
The engine applies it, because the engine counts the connection slots
(`MaxConns`, 256). Every idle deadline is clamped to it.

Without the ceiling, `MaxConns` was the only bound left. It caps concurrency,
not lifetime. An agent that moves one byte in each idle period refreshes the
idle gap forever. 256 of those connections are every slot on the gateway.
One hour is generous for real work (approximately 4.5 GB at 10 Mbit), and
finite. That is the point.

The accepted consequence: **a long-lived WebSocket or SSE subscription is
cut at one hour and must reconnect.** That is the design, not an oversight.
The agent behind this fence is hostile. It does not get an unbounded hold on
a finite slot.

**Telling the three apart in the log.** The engine writes one `relay end=`
line for each cut that it imposes, with `conn=` (the preamble connection ID),
`sni=`, `src=`, `dst=`, and `age=`:

| Line | What happened |
|---|---|
| `relay end=lifetime_ceiling … age=… limit=…` | A healthy connection hit the hour. The fence cut it. `age` ≈ `limit` |
| `relay end=idle_timeout … age=… idle=…` | Nothing moved in either direction for `idle`. `age` is far under the limit |
| `relay end=network … err=…` | The read or write failed on its own. `err` is the OS or TLS error |
| `relay end=shutdown …` | The engine was in shutdown, not the connection |

A peer that closed normally logs nothing. Thus:

- Only a ceiling cut names `limit=`.
- Only an idle cut names `idle=`.
- Only a network failure carries `err=`.

The agent sees an orderly half-close (`CloseWrite` on both legs) in all
three. Thus the log is the authority on which one it was.

### 5.4 Unknown destinations

Traffic to unknown destinations still goes to the real internet. The Pi logs
a sample of each on the gateway. Nothing about them is sent to any other
place.

`vm/policy/allow.domains` is separate from `never_block` and `core.hosts`.
Allowed = allow.domains ∪ core.hosts. The broker appends a sample to
`/var/log/pi-fortress/unknown.jsonl`. The sample has:

- host
- SNI
- destination IP/port
- method
- path (no query)
- HTTP version
- ordered header **names**
- User-Agent (clipped to 256 bytes)
- content-type (128)
- body length
- the `Authorization` scheme alone
- up to 32 cookie names

The broker writes the row of the paranoid deny (`where=paranoid_deny`) before
the fence has stripped anything. Thus that row leaves out the path,
User-Agent, content-type, cookie names, and header names.

The header-derived fields are the whole exception: no other header value, no
body, no tokens. The body length is the `Content-Length` of the request that
went out, and 0 for a chunked body. The row has no hash of a header or a body
and no TLS client fingerprint. A body hash after the rewrite comes from the
credential: a person can guess a short body of known shape, such as an OAuth
refresh, and hash it until it matches.

`example.com` is the unknown canary (never_block, not allow). These names are
seeded in allow, so that a real session stays quiet:

- The Claude harvest names (platform.claude.com, claude.ai, Datadog).
- The GitHub blob and release hosts (raw, objects,
  release-assets.githubusercontent.com).
- The package indexes (npm, PyPI, the Go module proxy).

A listed name covers its subdomains. Thus downloads.claude.ai and
docs.github.com need no line of their own. Do not put the blob hosts on
`core.hosts`. There must be no token inject on docs or raw blobs.

### 5.6 Enrollment: claim codes, ledger, quarantine

No file moves from the Pi to the agent. On the Keys view, `c` issues a
**claim code** for a slot. The claim code:

- Has six characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no 0/O/1/I).
- Comes from `crypto/rand`.
- Is valid for five minutes.
- Is for a single use.

The screen shows the code, a countdown, and the exact lines for the agent
(`www.ClaimCommand`). These lines:

1. Fetch `http://10.77.0.1/claim/<CODE>` to a temp file.
2. Run `sha256sum -c` on it, against the hash of the script that the Pi will
   serve.
3. Run it with `sh`.

The claim file carries the sha256 of `setup.sh` and `ca.pem` at issue. The
script checks `setup.sh`. `setup.sh` then checks `ca.pem` against the hash
that the script gives. Thus an agent that answers for the address of the Pi by
ARP cannot swap any of the three. The script that comes back:

- Runs `setup.sh` (CA and DNS, as before).
- Writes `~/.claude/.credentials.json` when the slot has `CLAUDE_OAT`
  (placeholders, from `enroll.AgentCredentialsDoc`).
- Writes `~/.git-credentials` when the slot has `GITHUB_TOKEN`.
- Writes `~/.pi-fortress/env.sh`, with the kinds of the slot exported.

Live values never leave `secrets.env`.

Storage: two directories in `/var/lib/pi-fortress/www/`. Both are setgid.
Thus a file that the root TUI writes there still goes into the group of www.

- `claims/`, `root:pf-fortress 2750`. Only root writes it. www can read a
  claim, but it cannot create, change, rename or remove one.
- `claims-redeemed/`, `root:pf-fortress 2770`. www writes it: one marker
  for each spent code, and the ledger.

The TUI writes `claims/<CODE>.json` (0640). It has `code`, `slot`, `kinds`,
`issued`, `expires`, `setup_sha256`, and `ca_sha256`, and `git_hosts` when
the slot has `GITHUB_TOKEN`. www:

- Refuses expired claims, a claim file that root does not own, and a claim
  whose `setup_sha256` or `ca_sha256` is not the hash of the file that www
  serves now (a `pf apply` replaced it after the issue). A refused request
  does not spend the code.
- Redeems by making `claims-redeemed/<CODE>.redeemed` with `O_EXCL`, after
  all checks pass. This is what makes a second redeem fail, also when two
  redeems come at the same time. The marker is on disk, so a spent code
  stays spent after a restart or a reboot. A claim that was not redeemed
  stays valid until it expires.
- Writes `PI_IP`, the address that www binds, into the claim script. The
  `Host` of the request has no effect on the script.
- Never serves a listing of either directory.
- Answers wrong, used, and expired codes with the same 404.
- Allows ten attempts for each source address each minute, and 30
  attempts each minute for all sources on the agent segment together. An
  attempt that the per-source limit refuses does not count against the
  segment.

Root sweeps: each claim issue and each `pf apply` (`pf www -init-ledger`)
remove the claims with an mtime more than one hour old, and then the
marker of each claim that is gone. A marker never goes before its claim.
The sweep never opens a claim. Thus it is a floor on the five-minute
`expires`, and not the expiry check. The expiry check is in the redeem, on
every redeem. www gets only `SupplementaryGroups=pf-fortress` and
`ReadWritePaths` for `claims-redeemed/`. `secrets.env` stays inaccessible to
www. All other daemons are in `pf-fortress` too, but their units list
`/var/lib/pi-fortress/www` in `InaccessiblePaths`. Thus only root and www
can read a live code.

Ledger: `claims-redeemed/ledger.jsonl` (0660, same group). It has these
entries:

- `issued {code, slot, uid}` from the TUI.
- `redeemed {code, slot, ip}` from www, when a code is redeemed.
- `setup {ip, path}` from www, when `setup.sh`/`ca.pem` is fetched (GET
  only, one line for each address and path each minute).

`enroll.stats` reads it for System → Health: issued, redeemed, last redeem
and its address, and last setup fetch. The append is best effort. It comes
after the act that it records, and every caller discards its error. Thus a
ledger that cannot be written stops no issue and no redeem, and says so
nowhere. It is a record for the operator, not a control.

Last use: the broker appends `{t, slot, host, client_ip}` to
`/var/log/pi-fortress/use.jsonl` when it writes the live value of a slot into
a request (a header, or the buffered body of the refresh token). It does this
a maximum of one time for each slot each minute.

A §5.2b substitution refusal logs no use. The row waits until the request is
cleared for the origin server, and a refused request never clears. The
refusals that come after that point do leave a row: the 403 of the harvest
bind, `429 refresh_busy`, and a 502 on the origin leg. Thus a row means that
the broker was willing to spend the slot. It does not mean that the
credential reached anyone.

The Keys view shows the last time and host for each slot, or "never". It
reads a bounded tail of that log. If the tail did not reach the start of the
log, the screen shows "unknown (partial log)", not "never". The Keys view
does not read rotated files. Thus "never" is not evidence that a slot is idle.

Quarantine: `/etc/pi-fortress/broker/secrets.disabled`, a sidecar next to
`secrets.env` (`pf-broker:pf-fortress 0640`), one `<slot> <unix-ts>` per
line. The broker loads it again with `secrets.env` (stamp check on every
snapshot). It does not inject a placeholder of a disabled slot. It refuses
the request as in §5.2b, and logs `substitution_refused` with
`rule=refused:slot_disabled`.

The fence still knows the value, for stripping only. If the fence finds the
value of a disabled or expired slot in a request, it strips the value like a
foreign credential, also on the core host of that slot. It never injects the
value. A locked sealed store holds no values, and so strips none.

`slot.disable` is for operator and admin. `slot.restore`, `slot.purge`, and
`slot.delete` are for admin only. Every `pf apply` runs
`pf enroll purge --older-than 7d`. Thus a row disabled for seven days or more leaves
`secrets.env` at the next apply. The seven days are the eligibility, not a
timer. Nothing schedules that sweep. Thus a gateway on which nobody runs
apply keeps the row indefinitely. Until then, the screen shows "disabled
<n>d, purge in <m>d".
