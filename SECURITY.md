# Security policy

Pi Fortress is open source (Apache-2.0). It is open for evaluation. Use test
keys, or keys with a spend limit, while you evaluate. See
[`EVALUATION_NOTICE.txt`](EVALUATION_NOTICE.txt).

## Reporting

Email `security@praneos.ai`, or use GitHub private vulnerability
reporting: open the **Security** tab of the repo, then click **Report a
vulnerability**. Do not open a public GitHub issue or pull
request for a vulnerability. Do not post details at any location before
the fix ships. If you need an encrypted channel, say so in a first
message without details.

A useful report has:

- the version (`pf version`, plus the release tag or commit) and the
  `SHA256SUMS` lines of the bundle or binaries that you ran
  ([`docs/user_guide/verify.md`](docs/user_guide/verify.md));
- steps from a new shell in the agent VM, as commands or a script;
- evidence: a pcap, or the `strip.jsonl` rows that the fence wrote;
- the handle that you want in the credit, or "anonymous".

Challenge entries use the same address and format:
[`docs/challenge_rules.md`](docs/challenge_rules.md).

## Response

| Step | Target |
|---|---|
| Acknowledgement | 72 hours (a named person reads the inbox each day during the challenge window) |
| Verdict (reproduced, duplicate, out of scope) | 14 days |
| Confirmed bypass | becomes a fuzz corpus entry and a regression test, then the fix lands |

Coordinated disclosure: we publish the write-up when the fix ships. You
may publish 90 days after your report or when the fix ships, whichever
is first. Tell us if you need a different date.

## Safe harbour

Testing within the scope of [`docs/challenge_rules.md`](docs/challenge_rules.md),
against an installation you run yourself (the cloud lab or your own
Pi), is authorised. We will not pursue or support legal action over it.
We will say so if anyone asks. This does not cover:

- other people's installations;
- third parties: the model providers, canarytokens.org, any origin you
  do not control (we cannot authorise testing them);
- denial of service against anything shared;
- keeping or using data that is not yours, if you reach any: stop and
  report.

## Scope

The challenge scope applies to every report. The published non-claims
are out of scope ([`docs/risk_model.md`](docs/risk_model.md) §2.1,
README "What it does not do"):

- body exfiltration through a sanctioned API;
- quota and spend burn;
- anything that starts from root on the gateway;
- prompt injection itself;
- pinned-cert and HTTP/2-only clients.

Enrolment is in the challenge scope. Bugs outside the challenge
objective (the admin socket, the TUI, updates, the installer) are
also welcome. We credit them in the list below.

## Release checks

We build a release only after these checks pass:

- Dependencies match their recorded checksums (`go mod verify`).
  `govulncheck` finds no known vulnerability in code that `pf` calls. `pf` has
  three direct dependencies, all vendored.
- A secret scan of the source tree and of each release binary finds no
  private key or API token.
- Two independent builds of the tagged commit produce identical bytes.
  The key in [`docs/user_guide/verify.md`](docs/user_guide/verify.md)
  signs `SHA256SUMS`. Anyone can do the rebuild again from the public source.

## Credit

We credit every confirmed report by name, under the handle that you
select, unless you ask to stay anonymous. Fence bypasses go in
[`docs/hall_of_fame.md`](docs/hall_of_fame.md). All other reports go in the
list below. Credit goes to the first report of a
root cause. We thank a second report of the same cause privately.

### Credits

None yet.
