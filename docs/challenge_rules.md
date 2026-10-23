# Capture the key: challenge rules

Reports and entries: [`SECURITY.md`](../SECURITY.md). Credits:
[`hall_of_fame.md`](hall_of_fame.md). The source is open. You can read it,
build it, and fuzz it.

## Objective

The gateway holds one live credential of kind `CANARY`. The agent VM
holds only its placeholder, `pf_<slot>_CANARY`. You win if you do one of
these:

1. **Extraction.** Move the live canary value off the gateway: into the
   agent VM, to a host you control, anywhere outside the gateway's own
   store.
2. **Substitution.** Make the fence put the live value into a request
   that lands on an origin you control.

In the shipped policy, no host binds `CANARY`. A `*` line does not
cover it. Thus, if the value is at any location off the gateway, this is a bypass.

The canary is a canarytokens.org AWS key, enrolled as
the `CANARY` credential. Its first use from outside the gateway sends
an alert. Substitution of an AWS key into a SigV4-signed request does not work.
The client signs with the placeholder, so AWS rejects the signature.
Thus, only extraction applies.

## The seat

You run all of it yourself. Use one of these:

- **The cloud lab.** `sudo vm/cloudlab/bootstrap.sh --up` on a Linux
  host with `/dev/kvm`, from a checkout of a release tag
  ([`cloud_lab.md`](cloud_lab.md)). The `gw` VM is the gateway; `agent`
  is your seat.
- **Your own Pi**, installed from a published release with `install.sh`
  ([`gateway_install.md`](gateway_install.md)), with an agent machine or
  VM behind it.

Then:

1. Mint your own AWS canary at canarytokens.org. Then its alert comes to
   you.
2. Enrol it on the gateway: `sudo pf enroll mint --kind CANARY --stdin
   --expires none`. Paste the canary, push Enter, then push Ctrl-D.
3. Claim its placeholder into the agent (`sudo pf tui`, Agent network,
   Keys, `c` on the slot).

During the attack you have:

- A shell in the agent VM, with root access if you want it. The shell holds the `CANARY`
  placeholder.
- The source, the policy files (`vm/policy/`) and these rules, as
  published for the version you run.
- Nothing on the gateway: no shell, no console login, no credentials.

## In scope

- SNI/Host splits and domain fronting.
- Smuggling across the two-parser chain (the broker's HTTP/1.1 parser
  terminates and re-serialises).
- Chunked and trailer tricks.
- WebSocket upgrade after the decision.
- ALPN games.
- DNS rebinding, direct-IP, DoH, IPv6.
- The `:80` claim endpoint.
- Enrolment.
- Getting from the agent VM's network to code execution on the gateway.

## Out of scope

These are the published non-claims ([`risk_model.md`](risk_model.md)
§2.1, README "What it does not do"). Thus, the rules and the honest
limits are one list:

- Body exfiltration *through* the sanctioned API.
- Quota and spend burn.
- Anything that *starts* from root on the gateway. Getting there from
  the agent VM is in scope; starting there is not.
- Prompt injection itself.
- Pinned-cert and HTTP/2-only clients ([`http2.md`](http2.md)).
- Denial of service.
- Attacking the provider, canarytokens.org or any other third party.
- The hypervisor.
- Reading the gateway's disk, SD card, memory, snapshots or hypervisor
  state, or changing the gateway, its image or its installed tree.

**What that means for an entry.** You run the gateway on your own
hardware. You enrolled the canary yourself. Thus, you can always read
it off the disk. A canary trip alone therefore proves nothing. A valid
entry is a method that we can reproduce with all of these conditions:

- From a shell inside an unmodified agent VM.
- Against an unmodified gateway on a published version.
- With a canary of our own.

## Time

The challenge has no end date. It applies to every published release.
An entry counts from the time it reaches `security@praneos.ai`. We judge
an entry against the version that it names: a release tag, which the
signed `SHA256SUMS` pins. If these rules change, we change this file
first.

## Recognition

Every confirmed bypass gets a row in [`hall_of_fame.md`](hall_of_fame.md),
under the handle that you select. We credit other confirmed security bugs
in `SECURITY.md`. There is no money.

## Judging

- Valid means in scope, and reproduced by us from the agent VM seat on
  the published version.
- The first report of a root cause gets the credit. We thank later reports of
  the same cause privately. We credit different causes
  separately.
- Best bypass is our call, and it is final: fewest preconditions, widest
  class, clearest write-up.
- Every confirmed bypass becomes a fuzz corpus entry and a regression
  test before its fix lands. Its hall-of-fame row names the fix commit.

## Submission

Email `security@praneos.ai` with the subject `bypass: <one line>`.
Put these items in the email:

1. The version: the release tag, `pf version` as the gateway prints it,
   and the `SHA256SUMS` lines of the bundle you installed (or the commit
   the cloud lab was built from).
2. Which seat: the cloud lab or a Pi.
3. Steps from a new agent VM shell, as commands or a script.
4. Evidence: a pcap from the agent VM or your origin, and/or the
   `strip.jsonl` rows that the fence wrote. You can read those off the gateway
   after the run. You cannot use in the method anything that you read
   there.
5. The handle to credit, or "anonymous".

Do not open a public issue or pull request for a bypass before the fix
ships. Disclosure follows `SECURITY.md`.
