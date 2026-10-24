# Pi Fortress: notes for contributors and their coding agents

Pi Fortress is a network gateway between an AI coding agent and the
internet. Usually the gateway is a Raspberry Pi 5. The gateway:

- Inspects the TLS of the agent.
- Replaces placeholders with live credentials only for the service that
  owns the credential.
- Strips them at all other locations.
- Filters an optional home network.

The project has these parts:

- One Go binary, `pf` (`cmd/pf`, `internal/`).
- The shell and nftables around it (`vm/pi/`).
- The setup on the agent side (`vm/agent/`).
- The labs (`Vagrantfile`, `vm/cloudlab/`).
- The policy defaults (`vm/policy/`).

Licence: Apache-2.0.

## Read first

1. `docs/INDEX.md`: the map of all docs. Load only the docs that the task needs.
2. `docs/risk_model.md` §2.1: what is mitigated and what is not. A change
   that weakens a "Yes" row there is a bug. This is true also if the
   change fixes other problems.
3. `docs/fence.md` §5.2: the credential fence, the core of the project.
4. `docs/style.md`: the writing standard (ASD-STE100 Simplified Technical
   English). All Markdown, code comments, and help text follow it. The terms
   are in `docs/glossary.md`. Code comments never define them again.

The user guide (`docs/user_guide/`) is the public website. Nothing in it
can link outside that directory. Nothing in it can name a repo path or a
`make` target. If it does, `internal/docslint` fails the run.

## Build and test

Go version: `go.mod`. Builds use `vendor/`. They never fetch a toolchain.
The Makefile sets `GOFLAGS=-mod=vendor` and `GOTOOLCHAIN=local`.

```
make hooks      # once per clone: installs the leak-check pre-commit hook
make pf         # bin/pf for this machine
make smoke      # fast gate, no VMs: run before every commit
make test-mid   # the next gate up, before a pull request
make test-race  # full e2e against a race build of pf in the cloud lab, before a release
make e2e PF_SSH_CONFIG=...   # the full suite over SSH: the cloud lab or a real Pi
make docs       # build the website; must print "No issues found"
```

The cloud lab (`docs/cloud_lab.md`) needs a Linux host with `/dev/kvm`.
`sudo vm/cloudlab/bootstrap.sh --up` starts it. `vm/cloudlab/lab.sh
test` runs the e2e suite against it with the correct SSH config. For a real
Pi, use `PF_TARGET=pi PF_SSH_CONFIG=... make e2e`. A pull request that
changes the fence, DNS or nftables should say which gate it passed.

A confirmed bypass becomes a fuzz corpus entry and a regression test
before its fix. Send security issues as `SECURITY.md` tells you. Never
send them in a public issue.

## Network rules for tests

Lab tests may reach well-known safe hosts (Google, Cloudflare, IANA
`example.com`). Block tests use canaries only:

- IP: `192.0.2.1` (RFC 5737 TEST-NET)
- Domain: `pi-fortress-block.test` (RFC 2606)

A hostname taken from a fetched blocklist feed may be checked with `dig`
to the Pi (sinkhole). Never curl, ping, or otherwise connect to an
untrusted host to prove a drop.

Never add host routes, bridge addresses or firewall rules to make a lab
test pass. The tests check the isolation between segments.
