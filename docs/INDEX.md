# Doc index

Read this file. Then read only the files that the task needs.

Repo root: `README.md` (landing page, install),
`SECURITY.md` (reporting, safe harbour, credit), `AGENTS.md` (build,
tests, network rules for tests), `LICENSE` (Apache-2.0).

## Start here

| File | When |
|---|---|
| `risk_model.md` | the problem, the attack table (what is and is not mitigated), the hostile uplink, the non-goals |
| `fence.md` | the credential fence: placeholders, substitution, stripping, sealed store, encodings, WebSocket, unknown destinations, enrolment |
| `user_guide/` | the public manual, deployed as the website: getting started, verify a download, Pi setup, home network, public Wi-Fi, architecture, use cases, comparison, FAQ. All links in it stay inside the directory |
| `challenge_rules.md` | capture-the-key: the `CANARY` objective, the seat (cloud lab or your own Pi), in and out of scope, window of 60 days from the first signed release, judging, submission |
| `style.md` | the writing standard for all docs, code comments and help text: ASD-STE100 Simplified Technical English, what a rewrite must not change |
| `glossary.md` | the one list of terms (gateway, origin server, placeholder, live credential, strip, refuse, drop, core host) that docs and code comments use |
| `hall_of_fame.md` | confirmed fence bypasses: date, handle, class, fix commit; inclusion rule |

## Install and run

| File | When |
|---|---|
| `gateway_install.md` | `install.sh` + `pf install` + `pf upgrade` on a Pi OS arm64 or Debian/Ubuntu amd64 gateway; the two signers; what is still manual |
| `installer.md` | the earlier installer design (embedded assets, `.deb`, a Pi image), kept as the record. `gateway_install.md` replaces it |
| `cloud_lab.md` | the Pi, house, desk and agents as VMs on one KVM host; the e2e suite, also against a real Pi |
| `lab.md` | operator manual: the VirtualBox lab, daily commands, a real Pi, the desktop host, secrets, enrolment, policy files, lab caveats |
| `signed_ship.md` | shipping a dev build to a Pi without sudo: signed bundle to `pfship`, root verifies, refuses rollbacks, swaps and applies, restores on failure |
| `release.md` | `make release`: reproducible `pf` build, `SHA256SUMS` signed in namespace `pi-fortress-dist`, `release-verify` rebuild-and-compare, verifying a download, key custody, the docs site |

## Design

| File | When |
|---|---|
| `privilege_split.md` | engine versus broker, users, socket, sandbox |
| `http2.md` | why the engine uses HTTP/1.1 only, and what can change this decision |
| `git_push.md` | git smart-HTTP push only to repos in `git_push.allow`. An empty file refuses all pushes |
| `ssh_allow.md` | TCP 22 egress to operator-listed public IPs from the agent segment and, under strict egress, plain segments; `ssh_allow.ips`, empty by default |
| `paranoid_mode.md` | opt-in default-deny of agent destinations: `PARANOID=1`, `allow.domains` plus core hosts; a plain segment's own `PARANOID=on` and `allow.<name>.domains` |

## Background

| File | When |
|---|---|
| `user_guide/tutorials/` | networking refresher (IP/routing/NAT, VLANs, DNS, TLS, nftables, HTTP/OAuth). Each tutorial shows where Pi Fortress uses the topic. Start at `tutorials/README.md` |
| `diagrams/` | Mermaid diagrams of module structure and request flows. Start at `diagrams/README.md` |

## Do not open

- `bin/pf`, `vm/pi/pf` (binaries)
- `vm/policy/generated/` (feed dumps, CA copies)
- `vendor/` (vendored dependencies. Change them with `go mod vendor`, not manually)
