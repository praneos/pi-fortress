.PHONY: up apply fetch test smoke test-mid test-race go-test apply-test shell-test leak-check leak-check-test mermaid-check hooks lab-test e2e distro-test observe status halt destroy pf split-bin fuzz audit dupes inline pi-check pi-sync pi-ship pi-provision pi-ssh agent-up agent-reload agent-provision agent-shell agent-destroy agent-audit

CGO_ENABLED ?= 0
# Supply chain: each build resolves modules from vendor/. It never
# fetches a toolchain that the go.mod of a dependency asks for. The
# checksum database covers pinned tool versions like all other modules.
export GOTOOLCHAIN = local
export GOFLAGS = -mod=vendor
GOVULNCHECK ?= v1.8.0
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)
FUZZTIME ?= 15
# RACE=1 builds pf with the Go race detector, for the cloud lab only
# (docs/cloud_lab.md, Race tier). A race build never ships: the targets
# that make a shipped artifact refuse it (no_race below).
RACE ?= 0

# no_race: the first recipe line of each target that makes a shipped
# artifact or puts pf on a real Pi.
define no_race
@test "$(RACE)" != 1 || { echo "$@: refused with RACE=1. A race build is for the cloud lab only and never ships." >&2; exit 1; }
endef

up:
	./vm/bin/up.sh

fetch:
	./vm/bin/fetch.sh

apply:
	./vm/bin/apply.sh

go-test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

lab-test:
	CGO_ENABLED=$(CGO_ENABLED) go test -tags=vagrant -count=1 -timeout 20m $(if $(filter 1,$(V)),-v,) ./vm/itest

# The same suite over an ssh config: a real Pi or the cloud lab (docs/cloud_lab.md).
e2e:
	@test -n "$(PF_SSH_CONFIG)" || { echo "e2e: set PF_SSH_CONFIG (docs/cloud_lab.md)" >&2; exit 1; }
	CGO_ENABLED=$(CGO_ENABLED) go test -tags=vagrant -count=1 -timeout 45m $(if $(filter 1,$(V)),-v,) $(if $(RUN),-run '$(RUN)',) ./vm/itest

cloudlab-%:
	./vm/cloudlab/lab.sh $*

distro-test:
	CGO_ENABLED=$(CGO_ENABLED) go test -tags=distro -count=1 -timeout 45m $(if $(filter 1,$(V)),-v,) ./vm/setuptest

apply-test: pf
	@./vm/pi/apply_test.sh
	@./vm/pi/usb_nic_switch_test.sh
	@./vm/pi/ca_restart_test.sh
	@./vm/desk/setup_test.sh
	@./vm/agent/routes_test.sh
	@./vm/agent/clock_test.sh

# Static check over the shell scripts. No pf build, no VM: it runs in
# seconds and goes first. Thus a broken script fails before the long suites.
shell-test:
	@./scripts/shell_test.sh

test: shell-test go-test apply-test lab-test appliance-test

# Private content in the public tree: the private marker, a path into the
# private workspace, the name of a private doc, a key, a home path. Full
# tree. The hooks below run the same script on the staged files of a commit
# and on each pushed tree.
leak-check:
	@./scripts/leak_check.sh

leak-check-test:
	@./scripts/leak_check_test.sh

# Mermaid is drawn in the browser, so no build step parses it. A ; in a
# sequenceDiagram ends the statement and breaks the diagram on GitHub.
mermaid-check:
	@./scripts/mermaid_check.sh

# Point git at scripts/git-hooks: pre-commit and pre-push run leak_check.sh.
# This is for each clone. Run it one time after you clone.
hooks:
	@git config core.hooksPath scripts/git-hooks
	@echo "hooks: core.hooksPath=scripts/git-hooks"

# Release test gates, cheapest first:
# - smoke needs no VM and no network other than what docs fetches.
# - test-mid needs the cloud lab up (docs/cloud_lab.md). It runs the groups
#   that cover the policy and all segments, not the slow lifecycle and
#   reboot groups.
# - e2e and lab-test are the full suite.
smoke: shell-test leak-check leak-check-test mermaid-check go-test apply-test appliance-test
	@if command -v uvx >/dev/null 2>&1; then $(MAKE) -s docs; else echo "smoke: uvx not on PATH, skipping docs"; fi

test-mid:
	./vm/cloudlab/lab.sh sync
	./vm/cloudlab/lab.sh test -run 'TestLab/(policy|enroll|dns-segments|agent-vm|house|desk)$$'

# Race tier (docs/cloud_lab.md): the full e2e suite against a race build
# of pf on gw. lab.sh test fails if the gw journal shows a data race. At
# the end, a normal sync puts a normal pf back on gw, also after a failure.
# The race report stays in vm/cloudlab/.vagrant/race.log.
RACE_TIMEOUT ?= 150m
test-race:
	@test "$(RACE)" != 1 || { echo "test-race: run it with no RACE=1. It makes the race build itself." >&2; exit 1; }
	PF_RACE=1 ./vm/cloudlab/lab.sh sync
	@rc=0; PF_E2E_REBOOT=1 ./vm/cloudlab/lab.sh test -timeout $(RACE_TIMEOUT) $(if $(filter 1,$(V)),-v,) $(if $(RUN),-run '$(RUN)',) || rc=$$?; \
	echo "test-race: lab.sh sync, to put a normal pf back on gw"; \
	./vm/cloudlab/lab.sh sync || echo "test-race: WARNING: gw can still run the race build of pf. Run: vm/cloudlab/lab.sh sync" >&2; \
	exit $$rc

fuzz:
	./scripts/fuzz.sh $(FUZZTIME)

# Clone report. -t 40 is exploratory and noisy: read it, but do not gate CI
# on it. GOFLAGS is cleared for the same reason as audit. dupl has no tags.
# The pseudo-version pins a commit, and the checksum database covers it.
DUPL_T ?= 40
DUPL_VERSION ?= v0.0.0-20260401084720-c99c5cf5c202
dupes:
	@GOFLAGS= go run github.com/golangci/dupl@$(DUPL_VERSION) -t $(DUPL_T) -plumbing . | grep -v _test.go || echo "no clones at -t $(DUPL_T)"

# Inline report. Compare the output of two branches to find a refactor
# that pushed a helper over the 80-node budget.
inline:
	@CGO_ENABLED=$(CGO_ENABLED) go build -gcflags=-m ./... 2>&1 | grep -E 'can inline|cannot inline' | sort -u

# GOFLAGS cleared: go run pkg@version cannot resolve under -mod=vendor.
audit:
	@go mod verify
	@GOFLAGS= go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK) ./...

# RACE=1: the race detector needs cgo, and Go refuses -race with
# -buildmode=pie on linux/amd64. No -s -w: the symbols stay for the reports.
# Only linux/amd64: a cross race build for arm64 needs an arm64 C
# compiler, and the race runtime on arm64 needs a kernel with a 48-bit
# address space.
pf:
ifeq ($(RACE),1)
	@test "$(GOOS)/$(GOARCH)" = linux/amd64 || { echo "pf: RACE=1 builds only linux/amd64 (the cloud lab), not $(GOOS)/$(GOARCH)" >&2; exit 1; }
	@CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -race -trimpath -o bin/pf ./cmd/pf
	@echo "bin/pf $(GOOS)/$(GOARCH) RACE (cloud lab only, never ship)"
else
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -buildmode=pie -trimpath -ldflags '-s -w' -o bin/pf ./cmd/pf
	@echo "bin/pf $(GOOS)/$(GOARCH)"
endif

split-bin: pf
	@cp -f bin/pf vm/pi/pf

# Public release: reproducible pf for linux/amd64 + arm64, SHA256SUMS and
# an SSH signature in namespace pi-fortress-dist (never the Pi ship one).
# Refer to docs/release.md. RELEASE_DIR defaults to dist/<version>/.
.PHONY: release release-gate release-verify release-check release-lint
DIST_KEY ?= ~/.ssh/pi_fortress_dist
RELEASE_DIR ?=
REV ?= HEAD
release:
	$(no_race)
	@SIGN_KEY=$(DIST_KEY) RELEASE_DIR=$(RELEASE_DIR) RELEASE_UNSIGNED=$(RELEASE_UNSIGNED) APPLIANCE=$(APPLIANCE) PI_SEED="$(PI_SEED)" ./scripts/release.sh release

# release-lint: the per-arch bundles that make release just built (or an
# already-built RELEASE_DIR) never ship the lab marker file or an
# unconditional -lab-echo. make release already runs this before it
# signs. This target runs it again alone, for example in CI against a
# directory that it did not build.
release-lint:
	@RELEASE_DIR=$(RELEASE_DIR) ./scripts/release.sh lint

# Before a release: dependencies match go.sum, no known vulnerability in
# code that pf calls (govulncheck, a dev tool fetched by go run, never
# linked), and no credential in the tracked tree. make release scans its
# own binaries the same way before it signs.
release-gate:
	go mod verify
	GOFLAGS= go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK) ./...
	go test -count=1 ./internal/secretscan

release-verify:
	@REV=$(REV) ./scripts/release.sh verify

release-check:
	@./scripts/release.sh check '$(SUMS)' '$(SIG)' '$(SIGNERS)'

# Evaluation appliance: the lab VMs sealed into an OVA pair in
# dist/<version>/ (docs/release.md). make release APPLIANCE=1 builds it
# into a signed release. appliance-test lints a fake root, with no VMs.
.PHONY: appliance appliance-test
appliance:
	$(no_race)
	@./scripts/appliance.sh $(RELEASE_DIR)

appliance-test: pf
	@./vm/appliance/lint_test.sh
	@./vm/appliance/apply_test.sh

# Public docs site: docs/user_guide/ built with Zensical into build/docs/,
# and deployed manually to Cloudflare Pages (docs/release.md "Docs site").
# Versions are pinned. Thus a build today and next month use the same
# renderer, and the deploy runs the selected wrangler, not the version
# that npm serves that day.
.PHONY: docs docs-push
ZENSICAL_VERSION ?= 0.0.63
WRANGLER_VERSION ?= 4.151.1
DOCS_PROJECT ?=
docs:
	uvx --from zensical==$(ZENSICAL_VERSION) zensical build -f zensical.toml -s

# docs-push refuses before it builds if an owner placeholder on the site
# is not filled or the leak check fails. A deploy is public immediately.
# The site links SECURITY.md in the repo, so it runs the full check.
docs-push:
	@test -n "$(DOCS_PROJECT)" || { echo "docs-push: set DOCS_PROJECT, e.g. DOCS_PROJECT=pi-fortress-docs make docs-push"; exit 1; }
	@./scripts/release.sh placeholders
	@./scripts/leak_check.sh
	@$(MAKE) --no-print-directory docs
	npx wrangler@$(WRANGLER_VERSION) pages deploy build/docs --project-name=$(DOCS_PROJECT) --branch=main

# Real Pi over SSH: PI_IP=10.79.0.1 make pi-ship
# (PI_IP here is the address that you use to reach the Pi, not the
# 10.77.0.1 agent-side address that vm/pi/net.env calls PI_IP. After the
# VLAN cutover, that is the desk segment address 10.79.0.1. Before it, it
# is the Wi-Fi address of the Pi on your LAN.)
PI_IP ?=
# The login user of the Pi. Set your own in the environment or on the
# command line, for example PI_USER=alice make pi-ssh PI_IP=10.79.0.1.
PI_USER ?= pi
PI_DIR ?= /opt/pi-fortress
PI = $(PI_USER)@$(PI_IP)
# IPQoS none: OpenSSH marks sessions DSCP EF. That puts them in the Wi-Fi
# voice queue, which the radio of the Pi stalls under power saving.
# ControlMaster: pi-ship is two rsyncs and an ssh. Without a shared
# master, each one authenticates and a passphrased key prompts three
# times. The master stays 60 s after the last session: long enough for
# the chain, and short enough that it is gone before the next chain.
PI_SSH = ssh -o IPQoS=none -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ControlMaster=auto -o ControlPath=~/.ssh/pf-%C -o ControlPersist=60

# Files that the Pi owns. The TUI edits them in place under /opt (admin
# resolves PolicyDir through the /vagrant symlink). Thus a plain --delete
# rsync would revert each operator edit and then apply the reverted lists.
# The ship excludes them and seeds them only when they are absent. Thus,
# for these files, the copy on the Pi wins. A git change to
# never_block.domains or sources.json does not get to an existing Pi
# until a person applies it there. house_default.domains is shipped code
# and is intentionally not in this list. generated/ holds the CA and agent
# credentials of the Pi. alert.url is gitignored and cannot seed.
PI_OWNED = core.hosts.local key_prefixes.rules.local doh.ips.local doh.domains.local house.domains house_never_block.domains house_private_dns.domains house_private_dns.ips blacklist.domains blacklist.ips never_block.domains never_block.ips direct_ip.allow house_direct_ip.allow ssh_allow.ips ntp_pass.ips git_push.allow allow.domains dns_types.allow sources.json
PI_KEEP = --exclude '/vm/policy/generated/' --exclude '/vm/policy/alert.url' $(foreach f,$(PI_OWNED),--exclude '/vm/policy/$(f)')
PI_SEED = $(addprefix vm/policy/,$(PI_OWNED))

pi-check:
	@test -n "$(PI_IP)" || { echo "set PI_IP, e.g. PI_IP=192.168.1.50 make $(MAKECMDGOALS)"; exit 1; }

pi-sync: pi-check
	$(no_race)
	@rsync -a --delete --exclude .git --exclude .vagrant $(PI_KEEP) -e "$(PI_SSH)" ./ $(PI):$(PI_DIR)/
	@rsync -a --ignore-existing -e "$(PI_SSH)" $(PI_SEED) $(PI):$(PI_DIR)/vm/policy/

# Signed ship (docs/signed_ship.md): no sudo on the Pi. pi-bundle tars
# the tracked and untracked-but-not-ignored files of the working tree (thus
# .cache/, build/ or a stray secrets.env never go with it). It uses the
# same keep and seed rules as pi-sync, plus a manifest. pi-sign signs it.
# pi-ship uploads the bundle and then the signature to pfship. The key of
# pfship can only write the upload directory. The Pi verifies, refuses
# rollbacks, swaps the tree and runs pf apply as root.
.PHONY: pi-bundle pi-sign pi-ship-sudo
SIGN_KEY ?= ~/.ssh/pi_fortress_release
PI_SHIP_USER ?= pfship
PI_SHIP_KEY ?= ~/.ssh/pi_fortress_ship
PI_BUNDLE ?= bin/pf-bundle.tar
PI_STAGE ?= .pi-fortress-stage

# The arch of pi-bundle, independent of the GOARCH for pf/split-bin in
# other targets (host arch by default). make pi-bundle builds arm64
# unless GOARCH is on the command line or in the environment. Thus the
# behaviour of make pi-ship does not change. make pi-bundle GOARCH=amd64
# builds the amd64 bundle for a generic gateway or the lab.
ifneq ($(filter command line environment,$(origin GOARCH)),)
PI_BUNDLE_ARCH := $(GOARCH)
else
PI_BUNDLE_ARCH := arm64
endif

pi-bundle:
	$(no_race)
	@$(MAKE) -s split-bin GOARCH=$(PI_BUNDLE_ARCH)
	@PI_SEED="$(PI_SEED)" ./scripts/release.sh pi-bundle $(PI_BUNDLE) "$$(git rev-parse --short HEAD)$$(git diff --quiet HEAD -- || echo -dirty)"

pi-sign:
	@rm -f $(PI_BUNDLE).sig
	@ssh-keygen -Y sign -f $(SIGN_KEY) -n pi-fortress-release $(PI_BUNDLE)

pi-ship: pi-check
	$(no_race)
	@test -f $(SIGN_KEY) -a -f $(PI_SHIP_KEY) || { echo "pi-ship: no $(SIGN_KEY) or $(PI_SHIP_KEY). One-time setup: docs/signed_ship.md, Setup. Until then: make pi-ship-sudo PI_IP=$(PI_IP)"; exit 1; }
	@$(MAKE) -s pi-bundle
	@$(MAKE) -s pi-sign
	@rsync -t -e "$(PI_SSH) -i $(PI_SHIP_KEY) -o IdentitiesOnly=yes" $(PI_BUNDLE) $(PI_SHIP_USER)@$(PI_IP):
	@rsync -t -e "$(PI_SSH) -i $(PI_SHIP_KEY) -o IdentitiesOnly=yes" $(PI_BUNDLE).sig $(PI_SHIP_USER)@$(PI_IP):
	@echo "uploaded; result: $(PI_SSH) $(PI) tail -1 /var/log/pi-fortress/ship.jsonl"
	@echo "then, once the box checks out: $(PI_SSH) -t $(PI) sudo pf ship confirm -- within the dead-man window (10 min by default), or the Pi rolls itself back"

# The old loop, for a Pi without pfship, or a bundle that the Pi refuses.
# sudo prompts one time for the login password. After a signed ship, root
# owns the tree. Thus the files go into a staging dir first, and sudo
# rsync moves them. The floor stamp of the tree stays after the --delete.
# An armed confirm from an earlier signed ship is disarmed before the
# apply. Its .prev is not the tree that this push replaced, and the
# dead-man timer would swap it back over the push.
pi-ship-sudo: pi-check
	$(no_race)
	@$(MAKE) -s split-bin GOARCH=arm64
	@rsync -a --delete --exclude .git --exclude .vagrant $(PI_KEEP) -e "$(PI_SSH)" ./ $(PI):$(PI_STAGE)/
	@rsync -a -e "$(PI_SSH)" $(PI_SEED) $(PI):$(PI_STAGE)/vm/policy/
	@$(PI_SSH) -t $(PI) "sudo rsync -a --delete --chown=root:root --exclude .git --exclude .vagrant --exclude /.pf-ship-version $(PI_KEEP) $(PI_STAGE)/ $(PI_DIR)/ && sudo rsync -a --ignore-existing --chown=root:root $(addprefix $(PI_STAGE)/,$(PI_SEED)) $(PI_DIR)/vm/policy/ && sudo pf ship confirm && sudo pf apply"

pi-ssh: pi-check
	@$(PI_SSH) $(PI)

# Agent VMs bridged onto the cable to the real Pi. Without AGENT_BRIDGE, the
# Vagrantfile puts the second NIC on the internal lab network.
# enp6s0.20 is the VLAN child that carries the agent segment. The desktop
# host uses the same cable on VLAN 79 and cannot reach it.
AGENT_BRIDGE ?= enp6s0.20
AGENT_COUNT ?= 1
# AGENT_SUDO=1 gives the `agent` user of the VM passwordless sudo. Off by
# default: the work of the agent runs unprivileged unless you ask for it.
# The provision of the VM reads it. Thus, on an existing VM, change it
# with `make agent-provision AGENT_SUDO=1` (or =0 to remove it).
AGENT_SUDO ?= 0
AGENT_ENV = AGENT_BRIDGE=$(AGENT_BRIDGE) AGENT_COUNT=$(AGENT_COUNT) AGENT_SUDO=$(AGENT_SUDO)
AGENT_VMS = $(shell seq 1 $(AGENT_COUNT) | sed -e '1s/^1$$/agent/' -e 's/^\([2-9][0-9]*\)$$/agent\1/')

agent-up:
	@$(AGENT_ENV) vagrant up $(AGENT_VMS)
	@echo "$(AGENT_VMS) bridged on $(AGENT_BRIDGE)"

agent-reload:
	@$(AGENT_ENV) vagrant halt $(AGENT_VMS)
	@$(AGENT_ENV) vagrant up $(AGENT_VMS)
	@echo "$(AGENT_VMS) bridged on $(AGENT_BRIDGE)"

agent-provision:
	@$(AGENT_ENV) vagrant provision $(AGENT_VMS) --provision-with bootstrap

# A shell as the user that the work of the agent runs as, not as vagrant.
agent-shell:
	@$(AGENT_ENV) vagrant ssh agent -- -t sudo -iu agent

agent-destroy:
	@$(AGENT_ENV) vagrant destroy -f $(AGENT_VMS)

# Read back the VirtualBox settings of each agent VM: host-guest channels
# and unused devices off, no shared folder, no host-only NIC beside a bridge.
agent-audit:
	@for v in $(AGENT_VMS); do ./vm/agent/audit.sh "pi-fortress-$$v" || exit 1; done

pi-provision: pi-check
	$(no_race)
	@$(MAKE) -s split-bin GOARCH=arm64
	@$(MAKE) -s pi-sync
	@$(PI_SSH) -t $(PI) sudo $(PI_DIR)/vm/pi/provision.sh

observe:
	./vm/bin/observe.sh once

status:
	./vm/bin/status.sh

halt:
	./vm/bin/halt.sh

destroy:
	./vm/bin/destroy.sh
