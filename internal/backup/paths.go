// Package backup exports the state that a rebuilt pi-fortress needs to be
// the same fence again, and restores it.
//
// The content of a backup is the full design, and the two obvious answers
// are both wrong. "Everything under /etc/pi-fortress" restores a box that
// cannot start. pf apply compiles most of that directory from the policy
// lists, and half of it is keyed to hardware that no longer exists.
// "Everything including the secrets and the CA" makes the archive a
// credential dump. The one file that an operator most wants on a laptop
// becomes the one file that they must guard as carefully as the Pi. That
// is the same as no backup.
//
// So a backup carries operator intent (the lists, the env files, the feed
// sources), and carries no identity. The secrets store, the CA key and the
// WireGuard key are not excluded by a check that a flag could skip: they
// are not in the format. A restore cannot overwrite them, because it never
// has them. Each manifest states the cost plainly: a restore onto dead
// hardware gives back a policy, not a fence that works, and the credentials
// must be minted again.
//
// One thing in the archive is a secret. To call this format
// credential-free would be a lie that an operator could act on. alert.url
// is a webhook whose path is its bearer token. It is here because it is
// operator intent that is in no other location (see PolicyFiles). So an
// archive is not a credential dump, but it is also not safe to publish.
// Treat it as confidential, and rotate the alert webhook if one leaks.
package backup

import (
	"path/filepath"
	"regexp"
	"sort"

	"pi-fortress/internal/policycompile"
)

// PolicyFiles is the policy state that is on the Pi and in no other
// location: PiOwned plus alert.url. The Makefile excludes alert.url by name,
// not through PI_OWNED, because it is gitignored and so cannot seed a new
// Pi. It is still the file of the operator, so a backup carries it.
func PolicyFiles() []string {
	out := append(PiOwned(), "alert.url")
	sort.Strings(out)
	return out
}

// PiOwned is the rsync contract: the files that make pi-ship must not
// delete from the Pi, because the copy on the Pi is the only copy.
//
// It comes from policycompile, and is not a written list. The Makefile
// already gives the same set by hand as PI_OWNED, where it drives the
// --delete exclusions. The next ship silently deletes from the Pi a list
// that is TUI-editable but not in that exclusion set. A hand-written third
// copy here would be a third chance to make that mistake.
// TestPiOwnedMatchesMakefile holds the Makefile to this one.
func PiOwned() []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, seg := range []policycompile.SegmentPolicy{
		policycompile.SegmentFor(policycompile.DenyByDefault),
		policycompile.SegmentFor(policycompile.AllowByDefault),
	} {
		for _, l := range seg.Lists() {
			add(l.Name)
		}
	}
	// Not a segment list, but the list of the operator: which feeds run, and
	// which ones the operator disabled. Without it, the reason for the shape
	// of the block list is lost.
	add("sources.json")
	// Also not a segment list: the repos the broker lets the agent push to.
	add("git_push.allow")
	// Nor this: the name and type pairs the agent resolver forwards past
	// its address-only filter.
	add("dns_types.allow")
	// Nor this: the core.hosts lines of the operator. Upgrades keep these
	// lines, and replace core.hosts itself.
	add("core.hosts.local")
	sort.Strings(out)
	return out
}

// EtcFiles is the operator-authored half of /etc/pi-fortress. apply
// compiles all else there from these files plus the policy lists. So a
// copy of it would restore a stale copy of something that apply is about
// to rewrite in any case.
//
// segments.d is a directory and is walked, not listed.
var EtcFiles = []string{
	"net.env",
	"net.env.local",
	"house.env",
	"paranoid.env",
	// The DHCP reservations of the house, which Devices r in the TUI writes.
	// Nothing compiles them, so the archive is their only other copy.
	"house.hosts",
}

const SegmentsDir = "segments.d"

// segAllowName is the paranoid allowlist of a plain segment, as it is
// beside segments.d (render.SegmentAllowPath): allow.<segment>.domains. The
// segment part is held to the segment-name pattern of render, so an
// archive cannot name anything else in /etc/pi-fortress. It is carried
// because apply refuses a desk restored with PARANOID=on and without its list.
var segAllowName = regexp.MustCompile(`^allow\.[a-z][a-z0-9_-]{0,15}\.domains$`)

func segAllowFile(segment string) string { return "allow." + segment + ".domains" }

// segHostsName is the DHCP reservations of a plain segment beside
// segments.d (render.SegmentHostsPath). It is held to the same segment-name
// pattern as segAllowName, and carried for the same reason: it is the
// per-segment twin of house.hosts, and the archive is its only other copy.
var segHostsName = regexp.MustCompile(`^dhcp\.[a-z][a-z0-9_-]{0,15}\.hosts$`)

func segHostsFile(segment string) string { return "dhcp." + segment + ".hosts" }

// Excluded is what is intentionally absent, why, and what to do about it.
// It goes into each archive, not only into the docs. An operator who
// restores in two years has the tarball, and may not have the repository.
// They need to know that the CA is not in here at the time when they
// rebuild a dead box.
type Exclusion struct {
	What string `json:"what"`
	Why  string `json:"why"`
	Redo string `json:"redo"`
}

func Exclusions() []Exclusion {
	return []Exclusion{
		{
			What: "/etc/pi-fortress/broker/secrets.env",
			Why:  "live credentials; an archive holding them would need the same custody as the Pi",
			Redo: "pf enroll mint, per slot",
		},
		{
			What: "/var/lib/pi-fortress/engine/ca.pem",
			Why:  "the CA private key is this box's identity; a copy on a second box can impersonate the first to every enrolled agent",
			Redo: "pf engine -init-ca, then re-trust on each agent (setup.sh)",
		},
		{
			What: "/etc/pi-fortress/mullvad.conf and /etc/wireguard",
			Why:  "the WireGuard private key is issued per device; two peers on one key race each other",
			Redo: "download a fresh config from the provider",
		},
		{
			What: "/etc/pi-fortress/*.conf, paranoid.flags, broker.env, engine.env, generated/",
			Why:  "compiled from the files that are in here",
			Redo: "pf apply",
		},
		{
			What: "leases, offsets, observe.json, logs, monitor/",
			Why:  "state of a run that has ended; restoring it replays or misdates what the new box then sees",
			Redo: "nothing; it rebuilds itself",
		},
		{
			What: "/var/log/pi-fortress/audit.jsonl",
			Why:  "an append-only history, not restorable state; archive it separately if it is wanted",
			Redo: "nothing",
		},
	}
}

// Ifaces are recorded so that a restore can tell whether the archive came
// from hardware with the same shape as this one. apply.sh refuses to start
// a profile pinned to an interface name that is not there. The failure
// then looks like a broken box, not like a backup taken on other hardware.
var Ifaces = []string{"INT_IF", "WAN_IF", "HOUSE_IF", "WG_IF", "PARANOID", "UNTRUSTED_UPLINK"}

func etcPath(dir, name string) string  { return filepath.Join(dir, name) }
func archiveEtc(name string) string    { return "etc/" + name }
func archivePolicy(name string) string { return "policy/" + name }
