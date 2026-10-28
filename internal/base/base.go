// Package base holds parse and format primitives that all of pi-fortress
// shares. It imports nothing from this repo.
package base

import (
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"strings"
	"time"
)

// ISO is the wire timestamp: second resolution, UTC, no offset.
const ISO = "2006-01-02T15:04:05Z"

// NowISO formats now() in UTC. A nil now means time.Now.
func NowISO(now func() time.Time) string {
	t := time.Now()
	if now != nil {
		t = now()
	}
	return t.UTC().Format(ISO)
}

func ParseISO(s string) (time.Time, error) { return time.Parse(ISO, s) }

// EnvValue is the value half of a KEY=VALUE line, as the shell would give it
// after it sources the file. The whitespace around the assignment separates
// tokens and is not data. One layer of matching quotes is quoting and is not
// data. This is the only definition of that rule. Thus all readers of these
// files (doctor, the Go side of apply, the admin verbs) see the same value
// that the shell saw.
//
// It stops there intentionally. It keeps these forms literal:
//   - Parameter and command substitution ($VAR, $(...)).
//   - Backslash escapes.
//   - Adjacent quoting (a"b"c, and the idiom that closes a single-quoted run
//     to emit one quote and opens it again).
//   - An export prefix and a trailing unquoted # comment.
//
// The files that this reads are flat assignments of values that passed a
// character-class check. No code in the tree writes those forms. If this
// code interpreted them, it would be a second shell parser that is different.
func EnvValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if q := v[0]; (q == '"' || q == '\'') && v[len(v)-1] == q {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// ParseEnv reads KEY=VALUE lines. It skips blanks, # comments and lines
// with no =. It trims keys, and values go through EnvValue.
func ParseEnv(raw []byte) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		out[strings.TrimSpace(k)] = EnvValue(v)
	}
	return out
}

// StripLine removes a # or ; comment and the space around the rest of a
// list line.
func StripLine(raw string) string {
	line := raw
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	if i := strings.Index(line, ";"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// LoadEnvFile parses path. It tells apart a file that is not there and a
// file that is there but could not be read. The first is a configuration
// and gives an empty map. The second is a fault and gives the error. A
// caller that validates a proposed change against the current file must
// use this function. An empty map from a read failure is a gate that lets
// everything through.
func LoadEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseEnv(raw), nil
}

// LoadEnv parses path. An unreadable path gives an empty map. It is for
// readers that only show what they found. All code that makes a
// decision uses LoadEnvFile.
func LoadEnv(path string) map[string]string {
	env, err := LoadEnvFile(path)
	if err != nil {
		return map[string]string{}
	}
	return env
}

// LoadEnvFirst parses the first readable path and stops there.
func LoadEnvFirst(paths []string) map[string]string {
	for _, p := range paths {
		if raw, err := os.ReadFile(p); err == nil {
			return ParseEnv(raw)
		}
	}
	return map[string]string{}
}

// NetEnvLocal is the overlay of the operator. vm/pi/apply.sh sources it
// after the net.env that it found (vm/pi/net.env.local.example). It is one
// fixed path, not a sibling of the base, because apply reads that path. In
// the Vagrant lab, the base comes from the checkout, and the overlay still
// comes from /etc.
const NetEnvLocal = "/etc/pi-fortress/net.env.local"

// NetEnvPaths is the search order for the base net.env: the checkout of
// the lab first, then the installed copy.
func NetEnvPaths() []string {
	return []string{"/vagrant/vm/pi/net.env", "/etc/pi-fortress/net.env"}
}

// PolicyDir is the policy directory that all readers and editors of the
// lists of the operator must use: the directory that vm/pi/apply.sh
// compiles from. apply uses the checkout that it runs from: /vagrant in
// the lab and on a manually set Pi, /opt/pi-fortress on a pf install box.
// A tree is a directory that holds vm/pi/net.env and vm/policy. apply uses
// /etc/pi-fortress only when there is no tree. Before, the TUI, pf fetch and
// pf backup stopped at /vagrant and then edited /etc/pi-fortress. On a pf
// install box, apply never reads that directory. Thus the code wrote blocks
// and revocations, and silently never applied them. PI_FORTRESS_POLICY
// overrides.
func PolicyDir() string {
	return policyDirFrom(os.Getenv("PI_FORTRESS_POLICY"), []string{"/vagrant", "/opt/pi-fortress"}, "/etc/pi-fortress")
}

func policyDirFrom(env string, trees []string, fallback string) string {
	if v := strings.TrimSpace(env); v != "" {
		return v
	}
	for _, t := range trees {
		net, err := os.Stat(t + "/vm/pi/net.env")
		if err != nil || !net.Mode().IsRegular() {
			continue
		}
		if pol, err := os.Stat(t + "/vm/policy"); err == nil && pol.IsDir() {
			return t + "/vm/policy"
		}
	}
	return fallback
}

// LoadEnvOverlay parses the first readable file of paths, and then puts
// overlay on top. apply.sh reads this pair the same way: it sources the
// base, then sources the file of the operator, and the last assignment
// wins. All readers of net.env must use this function. A reader that uses
// only the base reports the shipped values, but the fence uses the
// overridden values. Then the firewall and the daemons of the box have
// different PI_IP and AGENT_NET values.
//
// The function reads the two halves leniently. If an overlay is present
// but cannot be read, the function uses the base without an error. The
// result is the same difference as above. The operator
// creates the overlay, so its mode is the mode that the operator set. All
// callers have the Defaults() shape and cannot return an error. Thus the
// check is where an operator can act on it: doctor reads the same pair
// and fails on an overlay that it can see but cannot read
// (internal/doctor/doctor.go). If a caller must make a decision on these
// values, give it LoadEnvFile and propagate the error.
func LoadEnvOverlay(paths []string, overlay string) map[string]string {
	env := LoadEnvFirst(paths)
	maps.Copy(env, LoadEnv(overlay))
	return env
}

// LoadNetEnv is LoadEnvOverlay over the net.env pair of the box.
func LoadNetEnv() map[string]string { return LoadEnvOverlay(NetEnvPaths(), NetEnvLocal) }

// MustPrefixes parses CIDR literals fixed at build time.
func MustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// CheckBindHost refuses a listen host that is not one unicast address. A
// daemon that the agent reaches binds the address of the agent NIC. The
// wildcard (0.0.0.0, ::, or an empty host) also listens on the house and
// uplink interfaces. There, only the input rules would protect a listener
// that the operator did not want to expose. CheckBindHost refuses a
// hostname, because it resolves to the answer of the resolver at start.
// "localhost" stays for tests and for loopback-only use.
func CheckBindHost(host string) error {
	if host == "localhost" {
		return nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("need a unicast IP (the agent NIC), not a hostname or an empty host")
	}
	if a.IsUnspecified() || a.IsMulticast() {
		return errors.New("binds the agent IP only, not 0.0.0.0 or ::")
	}
	return nil
}
