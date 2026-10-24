package admin

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"pi-fortress/internal/base"
	"pi-fortress/internal/render"
)

// The seat can change what the box resolves through, and nothing else in
// net.env. PI_IP, AGENT_NET and the interface names are intentionally not
// editable here. An operator on the segment that those keys describe would
// change the address of their own connection. The next apply would then
// stop the seat too. For those keys, use an editor and a reboot. This is
// slow intentionally.
//
// Edits go into net.env.local, never into net.env. A ship overwrites
// net.env from git and keeps net.env.local. Thus a change in the base file
// stays until the next ship, and then disappears silently. This file exists
// to prevent that failure. It is not a style choice.
//
// AGENT_DNS and FAKEIP_NET set how the agent segment resolves. This is the
// same kind of setting as the upstream: neither moves an address that the
// seat connects over. Render refuses a bad placement of the pool against
// AGENT_NET, the house and segments.d (renderErr below). The validators
// only accept what render would parse.
//
// NetKeys is each key that SetNetEnv accepts. The TUI must have a row for
// each key in the list (tui TestHouseSettingsGroupEveryKeyOnce). Only
// `pf admin` can change a key that is settable here but absent there.
var NetKeys = append([]string{"DNS_UPSTREAM", "DOT_AUTH_NAME", "DOT_IPS", "UNTRUSTED_UPLINK", "AGENT_DNS", "FAKEIP_NET"}, render.ConnLimitKeys...)

// NetChoices are the keys whose value is one of a few words. Enter on the
// row steps to the next word. The first word is what an absent line means.
var NetChoices = map[string][]string{"AGENT_DNS": {render.AgentDNSFakeIP, render.AgentDNSForward}}

// DefaultFakeIPNet is the pool an empty FAKEIP_NET renders.
const DefaultFakeIPNet = render.DefaultFakeIPNet

var netKeys = map[string]func(string) error{
	"DNS_UPSTREAM":     checkAddr,
	"DOT_AUTH_NAME":    checkDNSNameOrEmpty,
	"DOT_IPS":          checkAddrsOrEmpty,
	"UNTRUSTED_UPLINK": checkZeroOne,
	"AGENT_DNS":        checkAgentDNS,
	"FAKEIP_NET":       checkFakeIPNetOrEmpty,
}

// The connection budgets (render/connlimit.go) are the same kind of
// setting. None of them moves an address. Each one fails toward the seat,
// not against it, because the code never counts established flows, such as
// the session that makes the edit. Each uses the check of render. Thus the
// next apply renders each value that this accepts.
func init() {
	for _, k := range render.ConnLimitKeys {
		netKeys[k] = func(v string) error { return render.CheckConnLimit(k, v) }
	}
}

// checkAgentDNS is AGENT_DNS; empty is fakeip, as it is to render.
func checkAgentDNS(v string) error {
	switch v {
	case "", render.AgentDNSForward, render.AgentDNSFakeIP:
		return nil
	}
	return errors.New("want " + render.AgentDNSForward + " or " + render.AgentDNSFakeIP)
}

// checkFakeIPNetOrEmpty is FAKEIP_NET; empty is render's default pool.
func checkFakeIPNetOrEmpty(v string) error {
	if v == "" {
		return nil
	}
	return render.CheckFakeIPNet(v)
}

// NetDoT is the provider of the box itself: a name and the addresses of
// that name. pf render refuses each half without the other. Refer to
// HouseDoT.
var NetDoT = []string{"DOT_AUTH_NAME", "DOT_IPS"}

// NetOnOff are the keys that the TUI changes with one key press. Each has
// the value that an absent line means.
var NetOnOff = map[string]string{"UNTRUSTED_UPLINK": "0"}

// reDNSName is a copy of the one in render, not an export. If this accepts
// a name that render rejects, the file bricks the next apply.
// TestSetNetEnvRefusesWhatRenderRefuses catches the drift. The code does
// not trust two copies to stay equal.
var reDNSName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func checkDNSNameOrEmpty(v string) error {
	if v == "" || reDNSName.MatchString(v) {
		return nil
	}
	return errors.New("want a domain name, lowercase")
}

// checkAddrsOrEmpty accepts the space-separated list that DOT_IPS is. A
// provider usually publishes two addresses, and the stub wants both.
func checkAddrsOrEmpty(v string) error {
	if v == "" {
		return nil
	}
	for _, f := range strings.Fields(v) {
		if err := checkAddr(f); err != nil {
			return err
		}
	}
	return nil
}

func checkZeroOne(v string) error {
	if v != "" && v != "0" && v != "1" {
		return errors.New("want 0 or 1")
	}
	return nil
}

// NetEnv is what the box runs: net.env with net.env.local on top of it, in
// the same order that apply sources them. Before, the code read only the
// base file. It showed the operator the shipped value while the box ran the
// overlay value. The overlay is the intended way to enable DoT.
func (c *Config) NetEnv() map[string]string {
	return base.LoadEnvOverlay(c.netEnvBase(), c.netEnvLocal())
}

// netEnvBase is the shipped file. Defaults resolves it to the one of
// base.NetEnvPaths that exists. A test names its own.
func (c *Config) netEnvBase() []string {
	if c.NetEnvPath != "" {
		return []string{c.NetEnvPath}
	}
	return base.NetEnvPaths()
}

func (c *Config) netEnvLocal() string {
	if c.NetEnvLocal != "" {
		return c.NetEnvLocal
	}
	return base.NetEnvLocal
}

// SetNetEnv writes kv to net.env.local as one edit. It refuses a
// combination that pf render would refuse. It does not leave a file that
// makes the next apply fail. The DoT keys are the reason that it takes a
// map. A provider is a name and its addresses, and render refuses each one
// alone. Thus edits of one key at a time could never give a valid box.
//
// The warning that it returns is the config that was already broken before
// this edit. A refusal there too would make a trap: a seat that cannot
// repair its own fault. An operator with a half-written house.env could not
// touch net.env until they found an editor. Thus the seat lets the operator
// edit a box that did not render before, and tells what is still wrong.
func (c *Config) SetNetEnv(kv map[string]string) (string, error) {
	keys, err := checkedKeys(kv, netKeys)
	if err != nil {
		return "", err
	}

	was := c.NetEnv()
	now := map[string]string{}
	for k, v := range was {
		now[k] = v
	}
	for _, k := range keys {
		now[k] = kv[k]
	}
	before := c.renderErr(was, c.HouseEnv)
	if err := c.renderErr(now, c.HouseEnv); err != nil {
		if before == nil {
			return "", err
		}
		// Broken before, and still broken. The edit goes in, and the operator
		// sees what is left.
	}
	if err := c.withEditLock(func() error {
		return setEnvLines(c.netEnvLocal(), kv, keys, alwaysQuote)
	}); err != nil {
		return "", err
	}
	// The code reads Config.Net one time at startup. All screens and all
	// segment lookups answer from it. Thus an edit that did not refresh it
	// would report success. The screen would then show the old value until the
	// process restarted.
	c.Net = c.NetEnv()
	if err := c.renderErr(c.Net, c.HouseEnv); err != nil {
		return "the configuration still does not render: " + err.Error(), nil
	}
	return "", nil
}

// renderErr runs all checks that pf render runs, off the box. Nothing here
// needs root or a Pi, because Live is what asks the kernel for interfaces
// and the pf-dns account.
func (c *Config) renderErr(env map[string]string, houseEnv string) error {
	return c.renderErrIn(env, houseEnv, c.SegmentsDir)
}

// renderErrIn is the same check against a segments directory that is not
// the one of the box. A candidate segments.d is such a directory. A segment
// edit needs it for the same reason that a house edit needs the house.env
// path. Render reads the directory itself. Thus the only way to ask what
// the edit would do is to give render a directory that holds the edit.
func (c *Config) renderErrIn(env map[string]string, houseEnv, segmentsDir string) error {
	limits := map[string]string{}
	for _, k := range render.ConnLimitKeys {
		limits[k] = env[k]
	}
	_, err := render.Load(render.Options{
		Net: render.Net{
			ConnLimits:      limits,
			AgentNet:        env["AGENT_NET"],
			PiIP:            env["PI_IP"],
			AgentIP:         env["AGENT_IP"],
			DNSUpstream:     env["DNS_UPSTREAM"],
			DoTAuthName:     env["DOT_AUTH_NAME"],
			DoTIPs:          env["DOT_IPS"],
			UntrustedUplink: env["UNTRUSTED_UPLINK"],
			AgentDNS:        env["AGENT_DNS"],
			FakeIPNet:       env["FAKEIP_NET"],
			EnvSrc:          c.NetEnvPath,
		},
		HouseEnv:    houseEnv,
		SegmentsDir: segmentsDir,
	})
	return err
}

// alwaysQuote is the rule of net.env. The file is sourced, so the code
// quotes each value, whether it needs it or not.
func alwaysQuote(string) bool { return true }

// quoteHouse is the rule of house.env: only the keys that pf render trims
// quotes from. These are the only keys that can hold a space.
func quoteHouse(key string) bool { return slices.Contains(HouseDoT, key) }

// neverQuote is the rule of segments.d. pf render parses those files and
// nothing sources them. Thus a quote stays as part of the value. Also, none
// of the three editable values can hold a space.
func neverQuote(string) bool { return false }

// setEnvLines writes each key again in place. It keeps the comments and the
// order of the file, and appends the keys that the file does not have yet.
// If the file does not exist, it creates the file with only the appended
// lines. That is what net.env.local is on a box that never had one.
//
// quote is per key and is not cosmetic. apply.sh sources net.env, so each
// value there is quoted. DOT_IPS is two addresses: without quotes, the
// shell reads the second address as a command to run. pf render parses
// house.env and does not source it. Thus a quote there stays as part of
// the value. The exception is the two keys that render strips quotes from.
// These are exactly the two keys that can hold a list. vm/itest sources
// the full house.env, so an unquoted list there runs its second address
// as a command. The validators reject a value that contains its own quote.
// Thus nobody can escape out of this.
func setEnvLines(path string, kv map[string]string, keys []string, quote func(string) bool) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	return writeLines(path, editEnvLines(lines, kv, keys, quote))
}

// editEnvLines is setEnvLines on lines that are already in memory. Thus a
// writer that must also remove lines (setSegmentLines) reads and writes the
// file one time.
func editEnvLines(lines []string, kv map[string]string, keys []string, quote func(string) bool) []string {
	value := func(k string) string {
		if quote(k) {
			return k + "='" + kv[k] + "'"
		}
		return k + "=" + kv[k]
	}
	for _, k := range keys {
		done := false
		for i, l := range lines {
			if name, _, cut := strings.Cut(l, "="); cut && strings.TrimSpace(name) == k {
				lines[i], done = value(k), true
			}
		}
		if !done {
			lines = append(lines, value(k))
		}
	}
	return lines
}
