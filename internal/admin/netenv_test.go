package admin

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/base"
)

// netConfig is a box with a shipped net.env and no overlay yet. All boxes
// are like this before the first DoT edit.
func netConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	dir := t.TempDir()
	c.NetEnvPath = filepath.Join(dir, "net.env")
	c.NetEnvLocal = filepath.Join(dir, "net.env.local")
	write(t, c.NetEnvPath, `AGENT_NET=10.77.0.0/24
PI_IP=10.77.0.1
AGENT_IP=10.77.0.10
# Upstream DNS over TLS. Empty is the plaintext forward.
DOT_AUTH_NAME=
DOT_IPS=
DNS_UPSTREAM=9.9.9.9
UNTRUSTED_UPLINK=0
`)
	write(t, c.HouseEnv, "")
	c.Net = c.NetEnv()
	return c
}

// The overlay is the file that a ship keeps. net.env is the file that a
// ship overwrites. An edit in the base file works until the next ship, and
// then stops silently. That is the worse of the two failures, because
// nothing reports it.
func TestSetNetEnvWritesTheOverlayAndLeavesTheShippedFile(t *testing.T) {
	c := netConfig(t)
	shipped, err := os.ReadFile(c.NetEnvPath)
	if err != nil {
		t.Fatal(err)
	}
	if warn, err := c.SetNetEnv(map[string]string{
		"DOT_AUTH_NAME": "dns.quad9.net",
		"DOT_IPS":       "9.9.9.9 149.112.112.112",
	}); err != nil || warn != "" {
		t.Fatalf("warn=%q err=%v", warn, err)
	}
	after, err := os.ReadFile(c.NetEnvPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(shipped) {
		t.Fatalf("net.env was rewritten:\n%s", after)
	}
	// apply.sh sources it, so the two addresses must arrive as one value.
	// Without quotes, the shell reads the second address as a command.
	local, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(local), "DOT_IPS='9.9.9.9 149.112.112.112'") {
		t.Fatalf("DOT_IPS is not quoted:\n%s", local)
	}
	env := base.LoadEnvOverlay([]string{c.NetEnvPath}, c.NetEnvLocal)
	if env["DOT_IPS"] != "9.9.9.9 149.112.112.112" || env["DOT_AUTH_NAME"] != "dns.quad9.net" {
		t.Fatalf("the overlay does not read back: %+v", env)
	}
	// The code reads it one time at startup, and all screens answer from it.
	// Thus an edit that does not refresh it reports success and continues to
	// show the old value.
	if c.Net["DOT_AUTH_NAME"] != "dns.quad9.net" {
		t.Fatalf("Config.Net is stale: %q", c.Net["DOT_AUTH_NAME"])
	}
}

// The file of the operator stays correct after the edit. The comment above
// a key stays above it. The key order is the order of the file. The code
// appends a key that the file never had, and does not lose the rest.
func TestSetNetEnvKeepsCommentsAndOrder(t *testing.T) {
	c := netConfig(t)
	write(t, c.NetEnvLocal, `# Set by hand on the ship, do not lose this line.
DNS_UPSTREAM=1.1.1.1
# The uplink is a cafe.
UNTRUSTED_UPLINK=1
`)
	if _, err := c.SetNetEnv(map[string]string{"DNS_UPSTREAM": "8.8.8.8", "DOT_IPS": ""}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatal(err)
	}
	want := `# Set by hand on the ship, do not lose this line.
DNS_UPSTREAM='8.8.8.8'
# The uplink is a cafe.
UNTRUSTED_UPLINK=1
DOT_IPS=''
`
	if string(raw) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", raw, want)
	}
}

// pf render refuses a DoT name without its addresses. A writer that let one
// through would leave a file that fails the next apply. An operator who
// cannot apply cannot fix it from the seat either. This is also the drift
// check on the copy of the name regexp of render.
func TestSetNetEnvRefusesWhatRenderRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		kv   map[string]string
		want string
	}{
		{"name alone", map[string]string{"DOT_AUTH_NAME": "dns.quad9.net"}, "DOT_IPS"},
		{"addresses alone", map[string]string{"DOT_IPS": "9.9.9.9"}, "DOT_AUTH_NAME"},
		{"not a name", map[string]string{"DOT_AUTH_NAME": "Not A Name"}, "domain name"},
		{"not an address", map[string]string{"DOT_IPS": "9.9.9.9 nope"}, "DOT_IPS"},
		{"a quote", map[string]string{"DOT_AUTH_NAME": "a'b.net"}, "domain name"},
		{"unknown key", map[string]string{"PI_IP": "10.77.0.2"}, "unknown key"},
		{"conn cap under the floor", map[string]string{"AGENT_CONN_PER_IP": "4"}, "AGENT_CONN_PER_IP"},
		{"rate without a burst", map[string]string{"HOUSE_NEW_PER_IP": "100"}, "HOUSE_NEW_PER_IP"},
		{"device cap over the total", map[string]string{"SEG_CONN_PER_IP": "9000", "SEG_CONN_TOTAL": "8192"}, "SEG_CONN_TOTAL"},
		{"segment total under the floor", map[string]string{"SEG_NEW_TOTAL": "50/100"}, "SEG_NEW_TOTAL"},
		{"device rate over the segment total", map[string]string{"SEG_NEW_PER_IP": "400/800"}, "SEG_NEW_TOTAL"},
		{"nothing", map[string]string{}, "nothing to set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := netConfig(t)
			_, err := c.SetNetEnv(tc.kv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want one mentioning %q", err, tc.want)
			}
			if _, err := os.Stat(c.NetEnvLocal); err == nil {
				t.Fatal("a refused edit wrote the overlay anyway")
			}
		})
	}
	// The pair together is the combination render accepts.
	c := netConfig(t)
	if _, err := c.SetNetEnv(map[string]string{
		"DOT_AUTH_NAME": "dns.quad9.net", "DOT_IPS": "9.9.9.9 149.112.112.112",
	}); err != nil {
		t.Fatal(err)
	}
}

// The seat can set the connection budgets. They go into the overlay, and 0
// (off) is a value, not a refusal.
func TestSetNetEnvTakesTheConnectionBudgets(t *testing.T) {
	c := netConfig(t)
	if _, err := c.SetNetEnv(map[string]string{"AGENT_CONN_PER_IP": "192", "HOUSE_NEW_PER_IP": "200/800", "SEG_CONN_TOTAL": "0", "SEG_NEW_TOTAL": "400/2000"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AGENT_CONN_PER_IP='192'", "HOUSE_NEW_PER_IP='200/800'", "SEG_CONN_TOTAL='0'", "SEG_NEW_TOTAL='400/2000'"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("overlay lacks %s:\n%s", want, b)
		}
	}
}

// NetKeys is the list from which the TUI builds rows. netKeys is what
// SetNetEnv accepts. A key in one list but not the other is settable only
// through `pf admin`, or is a row where the code refuses each edit.
func TestNetKeysIsEverySettableKey(t *testing.T) {
	for _, k := range NetKeys {
		if _, ok := netKeys[k]; !ok {
			t.Errorf("NetKeys has %s and SetNetEnv refuses it", k)
		}
	}
	for k := range netKeys {
		if !slices.Contains(NetKeys, k) {
			t.Errorf("SetNetEnv takes %s and NetKeys lacks it", k)
		}
	}
	if len(NetKeys) != len(netKeys) {
		t.Errorf("NetKeys lists a key twice: %v", NetKeys)
	}
	for k, vs := range NetChoices {
		for _, v := range vs {
			if err := netKeys[k](v); err != nil {
				t.Errorf("choice %s=%s is refused: %v", k, v, err)
			}
		}
	}
	if err := netKeys["FAKEIP_NET"](DefaultFakeIPNet); err != nil {
		t.Errorf("the default pool is refused: %v", err)
	}
}

// A box whose configuration was already broken must still be editable. If
// not, the seat cannot repair its own fault. The edit goes in and says what
// is left.
func TestSetNetEnvEditsAnAlreadyBrokenConfigAndSaysSo(t *testing.T) {
	c := netConfig(t)
	// HOUSE_DOT_IPS without DOT_IPS is one of render's own refusals.
	write(t, c.HouseEnv, "HOUSE_IF=eth1\nHOUSE_DOT_AUTH_NAME=dns.quad9.net\nHOUSE_DOT_IPS=9.9.9.9\n")
	warn, err := c.SetNetEnv(map[string]string{"DNS_UPSTREAM": "1.1.1.1"})
	if err != nil {
		t.Fatalf("a broken box refused an unrelated edit: %v", err)
	}
	if !strings.Contains(warn, "HOUSE_DOT_IPS") {
		t.Fatalf("warning does not name what is still wrong: %q", warn)
	}
	if got := c.NetEnv()["DNS_UPSTREAM"]; got != "1.1.1.1" {
		t.Fatalf("the edit did not land: %q", got)
	}
}

// The code parses house.env and does not source it. Thus a plain key must
// not have quotes, because the quotes would stay as part of the value. The
// DoT pair is the exception. pf render strips quotes from exactly those
// two, and vm/itest does source the file. There, an unquoted list of
// addresses runs its second element as a command. Both files now go through
// one writer. That is why the test asserts the rule and does not assume it.
func TestSetHouseEnvQuotesOnlyTheDoTPair(t *testing.T) {
	c := netConfig(t)
	write(t, c.HouseEnv, "HOUSE_IF=eth1\n")
	if err := c.SetHouseEnv("HOUSE_DNS_UPSTREAM", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "'") {
		t.Fatalf("a plain house key was quoted:\n%s", raw)
	}
	if base.LoadEnv(c.HouseEnv)["HOUSE_DNS_UPSTREAM"] != "1.1.1.1" {
		t.Fatalf("%s", raw)
	}
	// The pair is the exception. Render forces the order of the three steps
	// below, and the test asserts that order. A plaintext house upstream must
	// go before the box enables DoT, because with DOT_IPS set, the Pi drops
	// plaintext DNS that leaves it. The house provider comes last. It needs
	// the provider of the box, because it is a second stub beside the first.
	if err := c.SetHouseEnv("HOUSE_DNS_UPSTREAM", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetNetEnv(map[string]string{"DOT_AUTH_NAME": "dns.quad9.net", "DOT_IPS": "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetHouseEnvKeys(map[string]string{
		"HOUSE_DOT_AUTH_NAME": "dns.quad9.net",
		"HOUSE_DOT_IPS":       "9.9.9.9 149.112.112.112",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "HOUSE_DOT_IPS='9.9.9.9 149.112.112.112'\n") {
		t.Fatalf("the list is not quoted, so sourcing this file runs its second address:\n%s", raw)
	}
	// And render still reads it as the two addresses, quotes stripped.
	if err := c.renderErr(c.NetEnv(), c.HouseEnv); err != nil {
		t.Fatalf("what was written does not render: %v", err)
	}
}

// Here, the audit log must say to which provider the box pointed, and when.
// Thus the keys must reach the entry. They are config values, not secrets.
// Args.Secret is the field that must never appear.
func TestNetEnvSetIsAudited(t *testing.T) {
	c, path := auditCfg(t)
	dir := t.TempDir()
	c.NetEnvPath = filepath.Join(dir, "net.env")
	c.NetEnvLocal = filepath.Join(dir, "net.env.local")
	write(t, c.NetEnvPath, "AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nAGENT_IP=10.77.0.10\nDNS_UPSTREAM=9.9.9.9\n")
	if _, err := c.Call(RoleAdmin, "net.env.set", Args{Env: map[string]string{
		"DOT_AUTH_NAME": "dns.quad9.net", "DOT_IPS": "9.9.9.9",
	}}); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("%d entries", len(lines))
	}
	e := lines[0]
	if e.Verb != "net.env.set" || !e.OK || e.Args["env.DOT_AUTH_NAME"] != "dns.quad9.net" || e.Args["env.DOT_IPS"] != "9.9.9.9" {
		t.Fatalf("%+v", e)
	}
}

// On the Logs screen, the operator reads raw log text. The screen had a
// case for the resolver log of the house and for no other log. It did not
// show the log of the agents, which is the busiest file that the box
// writes. It did not show the log of a plain segment, which nothing else on
// the seat could show either.
func TestLogListCoversEveryResolverLog(t *testing.T) {
	c := testConfig(t)
	dir := t.TempDir()
	c.SegmentsDir = filepath.Join(dir, "segments.d")
	c.DNSLogPath = filepath.Join(dir, "dns.jsonl")
	c.HouseDNSLog = filepath.Join(dir, "dns-house.jsonl")
	if err := os.MkdirAll(c.SegmentsDir, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(c.SegmentsDir, "desk.env"), "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	write(t, c.DNSLogPath, `{"t":"2026-09-18T10:00:00Z","src":"10.77.0.10","name":"api.example","qtype":"A","act":"resolved","answer":"93.184.216.34"}`+"\n")
	write(t, filepath.Join(dir, "dns-desk.jsonl"), `{"t":"2026-09-18T10:00:01Z","src":"10.79.0.2","name":"seat.example","qtype":"A","act":"blocked"}`+"\n")

	names := c.LogList()
	for _, want := range []string{"agent dns", "house dns", "dns desk"} {
		if !slices.Contains(names, want) {
			t.Fatalf("no %q tab: %v", want, names)
		}
	}
	// Rendered for a person, not left as the shape a parser wants.
	agent, err := c.Log(LogAgentDNS, 10)
	if err != nil || len(agent) != 1 || !strings.Contains(agent[0], "api.example") || strings.Contains(agent[0], "{") {
		t.Fatalf("agent dns: %v %q", err, agent)
	}
	desk, err := c.Log(LogSegDNS, 10)
	if err != nil || len(desk) != 1 || !strings.Contains(desk[0], "seat.example") {
		t.Fatalf("desk dns: %v %q", err, desk)
	}
	// One past the last segment is not a log.
	if _, err := c.Log(LogSegDNS+1, 10); err == nil {
		t.Fatal("a segment that does not exist answered with a log")
	}
}
