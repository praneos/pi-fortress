package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// segConfig is a box with one plain segment, the desk, written as the real
// one is: a comment, the three keys that the editor never touches, and no
// lines for the three editable keys. Thus a read answers with their
// defaults. It is built on netConfig, because each check here runs the
// edit through pf render, and render needs a net.env to render against.
func segConfig(t *testing.T) (*Config, string) {
	t.Helper()
	c := netConfig(t)
	c.SegmentsDir = filepath.Join(filepath.Dir(c.NetEnvPath), "segments.d")
	if err := os.MkdirAll(c.SegmentsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.SegmentsDir, "desk.env")
	write(t, path, "# the operator's own seat\nIF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	return c, path
}

func TestSegmentEnvFillsInTheDefaultsForTheKeysTheFileLeavesOut(t *testing.T) {
	c, _ := segConfig(t)
	env, err := c.SegmentEnv("desk")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"IF": "eth0.79", "NET": "10.79.0.0/30", "IP": "10.79.0.1",
		"ADMIN": "no", "SSH_TO": "", "BLOCK_DIRECT_IP": "on",
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s=%q want %q in %+v", k, env[k], v, env)
		}
	}
}

func TestSegmentEnvRefusesASegmentThisBoxDoesNotHave(t *testing.T) {
	c, _ := segConfig(t)
	write(t, filepath.Join(filepath.Dir(c.SegmentsDir), "decoy.env"), "IF=eth0.90\n")
	for _, name := range []string{"cctv", "../decoy", "Desk", "", "desk.env"} {
		if env, err := c.SegmentEnv(name); err == nil {
			t.Fatalf("%q was read as a segment: %+v", name, env)
		}
	}
}

// Each editable key round-trips. The file keeps all that it had: the
// comment, the three fixed keys, and their order.
func TestSetSegmentEnvWritesEachEditableKey(t *testing.T) {
	c, path := segConfig(t)
	for _, tc := range []struct{ key, value string }{
		{"ADMIN", "yes"},
		{"SSH_TO", "10.77.0.10-10.77.0.12"},
		{"BLOCK_DIRECT_IP", "off"},
	} {
		if warn, err := c.SetSegmentEnvKeys("desk", map[string]string{tc.key: tc.value}); err != nil || warn != "" {
			t.Fatalf("%s=%s: %v, warn %q", tc.key, tc.value, err, warn)
		}
		env, err := c.SegmentEnv("desk")
		if err != nil {
			t.Fatal(err)
		}
		if env[tc.key] != tc.value {
			t.Fatalf("%s reads back as %q", tc.key, env[tc.key])
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# the operator's own seat\nIF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n" +
		"ADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\nBLOCK_DIRECT_IP=off\n"
	if string(raw) != want {
		t.Fatalf("the file lost its comment or its order:\n%s\nwant\n%s", raw, want)
	}
}

// When a key is set to its default, the code writes the word of the
// default and does not remove the line. setEnvLines only writes again or
// appends. pf render refuses a segment line that is present and empty.
// Thus this code cannot remove the line without its own writer. A read
// gives the same answer in both cases.
func TestSetSegmentEnvWritesTheDefaultRatherThanRemovingTheLine(t *testing.T) {
	c, path := segConfig(t)
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"BLOCK_DIRECT_IP": "on"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "BLOCK_DIRECT_IP=on\n") {
		t.Fatalf("the default was not written:\n%s", raw)
	}
	_, err = c.SetSegmentEnvKeys("desk", map[string]string{"BLOCK_DIRECT_IP": ""})
	if err == nil {
		t.Fatal("an empty value was accepted; pf render refuses that line")
	}
	// And the check of the key itself refuses it, not the candidate render.
	// The render would answer with a line number in a temp directory that no
	// longer exists when the operator reads it.
	if !strings.Contains(err.Error(), "on or off") || strings.Contains(err.Error(), "segments.d.check") {
		t.Fatalf("the refusal is the candidate's, not the key's: %v", err)
	}
}

// The code refuses IF, NET and IP with the reason, and does not ignore them
// silently. An operator who cannot see the reason cannot know that the
// change needs an editor and a reboot.
func TestSetSegmentEnvRefusesTheKeysThatMoveTheSegment(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	for _, key := range SegmentFixed {
		_, err := c.SetSegmentEnvKeys("desk", map[string]string{key: "eth0.80"})
		if err == nil {
			t.Fatalf("%s was editable from a screen", key)
		}
		for _, want := range []string{key, "session making the change", path} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: the refusal does not say %q: %v", key, want, err)
			}
		}
	}
	if got := read(t, path); got != before {
		t.Fatalf("a refused edit wrote the file:\n%s", got)
	}
}

func TestSetSegmentEnvRefusesWhatRenderRefuses(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	for _, tc := range []struct{ key, value, want string }{
		{"ADMIN", "maybe", "yes or no"},
		{"BLOCK_DIRECT_IP", "no", "on or off"},
		{"DOT_IPS", "9.9.9.9", "unknown key"},
		// The format is the check of this file. The check for "inside AGENT_NET"
		// is in pf render, through the candidate directory.
		{"SSH_TO", "10.77.0.10-", "IPv4 address"},
		{"SSH_TO", "10.99.0.5", "AGENT_NET"},
		{"SSH_TO", "10.77.0.12-10.77.0.10", "10.77.0.12"},
	} {
		_, err := c.SetSegmentEnvKeys("desk", map[string]string{tc.key: tc.value})
		if err == nil {
			t.Fatalf("%s=%s was accepted", tc.key, tc.value)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s=%s: refusal %q does not say %q", tc.key, tc.value, err, tc.want)
		}
	}
	if got := read(t, path); got != before {
		t.Fatalf("a refused edit wrote the file:\n%s", got)
	}
}

// The code refuses a candidate that does not render, and the file is
// byte-identical after. That is the full reason to render a copy, and not
// to write the edit and roll it back. An operator cannot act on a refusal
// that already changed the file.
func TestSetSegmentEnvRefusesACandidateThatDoesNotRenderAndChangesNothing(t *testing.T) {
	c, path := segConfig(t)
	write(t, filepath.Join(c.SegmentsDir, "cctv.env"), "IF=eth0.80\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
	before := read(t, path)
	// 10.80.0.5 is on the cctv segment, not in AGENT_NET. Thus render refuses
	// it, although it is a well-formed address.
	_, err := c.SetSegmentEnvKeys("desk", map[string]string{"SSH_TO": "10.80.0.5"})
	if err == nil {
		t.Fatal("an SSH_TO outside AGENT_NET was accepted")
	}
	if got := read(t, path); got != before {
		t.Fatalf("the file is not byte-identical after the refusal:\n%s\nwas\n%s", got, before)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(c.SegmentsDir), "segments.d.check*")); len(left) != 0 {
		t.Fatalf("the candidate directory was left behind: %v", left)
	}
}

// A box with a fault in a different segment also did not render before
// this edit. Thus the edit goes in, and the operator sees what is still
// wrong. A refusal there would make a trap: a seat that cannot repair its
// own fault. The gate of the desk itself could not be enabled again until
// someone found an editor for a file in a different segment.
func TestSetSegmentEnvEditsABoxThatAlreadyDoesNotRenderAndSaysWhatIsLeft(t *testing.T) {
	c, _ := segConfig(t)
	write(t, filepath.Join(c.SegmentsDir, "cctv.env"), "IF=eth0.80\nNET=10.80.0.0/24\nIP=10.99.0.1\n")
	warn, err := c.SetSegmentEnvKeys("desk", map[string]string{"BLOCK_DIRECT_IP": "off"})
	if err != nil {
		t.Fatalf("an edit was refused over a neighbour's broken file: %v", err)
	}
	if !strings.Contains(warn, "does not render") || !strings.Contains(warn, "cctv") {
		t.Fatalf("the warning does not say what is still wrong: %q", warn)
	}
	env, err := c.SegmentEnv("desk")
	if err != nil || env["BLOCK_DIRECT_IP"] != "off" {
		t.Fatalf("the edit did not go in: %+v %v", env, err)
	}
}

// ADMIN=no is a warning, not a refusal. It is a legitimate change. The
// operator often makes it over the same segment that it closes. Thus the
// seat must say what will occur, and when.
func TestSetSegmentEnvWarnsThatAdminNoClosesSSHAtTheNextApply(t *testing.T) {
	c, _ := segConfig(t)
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"ADMIN": "yes"}); err != nil {
		t.Fatal(err)
	}
	warn, err := c.SetSegmentEnvKeys("desk", map[string]string{"ADMIN": "no"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssh", "desk", "next apply"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("the warning does not say %q: %q", want, warn)
		}
	}
	env, err := c.SegmentEnv("desk")
	if err != nil || env["ADMIN"] != "no" {
		t.Fatalf("the edit did not go in: %+v %v", env, err)
	}
}

// The name is the only path check. Thus it must hold on the name of a file
// that exists. ../decoy is an env file one level up. The writer must not
// edit it and must not report success.
func TestSetSegmentEnvRefusesASegmentThisBoxDoesNotHave(t *testing.T) {
	c, _ := segConfig(t)
	decoy := filepath.Join(filepath.Dir(c.SegmentsDir), "decoy.env")
	write(t, decoy, "IF=eth0.90\n")
	before := read(t, decoy)
	for _, name := range []string{"cctv", "../decoy", "Desk", "desk.env", ""} {
		if _, err := c.SetSegmentEnvKeys(name, map[string]string{"ADMIN": "yes"}); err == nil {
			t.Fatalf("%q was written as a segment", name)
		}
	}
	if got := read(t, decoy); got != before {
		t.Fatalf("a name that leaves segments.d wrote the file it pointed at:\n%s", got)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The seat runs the same render. Thus a screen also cannot give a segment
// on the house cable SSH to the Pi or into the agents. The refused edit
// leaves the file as it was.
func TestSetSegmentEnvRefusesAdminOnAVLANOfTheHouse(t *testing.T) {
	c, _ := segConfig(t)
	write(t, c.HouseEnv, "HOUSE_IF=eth1\n")
	path := filepath.Join(c.SegmentsDir, "iot.env")
	write(t, path, "IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n")
	before := read(t, path)
	for _, kv := range []map[string]string{{"ADMIN": "yes"}, {"SSH_TO": "10.77.0.10"}} {
		_, err := c.SetSegmentEnvKeys("iot", kv)
		if err == nil || !strings.Contains(err.Error(), "is a VLAN on HOUSE_IF=eth1") {
			t.Fatalf("%v on a VLAN of the house: %v", kv, err)
		}
		if got := read(t, path); got != before {
			t.Fatalf("the file changed after the refusal:\n%s", got)
		}
	}
	if _, err := c.SetSegmentEnvKeys("iot", map[string]string{"BLOCK_DIRECT_IP": "off"}); err != nil {
		t.Fatalf("a house-trust edit was refused: %v", err)
	}
}
