package admin

import (
	"strings"
	"testing"
)

// Each connection key of a plain segment round-trips, "0" included. The
// file keeps its comment and its fixed keys in their order.
func TestSetSegmentEnvWritesTheConnectionBudget(t *testing.T) {
	c, path := segConfig(t)
	kv := map[string]string{"CONN_PER_IP": "512", "NEW_PER_IP": "0", "CONN_TOTAL": "8192", "NEW_TOTAL": "200/400"}
	for k, v := range kv {
		if _, err := c.SetSegmentEnvKeys("desk", map[string]string{k: v}); err != nil {
			t.Fatalf("%s=%s: %v", k, v, err)
		}
	}
	env, err := c.SegmentEnv("desk")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if env[k] != v {
			t.Fatalf("%s reads back as %q, want %q", k, env[k], v)
		}
	}
	if raw := read(t, path); !strings.HasPrefix(raw, "# the operator's own seat\nIF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n") {
		t.Fatalf("the file lost its comment or its order:\n%s", raw)
	}
}

// A bad value is refused by the check of the key, with the reason of
// render, and the file stays as it was.
func TestSetSegmentEnvRefusesABadConnectionBudget(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	for _, tc := range []struct{ key, value string }{
		{"CONN_PER_IP", "8"},
		{"CONN_PER_IP", "0128"},
		{"NEW_PER_IP", "50"},
		{"NEW_PER_IP", "50/10"},
		{"CONN_TOTAL", "lots"},
		{"NEW_TOTAL", "50/100"},
	} {
		_, err := c.SetSegmentEnvKeys("desk", map[string]string{tc.key: tc.value})
		if err == nil {
			t.Fatalf("%s=%s was accepted", tc.key, tc.value)
		}
		if !strings.HasPrefix(err.Error(), tc.key+": want 0 or") {
			t.Fatalf("%s=%s: the refusal is not the key's: %v", tc.key, tc.value, err)
		}
		if read(t, path) != before {
			t.Fatalf("%s=%s changed the file", tc.key, tc.value)
		}
	}
}

// A per-device cap above the total of the segment never limits anything.
// The candidate render refuses it with the SEG_ total that the file
// leaves out, as apply does.
func TestSetSegmentEnvRefusesAPerDeviceCapAboveTheInheritedTotal(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"CONN_PER_IP": "8192"}); err == nil || !strings.Contains(err.Error(), "CONN_TOTAL") {
		t.Fatalf("a cap above the 4096 total was not refused: %v", err)
	}
	if read(t, path) != before {
		t.Fatal("the refused edit changed the file")
	}
}

// Empty removes the line. A line that is present and empty reads as 0 in
// render, and 0 turns the limit off. Thus "use the SEG_ value" must be no
// line at all. The other lines stay as they were.
func TestSetSegmentEnvEmptyConnectionBudgetRemovesTheLine(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"CONN_PER_IP": "512", "CONN_TOTAL": "8192"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"CONN_PER_IP": ""}); err != nil {
		t.Fatal(err)
	}
	if raw, want := read(t, path), before+"CONN_TOTAL=8192\n"; raw != want {
		t.Fatalf("empty did not remove only its own line:\n%s\nwant\n%s", raw, want)
	}
	env, err := c.SegmentEnv("desk")
	if err != nil {
		t.Fatal(err)
	}
	if env["CONN_PER_IP"] != "" {
		t.Fatalf("CONN_PER_IP reads back as %q", env["CONN_PER_IP"])
	}
	// Empty on a key that the file does not have is not an error, and
	// writes nothing.
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"NEW_PER_IP": "  "}); err != nil {
		t.Fatal(err)
	}
	if raw := read(t, path); strings.Contains(raw, "NEW_PER_IP") {
		t.Fatalf("an empty value wrote a line:\n%s", raw)
	}
}

func TestSegmentConnInheritedIsTheSEGValueOrTheDefault(t *testing.T) {
	net := map[string]string{"SEG_CONN_PER_IP": "256", "SEG_CONN_TOTAL": "0"}
	for _, tc := range []struct {
		key, want string
		def       bool
	}{
		{"CONN_PER_IP", "256", false},
		{"CONN_TOTAL", "0", false},
		{"NEW_PER_IP", "50/200", true},
		{"NEW_TOTAL", "300/600", true},
	} {
		if v, def := SegmentConnInherited(net, tc.key); v != tc.want || def != tc.def {
			t.Fatalf("%s: %q %v, want %q %v", tc.key, v, def, tc.want, tc.def)
		}
	}
}
