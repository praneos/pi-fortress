package tui

import (
	"os"
	"strings"
	"testing"
)

// A text prompt opens on the current value of the key. Enter keeps it, an
// emptied prompt cancels, and "-" is the one way to clear. Before, an empty
// submit saved "" and cleared HOUSE_ADMIN_IP, SSH_TO or WG_IF.
func TestTextPromptOpensOnTheValueAndEmptyCancels(t *testing.T) {
	c, _ := testConfig(t)
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	open := func() *Fake { return NewFake(100, 40).Type(settingsDown("HOUSE_ADMIN_IP")).Press(KeyEnter) }
	f := NewFake(100, 40).Type(settingsDown("HOUSE_ADMIN_IP")).Press(KeyEnter)
	last := run(t, c, f).Last()
	if !strings.Contains(last, "HOUSE_ADMIN_IP (- clears): 10.78.0.5_") {
		t.Fatalf("the prompt does not open on the value:\n%s", last)
	}
	erase := make([]KeyKind, len("10.78.0.5"))
	for i := range erase {
		erase[i] = KeyBackspace
	}
	for _, f := range []*Fake{open().Press(KeyEnter), open().Press(erase...).Press(KeyEnter)} {
		run(t, c, f)
		if got, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(got), "HOUSE_ADMIN_IP=10.78.0.5\n") {
			t.Fatalf("Enter changed the key:\n%s", got)
		}
	}
	f = run(t, c, open().Press(erase...).Press(KeyEnter))
	if !strings.Contains(f.Last(), "cancelled") {
		t.Fatalf("an emptied prompt did not say it cancelled:\n%s", f.Last())
	}
	run(t, c, open().Press(erase...).Type("10.78.0.6").Press(KeyEnter))
	if got, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(got), "HOUSE_ADMIN_IP=10.78.0.6\n") {
		t.Fatalf("a new value was not saved:\n%s", got)
	}
	run(t, c, open().Press(erase...).Type("-").Press(KeyEnter))
	if got, _ := os.ReadFile(c.HouseEnv); strings.Contains(string(got), "10.78.0.6") {
		t.Fatalf("- did not clear the key:\n%s", got)
	}
}

// The SSH_TO of the desk is the segment half of the same prompt.
func TestSegmentTextPromptEmptyCancels(t *testing.T) {
	c, path := segSettings(t)
	body := "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nSSH_TO=10.77.0.10\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	erase := make([]KeyKind, len("10.77.0.10"))
	for i := range erase {
		erase[i] = KeyBackspace
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("SSH_TO")).Press(KeyEnter).Press(erase...).Press(KeyEnter))
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Fatalf("an emptied prompt rewrote the segment:\n%s", got)
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("SSH_TO")).Press(KeyEnter).Press(erase...).Type("-").Press(KeyEnter))
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "SSH_TO=10.77.0.10") {
		t.Fatalf("- did not clear SSH_TO:\n%s", got)
	}
}
