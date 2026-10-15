package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzHarvestRoundTrip: a harvested value either reads back identical from
// secrets.env or is refused; it never changes another row or adds one.
func FuzzHarvestRoundTrip(f *testing.F) {
	f.Add("sk-ant-oat01-newvalue")
	f.Add("with space")
	f.Add("hash#comment")
	f.Add("line\nb0b1b2b3b4b5b6b7_CLAUDE_OAT=injected")
	f.Fuzz(func(t *testing.T, v string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secrets.env")
		slot, other := "a1b2c3d4e5f67890", "b0b1b2b3b4b5b6b7"
		seed := EnvKey(slot, "CLAUDE_OAT") + "=old\n" + EnvKey(other, "CLAUDE_OAT") + "=keep\n"
		if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
			t.Fatal(err)
		}
		st := Open(path)
		err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
			return []Slot{{ID: slot, Kind: "CLAUDE_OAT", Live: v}}, nil
		})
		snap, serr := st.Snapshot()
		if serr != nil {
			t.Fatal(serr)
		}
		if len(snap) != 2 || snap[EnvKey(other, "CLAUDE_OAT")].Live != "keep" {
			t.Fatalf("harvest of %q disturbed other rows: %+v", v, snap)
		}
		got := snap[EnvKey(slot, "CLAUDE_OAT")].Live
		if err != nil {
			if !errors.Is(err, ErrBadLive) {
				t.Fatalf("unexpected error %v", err)
			}
			if got != "old" {
				t.Fatalf("refused harvest of %q still changed the row to %q", v, got)
			}
			return
		}
		if got != v {
			t.Fatalf("harvested %q, read back %q", v, got)
		}
	})
}
