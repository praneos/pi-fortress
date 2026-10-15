package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireSpansHarvestHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "b0b1b2b3b4b5b6b7"
	if err := os.WriteFile(path, []byte(EnvKey(slot, "CLAUDE_ORT")+"=sk-ant-ort01-old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	if !st.Acquire(slot) {
		t.Fatal("first acquire refused")
	}
	if st.Acquire("B0B1B2B3B4B5B6B7") {
		t.Fatal("second acquire of a held slot succeeded")
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !snap[EnvKey(slot, "CLAUDE_ORT")].Busy {
		t.Fatal("held slot not busy in snapshot")
	}
	if err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) { return cur, nil }); err != ErrBusy {
		t.Fatalf("Harvest on a held slot: %v", err)
	}
	err = st.HarvestHeld(slot, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slot, Kind: "CLAUDE_ORT", Live: "sk-ant-ort01-new"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st.Release(slot)
	snap, err = st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if sl := snap[EnvKey(slot, "CLAUDE_ORT")]; sl.Busy || sl.Live != "sk-ant-ort01-new" {
		t.Fatalf("%+v", sl)
	}
	if !st.Acquire(slot) {
		t.Fatal("acquire after release refused")
	}
	st.Release(slot)
}
