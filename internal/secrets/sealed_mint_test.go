package secrets

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A mint must seal the row that it writes. Only the process that got
// the passphrase holds the key. A CLI process opens its own Store and
// never gets the key. Thus a mint into a sealed store cannot succeed.
// The refusal must say that in the terms that the operator types. It
// must not leave them with "no passphrase has been entered" and no way
// out. It must also occur before the store is touched, so a locked box
// is never left half-minted.
func TestMintIntoASealedStoreIsRefusedAndNamesTheWayBack(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	locked := Open(path)
	if err := locked.MintAllowed(); !errors.Is(err, ErrSealedMint) {
		t.Fatalf("MintAllowed: %v", err)
	}
	_, err = locked.MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "ghp_x"})
	if !errors.Is(err, ErrSealedMint) {
		t.Fatalf("MintKinds: %v", err)
	}
	// Still the same refusal below, said better: code that already
	// matches on the locked sentinel continues to match.
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("stopped being a locked-store error: %v", err)
	}
	for _, want := range []string{"store is locked", "pf enroll unseal", "pf enroll seal", "pf unlock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal never names %q: %s", want, err)
		}
	}
	// A slot with no value is still a mint. It writes no secret, and that
	// was the argument to let it through. It is refused anyway. If a store
	// refuses one shape of mint and accepts another, the operator must
	// remember that rule.
	if _, err := locked.MintKinds([]string{"GITHUB_TOKEN"}, nil); !errors.Is(err, ErrSealedMint) {
		t.Fatalf("empty-value mint: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("the store was rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// The refusal is on the mint path, not on writes in general. DeleteSlot
// rewrites whole lines and never asks for a value. Thus an operator can
// still delete a slot from a box that nobody has unlocked.
func TestDeleteStillWritesToALockedStore(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	removed, err := Open(path).DeleteSlot(slotA)
	if err != nil {
		t.Fatalf("delete on a locked store: %v", err)
	}
	if len(removed) != 1 || removed[0] != "GITHUB_TOKEN" {
		t.Fatalf("removed %v", removed)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), slotA) {
		t.Fatalf("the slot survived the delete:\n%s", raw)
	}
	if !strings.Contains(string(raw), sealedHeader) {
		t.Fatalf("the delete dropped the sealed header:\n%s", raw)
	}
}
