package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sealTestStore(t *testing.T, body string) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Open(path), path
}

const (
	slotA = "a1b2c3d4e5f67890"
	slotB = "b0b1b2b3b4b5b6b7"
	liveA = "lab_fence_github"
	liveB = "sk-ant-oat01-aaaaaaaa"
)

func plainBody() string {
	return "# operator note\n" +
		EnvKey(slotA, "GITHUB_TOKEN") + "=" + liveA + "\n" +
		EnvKey(slotB, "CLAUDE_OAT") + "=" + liveB + "\n" +
		EnvKey(slotB, "CLAUDE_ORT") + "=\n"
}

func TestSealRoundTrip(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, live := range []string{liveA, liveB} {
		if strings.Contains(string(raw), live) {
			t.Fatalf("a value survived in the clear:\n%s", raw)
		}
	}
	if !strings.Contains(string(raw), "# operator note") {
		t.Fatalf("a comment was dropped:\n%s", raw)
	}

	// The inventory stays readable with no key: which slots exist, what
	// kinds, and that they wait. That makes a sealed box
	// diagnosable.
	locked := Open(path)
	snap, err := locked.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 3 {
		t.Fatalf("inventory %+v", snap)
	}
	for k, sl := range snap {
		if sl.Live != "" || !sl.Sealed {
			t.Fatalf("%s: %+v", k, sl)
		}
	}
	if st, _ := locked.State(); !st.Sealed || st.Unlocked || st.Fault != "" {
		t.Fatalf("%+v", st)
	}

	if err := locked.Unlock([]byte("wrong horse")); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := locked.Unlock([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	snap, err = locked.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap[EnvKey(slotA, "GITHUB_TOKEN")].Live != liveA || snap[EnvKey(slotB, "CLAUDE_OAT")].Live != liveB {
		t.Fatalf("%+v", snap)
	}
	if got := snap[EnvKey(slotB, "CLAUDE_ORT")]; got.Live != "" || !got.Sealed {
		t.Fatalf("an empty slot is not a sealed value: %+v", got)
	}

	if err := locked.Unseal([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), liveA) || strings.Contains(string(raw), sealedHeader) {
		t.Fatalf("unseal:\n%s", raw)
	}
}

// The first of the two properties that make a sealed file safe in front
// of a build that is older than sealing: the encoding must fail
// ValidLive. Thus such a build discards the value, and the slot reads
// empty. Base64 alone would pass, and go into live traffic as a token.
func TestSealedValueFailsValidLive(t *testing.T) {
	sealer, err := NewHeader([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	v := sealer.Seal(EnvKey(slotA, "GITHUB_TOKEN"), liveA)
	if ValidLive(v) {
		t.Fatalf("an old build would have injected %q", v)
	}
	if !strings.HasPrefix(v, "#") {
		t.Fatalf("an old build cuts at '#'; %q does not start with one", v)
	}
}

// The second: '#' is a comment to each older reader, so the header
// alone protects nothing. A build that does understand sealing must
// refuse a version that it does not know. It must not read the values
// under it as if they were plain.
func TestUnknownSealedVersionIsRefused(t *testing.T) {
	body := "#pf-sealed v9 scrypt N=32768 r=8 p=1 salt=AAAAAAAAAAAAAAAAAAAAAA canary=AAAA\n" +
		EnvKey(slotA, "GITHUB_TOKEN") + "=" + liveA + "\n"
	s, _ := sealTestStore(t, body)
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got := snap[EnvKey(slotA, "GITHUB_TOKEN")]; got.Live != "" || !got.Sealed {
		t.Fatalf("a value under an unknown version was read: %+v", got)
	}
	st, _ := s.State()
	if !st.Sealed || st.Unlocked || !strings.Contains(st.Fault, "unsupported sealed format version") {
		t.Fatalf("%+v", st)
	}
}

// The whole-file rule exists to prevent this downgrade. It must make the
// whole store fail. It must not leave one usable plaintext value under a
// header that still says sealed.
func TestPlaintextInSealedFileFailsTheStoreShut(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, EnvKey(slotA, "GITHUB_TOKEN")+"=") {
			line = EnvKey(slotA, "GITHUB_TOKEN") + "=" + liveA
		}
		out = append(out, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0600); err != nil {
		t.Fatal(err)
	}

	tampered := Open(path)
	if err := tampered.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	snap, err := tampered.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for k, sl := range snap {
		if sl.Live != "" || !sl.Sealed {
			t.Fatalf("%s stayed usable: %+v", k, sl)
		}
	}
	st, _ := tampered.State()
	if st.Unlocked || !strings.Contains(st.Fault, "plaintext value") {
		t.Fatalf("%+v", st)
	}
}

// A ciphertext carries the slot and kind that it was written for. Thus a
// ciphertext moved to the line of another slot fails to open. That slot
// does not answer with the credential of another slot.
func TestSealedValueIsBoundToItsSlot(t *testing.T) {
	sealer, err := NewHeader([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	v := sealer.Seal(EnvKey(slotA, "GITHUB_TOKEN"), liveA)
	if _, err := sealer.Unseal(EnvKey(slotB, "GITHUB_TOKEN"), v); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("moved ciphertext opened: %v", err)
	}
	got, err := sealer.Unseal(EnvKey(slotA, "GITHUB_TOKEN"), v)
	if err != nil || got != liveA {
		t.Fatalf("%q %v", got, err)
	}
}

// A removal of the header does not downgrade the store either. The
// values still start with '#', so they read as comments, and each slot
// reads empty. Both directions fail shut.
func TestHeaderRemovalFailsShut(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !isSealedHeader(line) {
			out = append(out, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	snap, err := Open(path).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for k, sl := range snap {
		if sl.Live != "" {
			t.Fatalf("%s: %+v", k, sl)
		}
	}
}

// Before, sealing copied a legacy unslotted row through with no change.
// Thus a token older than the slot model stayed in the clear inside the
// artifact that goes onto a backup or an appliance image. Nothing else
// saw it, because the running store ignores an unslotted row. The broker
// could not see it, and anyone with the card could read it.
func TestSealRefusesLegacyUnslottedSecret(t *testing.T) {
	const legacy = "sk-ant-oat01-never-migrated"
	s, path := sealTestStore(t, plainBody()+"CLAUDE_OAT="+legacy+"\n")

	err := s.Seal([]byte("pw"))
	if err == nil {
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), legacy) {
			t.Fatalf("a live credential rode into the sealed artifact in the clear:\n%s", raw)
		}
		t.Fatal("sealing an unmigrated store reported success")
	}
	if !errors.Is(err, ErrLegacyUnslotted) {
		t.Fatalf("%v", err)
	}
	// The operator must know which row to move. An error that only says
	// "migrate" makes them grep a file that they cannot read.
	if !strings.Contains(err.Error(), "CLAUDE_OAT") {
		t.Fatalf("the error does not name the row: %v", err)
	}
	// A refusal is better than a discard. The value may be the only copy of
	// a credential still in use. Thus it stays exactly where the operator
	// left it, and the file is not rewritten at all.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), legacy) || strings.Contains(string(raw), sealedHeader) {
		t.Fatalf("the refused seal touched the file:\n%s", raw)
	}
}

// An unslotted row with nothing after the '=' is a leftover name, not a
// credential. Thus it must not stand between an operator and a sealed
// store.
func TestSealAllowsEmptyLegacyRow(t *testing.T) {
	s, path := sealTestStore(t, plainBody()+"CLAUDE_OAT=\n")
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), sealedHeader) {
		t.Fatalf("an empty legacy row blocked sealing:\n%s", raw)
	}
}

// The order that apply already uses (migrate, then seal) must continue
// to work. If not, the fix only moves the operator from a silent leak to
// a store that they can never seal.
func TestMigrateThenSealLeavesNoPlaintext(t *testing.T) {
	const legacy = "sk-ant-oat01-was-unslotted"
	s, path := sealTestStore(t, plainBody()+"CLAUDE_OAT="+legacy+"\n")
	moved, err := s.MigrateUnslotted()
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 1 || moved[0].Old != "CLAUDE_OAT" {
		t.Fatalf("%+v", moved)
	}
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, live := range []string{legacy, liveA, liveB} {
		if strings.Contains(string(raw), live) {
			t.Fatalf("a value survived in the clear:\n%s", raw)
		}
	}
	if err := s.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sl := range snap {
		if sl.Live == legacy {
			found = true
		}
	}
	if !found {
		t.Fatalf("the migrated credential did not survive sealing: %+v", snap)
	}
}

// A write with no key would have to write plaintext, so it does not
// occur at all.
func TestSealedStoreRefusesToWriteLocked(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	locked := Open(path)
	err := locked.Harvest(slotB, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slotB, Kind: "CLAUDE_OAT", Live: "sk-ant-oat01-zzzz"}}, nil
	})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("%v", err)
	}
}

// Unlocked, a harvest re-seals what it writes.
func TestHarvestResealsOnWrite(t *testing.T) {
	s, path := sealTestStore(t, plainBody())
	if err := s.Seal([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	next := "sk-ant-oat01-" + strings.Repeat("z", 20)
	if err := s.Harvest(slotB, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slotB, Kind: "CLAUDE_OAT", Live: next}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), next) {
		t.Fatalf("harvest wrote in the clear:\n%s", raw)
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap[EnvKey(slotB, "CLAUDE_OAT")].Live != next {
		t.Fatalf("%+v", snap[EnvKey(slotB, "CLAUDE_OAT")])
	}
	if st, _ := s.State(); st.Fault != "" {
		t.Fatalf("%+v", st)
	}
}

// Sealing copies comments and other non-slot lines as they are. Thus it
// refuses a line that carries a credential: a rotated token kept as a
// comment, a stray value with no key, a row that no slot claims, the
// note after a value. The error names the lines by number and never
// echoes their text. The file stays exactly as it was.
func TestSealRefusesSecretShapedClearLines(t *testing.T) {
	old := "ghp_" + strings.Repeat("Q7", 18)
	for _, tc := range []struct {
		name, line, want string
		err              error
	}{
		{"rotated token in a comment", "# " + EnvKey(slotA, "GITHUB_TOKEN") + "=" + old, "line 2", ErrPlainSecretLine},
		{"bare value", old, "line 2", ErrPlainSecretLine},
		// The unslotted-row refusal reads the note as the value of the row and
		// names the key. In both cases, nothing is sealed through.
		{"unslotted empty row with a note", "OPENAI_API_KEY= # was " + old, "OPENAI_API_KEY", ErrLegacyUnslotted},
		{"note after a slot value", EnvKey(slotA, "OPENAI_API_KEY") + "=fresh_value_x # old " + old, "line 2", ErrPlainSecretLine},
		{"long run of an unknown shape", "# backup: Zx9_k2LmQ0pRt7vWy4aB", "line 2", ErrPlainSecretLine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "# operator note\n" + tc.line + "\n" + EnvKey(slotB, "CLAUDE_OAT") + "=" + liveB + "\n"
			s, path := sealTestStore(t, body)
			err := s.Seal([]byte("correct horse"))
			if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
			if strings.Contains(err.Error(), old) || strings.Contains(err.Error(), "Zx9_") {
				t.Fatalf("the error echoes the value: %v", err)
			}
			raw, _ := os.ReadFile(path)
			if string(raw) != body {
				t.Fatalf("the file changed:\n%s", raw)
			}
		})
	}
}

// What the refusal must not change: prose comments, and the header at
// the start of the shipped example file.
func TestSealKeepsOrdinaryComments(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "vm", "policy", "secrets.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(example) + "# rotated the github token on 2026-10-01, see the runbook\n" + plainBody()
	s, path := sealTestStore(t, body)
	if err := s.Seal([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "# rotated the github token") || strings.Contains(string(raw), liveA) {
		t.Fatalf("sealed:\n%s", raw)
	}
}

// loadFile cuts a line at its first '#'. Thus KEY=value # note is a
// slot that works. Sealing reads it the same way: it seals only the
// value, and keeps the note on a separate line above it.
func TestSealCutsAnInlineComment(t *testing.T) {
	body := EnvKey(slotA, "GITHUB_TOKEN") + "=" + liveA + " # the lab token\n" +
		EnvKey(slotB, "CLAUDE_ORT") + "= # waiting for a mint\n"
	s, path := sealTestStore(t, body)
	if err := s.Seal([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), liveA) || !strings.Contains(string(raw), "# the lab token\n"+EnvKey(slotA, "GITHUB_TOKEN")+"=#pf1.") ||
		!strings.Contains(string(raw), "# waiting for a mint\n"+EnvKey(slotB, "CLAUDE_ORT")+"=\n") {
		t.Fatalf("sealed:\n%s", raw)
	}
	locked := Open(path)
	if err := locked.Unlock([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	snap, err := locked.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := locked.State(); st.Fault != "" {
		t.Fatalf("fault %q", st.Fault)
	}
	if got := snap[EnvKey(slotA, "GITHUB_TOKEN")].Live; got != liveA {
		t.Fatalf("live %q", got)
	}
}
