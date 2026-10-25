package www

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each field that ClaimScript writes into the script must match its
// grammar. A claim with a field outside the grammar gets the same answer
// as an unknown code.
func TestRedeemRefusesFieldsOutsideTheGrammar(t *testing.T) {
	s, _ := testServer(t)
	claims, good := issueTestClaim(t, s)
	cases := map[string]func(*Claim){
		"good":         func(*Claim) {},
		"slot quote":   func(c *Claim) { c.Slot = "a1b2c3d4e5f67890'; id; '" },
		"slot short":   func(c *Claim) { c.Slot = "a1b2c3" },
		"slot space":   func(c *Claim) { c.Slot = " a1b2c3d4e5f67890" },
		"slot upper":   func(c *Claim) { c.Slot = "A1B2C3D4E5F67890" },
		"kind heredoc": func(c *Claim) { c.Kinds = []string{"X\nPFEOF\nid\ncat <<'PFEOF'"} },
		"kind semi":    func(c *Claim) { c.Kinds = []string{"X; id"} },
		"kind lower":   func(c *Claim) { c.Kinds = []string{"github_token"} },
		"kind empty":   func(c *Claim) { c.Kinds = []string{""} },
		"sha quote":    func(c *Claim) { c.CASHA256 = "x'; id; '" },
		"sha setup":    func(c *Claim) { c.SetupSHA256 = "x\"; id; \"" },
	}
	for name, edit := range cases {
		code, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		c := good
		c.Code, c.Issued, c.Expires = code, now, now.Add(time.Minute)
		c.Kinds = append([]string(nil), good.Kinds...)
		edit(&c)
		raw, _ := json.Marshal(c)
		if err := os.WriteFile(filepath.Join(claims, code+".json"), raw, 0640); err != nil {
			t.Fatal(err)
		}
		_, err = RedeemClaim(claims, code)
		if name == "good" {
			if err != nil {
				t.Fatalf("good claim refused: %v", err)
			}
			continue
		}
		if err != ErrNoClaim {
			t.Errorf("%s: redeemed, want ErrNoClaim", name)
		}
	}
}

// ClaimScript does not write a field outside the grammar into the
// script, also when a caller gives it one directly. The script then
// stops.
func TestClaimScriptRefusesFieldsOutsideTheGrammar(t *testing.T) {
	const marker = "echo claim-field-marker"
	base := Claim{Code: "ABCDEFGH", Slot: "a1b2c3d4e5f67890", Kinds: []string{"GITHUB_TOKEN"},
		GitHosts: []string{"github.com"}, SetupSHA256: strings.Repeat("cd", 32), CASHA256: strings.Repeat("ab", 32)}
	if !validCode(base.Code) {
		t.Fatalf("test code %q is not a valid code", base.Code)
	}
	type tc struct {
		pi string
		c  Claim
	}
	slot, kind, ca := base, base, base
	slot.Slot = "a1b2c3d4e5f67890'; " + marker + "; '"
	kind.Kinds = []string{"X\nPFEOF\n" + marker + "\ncat >/dev/null <<'PFEOF'"}
	ca.CASHA256 = "x' ; " + marker + "; '"
	for name, x := range map[string]tc{
		"slot": {"10.77.0.1", slot},
		"kind": {"10.77.0.1", kind},
		"ca":   {"10.77.0.1", ca},
		"pi":   {"10.77.0.1'; " + marker + "; '", base},
	} {
		body := ClaimScript(x.pi, x.c)
		if strings.Contains(body, marker) {
			t.Errorf("%s: field outside the grammar in the script:\n%s", name, body)
		}
		if !strings.Contains(body, "exit 1") {
			t.Errorf("%s: script does not stop", name)
		}
	}
	if body := ClaimScript("10.77.0.1", base); !strings.Contains(body, "export GITHUB_TOKEN='pf_a1b2c3d4e5f67890_GITHUB_TOKEN'") {
		t.Fatalf("good claim not enrolled:\n%s", body)
	}
}

// filesByDir gives each directory under root, with the names in it.
func filesByDir(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if out[p] == nil {
				out[p] = map[string]bool{}
			}
			return nil
		}
		dir := filepath.Dir(p)
		if out[dir] == nil {
			out[dir] = map[string]bool{}
		}
		out[dir][filepath.Base(p)] = true
		return nil
	})
	return out
}

// The redeem side (www) can create files only in the directories that it
// writes during a redeem. Only a claim that root issued gives an enrol
// script: a claim file in one of those directories never redeems. The
// test finds those directories from one redeem of an issued claim, so it
// does not depend on the layout.
func TestClaimFileInARedeemWrittenDirectoryNeverRedeems(t *testing.T) {
	s, ts := testServer(t)
	_, issued := issueTestClaim(t, s)
	before := filesByDir(t, s.Dir)
	if code, _ := get(t, ts.URL+"/claim/"+issued.Code); code != 200 {
		t.Fatalf("the issued claim did not redeem: %d", code)
	}
	after := filesByDir(t, s.Dir)
	var written []string
	for dir, names := range after {
		for n := range names {
			if !before[dir][n] {
				written = append(written, dir)
				break
			}
		}
	}
	if len(written) == 0 {
		t.Fatal("the redeem wrote no file; nothing to check")
	}

	for _, dir := range written {
		code, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		c := Claim{Code: code, Slot: "a1b2c3d4e5f67890", Kinds: []string{"GITHUB_TOKEN"}, Issued: now, Expires: now.Add(ClaimTTL),
			SetupSHA256: issued.SetupSHA256, CASHA256: issued.CASHA256}
		raw, _ := json.Marshal(c)
		for _, name := range []string{code + ".json", code, code + ".redeemed"} {
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0640); err != nil {
				t.Fatal(err)
			}
		}
		status, body := get(t, ts.URL+"/claim/"+code)
		if status != 404 || strings.Contains(body, "enrolled slot") {
			t.Fatalf("a claim file in %s, a directory that the redeem writes, redeemed: %d\n%s", dir, status, body)
		}
	}
}
