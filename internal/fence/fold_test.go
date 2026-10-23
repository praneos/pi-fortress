package fence

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

// Case-flipped keys. A receiver folds the case back, so a
// flipped prefix is the same key and the rules strip it in any case.
var flipped = map[string]string{
	"akia" + strings.Repeat("x", 16):                 "aws_akia",
	"AkIa" + strings.Repeat("Q7", 8):                 "aws_akia",
	"GHP_" + strings.Repeat("a", 36):                 "github_classic",
	"Ghp_" + strings.Repeat("Ab", 18):                "github_classic",
	"sK-AnT-oAt01-" + strings.Repeat("Zz9_", 6):      "anthropic_oat",
	"SK-ANT-API03-" + strings.Repeat("a", 93) + "aa": "anthropic",
	"aizA" + strings.Repeat("b", 35):                 "google_api",
}

func TestCaseFlippedKeysAreStripped(t *testing.T) {
	ts := benchTokenSet(t)
	for key, rule := range flipped {
		body := []byte(`{"x":"` + key + `","y":1}`)
		if got := ts.rules(body); len(got) != 1 || got[0] != rule {
			t.Errorf("%.16s: rules %v, want %s", key, got, rule)
		}
		if out := ts.replace(body, stripRepl); bytes.Contains(out, []byte(key)) {
			t.Errorf("%.16s: not stripped: %s", key, out)
		}
	}
}

// End to end through Decide: the fence strips a flipped key in a body to a
// foreign host, and does not forward it.
func TestCaseFlippedKeyStrippedByDecide(t *testing.T) {
	key := "GhP_" + strings.Repeat("k", 36)
	body := `{"t":"` + key + `"}`
	raw := fmt.Sprintf("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	req := decide(t, "example.com", raw)
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), key) {
		t.Fatalf("flipped key forwarded:\n%s", out.String())
	}
}

// The fold is ASCII only. A Kelvin sign for the K or a long s for the s is
// an encoding, like base32. A match on it would put multi-byte runes in
// the rules and split the prefilter from the regexp.
func TestFoldIsASCIIOnly(t *testing.T) {
	re := mustRE(t)
	for _, s := range []string{
		"AKIA" + strings.Repeat("X", 16),
		"ſk-ant-oat01-" + strings.Repeat("a", 30),
		"AKIA" + strings.Repeat("K", 16),
	} {
		if re.MatchString(" " + s + " ") {
			t.Errorf("%q matched", s)
		}
	}
	ts := benchTokenSet(t)
	if !ts.fold || !ts.complete || !ts.bounded {
		t.Fatalf("fold=%v complete=%v bounded=%v", ts.fold, ts.complete, ts.bounded)
	}
	for _, p := range ts.prefixes {
		if !bytes.Equal(p, bytes.ToLower(p)) {
			t.Errorf("prefix %q is not lower case", p)
		}
	}
}

// The scan finds a placeholder in any letter case. Only the spelling of
// the gateway is exact, and only an exact placeholder gets a live value.
func TestPlaceholderStaysExact(t *testing.T) {
	for in, exact := range map[string]bool{
		"pf_0123456789abcdef_GITHUB_TOKEN":  true,
		"pf_0123456789ABCDEF_GITHUB_TOKEN":  true,
		"PF_0123456789abcdef_GITHUB_TOKEN":  false,
		"pf_0123456789abcdef_github_token":  false,
		"pf_0123456789abcdef_GITHUB_TOKENx": false,
	} {
		b := []byte(in)
		sp := secrets.FindPlaceholderSpans(b)
		if len(sp) != 1 || sp[0] != [2]int{0, len(b)} {
			t.Fatalf("%s: spans %v", in, sp)
		}
		if secrets.PlaceholderExact(b, sp[0]) != exact {
			t.Fatalf("%s: exact %v", in, !exact)
		}
	}
}

// indexFold is bytes.Index over a lowered copy, without the copy.
func TestIndexFoldMatchesLoweredIndex(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	const al = "aAkKsSiI_-0189xX "
	needles := []string{"akia", "ghp_", "sk-ant-api03-", "_", "k", "x-0"}
	for range 5000 {
		b := make([]byte, r.Intn(40))
		for i := range b {
			b[i] = al[r.Intn(len(al))]
		}
		for _, n := range needles {
			want := bytes.Index(bytes.ToLower(b), []byte(n))
			if got := indexFold(b, []byte(n)); got != want {
				t.Fatalf("indexFold(%q, %q) = %d, want %d", b, n, got, want)
			}
		}
	}
}

// The prefilter and the whole-text regexp agree on mixed-case text.
// FuzzTokenWindows checks this property for the exact rules.
func TestFoldedWindowsMatchWholeTextRegexp(t *testing.T) {
	re := mustRE(t)
	ts := tokensFor(re)
	r := rand.New(rand.NewSource(11))
	var keys []string
	for k := range flipped {
		keys = append(keys, k)
	}
	for range 2000 {
		var sb strings.Builder
		for range 1 + r.Intn(4) {
			sb.WriteString(string(body(r.Intn(60), r.Int63())))
			k := []byte(keys[r.Intn(len(keys))])
			for i := range k {
				if r.Intn(3) == 0 {
					k[i] ^= 0x20 * byte(r.Intn(2)) * boolByte(k[i]|0x20 >= 'a' && k[i]|0x20 <= 'z')
				}
			}
			if r.Intn(4) == 0 {
				k = k[:r.Intn(len(k))]
			}
			sb.Write(k)
		}
		s := sb.String()
		want := re.FindAllIndex([]byte(s), -1)
		got := ts.matches([]byte(s))
		if len(got) != len(want) {
			t.Fatalf("%q: %d matches, regexp %d", s, len(got), len(want))
		}
		for i := range got {
			if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
				t.Fatalf("%q: %v vs %v", s, got[i][:2], want[i])
			}
		}
	}
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
