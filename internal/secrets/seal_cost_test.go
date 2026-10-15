package secrets

import (
	"errors"
	"strings"
	"testing"
)

// The header is plaintext, and it is on the card. Anyone who can rewrite
// the store can rewrite its KDF parameters. Unlock must derive the key
// before the canary can say that the header was ever ours. Thus an
// unauthenticated file can demand the work that the header asks for. At
// N=1<<24 and r=8, that is sixteen gigabytes of scrypt on a gateway with
// far less. That is the box down, not a wrong passphrase.
func TestParseHeaderRefusesRuinousKDFParameters(t *testing.T) {
	sealer, err := NewHeader([]byte("a passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	base := sealer.Header()
	if _, err := ParseHeader(base.String()); err != nil {
		t.Fatalf("the default header no longer parses: %v", err)
	}
	for _, c := range []struct{ name, field, value string }{
		{"memory", "N=32768", "N=16777216"},
		{"block size", "r=8", "r=4096"},
		{"parallelism", "p=1", "p=65536"},
	} {
		t.Run(c.name, func(t *testing.T) {
			line := strings.Replace(base.String(), c.field, c.value, 1)
			if line == base.String() {
				t.Fatalf("header does not contain %q: %s", c.field, line)
			}
			if _, err := ParseHeader(line); !errors.Is(err, ErrSealedHeader) {
				t.Fatalf("ParseHeader accepted %s: err %v", c.value, err)
			}
		})
	}
}
