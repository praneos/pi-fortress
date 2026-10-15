package base

import "testing"

// The shell removes one layer of quotes. It does not remove all quote
// characters at the two ends.
func TestParseEnvStripsOneLayerOnly(t *testing.T) {
	got := ParseEnv([]byte("NESTED=\"'x'\"\nBARE=\"\nMISMATCH=\"x'\n"))
	for k, want := range map[string]string{"NESTED": "'x'", "BARE": "\"", "MISMATCH": "\"x'"} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}
