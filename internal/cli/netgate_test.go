package cli

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetgateVerbs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, netgateUsage},
		{[]string{"bogus"}, 2, netgateUsage},
		{[]string{"ping", "bogus"}, 2, "bogus"},
		{[]string{"run", "-config", filepath.Join(t.TempDir(), "missing.json")}, 1, "missing.json"},
	} {
		var stderr bytes.Buffer
		code := runNetgate(tc.args, io.Discard, &stderr)
		if code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("pf netgate %q: code %d, stderr %q; want %d and %q", tc.args, code, stderr.String(), tc.code, tc.want)
		}
	}
}
