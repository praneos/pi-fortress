package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestFlagsAfterVerbAreHonoured pins the half that the operator sees.
// Before, flag.Parse discarded a flag typed after the subcommand, because
// it stops at the first word that is not a flag. pf then ran with the
// default and reported on a directory that the operator had just said
// not to use.
func TestFlagsAfterVerbAreHonoured(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	code := runMonitor([]string{"show", "-dir", dir, "-n", "3"}, io.Discard, &stderr)
	if got := stderr.String(); !strings.Contains(got, dir) {
		t.Fatalf("pf monitor show -dir %s read somewhere else (code %d); stderr = %q", dir, code, got)
	}
}

// TestSurplusArgsRefused covers the other half. A word that no verb takes
// is a typo. If the verb runs anyway, it tells the operator that their
// argument was accepted. -h after the verb is the same mistake from the
// other side: it must print the help, not run the command.
func TestSurplusArgsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(args []string, stdout, stderr io.Writer) int
		args []string
		code int
		want string
	}{
		{"monitor typo", runMonitor, []string{"show", "bogus"}, 2, "bogus"},
		{"observe typo", runObserve, []string{"show", "bogus"}, 2, "bogus"},
		{"alert typo", runAlert, []string{"show", "bogus"}, 2, "bogus"},
		{"monitor help after verb", runMonitor, []string{"show", "-h"}, 0, "-interval"},
		{"observe help after verb", runObserve, []string{"show", "-h"}, 0, "-interval"},
		{"alert help after verb", runAlert, []string{"show", "-h"}, 0, "-strip"},
		{"fetch typo", runFetch, []string{"bogus"}, 2, "bogus"},
		{"compile typo", runCompile, []string{"bogus"}, 2, "bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := tc.run(tc.args, io.Discard, &stderr)
			got := stderr.String()
			if code != tc.code || !strings.Contains(got, tc.want) {
				t.Fatalf("code = %d want %d; stderr = %q want it to mention %q", code, tc.code, got, tc.want)
			}
		})
	}
}
