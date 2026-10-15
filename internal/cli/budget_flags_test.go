package cli

import (
	"bytes"
	"strings"
	"testing"
)

// A negative threshold is a typo in net.env. If the broker reads it as
// "off", the operator thinks that a limit is armed. The broker
// refuses it before it opens a socket or reads a policy file.
func TestBrokerRefusesANegativeBudget(t *testing.T) {
	for _, flag := range []string{
		"-slot-warn-requests=-1",
		"-slot-stop-requests=-1",
		"-slot-warn-upload-mb=-1",
		"-slot-stop-upload-mb=-1",
	} {
		t.Run(flag, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := Main([]string{"broker", flag, "-agent-net", "10.77.0.0/24"}, &out, &errb); code == 0 {
				t.Fatalf("accepted %s", flag)
			}
			if !strings.Contains(errb.String(), "not a count") {
				t.Fatalf("stderr for %s: %q", flag, errb.String())
			}
		})
	}
}
