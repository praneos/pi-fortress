package cli

import (
	"bytes"
	"strings"
	"testing"
)

// A misspelled EYEBALL in net.env must not read as off. The broker
// refuses it before it opens a socket or reads a policy file.
func TestBrokerRefusesAnUnknownEyeballMode(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"broker", "-eyeball=block", "-agent-net", "10.77.0.0/24"}, &out, &errb); code == 0 {
		t.Fatal("accepted -eyeball=block")
	}
	if !strings.Contains(errb.String(), "off, audit or refuse") {
		t.Fatalf("stderr: %q", errb.String())
	}
}
