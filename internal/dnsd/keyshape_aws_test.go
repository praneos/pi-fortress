package dnsd

import (
	"strings"
	"testing"
)

// Names are case-insensitive, so the AWS rules apply in any case. In a
// case other than upper case, they apply only at the exact length of an
// AWS key id. An ordinary name that starts with asia or akia and continues
// resolves. A key in a label is refused in any spelling.
func TestAWSShapesOnNames(t *testing.T) {
	k := mustKeyShapes(t)
	body := strings.Repeat("Q7", 8)
	for _, name := range []string{
		"asiapacificcommunications.com", "www.asiapacificcommunications.com.",
		"asiapacificsoutheastregion.example.com", "asianfoodnetworkrecipes.example",
		"cdn.akiapolaawlongnamehere.example.net", "trustasiasha384intermediate.example",
		"asiakuecheerlangen.de",
	} {
		if got := k.match(name); got != "" {
			t.Errorf("%q matched %q", name, got)
		}
	}
	for name, want := range map[string]string{
		"akia" + strings.ToLower(body) + ".evil.example":                                           "aws_akia",
		"AKIA" + body + ".evil.example":                                                            "aws_akia",
		"x.AKIA" + body + "Q7Q7.evil.example":                                                      "aws_akia",
		"asia" + strings.ToLower(body) + ".evil.example":                                           "aws_asia",
		"tun.akia" + strings.ToLower(body[:8]) + "." + strings.ToLower(body[8:]) + ".evil.example": "aws_akia",
	} {
		if got := k.match(name); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}

// The leads of the other rules and their missing \b change nothing that a
// name can carry. A label holds no escape. A distinctive prefix in a label
// is a key, whatever comes before it in the run.
func TestDistinctivePrefixAnywhereInARun(t *testing.T) {
	k := mustKeyShapes(t)
	a := strings.Repeat("A", 36)
	if got := k.match("xyzghp_" + a + ".evil.example"); got != "github_classic" {
		t.Errorf("a glued ghp_ key: %q", got)
	}
	for _, name := range []string{"task-" + strings.Repeat("a1", 30) + ".example.com", "kiosk-admin-" + strings.Repeat("b2", 25) + ".example.com"} {
		if got := k.match(name); got != "" {
			t.Errorf("%q matched %q", name, got)
		}
	}
}
