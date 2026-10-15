package admin

import (
	"testing"

	"pi-fortress/internal/dnslog"
)

func TestPrintableCutsToASCII(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"api.example":           "api.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"a\u009b2Jb.example":    "a?2Jb.example",
		"a\u009d0;x\u0007.test": "a?0;x?.test",
		"‮gnp.exe.test":         "?gnp.exe.test",
		"\x1b[2Jx\r\n.test":     "?[2Jx??.test",
		"wide中.test":            "wide?.test",
		"zw​j.test":             "zw?j.test",
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}

// A device picks the names that it queries. Thus a C1 CSI or a bidi
// override in a name must not reach the terminal of the operator through
// the log screen. This applies to a resolver row and to a passed-through
// dnsmasq line.
func TestReadableDNSNeverPassesTerminalControls(t *testing.T) {
	in := []string{
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:00Z", Src: "10.78.0.5", Name: "x\u009b31m.test", QType: "A", Act: dnslog.ActResolved, Answer: "1.2.3.4"}),
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:01Z", Src: "10.78.0.5", Name: "‮gnp.test", QType: "A", Act: dnslog.ActBlocked}),
		"Sep 18 dnsmasq[9]: query[A] y\u009d0;t\u0007.test from 10.78.0.5",
	}
	want := []string{
		"2026-09-18T10:00:00Z 10.78.0.5 A x?31m.test resolved 1.2.3.4",
		"2026-09-18T10:00:01Z 10.78.0.5 A ?gnp.test blocked",
		"Sep 18 dnsmasq[9]: query[A] y?0;t?.test from 10.78.0.5",
	}
	got := readableDNS(in)
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %q want %q", i, got[i], want[i])
		}
	}
}
