package alert

import (
	"strings"
	"testing"
)

// FuzzParseWGShow: no output of `wg show` makes ParseWGShow panic. Never
// is true exactly when it found no handshake. A handshake is a positive
// stamp. The endpoint is one token of the endpoints text that has a
// colon, or empty.
func FuzzParseWGShow(f *testing.F) {
	f.Add("PEERKEY=\t1700000000\n", "PEERKEY=\t203.0.113.5:51820\n")
	f.Add("a\t0\nb\t1700000001\nc\t1700000000\n", "a\t(none)\nb\t[2001:db8::1]:51820\nc\t1.2.3.4:1\n")
	f.Add("-5\n9223372036854775807\n\n", "1.2.3.4:5\nk 10.0.0.0/8\n")
	f.Fuzz(func(t *testing.T, latest, endpoints string) {
		st := ParseWGShow(latest, endpoints)
		if st.Never != st.Handshake.IsZero() {
			t.Fatalf("Never=%v with handshake %v", st.Never, st.Handshake)
		}
		if !st.Never && st.Handshake.Unix() <= 0 {
			t.Fatalf("handshake stamp %d", st.Handshake.Unix())
		}
		if st.Endpoint != "" {
			if !strings.Contains(st.Endpoint, ":") || strings.ContainsAny(st.Endpoint, " \t\n\r\v\f") {
				t.Fatalf("endpoint %q", st.Endpoint)
			}
			if !strings.Contains(endpoints, st.Endpoint) {
				t.Fatalf("endpoint %q not in the input", st.Endpoint)
			}
		}
	})
}
