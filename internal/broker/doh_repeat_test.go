package broker

import (
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/preamble"
)

// A header field can repeat, and the origin reads each copy. The
// classifier got only the first copy. Thus an agent could put a harmless
// value in the first Content-Type and the real DoH type in a second. It
// could then reach a resolver that the fence never saw. The path here is
// innocuous on purpose: only the media type shows what this request is.
func TestRepeatedContentTypeIsStillDoH(t *testing.T) {
	b, _ := testBroker(t)
	var forwarded int32
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&forwarded, 1)
	})
	p := preamble.Preamble{
		SNI:     "dns.google",
		OrigDst: netip.MustParseAddrPort("8.8.8.8:443"),
		Src:     netip.MustParseAddrPort("10.77.0.10:51000"),
	}
	got := roundtrip(t, b, p, "POST /upload HTTP/1.1\r\nHost: dns.google\r\n"+
		"Content-Type: text/plain\r\nContent-Type: application/dns-message\r\n"+
		"Content-Length: 0\r\n\r\n")
	if !strings.Contains(got, "dns_pin") {
		t.Fatalf("a repeated Content-Type carrying the DoH type was not refused: %q", got)
	}
	if atomic.LoadInt32(&forwarded) != 0 {
		t.Fatal("doh query forwarded to origin")
	}
}
