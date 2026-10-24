package tlssni

import (
	"crypto/tls"
	"testing"
)

// BenchmarkParse reads the name from a real ClientHello of crypto/tls (a
// post-quantum key share, so the size of a browser hello).
func BenchmarkParse(b *testing.B) {
	hello := captureClientHello(b, &tls.Config{ServerName: "news.ycombinator.com"})
	if h, need, err := Parse(hello); err != nil || need != 0 || h.ServerName != "news.ycombinator.com" {
		b.Fatalf("parse: %+v %d %v", h, need, err)
	}
	b.SetBytes(int64(len(hello)))
	b.ReportAllocs()
	for b.Loop() {
		Parse(hello)
	}
}
