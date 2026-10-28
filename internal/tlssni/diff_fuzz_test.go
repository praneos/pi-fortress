package tlssni

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/hello"
)

// clientHello is the first flight that crypto/tls sends for name: a real
// ClientHello, with its record header.
func clientHello(t testing.TB, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64<<10)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// FuzzSNIAgree: the house SNI check (this package) and the agent fence
// (internal/hello) parse ClientHellos separately. Their return values are
// different intentionally. This package changes to lowercase, removes a
// trailing dot and refuses a name of digits and dots. hello keeps the raw
// bytes and checks the full extension block. But a hello that both accept must name the same
// server in both. If not, one gateway routes a flow that the other judges
// under a different name.
func FuzzSNIAgree(f *testing.F) {
	for _, name := range []string{"example.com", "API.Example.COM", "a.b.c.example.org", "xn--bcher-kva.example"} {
		f.Add(clientHello(f, name))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ts, need, terr := Parse(b)
		hs, herr := hello.Parse(b)
		if terr != nil || need != 0 || herr != nil {
			return
		}
		want := strings.TrimSuffix(strings.ToLower(hs.SNI), ".")
		if ts.ServerName != want {
			t.Fatalf("tlssni says %q, hello says %q", ts.ServerName, hs.SNI)
		}
	})
}

// dnsName is a name of n bytes: labels of 63 letters or less, with dots
// between them. The last label is not empty.
func dnsName(n int) string {
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strings.Repeat("a", min(63, n-b.Len())))
	}
	name := b.String()
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-2] + "aa"
	}
	return name
}

// Both parsers check the length of the name after they remove one
// trailing dot. Thus a name of 253 bytes and a dot is valid in both, and a
// name of 254 bytes is valid in neither.
func TestSNILengthAgree(t *testing.T) {
	base := captureClientHello(t, &tls.Config{InsecureSkipVerify: true})
	for _, n := range []int{252, 253, 254} {
		for _, dot := range []string{"", "."} {
			name := dnsName(n)
			if len(name) != n {
				t.Fatalf("dnsName(%d) has %d bytes", n, len(name))
			}
			name += dot
			b := insertExt(t, base, sniExt(name))
			ts, need, terr := Parse(b)
			hs, herr := hello.Parse(b)
			if need != 0 || herr != nil {
				t.Fatalf("%d%q: need=%d hello err=%v", n, dot, need, herr)
			}
			tOK := terr == nil && ts.ServerName != ""
			hOK := hs.SNI != ""
			want := n <= 253
			if tOK != want || hOK != want {
				t.Errorf("%d bytes%q: tlssni %v (%v), hello %v; want %v", n, dot, tOK, terr, hOK, want)
			}
		}
	}
}
