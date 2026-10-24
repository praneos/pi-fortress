package tlssni

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// FuzzParse: each byte stream gives a parsed Hello, a request for more
// bytes, or one of ErrNotTLS/ErrMalformed. It never gives a panic. The
// fuzzer also cuts the input at cut and examines the two calls together:
//
//   - A request for more bytes is never larger than maxHandshake.
//   - An error on a prefix stays the same error when more bytes come.
//   - A result on a prefix stays the same result when more bytes come.
//   - A request for n more bytes is a lower limit: fewer bytes give no result.
//   - A result does not change when junk comes after the input.
//   - A ServerName obeys the Hello doc: lowercase, no trailing dot, only
//     [a-z0-9._-], 1 to 253 bytes, not only digits and dots.
//   - When crypto/tls on the server side accepts the same bytes, it sees
//     the same server name and the same ECH flag.
func FuzzParse(f *testing.F) {
	hello := captureClientHello(f, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	seeds := [][]byte{
		hello,
		captureClientHello(f, &tls.Config{ServerName: "API.Example.COM", InsecureSkipVerify: true}),
		captureClientHello(f, &tls.Config{InsecureSkipVerify: true}), // no SNI
		insertECH(f, hello),
		insertOuterECH(f, hello),
		fragment(f, hello, 3),
		fragment(f, hello, 100),
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		{0x16, 0x03, 0x01, 0xff, 0xff},
		{},
	}
	for _, s := range seeds {
		f.Add(s, uint16(len(s)))
	}
	for i := 0; i < len(hello); i += 7 {
		f.Add(hello, uint16(i))
	}
	f.Fuzz(func(t *testing.T, data []byte, cut uint16) {
		h, need, err := Parse(data)
		checkResult(t, h, need, err)

		c := int(cut) % (len(data) + 1)
		ph, pneed, perr := Parse(data[:c])
		checkResult(t, ph, pneed, perr)
		switch {
		case perr != nil:
			if err != perr {
				t.Fatalf("prefix of %d bytes gives %v, full input gives (%+v, %d, %v)", c, perr, h, need, err)
			}
		case pneed == 0:
			if err != nil || need != 0 || h != ph {
				t.Fatalf("prefix of %d bytes gives %+v, full input gives (%+v, %d, %v)", c, ph, h, need, err)
			}
		case len(data)-c < pneed && err == nil && need == 0:
			t.Fatalf("prefix of %d bytes asks for %d more, but %d more give %+v", c, pneed, len(data)-c, h)
		}

		if err != nil || need != 0 {
			return
		}
		junk := append(slices.Clip(data), 0x15, 0x03, 0x03, 0xff, 0xff)
		if jh, jneed, jerr := Parse(junk); jerr != nil || jneed != 0 || jh != h {
			t.Fatalf("trailing junk changes %+v to (%+v, %d, %v)", h, jh, jneed, jerr)
		}
		if chi := cryptoTLSHello(data); chi != nil {
			if want := strings.ToLower(chi.ServerName); h.ServerName != want {
				t.Fatalf("tlssni says %q, crypto/tls says %q", h.ServerName, chi.ServerName)
			}
			if ech := slices.Contains(chi.Extensions, 0xfe0d); h.ECH != ech {
				t.Fatalf("tlssni ECH=%v, crypto/tls ECH=%v", h.ECH, ech)
			}
		}
	})
}

// checkResult examines one return of Parse against its doc.
func checkResult(t *testing.T, h Hello, need int, err error) {
	t.Helper()
	switch {
	case err != nil:
		if err != ErrNotTLS && err != ErrMalformed {
			t.Fatalf("unexpected error: %v", err)
		}
		if need != 0 || h != (Hello{}) {
			t.Fatalf("error %v with need=%d hello=%+v", err, need, h)
		}
	case need < 0 || need > maxHandshake:
		t.Fatalf("need=%d is out of range", need)
	case need > 0:
		if h != (Hello{}) {
			t.Fatalf("need=%d but hello=%+v", need, h)
		}
	case h.ServerName != "":
		checkName(t, h.ServerName)
	}
}

// checkName fails when s is not a name that the Hello doc permits.
func checkName(t *testing.T, s string) {
	t.Helper()
	if len(s) > 253 || strings.HasSuffix(s, ".") {
		t.Fatalf("ServerName %q: too long or trailing dot", s)
	}
	onlyDigitsAndDots := true
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c == '-', c == '_':
			onlyDigitsAndDots = false
		case c >= '0' && c <= '9', c == '.':
		default:
			t.Fatalf("ServerName %q: byte %#x", s, c)
		}
	}
	if onlyDigitsAndDots {
		t.Fatalf("ServerName %q: only digits and dots", s)
	}
}

// insertOuterECH adds an outer encrypted_client_hello extension that
// crypto/tls can read (RFC 9849 §5): type outer, HKDF-SHA256 with
// AES-128-GCM, config_id, a 32-byte enc and a 16-byte payload. insertECH
// gives only 2 bytes of filler, which crypto/tls refuses.
func insertOuterECH(t testing.TB, hello []byte) []byte {
	t.Helper()
	ext := []byte{0xfe, 0x0d, 0x00, 58, 0x00, 0x00, 0x01, 0x00, 0x01, 0x42, 0x00, 32}
	ext = append(ext, make([]byte, 32)...)
	ext = append(ext, 0x00, 16)
	ext = append(ext, make([]byte, 16)...)
	return insertExt(t, hello, ext)
}

var errStop = errors.New("stop after the ClientHello")

// cryptoTLSHello gives data to a crypto/tls server and returns the
// ClientHelloInfo that it reads, or nil when crypto/tls refuses data. The
// conn is in memory, so no goroutine and no deadline are necessary.
func cryptoTLSHello(data []byte) *tls.ClientHelloInfo {
	var got *tls.ClientHelloInfo
	cfg := &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		got = chi
		return nil, errStop
	}}
	_ = tls.Server(&helloConn{r: bytes.NewReader(data)}, cfg).Handshake()
	return got
}

// TestCryptoTLSHelloSeesName makes sure that the differential in FuzzParse
// compares something: crypto/tls must read a real hello through helloConn.
func TestCryptoTLSHelloSeesName(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "Example.com", InsecureSkipVerify: true})
	chi := cryptoTLSHello(hello)
	if chi == nil || chi.ServerName != "Example.com" {
		t.Fatalf("crypto/tls did not read the hello: %+v", chi)
	}
	chi = cryptoTLSHello(insertOuterECH(t, hello))
	if chi == nil || !slices.Contains(chi.Extensions, 0xfe0d) {
		t.Fatalf("crypto/tls did not read the hello with ECH: %+v", chi)
	}
}

// helloConn reads from a fixed buffer and discards what is written to it.
type helloConn struct{ r *bytes.Reader }

func (c *helloConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *helloConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *helloConn) Close() error                     { return nil }
func (c *helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *helloConn) SetDeadline(time.Time) error      { return nil }
func (c *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (c *helloConn) SetWriteDeadline(time.Time) error { return nil }
