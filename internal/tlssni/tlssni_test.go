package tlssni

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// captureClientHello runs a real tls.Client handshake over a net.Pipe. It
// returns exactly the bytes that the client wrote for its ClientHello.
// net.Pipe pairs a Write with the Read(s) that consume it. Thus one Read
// with a sufficiently large buffer gets the full first flight.
func captureClientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(client, cfg).Handshake()
	}()
	buf := make([]byte, 32<<10)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	_ = server.Close()
	<-done
	return buf[:n]
}

// fragment changes a single-record ClientHello into two records. It cuts
// the handshake bytes at splitAt, to test reassembly across records.
func fragment(t testing.TB, hello []byte, splitAt int) []byte {
	t.Helper()
	if hello[0] != 0x16 {
		t.Fatalf("not a handshake record")
	}
	ver := hello[1:3]
	body := hello[5:]
	if splitAt <= 0 || splitAt >= len(body) {
		t.Fatalf("bad split point %d for body len %d", splitAt, len(body))
	}
	rec := func(payload []byte) []byte {
		out := make([]byte, 0, 5+len(payload))
		out = append(out, 0x16)
		out = append(out, ver...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
		return append(out, payload...)
	}
	var out []byte
	out = append(out, rec(body[:splitAt])...)
	out = append(out, rec(body[splitAt:])...)
	return out
}

// insertECH puts an encrypted_client_hello (0xfe0d) extension into a
// captured single-record ClientHello.
func insertECH(t testing.TB, hello []byte) []byte {
	t.Helper()
	return insertExt(t, hello, []byte{0xfe, 0x0d, 0x00, 0x02, 0xaa, 0xbb}) // type, len=2, 2 bytes of filler
}

// insertExt appends one extension (type, length and data) to the extensions
// of a captured single-record ClientHello. It corrects each length that
// changes: the extensions block, the handshake body, and the record.
func insertExt(t testing.TB, hello, newExt []byte) []byte {
	t.Helper()
	recLen := int(binary.BigEndian.Uint16(hello[3:5]))
	body := hello[5 : 5+recLen]
	bodyLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	chBody := body[4 : 4+bodyLen]

	off := 2 + 32
	sidLen := int(chBody[off])
	off += 1 + sidLen
	csLen := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	off += 2 + csLen
	cmLen := int(chBody[off])
	off += 1 + cmLen
	extLenOff := off
	extLen := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	extStart := off + 2
	extEnd := extStart + extLen
	if extEnd != len(chBody) {
		t.Fatalf("captured hello has trailing bytes past extensions")
	}

	out := make([]byte, 0, len(hello)+len(newExt))
	out = append(out, hello[:5+4]...) // record header + handshake header, fixed below
	out = append(out, chBody[:extLenOff]...)
	out = binary.BigEndian.AppendUint16(out, uint16(extLen+len(newExt)))
	out = append(out, chBody[extStart:extEnd]...)
	out = append(out, newExt...)

	newChBodyLen := len(out) - (5 + 4)
	out[5+1] = byte(newChBodyLen >> 16)
	out[5+2] = byte(newChBodyLen >> 8)
	out[5+3] = byte(newChBodyLen)

	newRecLen := len(out) - 5
	out[3] = byte(newRecLen >> 8)
	out[4] = byte(newRecLen)

	return out
}

func mustParse(t *testing.T, buf []byte) Hello {
	t.Helper()
	h, need, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if need != 0 {
		t.Fatalf("Parse: need=%d on a supposedly complete hello", need)
	}
	return h
}

func TestCapturedTLS12Only(t *testing.T) {
	cfg := &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}
	hello := captureClientHello(t, cfg)
	h := mustParse(t, hello)
	if h.ServerName != "example.com" {
		t.Fatalf("ServerName=%q", h.ServerName)
	}
}

// TestEveryPrefix gives each possible prefix of a real ClientHello to Parse.
// The ClientHello can be large (PQ key share). Each prefix that is shorter
// than the full hello must ask for more. It must never give an error or a
// wrong name.
func TestEveryPrefix(t *testing.T) {
	cfg := &tls.Config{ServerName: "News.YCombinator.com.", InsecureSkipVerify: true}
	hello := captureClientHello(t, cfg)
	if len(hello) < 200 {
		t.Fatalf("suspiciously small captured hello: %d bytes", len(hello))
	}
	for i := 0; i < len(hello); i++ {
		h, need, err := Parse(hello[:i])
		if err != nil {
			t.Fatalf("prefix %d: unexpected error %v", i, err)
		}
		if need <= 0 {
			t.Fatalf("prefix %d: need=%d, want >0", i, need)
		}
		if h.ServerName != "" {
			t.Fatalf("prefix %d: got a name before completion: %q", i, h.ServerName)
		}
	}
	h := mustParse(t, hello)
	if h.ServerName != "news.ycombinator.com" {
		t.Fatalf("ServerName=%q", h.ServerName)
	}
}

func TestFragmentedAcrossTwoRecords(t *testing.T) {
	cfg := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}
	hello := captureClientHello(t, cfg)
	body := hello[5:]
	frag := fragment(t, hello, len(body)/2)
	h := mustParse(t, frag)
	if h.ServerName != "example.com" {
		t.Fatalf("ServerName=%q", h.ServerName)
	}
}

func TestNoSNI(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	hello := captureClientHello(t, cfg)
	h := mustParse(t, hello)
	if h.ServerName != "" {
		t.Fatalf("ServerName=%q, want empty", h.ServerName)
	}
}

func TestECHExtensionDetected(t *testing.T) {
	cfg := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}
	hello := captureClientHello(t, cfg)
	withECH := insertECH(t, hello)
	h := mustParse(t, withECH)
	if !h.ECH {
		t.Fatalf("ECH not detected")
	}
	if h.ServerName != "example.com" {
		t.Fatalf("ServerName=%q", h.ServerName)
	}
}

func TestNonTLS(t *testing.T) {
	cases := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}, // application_data, not handshake
	}
	for i, c := range cases {
		_, _, err := Parse(c)
		if err != ErrNotTLS {
			t.Fatalf("case %d: err=%v, want ErrNotTLS", i, err)
		}
	}
}

func TestNonClientHelloHandshakeType(t *testing.T) {
	// A well-formed handshake record whose message type is ServerHello (2),
	// not ClientHello (1).
	buf := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}
	_, _, err := Parse(buf)
	if err != ErrNotTLS {
		t.Fatalf("err=%v, want ErrNotTLS", err)
	}
}

func TestCorruptedLengths(t *testing.T) {
	cases := [][]byte{
		{0x16, 0x03, 0x03, 0x00, 0x00},                         // zero record length
		{0x16, 0x03, 0x03, 0xff, 0xff, 1, 2, 3},                // record length beyond cap, no filler needed to detect
		{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff}, // handshake body len way bigger than possible
		{0x16, 0x03, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}, // bad minor version
	}
	for i, c := range cases {
		_, _, err := Parse(c)
		if err != ErrMalformed {
			t.Fatalf("case %d: err=%v, want ErrMalformed", i, err)
		}
	}
}

// sniExt is a server_name extension with one host_name.
func sniExt(name string) []byte {
	n := len(name)
	out := []byte{0x00, 0x00}
	out = binary.BigEndian.AppendUint16(out, uint16(n+5))
	out = binary.BigEndian.AppendUint16(out, uint16(n+3))
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	return append(out, name...)
}

// An extension type may occur only one time in a ClientHello (RFC 8446
// 4.2). Parse refuses a hello with a type two times. Thus the name that it
// gives is the one name that the TLS stack of the origin can read.
func TestDuplicateExtensionMalformed(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	if h := mustParse(t, insertExt(t, hello, []byte{0x0a, 0x0a, 0x00, 0x00})); h.ServerName != "example.com" {
		t.Fatalf("ServerName=%q", h.ServerName)
	}
	for name, buf := range map[string][]byte{
		"server_name": insertExt(t, hello, sniExt("other.example")),
		"ech":         insertECH(t, insertECH(t, hello)),
		"other type":  insertExt(t, insertExt(t, hello, []byte{0x0a, 0x0a, 0x00, 0x00}), []byte{0x0a, 0x0a, 0x00, 0x01, 0x00}),
	} {
		if _, _, err := Parse(buf); err != ErrMalformed {
			t.Fatalf("%s: err=%v, want ErrMalformed", name, err)
		}
	}
}

// A server name has labels of 1 to 63 bytes and at most one trailing dot.
func TestNormalizeHostNameLabels(t *testing.T) {
	long := strings.Repeat("a", 63)
	for in, want := range map[string]string{
		"Example.COM":           "example.com",
		"example.com.":          "example.com",
		long + ".com":           long + ".com",
		"example.c..":           "",
		"example..com":          "",
		".example.com":          "",
		long + "a.com":          "",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		got, err := normalizeHostName([]byte(in))
		if want == "" {
			if err == nil {
				t.Errorf("%q: got %q, want ErrMalformed", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
}
