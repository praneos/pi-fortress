package hello

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func u16(n int) []byte {
	return []byte{byte(n >> 8), byte(n)}
}

func ext(typ int, body []byte) []byte {
	out := u16(typ)
	out = append(out, u16(len(body))...)
	return append(out, body...)
}

func sniExt(host string) []byte {
	name := append([]byte{0}, u16(len(host))...)
	name = append(name, []byte(host)...)
	body := u16(len(name))
	body = append(body, name...)
	return ext(0, body)
}

func alpnExt(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	body := u16(len(list))
	body = append(body, list...)
	return ext(16, body)
}

func buildHello(sni string, alpns []string, ciphers []uint16) []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0)
	var cs []byte
	for _, c := range ciphers {
		cs = append(cs, byte(c>>8), byte(c))
	}
	body.Write(u16(len(cs)))
	body.Write(cs)
	body.Write([]byte{1, 0})
	var exts []byte
	if sni != "" {
		exts = append(exts, sniExt(sni)...)
	}
	if len(alpns) > 0 {
		exts = append(exts, alpnExt(alpns...)...)
	}
	exts = append(exts, ext(10, append(u16(2), 0x00, 0x1d))...)
	exts = append(exts, ext(11, []byte{1, 0})...)
	exts = append(exts, ext(13, append(u16(2), 0x04, 0x03))...)
	exts = append(exts, ext(43, []byte{2, 0x03, 0x04})...)
	body.Write(u16(len(exts)))
	body.Write(exts)
	raw := body.Bytes()
	hs := append([]byte{1, 0, 0, 0}, raw...)
	binary.BigEndian.PutUint32(hs[:4], uint32(len(raw)))
	hs[0] = 1
	rec := append([]byte{0x16, 0x03, 0x03, 0, 0}, hs...)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	return rec
}

func TestMinimalGolden(t *testing.T) {
	raw := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "example.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
	if h.H2Only {
		t.Fatal("h2only")
	}
	if len(h.ALPNs) != 1 || h.ALPNs[0] != "http/1.1" {
		t.Fatalf("alpn=%v", h.ALPNs)
	}
}

func TestGreaseCipherParses(t *testing.T) {
	raw := buildHello("example.com", []string{"http/1.1"}, []uint16{0x0a0a, 0x1301})
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	plain := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	p, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != p.SNI || len(h.ALPNs) != len(p.ALPNs) || h.H2Only != p.H2Only {
		t.Fatalf("grease changed the parse: %+v vs %+v", h, p)
	}
}

func TestH2Only(t *testing.T) {
	raw := buildHello("example.com", []string{"h2"}, []uint16{0x1301})
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !h.H2Only {
		t.Fatal("expected h2only")
	}
}

func TestIncomplete(t *testing.T) {
	raw := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	_, err := Parse(raw[:8])
	if err != ErrIncomplete {
		t.Fatalf("err=%v", err)
	}
}

func TestMalformed(t *testing.T) {
	_, err := Parse([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	if err != ErrMalformed {
		t.Fatalf("err=%v", err)
	}
}

func TestTrailingBytesOK(t *testing.T) {
	raw := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	raw = append(raw, 0xde, 0xad)
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "example.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
}

func TestCheckedInBlob(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "hello", "minimal.bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	if !bytes.Equal(b, want) {
		t.Fatalf("fixture drift: got %d bytes want %d", len(b), len(want))
	}
	h, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "example.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
}

func TestCaptureGoClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	cfg := &tls.Config{ServerName: "api.anthropic.com", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	d := net.Dialer{Timeout: 2 * time.Second}
	raw, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = tls.Client(raw, cfg).Handshake()
	helloBytes := <-got
	if len(helloBytes) == 0 {
		t.Fatal("no hello")
	}
	h, err := Parse(helloBytes)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "api.anthropic.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
	found := false
	for _, a := range h.ALPNs {
		if a == "http/1.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("alpn=%v", h.ALPNs)
	}
}

func TestHandshakeHeaderOnly(t *testing.T) {
	rec := buildHello("example.com", []string{"http/1.1"}, []uint16{0x1301})
	hs := rec[5:]
	h, err := Parse(hs)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "example.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
}

func TestEmptyRead(t *testing.T) {
	_, err := Parse(nil)
	if err != ErrIncomplete {
		t.Fatalf("err=%v", err)
	}
}

// helloWithExts is a ClientHello with the extension block exts. The
// declared length of the block is declared bytes.
func helloWithExts(exts []byte, declared int) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, u16(2)...)
	body = append(body, 0x13, 0x01, 1, 0)
	body = append(body, u16(declared)...)
	body = append(body, exts...)
	hs := append([]byte{1, 0, 0, 0}, body...)
	binary.BigEndian.PutUint32(hs[:4], uint32(len(body)))
	hs[0] = 1
	rec := append([]byte{0x16, 0x03, 0x03, 0, 0}, hs...)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	return rec
}

// The code reads the extension block as crypto/tls reads it. A hello that
// handshake refuses must not parse here into its own SNI or ALPN list.
func TestExtensionBlockExact(t *testing.T) {
	sni := sniExt("example.com")
	for name, raw := range map[string][]byte{
		"alpn past the declared end": helloWithExts(append(append([]byte{}, sni...), alpnExt("h2")...), len(sni)),
		"declared past the body":     helloWithExts(sni, len(sni)+4),
		"leftover inside the block":  helloWithExts(append(append([]byte{}, sni...), 0, 16), len(sni)+2),
		"repeated alpn":              helloWithExts(append(append(append([]byte{}, sni...), alpnExt("http/1.1")...), alpnExt("h2")...), len(sni)+len(alpnExt("http/1.1"))+len(alpnExt("h2"))),
		"repeated sni":               helloWithExts(append(append([]byte{}, sni...), sniExt("other.example")...), len(sni)+len(sniExt("other.example"))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err != ErrMalformed {
				t.Fatalf("err=%v", err)
			}
		})
	}
	exts := append(append([]byte{}, sni...), alpnExt("h2")...)
	h, err := Parse(helloWithExts(exts, len(exts)))
	if err != nil || h.SNI != "example.com" || !h.H2Only {
		t.Fatalf("h=%+v err=%v", h, err)
	}
}

// sniEntry is one entry of a ServerNameList: the name type and the name.
type sniEntry struct {
	typ  byte
	name string
}

// sniListExt is a server_name extension with the entries given, in order.
// extra bytes go after the last entry, inside the list.
func sniListExt(extra []byte, entries ...sniEntry) []byte {
	var list []byte
	for _, e := range entries {
		list = append(list, e.typ)
		list = append(list, u16(len(e.name))...)
		list = append(list, e.name...)
	}
	list = append(list, extra...)
	return ext(0, append(u16(len(list)), list...))
}

// A ServerNameList must not hold more than one name of the same type
// (RFC 6066 3). Parse refuses a list with two entries of one type, and
// does not select one of them.
func TestServerNameList(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		extra   []byte
		entries []sniEntry
		want    string
		err     error
	}{
		{desc: "one host_name", entries: []sniEntry{{0, "example.com"}}, want: "example.com"},
		{desc: "host_name in upper case", entries: []sniEntry{{0, "Example.COM"}}, want: "example.com"},
		{desc: "no entry"},
		{desc: "other type then host_name", entries: []sniEntry{{7, "x"}, {0, "example.com"}}, want: "example.com"},
		{desc: "invalid host_name", entries: []sniEntry{{0, "a b"}}},
		{desc: "entry cut short after host_name", extra: []byte{7, 0, 9, 'x'}, entries: []sniEntry{{0, "example.com"}}},
		{desc: "two host_names", entries: []sniEntry{{0, "a.example"}, {0, "b.example"}}, err: ErrMalformed},
		{desc: "same host_name two times", entries: []sniEntry{{0, "a.example"}, {0, "a.example"}}, err: ErrMalformed},
		{desc: "invalid then valid host_name", entries: []sniEntry{{0, "a b"}, {0, "b.example"}}, err: ErrMalformed},
		{desc: "two of other type", entries: []sniEntry{{0, "a.example"}, {7, "x"}, {7, "y"}}, err: ErrMalformed},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			e := sniListExt(tc.extra, tc.entries...)
			h, err := Parse(helloWithExts(e, len(e)))
			if tc.err != nil {
				if err != tc.err || h != nil {
					t.Fatalf("h=%+v err=%v, want %v", h, err, tc.err)
				}
				return
			}
			if err != nil || h.SNI != tc.want {
				t.Fatalf("h=%+v err=%v, want SNI %q", h, err, tc.want)
			}
		})
	}
}
