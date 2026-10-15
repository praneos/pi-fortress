package peekconn

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"pi-fortress/internal/hello"
)

func helloBytes(sni string) []byte {
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	ext := func(typ int, body []byte) []byte {
		out := u16(typ)
		out = append(out, u16(len(body))...)
		return append(out, body...)
	}
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{1, 0})
	host := []byte(sni)
	name := append([]byte{0}, u16(len(host))...)
	name = append(name, host...)
	sniBody := append(u16(len(name)), name...)
	var exts []byte
	exts = append(exts, ext(0, sniBody)...)
	alpn := []byte{8}
	alpn = append(alpn, []byte("http/1.1")...)
	exts = append(exts, ext(16, append(u16(len(alpn)), alpn...))...)
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

func TestWrapReplay(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	raw := helloBytes("example.com")
	errc := make(chan error, 1)
	go func() {
		_, err := c2.Write(raw)
		errc <- err
	}()
	pc, err := Wrap(c1, MaxPeek)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	h, err := hello.Parse(pc.Prefix())
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "example.com" {
		t.Fatalf("sni=%q", h.SNI)
	}
	go func() { _, _ = c2.Write([]byte("MORE")) }()
	buf := make([]byte, len(raw)+4)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:len(raw)], raw) {
		t.Fatal("prefix not replayed")
	}
	if string(buf[len(raw):]) != "MORE" {
		t.Fatalf("rest=%q", buf[len(raw):])
	}
}

func TestWrapMalformed(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _, _ = c2.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}) }()
	_, err := Wrap(c1, MaxPeek)
	if err == nil {
		t.Fatal("expected error")
	}
}
