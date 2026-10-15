package broker

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
)

const ws101 = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

const wsHandshake = "GET /socket HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
	"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"

// wsUpstream serves the origin leg of one upgrade. It parses the handshake
// as HTTP. Then the script owns the raw connection and the reader. The
// reader already holds the frames that arrived with the handshake.
func wsUpstream(t *testing.T, b *Broker, script func(req *httpwire.Request, conn net.Conn, br *bufio.Reader)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := httpwire.ReadRequest(br)
				if err != nil {
					return
				}
				script(req, c, br)
			}(c)
		}
	}()
	b.DialTLS = dialTo(ln)
}

func maskedFrame(fin bool, opcode byte, payload []byte) []byte {
	key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	f := appendWSHeader(nil, fin, opcode, &key, len(payload))
	off := len(f)
	f = append(f, payload...)
	wsMask(f[off:], key)
	return f
}

func plainFrame(fin bool, opcode byte, payload []byte) []byte {
	return append(appendWSHeader(nil, fin, opcode, nil, len(payload)), payload...)
}

// nextFrame reads one frame and returns the header and the unmasked
// payload. It is safe to call from the origin goroutine: it never calls Fatal.
func nextFrame(br *bufio.Reader) (wsHeader, []byte, error) {
	h, err := readWSHeader(br, 1<<24)
	if err != nil {
		return h, nil, err
	}
	p := make([]byte, h.length)
	if _, err := io.ReadFull(br, p); err != nil {
		return h, nil, err
	}
	if h.masked {
		wsMask(p, h.key)
	}
	return h, p, nil
}

// waitErr gets the error of the handler for a session that the broker
// itself stops. It does not close the client first, so it does not race
// the frame that the test just sent.
func waitErr(s *session) error { return <-s.errc }

// wsDiscardUpstream accepts the handshake and then reads all client data.
func wsDiscardUpstream(t *testing.T, b *Broker) {
	t.Helper()
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		_, _ = io.Copy(io.Discard, br)
	})
}

// openWSDiscard opens a session against an upstream that accepts the
// handshake and then reads all client data. It is for the tests that
// examine only how the broker refuses a bad client frame.
func openWSDiscard(t *testing.T) *session {
	t.Helper()
	b, _ := testBroker(t)
	wsDiscardUpstream(t, b)
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	return s
}

// openWS drives the handshake and returns the session plus the 101.
func openWS(t *testing.T, b *Broker, raw string) (*session, *httpwire.Response) {
	t.Helper()
	s := open(t, b, anthropic)
	s.send(raw)
	resp, err := httpwire.ReadUpgradeResponseHead(s.br)
	if err != nil {
		t.Fatal(err)
	}
	return s, resp
}

func stripLog(t *testing.T, b *Broker) string {
	t.Helper()
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{
		StripPath:   filepath.Join(dir, "strip.jsonl"),
		UnknownPath: filepath.Join(dir, "unknown.jsonl"),
	}
	return dir
}

func TestWebSocketUpgradeRelayedAndFramesScanned(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	live := "ghp_" + strings.Repeat("a", 36)
	type seen struct {
		req    *httpwire.Request
		frames [][]byte
	}
	done := make(chan seen, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		got := seen{req: req}
		_, _ = io.WriteString(conn, ws101)
		for {
			h, p, err := nextFrame(br)
			if err != nil {
				break
			}
			if !h.masked {
				t.Errorf("origin got an unmasked client frame, opcode %d", h.opcode)
			}
			got.frames = append(got.frames, append([]byte(nil), p...))
			if h.opcode == opClose {
				break
			}
			// Server frames must get to the agent byte for byte. This includes a
			// non-minimal length form that the origin selected itself.
			_, _ = conn.Write(plainFrame(true, opBinary, []byte("pong-"+string(p))))
		}
		done <- got
	})

	s, resp := openWS(t, b, wsHandshake+"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	if resp.Code != 101 || resp.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("101 not relayed verbatim: %d %v", resp.Code, resp.Fields)
	}
	s.send(string(maskedFrame(true, opText, []byte("token "+live+" end"))))
	h, p, err := nextFrame(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if h.masked || h.opcode != opBinary || string(p) != "pong-token pf_stripped end" {
		t.Fatalf("server frame: masked=%v opcode=%d payload=%q", h.masked, h.opcode, p)
	}
	s.send(string(maskedFrame(true, opClose, []byte{0x03, 0xe8})))
	got := <-done
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
	if got.req.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("extension offer reached the origin: %q", got.req.Get("Sec-WebSocket-Extensions"))
	}
	if got.req.Get("Sec-WebSocket-Key") == "" || got.req.Get("Sec-WebSocket-Version") != "13" {
		t.Fatalf("handshake mangled: %v", got.req.Fields)
	}
	if len(got.frames) != 2 || string(got.frames[0]) != "token pf_stripped end" {
		t.Fatalf("origin frames %q", got.frames)
	}
	if bytes.Contains(bytes.Join(got.frames, nil), []byte(live)) {
		t.Fatal("a live token left the Pi inside a frame")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"where":"ws"`) || !strings.Contains(string(raw), `"rule":"github_classic"`) {
		t.Fatalf("no ws strip event: %s", raw)
	}
	unk, _ := os.ReadFile(filepath.Join(dir, "unknown.jsonl"))
	if !strings.Contains(string(unk), `"where":"ws_open"`) || !strings.Contains(string(unk), `"where":"ws_close"`) {
		t.Fatalf("no session rows: %s", unk)
	}
	// 21 stripped text bytes plus the 2-byte close code, and the 26 bytes
	// the origin echoed.
	if !strings.Contains(string(unk), `"ws_sent":23,"ws_recv":26`) {
		t.Fatalf("byte counts missing: %s", unk)
	}
}

// The broker must strip a credential split across two fragments. The scan
// runs on the reassembled message, not per frame. Otherwise the sender can
// defeat it, because the sender selects where the frames break.
func TestWebSocketTokenSplitAcrossFragmentsStripped(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	live := "ghp_" + strings.Repeat("a", 36)
	half := len(live) / 2
	type seen struct{ frames [][]byte }
	done := make(chan seen, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		got := seen{}
		_, _ = io.WriteString(conn, ws101)
		for {
			h, p, err := nextFrame(br)
			if err != nil {
				break
			}
			got.frames = append(got.frames, append([]byte(nil), p...))
			if h.opcode == opClose {
				break
			}
		}
		done <- got
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	// Neither fragment contains the full token, so a per-frame scan misses it.
	// Use one send: three concurrent sends would race on the pipe.
	var frames []byte
	frames = append(frames, maskedFrame(false, opText, []byte("lead "+live[:half]))...)
	frames = append(frames, maskedFrame(true, opContinuation, []byte(live[half:]+" tail"))...)
	frames = append(frames, maskedFrame(true, opClose, []byte{0x03, 0xe8})...)
	s.send(string(frames))
	got := <-done
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
	joined := bytes.Join(got.frames, nil)
	if bytes.Contains(joined, []byte(live)) {
		t.Fatalf("the split token reached the origin whole: %q", joined)
	}
	// The two fragments coalesce into one forwarded data frame, then close.
	if len(got.frames) != 2 || !bytes.Contains(got.frames[0], []byte("pf_stripped")) {
		t.Fatalf("origin frames %q", got.frames)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"rule":"github_classic"`) {
		t.Fatalf("no strip event for the reassembled token: %s", raw)
	}
}

// The broker refuses a client frame that the fence cannot read, and tells
// the origin nothing. An orphan continuation has no data frame to continue.
// An unmasked frame comes from a client that ignored the spec. A reserved
// bit is an extension that nobody negotiated.
func TestWebSocketBadClientFrameRefused(t *testing.T) {
	rsv := maskedFrame(true, opText, []byte("deflated"))
	rsv[0] |= 0x40
	for _, tc := range []struct {
		name  string
		frame []byte
		want  error
	}{
		{"orphan continuation", maskedFrame(true, opContinuation, []byte("nope")), ErrWSFragment},
		{"unmasked", plainFrame(true, opText, []byte("unmasked")), ErrWSMask},
		{"reserved bit", rsv, ErrWSRSV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openWSDiscard(t)
			s.send(string(tc.frame))
			if err := waitErr(s); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

func TestWebSocketServerFramesByteExact(t *testing.T) {
	b, _ := testBroker(t)
	// A 200-byte payload in the 16-bit length form and a 4-byte payload in the
	// 64-bit form. Both are legal and non-minimal. The agent must see exactly
	// what the origin sent.
	odd := append([]byte{opBinary | 0x80, 126, 0, 200}, bytes.Repeat([]byte("z"), 200)...)
	odd = append(odd, opText|0x80, 127, 0, 0, 0, 0, 0, 0, 0, 4)
	odd = append(odd, "abcd"...)
	reply := make(chan byte, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		_, _ = conn.Write(odd)
		_, _ = conn.Write(plainFrame(true, opClose, nil))
		h, _, _ := nextFrame(br)
		reply <- h.opcode
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	got := make([]byte, len(odd))
	if _, err := io.ReadFull(s.br, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, odd) {
		t.Fatalf("server frames rewritten:\n%x\n%x", got, odd)
	}
	h, _, err := nextFrame(s.br)
	if err != nil || h.opcode != opClose {
		t.Fatalf("origin close not forwarded: %v %+v", err, h)
	}
	s.send(string(maskedFrame(true, opClose, []byte{0x03, 0xe8})))
	if op := <-reply; op != opClose {
		t.Fatalf("the agent's close reply did not reach the origin: opcode %d", op)
	}
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
}

func TestWebSocketOriginExtensionAborts(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, strings.TrimSuffix(ws101, "\r\n")+"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
		_, _ = conn.Write(plainFrame(true, opText, []byte("deflated")))
		_, _ = io.Copy(io.Discard, br)
	})
	s := open(t, b, anthropic)
	s.send(wsHandshake + "\r\n")
	rest, _ := io.ReadAll(s.br)
	if len(rest) != 0 {
		t.Fatalf("bytes reached the client after a refused extension: %q", rest)
	}
	if err := waitErr(s); !errors.Is(err, ErrWSExtension) {
		t.Fatalf("err=%v want ErrWSExtension", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"rule":"extension"`) {
		t.Fatalf("no extension log: %s", raw)
	}
}

func TestWebSocketPingPongPassThrough(t *testing.T) {
	b, _ := testBroker(t)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		h, p, err := nextFrame(br)
		if err != nil || h.opcode != opPing {
			t.Errorf("origin saw %v %+v", err, h)
			return
		}
		_, _ = conn.Write(plainFrame(true, opPong, p))
		_, _ = conn.Write(plainFrame(true, opClose, nil))
		_, _, _ = nextFrame(br)
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	s.send(string(maskedFrame(true, opPing, []byte("beat"))))
	h, p, err := nextFrame(s.br)
	if err != nil || h.opcode != opPong || string(p) != "beat" {
		t.Fatalf("pong: %v opcode=%d payload=%q", err, h.opcode, p)
	}
	if h2, _, err := nextFrame(s.br); err != nil || h2.opcode != opClose {
		t.Fatalf("close: %v %+v", err, h2)
	}
	s.send(string(maskedFrame(true, opClose, nil)))
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
}

func TestWebSocketNon101RelayedAsHTTP(t *testing.T) {
	b, _ := testBroker(t)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 8\r\nConnection: close\r\n\r\nno socks")
	})
	s := open(t, b, anthropic)
	s.send(wsHandshake + "\r\n")
	resp := s.read()
	if resp.Code != 403 || string(resp.Body) != "no socks" {
		t.Fatalf("code %d body %q", resp.Code, resp.Body)
	}
	_ = s.close()
}

func TestNonWebSocketUpgradeStillRefused(t *testing.T) {
	for _, extra := range []string{
		"Upgrade: h2c\r\nConnection: Upgrade\r\n",
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 8\r\n",
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n",
		"Upgrade: websocket\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n",
	} {
		b, _ := testBroker(t)
		dialed := false
		wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) { dialed = true })
		s := open(t, b, anthropic)
		s.send("GET /socket HTTP/1.1\r\nHost: api.anthropic.com\r\n" + extra + "\r\n")
		if resp := s.read(); resp.Code != 501 || !strings.Contains(string(resp.Body), "upgrade") {
			t.Fatalf("%q: code %d body %q", extra, resp.Code, resp.Body)
		}
		_ = s.close()
		time.Sleep(20 * time.Millisecond)
		if dialed {
			t.Fatalf("%q: origin saw a refused upgrade", extra)
		}
	}
}

func TestWebSocketPostUpgradeRefused(t *testing.T) {
	b, _ := testBroker(t)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		t.Error("origin saw a POST upgrade")
	})
	s := open(t, b, anthropic)
	s.send("POST /socket HTTP/1.1\r\nHost: api.anthropic.com\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n" +
		"Content-Length: 4\r\n\r\nbody")
	if resp := s.read(); resp.Code != 501 {
		t.Fatalf("code %d", resp.Code)
	}
	_ = s.close()
}

// A control frame is 125 bytes that the agent selects. The broker must
// strip a token in a ping or in a close reason as it strips one in a data
// message. The close status code must not change in the rewrite.
func TestWebSocketTokenInControlFrameStripped(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	live := "ghp_" + strings.Repeat("a", 36)
	done := make(chan [][]byte, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		var frames [][]byte
		_, _ = io.WriteString(conn, ws101)
		for {
			h, p, err := nextFrame(br)
			if err != nil {
				break
			}
			frames = append(frames, append([]byte{h.opcode}, p...))
			if h.opcode == opClose {
				break
			}
		}
		_, _ = conn.Write(plainFrame(true, opClose, nil))
		done <- frames
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	var raw []byte
	raw = append(raw, maskedFrame(true, opPing, []byte("k="+live))...)
	raw = append(raw, maskedFrame(true, opPong, []byte(live))...)
	raw = append(raw, maskedFrame(true, opClose, append([]byte{0x03, 0xe8}, "bye "+live...))...)
	s.send(string(raw))
	got := <-done
	if h, _, err := nextFrame(s.br); err != nil || h.opcode != opClose {
		t.Fatalf("the origin's close reply did not reach the agent: %v %+v", err, h)
	}
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
	want := []string{
		string([]byte{opPing}) + "k=pf_stripped",
		string([]byte{opPong}) + "pf_stripped",
		string([]byte{opClose}) + "\x03\xe8bye pf_stripped",
	}
	if len(got) != len(want) {
		t.Fatalf("origin frames %q", got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Fatalf("frame %d: got %q want %q", i, got[i], want[i])
		}
	}
	if bytes.Contains(bytes.Join(got, nil), []byte(live)) {
		t.Fatal("a live token left the Pi inside a control frame")
	}
	log, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if strings.Count(string(log), `"where":"ws"`) != 3 {
		t.Fatalf("want three ws strip events: %s", log)
	}
}
