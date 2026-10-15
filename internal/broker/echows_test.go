package broker

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

var coreEcho = preamble.Preamble{
	SNI:     "pf-core-echo.test",
	OrigDst: netip.MustParseAddrPort("192.0.2.2:443"),
	Src:     netip.MustParseAddrPort("10.77.0.20:40000"),
}

// The RFC 6455 1.3 example key and the accept that it must produce. The
// fixture computes the second from the first. Thus an assert on it tells
// the test that the fixture answered the handshake and did not only
// relay it.
const (
	echoWSKey    = "dGhlIHNhbXBsZSBub25jZQ=="
	echoWSAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
)

func echoWSHandshake(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: pf-core-echo.test\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + echoWSKey + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
}

// openEchoWS does the handshake against the lab fixture and returns the
// session when the 101 is in.
func openEchoWS(t *testing.T, b *Broker) *session {
	t.Helper()
	s := open(t, b, coreEcho)
	s.send(echoWSHandshake(echoWSPath))
	resp, err := httpwire.ReadUpgradeResponseHead(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 101 || resp.Get("Sec-WebSocket-Accept") != echoWSAccept {
		t.Fatalf("the fixture did not answer the handshake: %d %v", resp.Code, resp.Fields)
	}
	return s
}

// echoText sends one masked text frame and reads the frame that comes
// back. That frame is what the fence gave the origin: the fixture only
// reflects.
func echoText(t *testing.T, s *session, payload string) string {
	t.Helper()
	s.send(string(maskedFrame(true, opText, []byte(payload))))
	h, p, err := nextFrame(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if h.masked || h.opcode != opText {
		t.Fatalf("reflected frame: masked=%v opcode=%d", h.masked, h.opcode)
	}
	return string(p)
}

// closeEchoWS runs the closing handshake from the client side and waits
// for the handler. The handler must end by itself, not on a cut socket.
func closeEchoWS(t *testing.T, s *session) {
	t.Helper()
	s.send(string(maskedFrame(true, opClose, []byte{0x03, 0xe8})))
	h, p, err := nextFrame(s.br)
	if err != nil {
		t.Fatalf("the fixture's close reply did not reach the agent: %v", err)
	}
	if h.opcode != opClose || len(p) < 2 || p[0] != 0x03 || p[1] != 0xe8 {
		t.Fatalf("close frame: opcode=%d payload=%x", h.opcode, p)
	}
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
}

// The fixture is the only upstream in the tree that upgrades. Thus this
// is the only place that reads the frame scrub back from outside the
// fence.
func TestEchoWebSocketReflectsTheScrubbedFrame(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	live := "ghp_" + strings.Repeat("a", 36)

	s := openEchoWS(t, b)
	if got := echoText(t, s, "frame "+live+" end"); got != "frame pf_stripped end" {
		t.Fatalf("the agent read back %q", got)
	}
	closeEchoWS(t, s)

	if dialed.Load() {
		t.Fatal("the fixture dialled an origin")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"where":"ws"`) || !strings.Contains(string(raw), `"rule":"github_classic"`) {
		t.Fatalf("no ws strip row: %s", raw)
	}
	if strings.Contains(string(raw), live) {
		t.Fatalf("the strip log carries the token it stripped: %s", raw)
	}
	unk, _ := os.ReadFile(filepath.Join(dir, "unknown.jsonl"))
	if !strings.Contains(string(unk), `"where":"ws_open"`) || !strings.Contains(string(unk), `"where":"ws_close"`) {
		t.Fatalf("no session rows: %s", unk)
	}
}

// The agent-side client writes the handshake and both frames in one
// write (vm/itest/wsecho.go). Thus the frames arrive in the same read as
// the request head, and wait in the buffered reader of the client across
// the 101. The hardware run has that shape. A pump that read its own
// socket instead of that reader would drop them.
func TestEchoWebSocketFramesArrivingWithTheHandshake(t *testing.T) {
	b, _ := testBroker(t)
	live := "ghp_" + strings.Repeat("a", 36)
	s := open(t, b, coreEcho)
	s.send(echoWSHandshake(echoWSPath) +
		string(maskedFrame(true, opText, []byte("frame "+live+" end"))) +
		string(maskedFrame(true, opClose, []byte{0x03, 0xe8})))
	resp, err := httpwire.ReadUpgradeResponseHead(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 101 || resp.Get("Sec-WebSocket-Accept") != echoWSAccept {
		t.Fatalf("handshake: %d %v", resp.Code, resp.Fields)
	}
	h, p, err := nextFrame(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if h.opcode != opText || string(p) != "frame pf_stripped end" {
		t.Fatalf("opcode=%d payload=%q", h.opcode, p)
	}
	if h, _, err := nextFrame(s.br); err != nil || h.opcode != opClose {
		t.Fatalf("close reply: %v %+v", err, h)
	}
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
}

// The fence does not touch data for which it has no rule. It logs no
// incident for a frame that carried no credential.
func TestEchoWebSocketLeavesACleanFrameAlone(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	s := openEchoWS(t, b)
	const clean = `{"type":"content_block_delta","text":"ghp_ is a prefix"}`
	if got := echoText(t, s, clean); got != clean {
		t.Fatalf("a clean frame came back as %q", got)
	}
	closeEchoWS(t, s)
	if raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl")); len(raw) != 0 {
		t.Fatalf("a clean frame logged a strip: %s", raw)
	}
}

// The scan catches a token that the agent splits across two *fragments
// of one message*, because the scan runs on the reassembled message
// (ws.go wsToOrigin). It does not catch a token split across two
// *messages*. This test pins that residual and does not hide it, and
// docs/fence.md 5.3c says so. The fix would hold back the tail of one
// message until the next arrives. That is a stall on a socket that can
// correctly send nothing more.
func TestEchoWebSocketCatchesASplitFragmentAndNotASplitMessage(t *testing.T) {
	live := "ghp_" + strings.Repeat("a", 36)
	half := len(live) / 2

	t.Run("across fragments of one message", func(t *testing.T) {
		b, _ := testBroker(t)
		s := openEchoWS(t, b)
		var frames []byte
		frames = append(frames, maskedFrame(false, opText, []byte("lead "+live[:half]))...)
		frames = append(frames, maskedFrame(true, opContinuation, []byte(live[half:]+" tail"))...)
		s.send(string(frames))
		h, p, err := nextFrame(s.br)
		if err != nil {
			t.Fatal(err)
		}
		if h.opcode != opText || strings.Contains(string(p), live) {
			t.Fatalf("the split token crossed the fence whole: %q", p)
		}
		if string(p) != "lead pf_stripped tail" {
			t.Fatalf("reassembled message came back as %q", p)
		}
		closeEchoWS(t, s)
	})

	t.Run("across two messages", func(t *testing.T) {
		b, _ := testBroker(t)
		dir := stripLog(t, b)
		s := openEchoWS(t, b)
		var frames []byte
		frames = append(frames, maskedFrame(true, opText, []byte("lead "+live[:half]))...)
		frames = append(frames, maskedFrame(true, opText, []byte(live[half:]+" tail"))...)
		s.send(string(frames))
		var got []string
		for range 2 {
			h, p, err := nextFrame(s.br)
			if err != nil {
				t.Fatal(err)
			}
			if h.opcode != opText {
				t.Fatalf("opcode %d", h.opcode)
			}
			got = append(got, string(p))
		}
		// The residual, asserted: two messages are two scans, and neither half
		// matches a rule alone. Thus the token reaches the origin in the pieces
		// that the agent chose. A receiver that joins them has the token again.
		if strings.Join(got, "") != "lead "+live+" tail" {
			t.Fatalf("messages came back as %q", got)
		}
		closeEchoWS(t, s)
		if raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl")); len(raw) != 0 {
			t.Fatalf("a message-boundary split logged a strip after all: %s", raw)
		}
	})
}

// A control frame is 125 bytes that the agent chooses. The fixture pong
// carries back all that the fence left in the ping.
func TestEchoWebSocketStripsAControlPayload(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	live := "ghp_" + strings.Repeat("a", 36)
	s := openEchoWS(t, b)
	s.send(string(maskedFrame(true, opPing, []byte("k="+live))))
	h, p, err := nextFrame(s.br)
	if err != nil {
		t.Fatal(err)
	}
	if h.opcode != opPong || string(p) != "k=pf_stripped" {
		t.Fatalf("pong: opcode=%d payload=%q", h.opcode, p)
	}
	closeEchoWS(t, s)
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"where":"ws"`) {
		t.Fatalf("no ws strip row for the ping: %s", raw)
	}
}

// Off the lab, and at all locations where the fixture is not, the broker
// refuses an upgrade exactly as before the fixture could answer one.
func TestEchoWebSocketUpgradeRefusedOutsideTheOnePath(t *testing.T) {
	openEcho := preamble.Preamble{
		SNI:     "pf-open-echo.test",
		OrigDst: netip.MustParseAddrPort("192.0.2.3:443"),
		Src:     coreEcho.Src,
	}
	for _, tc := range []struct {
		name string
		lab  bool
		p    preamble.Preamble
		raw  string
		code int
		body string
	}{
		{"without -lab-echo the core fixture is lab_only", false, coreEcho, echoWSHandshake(echoWSPath), 403, "lab_only"},
		{"on any other path it is still a 501", true, coreEcho, echoWSHandshake("/socket"), 501, "upgrade"},
		{"a query does not smuggle the path past the check", true, coreEcho, echoWSHandshake("/other?x=/ws"), 501, "upgrade"},
		{"the open fixture never upgrades", true, openEcho, strings.Replace(echoWSHandshake(echoWSPath), "pf-core-echo.test", "pf-open-echo.test", 1), 501, "upgrade"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			b.LabEcho = tc.lab
			var dialed atomic.Bool
			b.DialTLS = noDial(&dialed)
			s := open(t, b, tc.p)
			s.send(tc.raw)
			resp := s.read()
			if resp.Code != tc.code || !strings.Contains(string(resp.Body), tc.body) {
				t.Fatalf("code %d body %q", resp.Code, resp.Body)
			}
			_ = s.close()
			if dialed.Load() {
				t.Fatal("a refused upgrade reached an origin")
			}
		})
	}
}
