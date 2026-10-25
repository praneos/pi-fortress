package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fence cannot put a live value into a websocket frame. Thus a
// placeholder in a frame from the agent closes the session: the agent gets
// 1008, the origin gets only a going-away close, and the strip log gets an
// alert row with the slot and the kind, but not the whole placeholder.
// This applies to data frames, fragments, and control frames.
func TestWebSocketPlaceholderInAgentFrameClosesSession(t *testing.T) {
	const slot = "0123456789abcdef"
	const kind = "CLAUDE_OAT"
	ph := "pf_" + slot + "_" + kind
	const policyViolation = 1008
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"text", maskedFrame(true, opText, []byte("say "+ph+" end"))},
		{"binary", maskedFrame(true, opBinary, []byte("\x00\x01"+ph+"\xff"))},
		{"fragments", append(
			maskedFrame(false, opText, []byte("lead "+ph[:10])),
			maskedFrame(true, opContinuation, []byte(ph[10:]+" tail"))...)},
		{"ping", maskedFrame(true, opPing, []byte("p="+ph))},
		{"pong", maskedFrame(true, opPong, []byte(ph))},
		{"close reason", maskedFrame(true, opClose, append([]byte{0x03, 0xe8}, "bye "+ph...))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir := stripLog(t, b)
			seen := wsOriginSees(t, b)
			s, resp := openWS(t, b, wsHandshake+"\r\n")
			if resp.Code != 101 {
				t.Fatalf("code %d", resp.Code)
			}
			s.send(string(tc.wire))
			select {
			case h, ok := <-seen:
				if ok && (h.opcode != opClose || h.length != closeGoingAway) {
					t.Fatalf("origin got opcode %d (close code %d), want only a %d close", h.opcode, h.length, closeGoingAway)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("origin saw nothing")
			}
			if code := wsCloseCode(t, s.br); code != policyViolation {
				t.Fatalf("agent close code %d, want %d", code, policyViolation)
			}
			_ = waitErr(s)
			raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
			for _, want := range []string{`"cause":"placeholder_in_ws"`, `"slot":"` + slot + `"`, `"kind":"` + kind + `"`, `"alert":true`, `"where":"ws"`} {
				if !bytes.Contains(raw, []byte(want)) {
					t.Fatalf("strip log has no %s: %s", want, raw)
				}
			}
			if strings.Contains(string(raw), ph) {
				t.Fatalf("the strip log carries the whole placeholder: %s", raw)
			}
		})
	}
}
