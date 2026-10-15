package broker

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
)

// readMessage reads frames until a data message is complete. It sends
// control frames to ctl. It returns the message, its opcode and the number
// of frames it came in.
func readMessage(t *testing.T, br *bufio.Reader, ctl func(wsHeader, []byte)) ([]byte, byte, int) {
	t.Helper()
	var msg []byte
	var op byte
	frames := 0
	for {
		h, p, err := nextFrame(br)
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		if h.masked {
			t.Fatal("a server frame reached the agent masked")
		}
		if h.control() {
			ctl(h, p)
			continue
		}
		if frames == 0 {
			if h.opcode == opContinuation {
				t.Fatal("a message opened with a continuation frame")
			}
			op = h.opcode
		} else if h.opcode != opContinuation {
			t.Fatalf("frame %d of a message has opcode %d", frames, h.opcode)
		}
		frames++
		msg = append(msg, p...)
		if h.fin {
			return msg, op, frames
		}
	}
}

// A handshake with a substitution from the fence gives the origin a live
// value. The origin can put it in any frame that it sends back. The broker
// scrubs those frames as it scrubs a response body. Whole frames, a value
// split across fragments, a ping, and a close reason all get to the agent
// with the placeholder. Each one is a strip row. Without a substitution,
// the frames pass byte for byte (TestWebSocketServerFramesByteExact).
func TestWebSocketOriginFramesScrubbedAfterSubstitution(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	dummy := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	got := make(chan string, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		got <- req.Get("Authorization")
		_, _ = io.WriteString(conn, ws101)
		var out []byte
		out = append(out, plainFrame(true, opText, []byte("whole "+live+" end"))...)
		out = append(out, plainFrame(false, opText, []byte("split "+live[:30]))...)
		out = append(out, plainFrame(true, opPing, []byte("ping "+live))...)
		out = append(out, plainFrame(false, opContinuation, []byte(live[30:50]))...)
		out = append(out, plainFrame(true, opContinuation, []byte(live[50:]+" end"))...)
		big := bytes.Repeat([]byte("x"), 3*wsReadStep)
		copy(big[wsReadStep-20:], live)
		out = append(out, plainFrame(true, opBinary, big)...)
		out = append(out, plainFrame(true, opClose, append([]byte{0x03, 0xe8}, "bye "+live...))...)
		_, _ = conn.Write(out)
		_, _, _ = nextFrame(br)
	})
	s, resp := openWS(t, b, wsHandshake+"Authorization: Bearer "+dummy+"\r\n\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	if auth := <-got; auth != "Bearer "+live {
		t.Fatalf("the handshake was not substituted: %q", auth)
	}
	var ctl [][]byte
	keep := func(h wsHeader, p []byte) { ctl = append(ctl, append([]byte{h.opcode}, p...)) }

	msg, op, _ := readMessage(t, s.br, keep)
	if op != opText || string(msg) != "whole "+dummy+" end" {
		t.Fatalf("whole frame: op %d %q", op, msg)
	}
	msg, op, frames := readMessage(t, s.br, keep)
	if op != opText || string(msg) != "split "+dummy+" end" || frames < 1 {
		t.Fatalf("split message: op %d frames %d %q", op, frames, msg)
	}
	if len(ctl) != 1 || ctl[0][0] != opPing || string(ctl[0][1:]) != "ping "+dummy {
		t.Fatalf("ping between fragments: %q", ctl)
	}
	msg, op, _ = readMessage(t, s.br, keep)
	want := bytes.Repeat([]byte("x"), 3*wsReadStep)
	copy(want[wsReadStep-20:], live)
	want = bytes.Replace(want, []byte(live), []byte(dummy), 1)
	if op != opBinary || !bytes.Equal(msg, want) {
		t.Fatalf("a value across a read step: op %d, %d bytes, live left: %v", op, len(msg), bytes.Contains(msg, []byte(live)))
	}
	h, p, err := nextFrame(s.br)
	if err != nil || h.opcode != opClose || string(p) != "\x03\xe8bye "+dummy {
		t.Fatalf("close: %v %d %q", err, h.opcode, p)
	}
	s.send(string(maskedFrame(true, opClose, []byte{0x03, 0xe8})))
	if err := waitErr(s); err != nil {
		t.Fatalf("handle err=%v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"where":"ws_origin"`) || !strings.Contains(string(raw), `"rule":"secret:b0b1b2b3b4b5b6b7_CLAUDE_OAT"`) {
		t.Fatalf("no ws_origin strip row: %s", raw)
	}
	if strings.Contains(string(raw), live) {
		t.Fatalf("the strip log carries the value: %s", raw)
	}
}
