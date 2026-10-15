package broker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
)

// TestWSDeclaredLengthNotAllocated covers the allocation that the old
// reader made on the word of a peer. A frame header declares the full
// message bound and then sends a hundred bytes. The buffer must follow the
// bytes, so a run costs a read step, not the declared megabyte.
func TestWSDeclaredLengthNotAllocated(t *testing.T) {
	b, _ := testBroker(t)
	key := [4]byte{1, 2, 3, 4}
	wire := appendWSHeader(nil, true, opBinary, &key, defaultMaxMessage)
	wire = append(wire, bytes.Repeat([]byte("x"), 100)...)
	const runs = 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		_, err := b.wsToOrigin(bufio.NewReaderSize(bytes.NewReader(wire), 4096), io.Discard, nil, "h", "ip", nil, func() {})
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err=%v, want a short read", err)
		}
	}
	runtime.ReadMemStats(&after)
	per := (after.TotalAlloc - before.TotalAlloc) / runs
	if per > 128<<10 {
		t.Fatalf("a frame declaring %d bytes and sending 100 allocated %d bytes a run", defaultMaxMessage, per)
	}
}

// wsCloseCode reads the next frame from the client leg and returns its
// close status. It fails on a frame that is not a close.
func wsCloseCode(t *testing.T, br *bufio.Reader) uint16 {
	t.Helper()
	h, p, err := nextFrame(br)
	if err != nil {
		t.Fatalf("no close frame: %v", err)
	}
	if h.opcode != opClose || len(p) < 2 {
		t.Fatalf("frame opcode=%d payload=%q, want a close", h.opcode, p)
	}
	return binary.BigEndian.Uint16(p)
}

// wsOriginSees records the first frame the origin receives after the 101.
func wsOriginSees(t *testing.T, b *Broker) chan wsHeader {
	t.Helper()
	seen := make(chan wsHeader, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		h, p, err := nextFrame(br)
		if err != nil {
			close(seen)
			return
		}
		if h.opcode == opClose && len(p) >= 2 {
			h.length = int64(binary.BigEndian.Uint16(p))
		}
		seen <- h
		_, _ = io.Copy(io.Discard, br)
	})
	return seen
}

// TestWSOverCapCloses1009 covers both shapes of an over-bound message: one
// frame, and fragments that are each under the bound but whose sum is over
// it. The agent gets 1009. The origin gets a going-away close and never a
// byte of the message. strip.jsonl gets a row that names the size and the
// bound.
func TestWSOverCapCloses1009(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []byte
	}{
		{"one frame", maskedFrame(true, opText, bytes.Repeat([]byte("x"), 3000))},
		{"fragments", append(
			maskedFrame(false, opText, bytes.Repeat([]byte("x"), 1500)),
			maskedFrame(true, opContinuation, bytes.Repeat([]byte("x"), 1500))...,
		)},
		{"logging off", maskedFrame(true, opText, bytes.Repeat([]byte("x"), 3000))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir, noLog := "", tc.name == "logging off"
			if !noLog {
				dir = stripLog(t, b)
			}
			b.MaxMessage = 2048
			seen := wsOriginSees(t, b)
			s, resp := openWS(t, b, wsHandshake+"\r\n")
			if resp.Code != 101 {
				t.Fatalf("code %d", resp.Code)
			}
			s.send(string(tc.frames))
			if code := wsCloseCode(t, s.br); code != closeTooBig {
				t.Fatalf("close code %d, want %d", code, closeTooBig)
			}
			if err := waitErr(s); !errors.Is(err, ErrWSTooBig) {
				t.Fatalf("err=%v want ErrWSTooBig", err)
			}
			h, ok := <-seen
			if !ok || h.opcode != opClose || h.length != closeGoingAway {
				t.Fatalf("origin saw %+v (ok=%v), want only a %d close", h, ok, closeGoingAway)
			}
			if noLog {
				return
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
			for _, want := range []string{`"rule":"message_too_big"`, `"where":"ws"`, `"count":3000`, `"limit":2048`} {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("strip.jsonl lacks %s: %s", want, raw)
				}
			}
		})
	}
}

// TestWSOriginOverCapCloses1009 covers the origin direction. The broker
// refuses a frame header past maxOriginMessage on the header alone. The
// agent gets the same 1009.
func TestWSOriginOverCapCloses1009(t *testing.T) {
	b, _ := testBroker(t)
	dir := stripLog(t, b)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		_, _ = conn.Write(appendWSHeader(nil, true, opBinary, nil, maxOriginMessage+1))
		_, _ = io.Copy(io.Discard, br)
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	if code := wsCloseCode(t, s.br); code != closeTooBig {
		t.Fatalf("close code %d, want %d", code, closeTooBig)
	}
	if err := waitErr(s); !errors.Is(err, ErrWSTooBig) {
		t.Fatalf("err=%v want ErrWSTooBig", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "strip.jsonl"))
	if !strings.Contains(string(raw), `"where":"ws_origin"`) || !strings.Contains(string(raw), `"rule":"message_too_big"`) {
		t.Fatalf("no origin too-big row: %s", raw)
	}
}

// TestWSLargeMessageUnderCapRelayed covers the path where the copies were
// removed. A message bigger than wsCoalesce arrives in fragments. The
// broker reads it directly into the message buffer and writes it as header
// then payload. The origin must get it whole, as one frame, byte for byte.
// The size is a base64 phone photo (approximately 4.7 MB). The default cap
// exists to let this through.
func TestWSLargeMessageUnderCapRelayed(t *testing.T) {
	b, _ := testBroker(t)
	msg := make([]byte, 4700<<10)
	for i := range msg {
		msg[i] = byte('a' + i%26)
	}
	got := make(chan []byte, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, ws101)
		h, p, err := nextFrame(br)
		if err != nil || !h.fin || h.opcode != opBinary {
			got <- nil
			return
		}
		got <- p
		_, _ = conn.Write(plainFrame(true, opClose, nil))
		_, _, _ = nextFrame(br)
	})
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	third := len(msg) / 3
	s.send(string(maskedFrame(false, opBinary, msg[:third])) +
		string(maskedFrame(false, opContinuation, msg[third:2*third])) +
		string(maskedFrame(true, opContinuation, msg[2*third:])))
	if p := <-got; !bytes.Equal(p, msg) {
		t.Fatalf("origin got %d bytes, want the %d sent", len(p), len(msg))
	}
}
