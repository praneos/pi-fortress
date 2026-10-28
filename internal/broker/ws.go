package broker

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/placeholder"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

var (
	ErrWSRSV       = errors.New("broker: websocket frame sets a reserved bit")
	ErrWSOpcode    = errors.New("broker: websocket frame has a reserved opcode")
	ErrWSMask      = errors.New("broker: websocket frame is masked the wrong way")
	ErrWSControl   = errors.New("broker: websocket control frame is fragmented or oversized")
	ErrWSLength    = errors.New("broker: websocket frame length has the reserved high bit")
	ErrWSTooBig    = errors.New("broker: websocket message over the size bound")
	ErrWSBusy      = errors.New("broker: websocket message over the broker's byte budget")
	ErrWSExtension = errors.New("broker: origin accepted a websocket extension the fence did not offer")
	ErrWSProtocol  = errors.New("broker: origin switched to a protocol the fence did not ask for")
	ErrWSFragment  = errors.New("broker: websocket fragmentation is malformed")
	// ErrWSPlaceholder: an agent frame carried a placeholder. The broker did
	// not forward that frame.
	ErrWSPlaceholder = errors.New("broker: websocket frame carries a placeholder")
)

// errWSDone: the connection stopped HTTP at the 101, and both legs are
// closed. Handle must not look for another request on it.
var errWSDone = errors.New("broker: websocket session ended")

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA

	maxControlPayload = 125

	// defaultMaxMessage caps one agent-to-origin message, as the sum of its
	// fragments. The broker buffers that direction whole, because the scrub
	// must see a whole message. The agent can split a token across two
	// fragments. The old cap was 16 MiB. The broker allocated it at the start,
	// from the length that a frame declared, and copied it approximately three
	// times on the way out. Thus each connection held approximately 50 MiB, and
	// approximately 70 connections exhausted the 4 GB of the Pi. Now the buffer
	// grows only when bytes arrive. Each step takes from the broker-wide byte
	// budget (membudget.go). Thus the budget bounds the sum over all sockets,
	// not this cap times 256. This cap bounds only one message. Most of the
	// data that an agent sends is small JSON (chat turns, tool results, ~100 ms
	// audio chunks). Some data is larger. An inline image in a realtime event
	// is base64, so a 3.5 MB phone photo is approximately 4.7 MB on the wire.
	// A file upload from a remote browser, or a notebook cell with data, can be
	// megabytes. 5 MiB covers these. At two live copies, approximately 25 such
	// messages fit the default budget at the same time. The broker closes the
	// next one with 1013, not 1009. The cap still refuses a full recording in
	// one event (the OpenAI realtime API accepts up to 15 MiB per append). The
	// broker closes it with 1009 and logs it. The fix is to send it in chunks.
	defaultMaxMessage = 5 << 20

	// maxOriginMessage is the origin-to-agent bound. It is larger on purpose.
	// The broker forwards that direction frame by frame and never buffers it,
	// so its size costs the Pi nothing. Also, realtime APIs send bigger events
	// to the agent (full audio responses, transcripts) than the agent sends to
	// them. The bound stays as a sanity bound on a length field that the origin
	// selects. It is not a memory bound.
	maxOriginMessage = 16 << 20

	// wsReadStep is the maximum part of a declared frame that the broker
	// allocates before the bytes that fill it arrive. A header can declare a
	// megabyte and send ten bytes. The buffer grows when bytes arrive, never
	// from the declared length.
	wsReadStep = 32 << 10
	// wsKeepCap is the largest message buffer that the broker keeps across
	// messages. A session can send one big message and then stay idle for an
	// hour. That session gives back the remainder. It does not hold it for the
	// life of the socket.
	wsKeepCap = 64 << 10
	// wsCoalesce is the largest frame that the broker writes as one Write. The
	// broker writes a bigger frame as header then payload, so it never copies
	// the payload to put it behind a header. It coalesces smaller frames, so a
	// chat turn is one TLS record, not two.
	wsCoalesce = 16 << 10

	// RFC 6455 7.4.1 status codes the broker sends itself.
	closeGoingAway = 1001
	closePolicy    = 1008
	closeTooBig    = 1009
	// closeTryAgain is 1013 (IANA registry, "Try Again Later"). The message was
	// in its own bound, but the byte budget of the broker (membudget.go) had no
	// space to buffer it. The agent can connect again.
	closeTryAgain = 1013

	// ruleTooBig is the strip.jsonl rule for a message that the broker closed
	// for size. Count is the size that the message reached. Limit is the bound
	// that it crossed.
	ruleTooBig = "message_too_big"
)

func (b *Broker) maxMessage() int64 {
	if b.MaxMessage > 0 {
		return b.MaxMessage
	}
	return defaultMaxMessage
}

// headerToken reports whether a comma-separated header value carries tok.
func headerToken(v, tok string) bool {
	for part := range strings.SplitSeq(strings.ToLower(v), ",") {
		if strings.TrimSpace(part) == tok {
			return true
		}
	}
	return false
}

// isWebSocketUpgrade reports a complete RFC 6455 handshake. A request that
// is less than that stays a 501. The fence forwards a protocol switch only
// when it can parse the data after the switch. A handshake that carries a
// body is a smuggling shape, not a websocket.
func isWebSocketUpgrade(req *httpwire.Request) bool {
	if req.Method != "GET" || req.Chunked || req.ContentLength > 0 {
		return false
	}
	if len(req.Values("Upgrade")) != 1 || !strings.EqualFold(strings.TrimSpace(req.Get("Upgrade")), "websocket") {
		return false
	}
	if !headerToken(req.Get("Connection"), "upgrade") {
		return false
	}
	if strings.TrimSpace(req.Get("Sec-WebSocket-Key")) == "" {
		return false
	}
	return strings.TrimSpace(req.Get("Sec-WebSocket-Version")) == "13"
}

type wsHeader struct {
	fin    bool
	opcode byte
	masked bool
	key    [4]byte
	length int64
	// raw is the header exactly as it arrived. Thus a direction that forwards
	// frames without change puts the same bytes back on the wire.
	raw []byte
}

func (h wsHeader) control() bool { return h.opcode&0x8 != 0 }

// readWSHeader parses one frame header. max bounds a single frame before
// any allocation. The caller applies the per-message bound.
func readWSHeader(br *bufio.Reader, max int64) (wsHeader, error) {
	var h wsHeader
	var b [14]byte
	if _, err := io.ReadFull(br, b[:2]); err != nil {
		return h, err
	}
	if b[0]&0x70 != 0 {
		// RSV1..3 are extension bits. The fence strips each extension offer, so a
		// set bit means frames that the fence cannot read.
		return h, ErrWSRSV
	}
	h.fin = b[0]&0x80 != 0
	h.opcode = b[0] & 0x0f
	switch h.opcode {
	case opContinuation, opText, opBinary, opClose, opPing, opPong:
	default:
		return h, ErrWSOpcode
	}
	h.masked = b[1]&0x80 != 0
	n := 2
	switch l := b[1] & 0x7f; l {
	case 126:
		if _, err := io.ReadFull(br, b[2:4]); err != nil {
			return h, err
		}
		n = 4
		h.length = int64(binary.BigEndian.Uint16(b[2:4]))
	case 127:
		if _, err := io.ReadFull(br, b[2:10]); err != nil {
			return h, err
		}
		n = 10
		v := binary.BigEndian.Uint64(b[2:10])
		if v&(1<<63) != 0 {
			return h, ErrWSLength
		}
		h.length = int64(v)
	default:
		h.length = int64(l)
	}
	if h.masked {
		if _, err := io.ReadFull(br, b[n:n+4]); err != nil {
			return h, err
		}
		copy(h.key[:], b[n:n+4])
		n += 4
	}
	if h.control() && (!h.fin || h.length > maxControlPayload) {
		return h, ErrWSControl
	}
	if max > 0 && h.length > max {
		return h, ErrWSTooBig
	}
	h.raw = append([]byte(nil), b[:n]...)
	return h, nil
}

// appendWSHeader writes a header in the minimal length form. It is for the
// client leg. On that leg the payload length changes when the fence strips
// a token, and the broker makes a new mask key anyway.
func appendWSHeader(dst []byte, fin bool, opcode byte, key *[4]byte, n int) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	mask := byte(0)
	if key != nil {
		mask = 0x80
	}
	dst = append(dst, first)
	switch {
	case n < 126:
		dst = append(dst, mask|byte(n))
	case n <= 0xffff:
		dst = append(dst, mask|126, byte(n>>8), byte(n))
	default:
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		dst = append(dst, mask|127)
		dst = append(dst, l[:]...)
	}
	if key != nil {
		dst = append(dst, key[:]...)
	}
	return dst
}

func wsMask(p []byte, key [4]byte) {
	for i := range p {
		p[i] ^= key[i&3]
	}
}

// serveWS takes control of both legs after the origin agrees to the switch.
// The broker terminates TLS on both sides. Thus the frames here are
// plaintext RFC 6455, and each client frame carries its own mask key. The
// broker can scan the payload.
//
// substituted is true when the handshake carried a credential that the
// fence wrote in. In that case, the origin holds a live value that it can
// reflect into any frame. Thus the broker scrubs the origin frames as it
// scrubs a response body (originScrub). Otherwise the frames pass byte for
// byte.
func (b *Broker) serveWS(client net.Conn, cbr *bufio.Reader, up *upstream, ubr *bufio.Reader, p *preamble.Preamble, req *httpwire.Request, resp *httpwire.Response, slots map[string]secrets.Slot, host string, cp *stripCap, substituted bool) error {
	defer up.discard()
	if resp.Get("Sec-WebSocket-Extensions") != "" {
		// The broker removed the offer from the request, so an accept answers an
		// extension that nobody offered. The scan cannot see into
		// permessage-deflate frames. Nothing of this goes to the client.
		_ = b.logStrip(cp, clientIP(p), host, "ws", "extension")
		return ErrWSExtension
	}
	if !headerToken(resp.Get("Upgrade"), "websocket") {
		return ErrWSProtocol
	}
	// Send the 101 verbatim, minus a live credential that the origin reflected
	// into the handshake. That credential is the incident that docs/fence.md
	// §5.2 describes. It is not a header that the client needs. A credential
	// in a field name cannot be removed, so the switch does not occur.
	hit, err := rewriteHeaders(resp, slots)
	for _, key := range hit {
		_ = b.logStrip(cp, clientIP(p), host, "response", "secret:"+key)
	}
	if err != nil {
		_ = writeErr(client, 502, "502 Bad Gateway", "origin\n")
		return err
	}
	if _, err := resp.WriteTo(client); err != nil {
		return err
	}
	// Strip only, never inject: the reasoning is on fence.NewScanner.
	sc := fence.NewScanner(fence.Ctx{SNI: p.SNI, TokenRE: b.TokenRE, Rules: b.Rules, StripCore: b.StripCore}, req, b.Policy, slots)
	_ = b.logWS(p, req, host, "ws_open", 0, 0)
	var osc *originScrub
	if substituted {
		osc = newOriginScrub(slots)
	}
	sent, recv, err := b.relayWS(client, cbr, up.conn, ubr, sc, osc, host, clientIP(p), cp)
	_ = b.logWS(p, req, host, "ws_close", sent, recv)
	if err != nil {
		return err
	}
	return errWSDone
}

// relayWS runs both directions until one of them ends. Then it closes both
// legs, so the blocked read of the other direction returns.
//
// An agent message over the bound ends the session with a 1009 to the
// agent. relayWS sends the 1009 here, after both pumps are done. It closes
// the origin leg first, which ends the read of the other pump. It writes
// the close frame only when that pump did not stop in the middle of a
// frame. A close frame after half a frame is garbage to the client.
func (b *Broker) relayWS(client net.Conn, cbr *bufio.Reader, origin net.Conn, obr *bufio.Reader, sc *fence.Scanner, osc *originScrub, host, ip string, cp *stripCap) (int64, int64, error) {
	var sent, recv int64
	var mu sync.Mutex
	var first error
	// After one direction stops the session, the read of the other direction
	// fails because the broker closed it, not because the peer misbehaved.
	var down atomic.Bool
	fail := func(err error) {
		if err == nil || down.Load() || errors.Is(err, io.EOF) {
			return
		}
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
	}
	// Elsewhere, Idle is the budget of the broker for the full connection.
	// Here it is the gap between frames. A frame in either direction resets it.
	touch := func() {
		dl := time.Now().Add(b.idle())
		_ = client.SetDeadline(dl)
		_ = origin.SetDeadline(dl)
	}
	stop := func() {
		down.Store(true)
		_ = client.Close()
		_ = origin.Close()
	}
	// A direction that forwarded a close frame returns nil and does not stop
	// the other direction. Thus the close reply of the peer still gets to the
	// side that started the closing handshake (RFC 6455 5.5.1). Idle bounds a
	// peer that never answers.
	// closeCode is set before the broker closes the origin leg for an agent
	// message that the broker does not buffer (1009 over its bound, 1013 over
	// the byte budget). That close ends the read of the other pump. Because
	// closeCode is set, that pump keeps the client leg open for the close
	// frame. It does not close the client leg too.
	var closeCode atomic.Uint32
	end := func(err error) {
		if err != nil {
			if closeCode.Load() != 0 {
				return
			}
			stop()
			return
		}
		down.Store(true)
	}
	var torn bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := b.wsToOrigin(cbr, origin, sc, host, ip, cp, touch)
		sent = n
		fail(err)
		if code := agentCloseCode(err); code != 0 {
			// The client leg stays open for the close frame. Only the origin leg
			// closes now. This also ends the other pump.
			closeCode.Store(uint32(code))
			down.Store(true)
			_ = origin.Close()
			return
		}
		end(err)
	}()
	go func() {
		defer wg.Done()
		n, err := b.wsToClient(obr, client, osc, host, ip, cp, touch, &torn)
		recv = n
		fail(err)
		end(err)
	}()
	wg.Wait()
	if code := closeCode.Load(); code != 0 && !torn {
		_ = writeCloseFrame(client, uint16(code), closeReason(uint16(code)))
	}
	stop()
	return sent, recv, first
}

// agentCloseCode is the close status that the agent gets for an error that
// ended its direction by decision of the broker. For all other ends it is 0.
func agentCloseCode(err error) uint16 {
	switch {
	case errors.Is(err, ErrWSTooBig):
		return closeTooBig
	case errors.Is(err, ErrWSBusy):
		return closeTryAgain
	case errors.Is(err, ErrWSPlaceholder):
		return closePolicy
	}
	return 0
}

func closeReason(code uint16) string {
	switch code {
	case closeTryAgain:
		return "try again later"
	case closePolicy:
		return "policy violation"
	}
	return "message too big"
}

// writeMaskedFrame sends one client-to-origin frame in the minimal length
// form with a new mask key. The origin does not care which key masked a
// frame, only that a key did. writeMaskedFrame masks payload in place.
// Each caller gives a buffer that it does not use again. A masked copy was
// one of the copies that a megabyte message cost before.
func writeMaskedFrame(dst io.Writer, fin bool, opcode byte, payload []byte) (int, error) {
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return 0, err
	}
	wsMask(payload, key)
	if len(payload) <= wsCoalesce {
		frame := appendWSHeader(make([]byte, 0, 14+len(payload)), fin, opcode, &key, len(payload))
		if _, err := dst.Write(append(frame, payload...)); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	var hdr [14]byte
	if _, err := dst.Write(appendWSHeader(hdr[:0], fin, opcode, &key, len(payload))); err != nil {
		return 0, err
	}
	if _, err := dst.Write(payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// closePayload is a close frame body: the status code, then a reason.
func closePayload(code uint16, reason string) []byte {
	return append([]byte{byte(code >> 8), byte(code)}, reason...)
}

// writeCloseFrame sends the agent an unmasked (server) close frame.
func writeCloseFrame(dst io.Writer, code uint16, reason string) error {
	p := closePayload(code, reason)
	_, err := dst.Write(append(appendWSHeader(nil, true, opClose, nil, len(p)), p...))
	return err
}

// readGrow appends n bytes from src to buf. buf grows when the bytes
// arrive. It grows at most wsReadStep ahead of the bytes read, and never
// past limit. It doubles each time, so a megabyte costs a few allocations.
// The declared length of a frame is the claim of the peer. Memory follows
// the bytes. If take is set, readGrow asks it for the added capacity of
// each growth before the allocation. If take refuses, readGrow stops with
// ErrWSBusy, and buf does not change.
func readGrow(src io.Reader, buf []byte, n, limit int64, take func(grow int64) bool) ([]byte, error) {
	for n > 0 {
		step := int(min(n, wsReadStep))
		if cap(buf)-len(buf) < step {
			nc := max(len(buf)+step, min(2*cap(buf), int(limit)))
			if take != nil && !take(int64(nc-cap(buf))) {
				return buf, ErrWSBusy
			}
			nb := make([]byte, len(buf), nc)
			copy(nb, buf)
			buf = nb
		}
		m, err := io.ReadFull(src, buf[len(buf):len(buf)+step])
		buf = buf[:len(buf)+m]
		if err != nil {
			return buf, err
		}
		n -= int64(step)
	}
	return buf, nil
}

// logTooBig writes the row for a message that the broker closed for size.
// The row goes to the strip log, next to the extension refusal. Reason: the
// fence ends a session, and the operator reads that file for such events.
// The strip cap of the request does not apply to this row. The row ends
// the session, so there is only one. A session that used all its rows on
// scrubbed tokens must still tell why the broker cut it.
func (b *Broker) logTooBig(ip, host, where string, size, limit int64) {
	if b.Logs == nil {
		return
	}
	_ = b.Logs.Strip(jsonl.Strip{Host: host, Where: where, Rule: ruleTooBig, ClientIP: ip, Count: size, Limit: limit})
}

// wsPlaceholder reports the first placeholder in p. The fence substitutes
// into no frame, so the broker cannot forward a placeholder in one. A
// rewrite to a live value would give the agent a credential that it did
// not have. If the placeholder goes out as written, the origin gets the
// slot ID and the kind, and a placeholder put into a prompt comes back
// transformed, past the literal scrub. Thus the only correct action is to
// refuse the frame.
func wsPlaceholder(p []byte) (slot, kind string, ok bool) {
	sp := placeholder.FindPlaceholderSpans(p)
	if len(sp) == 0 {
		return "", "", false
	}
	slot, kind = placeholder.PlaceholderParts(p, sp[0])
	return slot, kind, true
}

// logWSPlaceholder writes the refusal row for a frame that carried a
// placeholder. Like logTooBig, it does not use the strip cap of the
// request: the row ends the session, so there is only one.
func (b *Broker) logWSPlaceholder(ip, host, slot, kind string) {
	if b.Logs == nil {
		return
	}
	canary := kind == corepolicy.KindCanary
	row := jsonl.Refused{
		Host:     host,
		Where:    "ws",
		Cause:    string(fence.CausePlaceholderInWS),
		Slot:     slot,
		Kind:     kind,
		Alert:    canary || b.alertRefusal(fence.CausePlaceholderInWS),
		ClientIP: ip,
	}
	if canary {
		row.Threat = threatCanary
	}
	_ = b.Logs.Refused(row)
}

// wsToOrigin reassembles each client data message from its fragments. It
// scans the full message for credentials one time, and forwards it as a
// single frame. A per-frame scan would miss a token split across a fragment
// boundary. The sender (the agent, here the adversary) selects that
// boundary. The HTTP body path guards the same boundary with an overlap
// carry (internal/httpwire/stream.go). This is the analogue for frames. A
// proxy can coalesce fragments into one frame: the origin gets the same
// message. The broker forwards control frames in order, also when they
// arrive between fragments. It also scrubs their payloads. A ping body or
// a close reason is 125 bytes that the agent selects. That is space for any
// token that this fence strips.
//
// A placeholder in a whole message or in a control payload ends the
// session (wsPlaceholder). The broker does not forward that frame. The
// origin gets a going-away close, and the agent gets 1008. The scan runs on
// the reassembled message, so a placeholder split across fragments is also
// found.
func (b *Broker) wsToOrigin(src *bufio.Reader, dst io.Writer, sc *fence.Scanner, host, ip string, cp *stripCap, touch func()) (int64, error) {
	limit := b.maxMessage()
	var total int64
	var msg []byte
	var msgOp byte
	var ctl [maxControlPayload]byte
	inMsg := false
	// tooBig ends the session for a message over limit. It does this at a
	// frame boundary on the origin leg (the broker wrote nothing of this
	// frame). Thus the origin gets a correct close before its connection goes.
	tooBig := func(size int64) (int64, error) {
		b.logTooBig(ip, host, "ws", size, limit)
		_, _ = writeMaskedFrame(dst, true, opClose, closePayload(closeGoingAway, ""))
		return total, ErrWSTooBig
	}
	// held is the capacity of the message buffer. While the broker scrubs and
	// writes a message, held also includes space for the scrub copy. All of it
	// comes from the byte budget of the broker before the allocation. It goes
	// back when the buffer shrinks and when this direction ends, however it ends.
	var held int64
	defer b.memGive(&held)
	take := func(n int64) bool { return b.memTake(&held, n) }
	// busy ends the session as tooBig does, at a frame boundary on the origin
	// leg. It is for a message that the budget has no space for. The agent gets
	// a close with 1013, which invites a retry. A 1009 does not.
	busy := func() (int64, error) {
		b.logMemBudget(ip, host, "ws")
		_, _ = writeMaskedFrame(dst, true, opClose, closePayload(closeGoingAway, ""))
		return total, ErrWSBusy
	}
	// refuse ends the session for a placeholder, at a frame boundary on the
	// origin leg, as tooBig does. The origin gets the same close as for size.
	// Thus it cannot tell that the fence found a placeholder.
	refuse := func(p []byte) error {
		slot, kind, ok := wsPlaceholder(p)
		if !ok {
			return nil
		}
		b.logWSPlaceholder(ip, host, slot, kind)
		_, _ = writeMaskedFrame(dst, true, opClose, closePayload(closeGoingAway, ""))
		return ErrWSPlaceholder
	}
	for {
		h, err := readWSHeader(src, limit)
		if errors.Is(err, ErrWSTooBig) {
			return tooBig(int64(len(msg)) + h.length)
		}
		if err != nil {
			return total, err
		}
		touch()
		if !h.masked {
			// RFC 6455 5.1: a client frame is always masked. A frame that is not masked
			// comes from a broken client, or from someone who replays our own bytes.
			return total, ErrWSMask
		}
		if h.control() {
			payload := ctl[:h.length]
			if _, err := io.ReadFull(src, payload); err != nil {
				return total, err
			}
			wsMask(payload, h.key)
			if err := refuse(payload); err != nil {
				return total, err
			}
			out := b.scrubControl(sc, host, ip, cp, h.opcode, payload)
			if len(out) > maxControlPayload {
				return total, ErrWSControl
			}
			n, err := writeMaskedFrame(dst, h.fin, h.opcode, out)
			if err != nil {
				return total, err
			}
			total += int64(n)
			if h.opcode == opClose {
				return total, nil
			}
			continue
		}
		if h.opcode == opContinuation {
			if !inMsg {
				return total, ErrWSFragment
			}
		} else {
			if inMsg {
				// A new data message began before the last one finished.
				return total, ErrWSFragment
			}
			inMsg, msgOp = true, h.opcode
		}
		// The broker adds the fragments together. The bound applies to a message,
		// not a frame. Otherwise a thousand 1 MiB fragments are one 1 GiB message.
		if int64(len(msg))+h.length > limit {
			return tooBig(int64(len(msg)) + h.length)
		}
		// Read directly into the message and unmask there. The old separate
		// per-frame buffer, which the code appended from, is gone.
		off := len(msg)
		msg, err = readGrow(src, msg, h.length, limit, take)
		if errors.Is(err, ErrWSBusy) {
			return busy()
		}
		if err != nil {
			return total, err
		}
		wsMask(msg[off:], h.key)
		if !h.fin {
			continue
		}
		if err := refuse(msg); err != nil {
			return total, err
		}
		// The scrub copy, taken from the budget while the broker writes it.
		scrubCost := int64(len(msg))
		if !take(scrubCost) {
			return busy()
		}
		// Text, binary and their continuations are all application data. A token
		// is ASCII, whichever type the frame claims to be.
		out, evs := sc.Scrub(msg, "ws")
		for _, ev := range evs {
			_ = b.logStrip(cp, ip, host, ev.Where, ev.Rule)
		}
		n, err := writeMaskedFrame(dst, true, msgOp, out)
		b.mem.release(scrubCost)
		held -= scrubCost
		if err != nil {
			return total, err
		}
		total += int64(n)
		if cap(msg) > wsKeepCap {
			msg = nil
			b.memGive(&held)
		} else {
			msg = msg[:0]
		}
		inMsg = false
	}
}

// scrubControl strips credentials from a control payload. A close frame
// keeps its two-byte status code, and the scrub starts after it. Ping and
// pong are scrubbed whole. A one-byte close is malformed under RFC 6455 and
// too short to carry anything, so it passes unchanged.
func (b *Broker) scrubControl(sc *fence.Scanner, host, ip string, cp *stripCap, opcode byte, payload []byte) []byte {
	skip := 0
	if opcode == opClose {
		if len(payload) < 2 {
			return payload
		}
		skip = 2
	}
	out, evs := sc.Scrub(payload[skip:], "ws")
	for _, ev := range evs {
		_ = b.logStrip(cp, ip, host, ev.Where, ev.Rule)
	}
	if len(evs) == 0 {
		return payload
	}
	return append(append([]byte(nil), payload[:skip]...), out...)
}

// originScrub rewrites the origin frames for a session whose handshake had
// a substitution. It changes each live value back to its placeholder, as
// the HTTP response scrub does. One scrubber runs per data message, across
// its fragments, so it catches a value that the origin splits over two
// frames. The broker fragments the message again on the way out. RFC 6455
// 5.4 permits an intermediary to do this when no extension is in use, and
// the fence strips each extension offer. Control payloads are scrubbed whole.
type originScrub struct {
	pairs [][2][]byte
	keys  []string
	sc    *httpwire.Scrubber
	seen  []int
	buf   []byte
	out   []byte
	// opSent is true after the first frame of the current message has gone
	// out. That frame carries the opcode.
	msgOp  byte
	opSent bool
}

func newOriginScrub(slots map[string]secrets.Slot) *originScrub {
	pairs, keys := scrubPairs(slots)
	if len(pairs) == 0 {
		return nil
	}
	return &originScrub{pairs: pairs, keys: keys, sc: httpwire.NewScrubber(nil, pairs), seen: make([]int, len(pairs))}
}

// hits names the slots whose values were rewritten since the last call.
func (o *originScrub) hits() []string {
	var out []string
	for i, n := range o.sc.Counts {
		if n > o.seen[i] {
			out = append(out, o.keys[i])
			o.seen[i] = n
		}
	}
	return out
}

// control scrubs a control payload. For a close frame, it scrubs the part
// after the status code. ok is false when the rewrite became larger than
// the bound of a control frame.
func (o *originScrub) control(opcode byte, payload []byte) (out []byte, hit []string, ok bool) {
	skip := 0
	if opcode == opClose && len(payload) >= 2 {
		skip = 2
	}
	counts := make([]int, len(o.pairs))
	out = httpwire.ReplaceAll(append([]byte(nil), payload[:skip]...), payload[skip:], o.pairs, counts)
	for i, n := range counts {
		if n > 0 {
			hit = append(hit, o.keys[i])
		}
	}
	return out, hit, len(out) <= maxControlPayload
}

// wsToClient validates each origin frame header. It forwards the frame
// byte for byte, or scrubbed when osc is set (originScrub). In both cases,
// the broker buffers no more than one read step. That is why the bound of
// this direction is maxOriginMessage and not the agent bound. torn is set
// while a frame is half written, so relayWS knows if a close frame can
// follow.
func (b *Broker) wsToClient(src *bufio.Reader, dst io.Writer, osc *originScrub, host, ip string, cp *stripCap, touch func(), torn *bool) (int64, error) {
	const limit = maxOriginMessage
	var msg, total int64
	tooBig := func(size int64) (int64, error) {
		// At a frame boundary on the client leg: the broker read the header of this
		// frame, but did not write it. This pump is the only writer to the client.
		b.logTooBig(ip, host, "ws_origin", size, limit)
		_ = writeCloseFrame(dst, closeTooBig, "message too big")
		return total, ErrWSTooBig
	}
	for {
		h, err := readWSHeader(src, limit)
		if errors.Is(err, ErrWSTooBig) {
			return tooBig(msg + h.length)
		}
		if err != nil {
			return total, err
		}
		touch()
		if h.masked {
			// RFC 6455 5.1: a server frame is never masked.
			return total, ErrWSMask
		}
		if !h.control() {
			if msg+h.length > limit {
				return tooBig(msg + h.length)
			}
			msg += h.length
			if h.fin {
				msg = 0
			}
		}
		if osc != nil {
			if err := b.scrubToClient(src, dst, osc, h, host, ip, cp, torn); err != nil {
				return total, err
			}
		} else {
			*torn = true
			if _, err := dst.Write(h.raw); err != nil {
				return total, err
			}
			if h.length > 0 {
				if _, err := io.CopyN(dst, src, h.length); err != nil {
					return total, err
				}
			}
			*torn = false
		}
		total += h.length
		if h.opcode == opClose {
			return total, nil
		}
	}
}

// scrubToClient forwards one origin frame through osc. It reads a data
// frame one step at a time. The scrubbed bytes of each step go out as a
// separate frame. The first frame has the opcode of the message, the frames
// after it are continuations, and the last frame has FIN. If the scrubber
// holds back all of a step, nothing goes out. Each frame is written whole,
// so torn is set only inside a Write.
func (b *Broker) scrubToClient(src *bufio.Reader, dst io.Writer, osc *originScrub, h wsHeader, host, ip string, cp *stripCap, torn *bool) error {
	emit := func(fin bool, opcode byte, payload []byte) error {
		frame := appendWSHeader(make([]byte, 0, 10+len(payload)), fin, opcode, nil, len(payload))
		*torn = true
		_, err := dst.Write(append(frame, payload...))
		*torn = false
		return err
	}
	if h.control() {
		var payload [maxControlPayload]byte
		if _, err := io.ReadFull(src, payload[:h.length]); err != nil {
			return err
		}
		out, hit, ok := osc.control(h.opcode, payload[:h.length])
		for _, key := range hit {
			_ = b.logStrip(cp, ip, host, "ws_origin", "secret:"+key)
		}
		if !ok {
			return ErrWSControl
		}
		return emit(true, h.opcode, out)
	}
	if h.opcode != opContinuation {
		osc.msgOp, osc.opSent = h.opcode, false
	}
	if osc.buf == nil {
		osc.buf = make([]byte, wsReadStep)
	}
	left := h.length
	for {
		n := min(left, int64(len(osc.buf)))
		if _, err := io.ReadFull(src, osc.buf[:n]); err != nil {
			return err
		}
		left -= n
		last := h.fin && left == 0
		osc.out = osc.sc.Push(osc.out[:0], osc.buf[:n], last)
		if len(osc.out) > 0 || last {
			op := byte(opContinuation)
			if !osc.opSent {
				op, osc.opSent = osc.msgOp, true
			}
			if err := emit(last, op, osc.out); err != nil {
				return err
			}
		}
		if last {
			for _, key := range osc.hits() {
				_ = b.logStrip(cp, ip, host, "ws_origin", "secret:"+key)
			}
		}
		if left == 0 {
			return nil
		}
	}
}

// logWS records the open and close of a relay. The strip log is the
// incident channel, and it would page the operator for each socket. Thus a
// session line goes to the unknown log. The TUI already reads broker rows
// there, and where=ws_* separates it from http.
func (b *Broker) logWS(p *preamble.Preamble, req *httpwire.Request, host, where string, sent, recv int64) error {
	if b.Logs == nil {
		return nil
	}
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	if sni == "" {
		sni = host
	}
	destIP, destPort := "", 0
	if p.OrigDst.IsValid() {
		destIP, destPort = p.OrigDst.Addr().String(), int(p.OrigDst.Port())
	}
	return b.Logs.Unknown(jsonl.Unknown{
		ClientIP:    clientIP(p),
		Host:        host,
		SNI:         sni,
		DestIP:      destIP,
		DestPort:    destPort,
		Method:      req.Method,
		Path:        pathOnly(req.Target),
		HTTPVersion: req.Proto,
		Where:       where,
		WSSent:      sent,
		WSRecv:      recv,
	})
}
