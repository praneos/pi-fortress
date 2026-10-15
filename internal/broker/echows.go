package broker

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"strings"

	"pi-fortress/internal/httpwire"
)

// echoWSPath is the one target on which the core fixture switches
// protocols. Each other target that it gets an upgrade request for stays
// the 501 that all other upgrades get. An end-to-end proof of the frame
// scrub needs only one path, and a narrow door is easier to analyze than
// a wide one.
const echoWSPath = "/ws"

// wsGUID is the RFC 6455 4.2.2 constant. The SHA-1 behind
// Sec-WebSocket-Accept is the handshake proof that the peer read the key.
// It is not a security property of this fence; the protocol names the
// digest.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// echoUpgrade reports that the lab fixture itself answers this
// handshake. Only the core fixture, only under -lab-echo, only on one
// path. Off the lab, the broker already refuses the core fixture fully
// (admit runs that gate first). Thus nothing here changes what a shipped
// box does. The open fixture is reachable from a shipped box and keeps
// its 501.
func (b *Broker) echoUpgrade(c *call) bool {
	return b.LabEcho && c.echoRole == "core" && pathOnly(c.req.Target) == echoWSPath
}

// echoWSOrigin gives the call an origin that is not on the network: one
// end of a net.Pipe, with the fixture's own peer on the other end. All
// the code after it (roundTrip, the 101, serveWS, both frame pumps) is
// the code that a real wss connection runs. Thus the agent gets back
// what the fence would put on the uplink. A second implementation of
// frame handling inside the echo would only prove itself.
func (b *Broker) echoWSOrigin(c *call) {
	origin, peer := net.Pipe()
	c.up.conn = b.idleOrigin(origin)
	c.up.br = bufio.NewReader(c.up.conn)
	go echoWSPeer(peer)
}

// echoWSPeer is the fixture end of the pipe: an RFC 6455 server that
// answers the handshake and sends each frame back as it arrived. It
// never scrubs and never substitutes. The frames that reach it have
// already crossed the fence. To reflect them unchanged is the full
// purpose: the agent reads what left.
func echoWSPeer(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := httpwire.ReadRequest(br)
	if err != nil {
		return
	}
	head := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(strings.TrimSpace(req.Get("Sec-WebSocket-Key"))) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	for {
		h, err := readWSHeader(br, defaultMaxMessage)
		if err != nil {
			return
		}
		payload := make([]byte, h.length)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		if h.masked {
			wsMask(payload, h.key)
		}
		op := h.opcode
		switch op {
		case opPong:
			// An unsolicited pong (RFC 6455 5.5.3). If the fixture reflected it as a
			// ping, the fixture would start an exchange of its own.
			continue
		case opPing:
			op = opPong
		}
		// This is the server leg, and a server frame is never masked
		// (RFC 6455 5.1). The fence forwards it to the agent byte for
		// byte, so these bytes are the assertion.
		frame := append(appendWSHeader(nil, h.fin, op, nil, len(payload)), payload...)
		if _, err := conn.Write(frame); err != nil {
			return
		}
		if op == opClose {
			return
		}
	}
}
