//go:build vagrant

package itest

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// A websocket client for the agent VM, built from what an agent segment
// always has. vm/agent/provision.sh installs curl, dnsutils, iproute2,
// nftables and ca-certificates and nothing else. Thus the client is
// `openssl s_client` (ca-certificates depends on openssl), with base64
// and timeout from coreutils. python3 is provisioned on the Pi, not on
// the agent. The websocket support of curl is experimental and not
// enabled in the Debian build. Even where it is enabled, curl does not
// give back the socket to write our own frame on. This suite cannot
// depend on either of them for a hardware run.
//
// The frames are built here and given as one base64 blob. The full TLS
// stream comes back as base64. Thus nothing binary must survive a shell
// or an ssh channel on the way. coreecho.go uses the same shape for its
// scripts, for the same reason. The engine in front of the broker
// terminates TLS with the gateway CA that the VM already trusts, and uses
// HTTP/1.1 only. Thus a handshake written manually is sufficient.

// The RFC 6455 1.3 example key and the accept that it must produce. An
// assert on the accept shows that a peer read the key and answered it. It
// was not a relay that sent a 101 that it made up.
const (
	wsClientKey  = "dGhlIHNhbXBsZSBub25jZQ=="
	wsClientHash = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
)

const (
	wsOpText  = 0x1
	wsOpClose = 0x8
)

// wsClientFrame builds one client-to-server frame, always masked: RFC
// 6455 5.1 requires it, and the fence ends the session on an unmasked
// frame. Payloads here are short, so the 64-bit length form never occurs.
func wsClientFrame(opcode byte, payload []byte) []byte {
	key := [4]byte{0x21, 0x43, 0x65, 0x87}
	f := []byte{0x80 | opcode}
	if n := len(payload); n < 126 {
		f = append(f, 0x80|byte(n))
	} else {
		f = append(f, 0x80|126, byte(n>>8), byte(n))
	}
	f = append(f, key[:]...)
	off := len(f)
	f = append(f, payload...)
	for i := off; i < len(f); i++ {
		f[i] ^= key[(i-off)&3]
	}
	return f
}

// wsEcho opens a websocket from the agent VM to the lab echo, sends one
// text frame, runs the closing handshake and returns the payloads of the
// data frames that came back. Those frames are what the fence put on the
// origin leg. The fixture reflects only what it got. Thus what the agent
// reads here is what left the Pi.
func wsEcho(t *testing.T, host, path, payload string) []string {
	t.Helper()
	var raw []byte
	raw = append(raw, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: "+wsClientKey+"\r\nSec-WebSocket-Version: 13\r\n\r\n"...)
	raw = append(raw, wsClientFrame(wsOpText, []byte(payload))...)
	raw = append(raw, wsClientFrame(wsOpClose, []byte{0x03, 0xe8})...)
	cmd := "echo " + base64.StdEncoding.EncodeToString(raw) + " | base64 -d | " +
		"timeout 20 openssl s_client -quiet -ign_eof -connect " + host + ":443 -servername " + host +
		" 2>/dev/null | base64 -w0"
	out, err := ssh(t, 45*time.Second, "agent", cmd)
	out = strings.TrimSpace(out)
	if out == "" {
		t.Fatalf("the agent read nothing back from wss://%s%s: %v", host, path, err)
	}
	blob, derr := base64.StdEncoding.DecodeString(out)
	if derr != nil {
		t.Fatalf("the agent's reply is not base64 (%v): %q", derr, out)
	}
	return wsFramePayloads(t, blob)
}

// wsFramePayloads reads the 101 and then the frames after it. A server
// frame is never masked (RFC 6455 5.1), and the fixture writes the
// minimal length form. Thus this stays small. Data that it cannot parse
// ends the walk, with no guess. The count assertion of the caller
// catches a short read.
func wsFramePayloads(t *testing.T, blob []byte) []string {
	t.Helper()
	i := bytes.Index(blob, []byte("\r\n\r\n"))
	if i < 0 {
		t.Fatalf("no response head came back: %q", blob)
	}
	head := string(blob[:i])
	if !strings.HasPrefix(head, "HTTP/1.1 101 ") {
		t.Fatalf("the gateway did not switch protocols:\n%s", head)
	}
	if !strings.Contains(head, "Sec-WebSocket-Accept: "+wsClientHash) {
		t.Fatalf("the handshake was not answered for the key we sent:\n%s", head)
	}
	var out []string
	for rest := blob[i+4:]; len(rest) >= 2; {
		op, n, p := rest[0]&0x0f, int(rest[1]&0x7f), 2
		switch n {
		case 126:
			if len(rest) < 4 {
				return out
			}
			n, p = int(rest[2])<<8|int(rest[3]), 4
		case 127:
			return out
		}
		if rest[1]&0x80 != 0 {
			p += 4
		}
		if len(rest) < p+n || op == wsOpClose {
			return out
		}
		out = append(out, string(rest[p:p+n]))
		rest = rest[p+n:]
	}
	return out
}
