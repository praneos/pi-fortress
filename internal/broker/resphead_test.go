package broker

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

// The agent never reads the injected live value in a response head. A
// field name cannot be rewritten, so a live value there gets 502. A live
// value in the reason phrase is scrubbed, and the origin's code stays.
// Each case runs on the buffered path (Content-Length) and on the
// streamed path (chunked).
func TestLiveValueInResponseHeadNeverReachesAgent(t *testing.T) {
	const live = "lab_fence_github"
	gh := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("140.82.112.3:443")}
	req := "GET / HTTP/1.1\r\nHost: github.com\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
	buffered := "Content-Length: 5\r\n\r\nhello"
	streamed := "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	for _, tc := range []struct {
		name, head string
		want502    bool
	}{
		{"name buffered", "HTTP/1.1 200 OK\r\nX-" + live + ": 1\r\n" + buffered, true},
		{"name streamed", "HTTP/1.1 200 OK\r\nX-" + live + ": 1\r\n" + streamed, true},
		{"reason buffered", "HTTP/1.1 400 " + live + "\r\n" + buffered, false},
		{"reason streamed", "HTTP/1.1 400 bad " + live + " token\r\n" + streamed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			saw := make(chan bool, 1)
			rawUpstream(t, b, func(_ int, r *httpwire.Request, c net.Conn) bool {
				saw <- strings.Contains(r.Get("Authorization"), live)
				_, _ = io.WriteString(c, tc.head)
				return false
			})
			s := open(t, b, gh)
			s.send(req)
			resp := s.read()
			_ = s.close()
			if !<-saw {
				t.Fatal("the broker did not inject the live value; the test proves nothing")
			}
			got := resp.Proto + " " + resp.Status + "\n"
			for _, f := range resp.Fields {
				got += f.Name + ": " + f.Value + "\n"
			}
			got += string(resp.Body)
			if strings.Contains(got, live) {
				t.Fatalf("the agent read the live value:\n%s", got)
			}
			if tc.want502 && resp.Code != 502 {
				t.Fatalf("code %d, want 502:\n%s", resp.Code, got)
			}
			if !tc.want502 && resp.Code != 400 {
				t.Fatalf("code %d, want the origin's 400:\n%s", resp.Code, got)
			}
		})
	}
}

// The same applies to the 101 of a websocket switch that carried a
// substituted credential: a live value in a field name gets 502.
func TestLiveValueInWebSocket101FieldNameIs502(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	dummy := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	b, _ := testBroker(t)
	saw := make(chan bool, 1)
	wsUpstream(t, b, func(req *httpwire.Request, conn net.Conn, _ *bufio.Reader) {
		saw <- req.Get("Authorization") == "Bearer "+live
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\nX-"+live+": 1\r\n"+
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
	})
	s := open(t, b, anthropic)
	s.send(wsHandshake + "Authorization: Bearer " + dummy + "\r\n\r\n")
	resp, err := httpwire.ReadUpgradeResponseHead(s.br)
	_ = s.close()
	if !<-saw {
		t.Fatal("the broker did not inject the live value; the test proves nothing")
	}
	if err == nil {
		for _, f := range resp.Fields {
			if strings.Contains(f.Name, live) {
				t.Fatalf("the agent read the live value in field name %q (code %d)", f.Name, resp.Code)
			}
		}
		if resp.Code != 502 {
			t.Fatalf("code %d, want 502", resp.Code)
		}
	}
}
