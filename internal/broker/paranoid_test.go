package broker

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

// The forward set here is deliberately small: github.com on the allow
// list (which carries its subdomains) and api.x.ai as an exact core
// host (which does not).
func paranoidBroker(t *testing.T) *Broker {
	t.Helper()
	b, _ := testBroker(t)
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.domains")
	core := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(allow, []byte("github.com\npf-core-echo.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("api.x.ai XAI_API_KEY\napi.anthropic.com CLAUDE_OAT\npf-core-echo.test *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := corepolicy.LoadForward(allow, core)
	if err != nil {
		t.Fatal(err)
	}
	b.Paranoid, b.Forward = true, f
	b.Logs = &jsonl.Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	return b
}

func TestParanoidRefusesUnlistedDestination(t *testing.T) {
	// The broker refuses an SNI outside the set before the pre-dial. A listed
	// SNI under an unlisted Host has already started a pre-dial. The broker
	// refuses that request before any part of it gets to the pre-dial.
	for _, tc := range []struct {
		name, sni, host string
		predial         bool
	}{
		{name: "both unlisted", sni: "evil.example", host: "evil.example"},
		{name: "sni miss", sni: "evil.example", host: "api.github.com"},
		{name: "core name is exact, not a suffix", sni: "evil.api.x.ai", host: "evil.api.x.ai"},
		{name: "host miss", sni: "api.github.com", host: "evil.example", predial: true},
		{name: "host is a subdomain of nothing listed", sni: "api.x.ai", host: "evil.api.x.ai", predial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := paranoidBroker(t)
			var dialed atomic.Bool
			b.DialTLS = noDial(&dialed)
			p := preamble.Preamble{SNI: tc.sni, OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
			body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
			if body != "paranoid\n" {
				t.Fatalf("body=%q", body)
			}
			if dialed.Load() && !tc.predial {
				t.Fatal("the origin was dialed for a refused sni")
			}
		})
	}
}

func TestParanoidForwardsListedName(t *testing.T) {
	for _, name := range []string{"github.com", "api.github.com", "api.x.ai"} {
		t.Run(name, func(t *testing.T) {
			b := paranoidBroker(t)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("origin\n"))
			})
			p := preamble.Preamble{SNI: name, OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
			if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: "+name+"\r\n\r\n"); body != "origin\n" {
				t.Fatalf("body=%q", body)
			}
		})
	}
}

// Off, the broker still forwards and logs the unknown host. That is the
// shipped policy that paranoid opts out of. Paranoid does not change it.
func TestParanoidOffStillForwards(t *testing.T) {
	b := paranoidBroker(t)
	b.Paranoid = false
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin\n"))
	})
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestParanoidRefusalLogsWhere(t *testing.T) {
	b := paranoidBroker(t)
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	roundtrip(t, b, p, "GET /pull HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	raw, err := os.ReadFile(b.Logs.UnknownPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"where":"paranoid_deny"`) || !strings.Contains(s, `"sni":"evil.example"`) {
		t.Fatal(s)
	}
}

// The deny row is written before the fence runs. Thus a key that the
// agent put in a field name must not get into the review log.
func TestParanoidRefusalLogsNoHeaderNames(t *testing.T) {
	b := paranoidBroker(t)
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	key := "ghp_" + strings.Repeat("a", 36)
	roundtrip(t, b, p, "GET /pull HTTP/1.1\r\nHost: evil.example\r\nX-"+key+": 1\r\n\r\n")
	raw, err := os.ReadFile(b.Logs.UnknownPath)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); !strings.Contains(s, `"where":"paranoid_deny"`) || strings.Contains(s, key) {
		t.Fatal(s)
	}
}

// A websocket is a forward like all other forwards. The broker refuses it
// at the handshake, before the 101 that would give the connection to
// frames.
func TestParanoidRefusesUnknownWebSocket(t *testing.T) {
	b := paranoidBroker(t)
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	raw := "GET /socket HTTP/1.1\r\nHost: evil.example\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if body := roundtrip(t, b, p, raw); body != "paranoid\n" {
		t.Fatalf("body=%q", body)
	}
	if dialed.Load() {
		t.Fatal("the origin was dialed for a refused websocket")
	}
}

// The blocklist runs first and keeps its own answer.
func TestParanoidBlocklistStillWins(t *testing.T) {
	b := paranoidBroker(t)
	b.Blocked = blocklist.New("github.com")
	p := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: github.com\r\n\r\n"); body != "blocked\n" {
		t.Fatalf("body=%q", body)
	}
}

// A refusal must not wait for a body that the client still holds. The
// answer goes out on the Expect, and the connection closes. A wait would
// give an unlisted destination a way to stall a broker slot.
func TestParanoidRefusesBeforeReadingTheBody(t *testing.T) {
	b := paranoidBroker(t)
	b.DialTLS = noDial(&atomic.Bool{})
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	raw := "POST /upload HTTP/1.1\r\nHost: evil.example\r\n" +
		"Content-Length: 9\r\nExpect: 100-continue\r\n\r\n"
	if body := roundtrip(t, b, p, raw); body != "paranoid\n" {
		t.Fatalf("body=%q", body)
	}
}

// The Host header can arrive with any case, dot and port that the client
// chose. The oracle only sees names. Thus the broker must not refuse a
// listed destination because of the spelling.
func TestParanoidNormalizesTheHostHeader(t *testing.T) {
	for _, host := range []string{"github.com", "GitHub.COM", "github.com:443", "github.com.", "  github.com  "} {
		t.Run(host, func(t *testing.T) {
			b := paranoidBroker(t)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("origin\n"))
			})
			p := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
			if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); body != "origin\n" {
				t.Fatalf("Host %q was refused: %q", host, body)
			}
		})
	}
}

// An empty Host falls back to the SNI, which the engine already examined.
// It must not read as an empty name that the oracle refuses.
func TestParanoidEmptyHostFallsBackToSNI(t *testing.T) {
	b := paranoidBroker(t)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin\n"))
	})
	p := preamble.Preamble{SNI: "api.github.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: \r\n\r\n"); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
}

// The decision is per request, not per connection. A listed first request
// must not carry an unlisted second request through on the same
// keep-alive.
func TestParanoidDecidesEveryRequestOnAConnection(t *testing.T) {
	b := paranoidBroker(t)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin\n"))
	})
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	p := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c1)
	for i, tc := range []struct{ host, want string }{
		{"github.com", "origin\n"},
		{"evil.example", "paranoid\n"},
	} {
		if _, err := io.WriteString(c1, "GET / HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := httpwire.ReadResponse(br, 1<<20, false)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if string(resp.Body) != tc.want {
			t.Fatalf("request %d for %q: body=%q", i, tc.host, resp.Body)
		}
	}
	c1.Close()
	<-errc
}

// The deny runs before the fence strips anything. Thus the row that it
// writes must carry none of the free text of the request. A token in the
// path, the User-Agent, the Content-Type or a cookie name would go into
// unknown.jsonl as the agent sent it.
func TestParanoidRefusalLogsNoRawRequestText(t *testing.T) {
	b := paranoidBroker(t)
	key := "ghp_" + strings.Repeat("A1b2", 9)
	p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	roundtrip(t, b, p, "GET /x/"+key+"?q="+key+" HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: ua-"+key+
		"\r\nContent-Type: text/"+key+"\r\nCookie: "+key+"=1\r\n\r\n")
	raw, err := os.ReadFile(b.Logs.UnknownPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"where":"paranoid_deny"`) {
		t.Fatalf("no paranoid row: %s", s)
	}
	if strings.Contains(s, key) || strings.Contains(s, "A1b2A1b2") {
		t.Fatalf("the row carries the raw request: %s", s)
	}
}

// Paranoid is the posture of the agent network. A source in FenceNets is
// not held to the forward set of the agent: its own PARANOID is in its
// resolver.
func TestParanoidHoldsOnlyTheAgentNet(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want string
	}{
		{"10.77.0.10:5000", "paranoid\n"},
		{"10.79.0.2:5000", "origin\n"},
	} {
		b := paranoidBroker(t)
		b.AgentNet = netip.MustParsePrefix("10.77.0.0/24")
		b.FenceNets = []netip.Prefix{netip.MustParsePrefix("10.79.0.0/30")}
		fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("origin\n"))
		})
		p := preamble.Preamble{SNI: "evil.example", OrigDst: netip.MustParseAddrPort("93.184.216.34:443"), Src: netip.MustParseAddrPort(tc.src)}
		if body := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"); body != tc.want {
			t.Fatalf("src %s: body=%q, want %q", tc.src, body, tc.want)
		}
	}
}
