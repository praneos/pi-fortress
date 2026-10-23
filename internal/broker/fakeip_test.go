package broker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/fakeip"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

var fakeNet = netip.MustParsePrefix("198.18.0.0/16")

// upstreamOK is the answer of the test origin. The broker's own 502 says
// "origin\n", so a test can tell a forward from a failed dial.
const upstreamOK = "upstream ok\n"

// fakeRig is a broker with fake-IP on, the pool that pf dns would write,
// and a resolver and dialer that record their requests. Nothing leaves
// the process. The resolver answers from answers. The dialer reaches the
// local test origin or fails.
type fakeRig struct {
	b        *Broker
	pool     *fakeip.Pool
	strip    string
	journal  string
	resolved atomic.Int32
	mu       sync.Mutex
	answers  []netip.Addr
	dialed   []netip.AddrPort
	snis     []string
	// fail lists addresses the dialer refuses, to drive the fallback.
	fail map[netip.Addr]bool
}

func newFakeRig(t *testing.T, answers ...string) *fakeRig {
	t.Helper()
	b, _ := testBroker(t)
	dir := t.TempDir()
	journal := filepath.Join(dir, "fakeip.journal")
	pool, err := fakeip.OpenPool(fakeNet, journal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	r := &fakeRig{b: b, pool: pool, strip: filepath.Join(dir, "strip.jsonl"), journal: journal, fail: map[netip.Addr]bool{}}
	for _, a := range answers {
		r.answers = append(r.answers, netip.MustParseAddr(a))
	}
	b.FakeIP = fakeip.NewTable(fakeNet, journal)
	b.Logs = &jsonl.Writer{StripPath: r.strip, UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	b.Resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
		r.resolved.Add(1)
		return r.answers, nil
	}
	srv := fakeUpstream(t, b, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamOK))
	})
	origin := dialTLSTo(srv)
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		r.mu.Lock()
		r.dialed = append(r.dialed, dst)
		r.snis = append(r.snis, sni)
		fail := r.fail[dst.Addr()]
		r.mu.Unlock()
		if fail {
			return nil, errors.New("refused by the test")
		}
		return origin(ctx, dst, sni)
	}
	return r
}

func (r *fakeRig) assign(t *testing.T, name string) netip.AddrPort {
	t.Helper()
	a, err := r.pool.Assign(name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(a, 443)
}

// journaled writes a mapping directly into the journal, as a pf dns from
// before Assign refused addresses could have left it. Thus the test
// examines the broker's own line without the line of the pool.
func (r *fakeRig) journaled(t *testing.T, a netip.Addr, name string) netip.AddrPort {
	t.Helper()
	f, err := os.OpenFile(r.journal, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%d %s %s\n", time.Now().Unix(), a, name); err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(a, 443)
}

func (r *fakeRig) dials() []netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.AddrPort(nil), r.dialed...)
}

// refusedAtPreamble sends a connection that the broker answers before
// any request. It reads the answer and the error that Handle returned.
func refusedAtPreamble(t *testing.T, b *Broker, p preamble.Preamble) (string, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	return string(resp.Body), <-errc
}

func stripRows(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}

// When fake-IP is off, or on for an address outside the pool, a
// connection takes exactly the path that it took before fake-IP. The
// broker dials OrigDst as given and resolves nothing. A pool address
// gets the ssrf refusal, as always.
func TestFakeIPOffParity(t *testing.T) {
	real := netip.MustParseAddrPort("93.184.216.34:443")
	req := "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
	for _, on := range []bool{false, true} {
		r := newFakeRig(t, "1.1.1.1")
		if !on {
			r.b.FakeIP = nil
		}
		p := preamble.Preamble{SNI: "api.github.com", OrigDst: real}
		if body := roundtrip(t, r.b, p, req); body != upstreamOK {
			t.Fatalf("on=%v body=%q", on, body)
		}
		if d := r.dials(); len(d) != 1 || d[0] != real || r.resolved.Load() != 0 {
			t.Fatalf("on=%v dialed %v, resolved %d", on, d, r.resolved.Load())
		}
	}
	r := newFakeRig(t, "1.1.1.1")
	r.b.FakeIP = nil
	p := preamble.Preamble{SNI: "api.github.com", OrigDst: r.assign(t, "api.github.com")}
	if body, err := refusedAtPreamble(t, r.b, p); body != "ssrf\n" || !errors.Is(err, ErrSSRF) {
		t.Fatalf("off, pool address: %q %v", body, err)
	}
}

// Mapped, with the SNI equal to the name in any letter case and with the
// root dot: the broker resolves the name, skips what dest.Allowed denies,
// dials the first allowed address, and verifies TLS against the SNI.
func TestFakeIPDialsResolvedAddress(t *testing.T) {
	r := newFakeRig(t, "10.0.0.1", "1.1.1.1", "8.8.8.8")
	p := preamble.Preamble{SNI: "API.GitHub.com.", OrigDst: r.assign(t, "api.github.com")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n"); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	d := r.dials()
	if len(d) != 1 || d[0] != netip.MustParseAddrPort("1.1.1.1:443") {
		t.Fatalf("dialed %v", d)
	}
	if r.snis[0] != "API.GitHub.com." {
		t.Fatalf("tls server name %q", r.snis[0])
	}
	if r.resolved.Load() != 1 {
		t.Fatalf("resolved %d times", r.resolved.Load())
	}
}

// After a dial error, the broker tries the next allowed address. It
// tries no more than three.
func TestFakeIPDialFallback(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1", "8.8.8.8")
	r.fail[netip.MustParseAddr("1.1.1.1")] = true
	p := preamble.Preamble{SNI: "api.github.com", OrigDst: r.assign(t, "api.github.com")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n"); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != 2 || d[1] != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("dialed %v", d)
	}

	r = newFakeRig(t, "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
	for _, a := range r.answers {
		r.fail[a] = true
	}
	p.OrigDst = r.assign(t, "api.github.com")
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n"); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != maxFakeDials {
		t.Fatalf("dialed %d addresses, want %d", len(d), maxFakeDials)
	}
}

// The broker refuses unmapped and mismatched at the preamble, with one
// body, a distinct cause in the strip log, and no lookup or dial.
func TestFakeIPRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, assign, sni string
		dst               string
		cause             string
	}{
		{name: "unmapped", sni: "api.github.com", dst: "198.18.200.7:443", cause: string(CauseFakeIPUnmapped)},
		{name: "excluded address", sni: "api.github.com", dst: "198.18.3.0:443", cause: string(CauseFakeIPUnmapped)},
		{name: "sni mismatch", assign: "api.github.com", sni: "evil.example", cause: string(CauseFakeIPSNIMismatch)},
		{name: "sni is a subdomain", assign: "github.com", sni: "evil.github.com", cause: string(CauseFakeIPSNIMismatch)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeRig(t, "1.1.1.1")
			p := preamble.Preamble{SNI: tc.sni, Src: netip.MustParseAddrPort("10.20.0.5:5000")}
			if tc.assign != "" {
				p.OrigDst = r.assign(t, tc.assign)
			} else {
				p.OrigDst = netip.MustParseAddrPort(tc.dst)
			}
			body, err := refusedAtPreamble(t, r.b, p)
			if body != fakeipBody || !errors.Is(err, ErrFakeIP) || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("body=%q err=%v", body, err)
			}
			rows := stripRows(t, r.strip)
			if !strings.Contains(rows, `"cause":"`+tc.cause+`"`) || !strings.Contains(rows, `"client_ip":"10.20.0.5"`) {
				t.Fatalf("strip log: %s", rows)
			}
			if r.resolved.Load() != 0 || len(r.dials()) != 0 {
				t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
			}
		})
	}
}

// A segment with INSPECT=on uses forward DNS, so a pool address from it
// is not an answer of pf dns. The broker refuses it, also for a name that
// the agent network has in the journal.
func TestFakeIPFromFenceSegmentRefused(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	r.b.AgentNet = netip.MustParsePrefix("10.20.0.0/24")
	r.b.FenceNets = []netip.Prefix{netip.MustParsePrefix("10.79.0.0/30")}
	dst := r.assign(t, "api.github.com")
	p := preamble.Preamble{SNI: "api.github.com", OrigDst: dst, Src: netip.MustParseAddrPort("10.79.0.2:5000")}
	body, err := refusedAtPreamble(t, r.b, p)
	if body != fakeipBody || !errors.Is(err, ErrFakeIP) || !strings.Contains(err.Error(), string(CauseFakeIPSegment)) {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if rows := stripRows(t, r.strip); !strings.Contains(rows, `"cause":"fakeip_segment"`) || !strings.Contains(rows, `"client_ip":"10.79.0.2"`) {
		t.Fatalf("strip log: %s", rows)
	}
	if r.resolved.Load() != 0 || len(r.dials()) != 0 {
		t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
	}
}

// The preamble cannot carry an empty SNI. Thus only a preamble built in
// the broker reaches the no-SNI refusal. The broker must still refuse.
func TestFakeIPNoSNI(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	p := &preamble.Preamble{OrigDst: r.assign(t, "api.github.com")}
	if name, cause := r.b.fakeAdmit(p); cause != CauseFakeIPNoSNI || name != "" {
		t.Fatalf("name=%q cause=%q", name, cause)
	}
	if !strings.Contains(stripRows(t, r.strip), string(CauseFakeIPNoSNI)) {
		t.Fatal("no strip row")
	}
}

// The broker refuses an SNI that carries a key, whole or split across
// labels, or a placeholder of the gateway. It refuses before the journal
// lookup and the resolve, and the key never reaches the strip log.
func TestFakeIPKeyShapedSNI(t *testing.T) {
	key := "ghp_" + strings.Repeat("A1b2", 9)
	for _, sni := range []string{
		key + ".evil.example",
		key[:20] + "." + key[20:] + ".evil.example",
		"pf_0123456789abcdef_GITHUB_TOKEN.evil.example",
	} {
		t.Run(sni, func(t *testing.T) {
			r := newFakeRig(t, "1.1.1.1")
			p := preamble.Preamble{SNI: sni, OrigDst: r.assign(t, sni)}
			body, err := refusedAtPreamble(t, r.b, p)
			if body != fakeipBody || !strings.Contains(err.Error(), string(CauseFakeIPKeyShape)) {
				t.Fatalf("body=%q err=%v", body, err)
			}
			rows := stripRows(t, r.strip)
			if strings.Contains(rows, key[:20]) || strings.Contains(rows, "0123456789abcdef") {
				t.Fatalf("key in the strip log: %s", rows)
			}
			if !strings.Contains(rows, `"host":"evil.example"`) || !strings.Contains(rows, `"alert":true`) {
				t.Fatalf("strip log: %s", rows)
			}
			if r.resolved.Load() != 0 || len(r.dials()) != 0 {
				t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
			}
		})
	}
}

// A case-flipped key is the same key to whoever receives the name. Thus the
// SNI check refuses the key in upper, lower, and mixed letter case.
func TestFakeIPKeyShapedSNIAnyCase(t *testing.T) {
	for sni, secret := range map[string]string{
		"GHP_" + strings.Repeat("A1b2", 9) + ".evil.example":          "A1b2A1b2A1b2",
		"Ghp_" + strings.Repeat("c3D4", 9) + ".evil.example":          "c3D4c3D4c3D4",
		"akia" + strings.Repeat("q7", 8) + ".evil.example":            "q7q7q7q7q7",
		"sK-aNt-OaT01-" + strings.Repeat("Zz9_", 6) + ".evil.example": "Zz9_Zz9_Zz9_",
	} {
		t.Run(sni[:8], func(t *testing.T) {
			r := newFakeRig(t, "1.1.1.1")
			p := preamble.Preamble{SNI: sni, OrigDst: r.assign(t, sni)}
			body, err := refusedAtPreamble(t, r.b, p)
			if body != fakeipBody || err == nil || !strings.Contains(err.Error(), string(CauseFakeIPKeyShape)) {
				t.Fatalf("body=%q err=%v", body, err)
			}
			if rows := stripRows(t, r.strip); strings.Contains(strings.ToLower(rows), strings.ToLower(secret)) {
				t.Fatalf("key in the strip log: %s", rows)
			}
			if r.resolved.Load() != 0 || len(r.dials()) != 0 {
				t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
			}
		})
	}
	// The placeholder check folds case too. The origin can undo the case.
	b, _ := testBroker(t)
	if got := b.keyRule("PF_0123456789ABCDEF_GITHUB_TOKEN.evil.example"); got != "placeholder" {
		t.Fatalf("an upper-cased placeholder spelling matched %q", got)
	}
	// A real name whose TLD completes a shape once the dot is gone.
	for _, name := range []string{"asiakuecheerlangen.de", "www.asiakuecheerlangen.de."} {
		if got := b.keyRule(name); got != "" {
			t.Fatalf("%s matched %q", name, got)
		}
	}
}

// The broker never dials a name that resolves only to addresses that
// dest.Allowed denies: private, loopback or the fake pool itself.
func TestFakeIPResolvedDenied(t *testing.T) {
	r := newFakeRig(t, "10.0.0.1", "127.0.0.1", "198.18.0.9", "192.168.1.1")
	p := preamble.Preamble{SNI: "rebind.example", OrigDst: r.assign(t, "rebind.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: rebind.example\r\n\r\n"); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != 0 {
		t.Fatalf("dialed %v", d)
	}
	if !strings.Contains(stripRows(t, r.strip), string(CauseFakeIPDestDenied)) {
		t.Fatal("no strip row")
	}
}

// The fixture net is TEST-NET-1, and only its two echo addresses are ever
// dialable. A name that rebinds to the block canary 192.0.2.1, or to any
// other address in the /24, gets the same denial as any reserved range.
func TestFakeIPResolvedIntoFixtureNetDenied(t *testing.T) {
	r := newFakeRig(t, "192.0.2.1", "192.0.2.7", "192.0.2.255")
	p := preamble.Preamble{SNI: "rebind.example", OrigDst: r.assign(t, "rebind.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: rebind.example\r\n\r\n"); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != 0 {
		t.Fatalf("dialed %v", d)
	}
	if !strings.Contains(stripRows(t, r.strip), string(CauseFakeIPDestDenied)) {
		t.Fatal("no strip row")
	}
}

// Paranoid decides by the SNI before the broker resolves anything. It
// refuses an unlisted name behind a good mapping with no lookup.
func TestFakeIPParanoidNoResolve(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	pb := paranoidBroker(t)
	r.b.Paranoid, r.b.Forward = pb.Paranoid, pb.Forward
	p := preamble.Preamble{SNI: "evil.example", OrigDst: r.assign(t, "evil.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"); body != "paranoid\n" {
		t.Fatalf("body=%q", body)
	}
	if r.resolved.Load() != 0 || len(r.dials()) != 0 {
		t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
	}
}

// The predial still runs the handshake in parallel with the first
// request. A mapped connection resolves and dials on the preamble alone.
// The broker does not resolve or dial a listed name, which admit refuses.
func TestFakeIPPredialAfterChecks(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	p := preamble.Preamble{SNI: "api.github.com", OrigDst: r.assign(t, "api.github.com")}
	drive(t, r.b, p, "")
	if r.resolved.Load() != 1 || len(r.dials()) != 1 {
		t.Fatalf("no predial: resolved %d, dialed %v", r.resolved.Load(), r.dials())
	}

	r = newFakeRig(t, "1.1.1.1")
	r.b.Blocked = blocklist.New("blocked.example")
	p = preamble.Preamble{SNI: "blocked.example", OrigDst: r.assign(t, "blocked.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n"); body != "blocked\n" {
		t.Fatalf("body=%q", body)
	}
	if r.resolved.Load() != 0 || len(r.dials()) != 0 {
		t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
	}
}

// A name that is an address resolves to itself. Thus to map it back and
// dial it would be a direct-IP connection with a pool address in front.
// The broker refuses it at the preamble, before the lookup and the dial,
// in each spelling that a resolver gives back unchanged.
func TestFakeIPLiteralNameRefused(t *testing.T) {
	for i, name := range []string{"203.0.114.9", "8.8.8.8", "127.1", "2130706433"} {
		t.Run(name, func(t *testing.T) {
			r := newFakeRig(t, "1.1.1.1")
			dst := r.journaled(t, netip.AddrFrom4([4]byte{198, 18, 200, byte(1 + i)}), name)
			p := preamble.Preamble{SNI: name + ".", OrigDst: dst, Src: netip.MustParseAddrPort("10.20.0.5:5000")}
			body, err := refusedAtPreamble(t, r.b, p)
			if body != fakeipBody || !errors.Is(err, ErrFakeIP) || !strings.Contains(err.Error(), string(CauseFakeIPLiteral)) {
				t.Fatalf("body=%q err=%v", body, err)
			}
			if !strings.Contains(stripRows(t, r.strip), `"cause":"`+string(CauseFakeIPLiteral)+`"`) {
				t.Fatalf("strip log: %s", stripRows(t, r.strip))
			}
			if r.resolved.Load() != 0 || len(r.dials()) != 0 {
				t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
			}
		})
	}
	// dialName holds the same line on its own, whatever admitted the name.
	r := newFakeRig(t, "1.1.1.1")
	if _, _, err := r.b.dialName(context.Background(), "8.8.8.8", 443, "8.8.8.8", "10.20.0.5"); !errors.Is(err, ErrSSRF) {
		t.Fatalf("dialName of a literal: %v", err)
	}
	if r.resolved.Load() != 0 || len(r.dials()) != 0 {
		t.Fatalf("resolved %d, dialed %v", r.resolved.Load(), r.dials())
	}
}

func TestAddrLiteral(t *testing.T) {
	for name, want := range map[string]bool{
		"203.0.114.9":        true,
		"203.0.114.9.":       true,
		"[::1]":              true,
		"::ffff:203.0.114.9": true,
		"fe80::1%eth0":       true,
		"127.1":              true,
		"2130706433":         true,
		"api.github.com":     false,
		"1password.com":      false,
		"9.example":          false,
		"a.b9":               false,
		"":                   false,
	} {
		if got := addrLiteral(name); got != want {
			t.Errorf("addrLiteral(%q) = %v, want %v", name, got, want)
		}
	}
}

// The SNI check is the check of pf dns: it also tries the last label, and
// a key split across any number of labels. Each refusal comes before the
// address and journal checks. Thus no strip row holds the key, also when
// the address is not in the journal or the SNI ends in a numeric label.
func TestFakeIPKeyShapedSNINeverInStripRow(t *testing.T) {
	key := "ghp_" + strings.Repeat("A1b2", 9)
	for _, sni := range []string{
		"x." + key,
		key,
		key + ".123",
		strings.Join(strings.Split(key, ""), ".") + ".evil.example",
		"x.pf_0123456789abcdef_GITHUB_TOKEN",
	} {
		t.Run(sni[:min(len(sni), 12)], func(t *testing.T) {
			r := newFakeRig(t, "1.1.1.1")
			p := preamble.Preamble{SNI: sni, OrigDst: netip.MustParseAddrPort("198.18.200.7:443")}
			body, err := refusedAtPreamble(t, r.b, p)
			if body != fakeipBody || err == nil || !strings.Contains(err.Error(), string(CauseFakeIPKeyShape)) {
				t.Fatalf("body=%q err=%v", body, err)
			}
			rows := stripRows(t, r.strip)
			if strings.Contains(rows, "A1b2A1b2") || strings.Contains(rows, "0123456789abcdef") || !strings.Contains(rows, `"alert":true`) {
				t.Fatalf("strip log: %s", rows)
			}
		})
	}
}
