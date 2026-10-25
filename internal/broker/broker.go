// Package broker is the pf broker daemon. It reads the engine preamble
// from the unix socket. It applies host, source and credential policy to
// each request and websocket, and dials the origin itself. internal/cli
// starts it.
package broker

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/dest"
	"pi-fortress/internal/fakeip"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

var (
	ErrSSRF     = errors.New("broker: destination not allowed")
	ErrSrc      = errors.New("broker: source outside the agent segment")
	ErrVerify   = errors.New("broker: upstream tls verify failed")
	ErrBusy     = errors.New("broker: refresh already in flight for this slot")
	ErrHarvest  = errors.New("broker: token response is not strict json")
	ErrResidue  = errors.New("broker: token response holds a token after the scrub")
	ErrLeftover = errors.New("broker: origin sent bytes past the framed response")
	ErrOpaque   = errors.New("broker: response to a substituted request in an encoding the scrub cannot read")
	ErrLiveName = errors.New("broker: response field name holds a live value or a placeholder")
)

type DialTLSFunc func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error)

type Broker struct {
	Policy  *corepolicy.Policy
	Store   *secrets.Store
	TokenRE *regexp.Regexp
	Rules   *fence.TokenRules
	// StripCore strips tokens of kinds a core host does not inject.
	StripCore  bool
	Roots      *x509.CertPool
	DialTLS    DialTLSFunc
	AllowHosts map[string]struct{}
	// Blocked is the compiled domain list. The engine refuses a listed
	// SNI. This list catches a listed Host behind an unlisted SNI. It also
	// keeps the block if a path ever bypasses the engine.
	Blocked *blocklist.Set
	// AgentNet, when valid, is the source prefix the fence serves. The
	// fence also serves FenceNets: each segment with INSPECT=on. Fake-IP
	// stays with AgentNet, because only the agent network gets those
	// answers from pf dns.
	AgentNet  netip.Prefix
	FenceNets []netip.Prefix
	Logs      *jsonl.Writer
	Idle      time.Duration
	// LabEcho enables the pf-core-echo.test fixture. The fixture reflects
	// the injected live token and harvests fake oauth tokens. Lab VM only.
	LabEcho bool
	// Paranoid means that docs/paranoid_mode.md is armed. The broker refuses
	// a name that Forward does not accept. It does not forward and log it.
	// Forward is the oracle for that refusal. The broker loads Forward only
	// when Paranoid is set.
	Paranoid bool
	Forward  *corepolicy.Forward
	// GitPush is git_push.allow. If it is nil, the broker refuses every git
	// push (docs/git_push.md).
	GitPush *corepolicy.GitPush
	// Recompress re-gzips a decoded response for a client that accepted
	// gzip. When it is off, the client gets identity. The origin leg stays
	// compressed in both cases. It costs CPU on the Pi, see docs/fence.md §5.3b.
	Recompress bool
	// MaxDecoded caps inflated response bytes; 0 means 64 MiB.
	MaxDecoded int64
	// MaxMessage caps one agent-to-origin WebSocket message, with all
	// fragments added together. 0 means 5 MiB (ws.go defaultMaxMessage gives
	// the reason). The broker buffers that direction whole for the scan, and
	// the buffer grows as bytes arrive. Thus this is also the maximum memory
	// for one message. Over it, the session closes with 1009. The broker
	// streams the origin-to-agent direction, with a separate bound
	// (maxOriginMessage).
	MaxMessage int64
	// MemBudget caps the bytes that all connections together can hold in
	// buffers: buffered request bodies and responses, WebSocket messages and
	// gzip re-encoders. 0 means 256 MiB; membudget.go gives the reason for
	// that number. Past it, a body or response streams where it can, and a
	// response goes out uncompressed. The broker refuses data that it must
	// buffer: 503 with Retry-After, or a WebSocket close 1013.
	MemBudget int64
	// Budget is the per-slot hourly ceiling of substituted requests and
	// uploaded body bytes (budget.go). The zero value counts nothing.
	Budget SlotBudget
	// Now is the clock that the hourly window reads. nil means time.Now. A
	// test injects a clock, so an hour of traffic does not take an hour.
	Now func() time.Time
	// FakeIP, when set, is the address journal of pf dns (internal/fakeip).
	// For a connection to an address in its pool, the broker maps the
	// address back to a name, holds the name to its SNI and resolves it here
	// (fakeip.go). nil means fake-IP is off. Then each connection takes the
	// path that it took before fake-IP existed.
	FakeIP *fakeip.Table
	// Resolve is the broker's own lookup for the name of a fake
	// destination. nil means the system resolver. The -resolver flag sets
	// NewResolver.
	Resolve ResolveFunc

	// dialTimeout overrides originDialTimeout, and dialTCP overrides the TCP
	// connect under dial. Thus a test can hold a real TLS handshake against a
	// local listener that never answers, and not wait ten seconds for it.
	dialTimeout time.Duration
	dialTCP     func(ctx context.Context, addr string) (net.Conn, error)

	useMu     sync.Mutex
	lastUse   map[string]time.Time
	saidCause map[fence.RefusalCause]bool
	budget    budget
	mem       memBudget
	expiry    expiryState
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

const defaultMaxDecoded = 64 << 20

func (b *Broker) maxDecoded() int64 {
	if b.MaxDecoded > 0 {
		return b.MaxDecoded
	}
	return defaultMaxDecoded
}

const maxRespBuf = 1 << 20

var ErrLabOnly = errors.New("broker: core echo is lab-only")

// defaultIdle is Idle when it is unset.
const defaultIdle = 30 * time.Second

// idle is Idle or its default. Handle runs once per connection, for all
// connections at the same time. Thus idle reads the default here and
// never writes it back.
func (b *Broker) idle() time.Duration {
	if b.Idle > 0 {
		return b.Idle
	}
	return defaultIdle
}

func (b *Broker) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	idle := b.idle()
	_ = conn.SetDeadline(time.Now().Add(idle))
	// The broker reads the preamble and each request head under that
	// absolute deadline. After a head is in, a silence limit bounds all of
	// the work instead. idleConn explains this.
	cc := &idleConn{Conn: conn, idle: idle}
	br := bufio.NewReader(cc)
	p, err := preamble.Decode(br)
	if err != nil {
		_ = writeErr(conn, 502, "502 Bad Gateway", "preamble\n")
		return err
	}
	// The engine refused this connection. It sends only the cause, for the
	// row (engrefused.go). Nothing is dialed or served.
	if p.Refused != "" {
		return b.engineRefused(p)
	}
	// A fake address is in a reserved range that dest.Allowed denies. Thus
	// the broker examines it before that check sees it. In dialName, the
	// real addresses that its name resolves to must pass dest.Allowed.
	fake := b.isFake(p.OrigDst)
	if !fake && !isEcho(p.OrigDst) && !echoHost(p.SNI, "") && !dest.Allowed(p.OrigDst) {
		_ = writeErr(conn, 403, "403 Forbidden", "ssrf\n")
		return ErrSSRF
	}
	// Slots belong to the agent segment. A preamble with a source at a
	// different location never reaches the fence, for example a house client
	// behind a misrouted redirect. A preamble that names no source at all
	// also never reaches the fence.
	if b.AgentNet.IsValid() && !b.serves(p.Src) {
		_ = writeErr(conn, 403, "403 Forbidden", "src\n")
		return ErrSrc
	}
	// fakeAdmit runs the same check on a pool address, with its own cause.
	if !fake && b.sniKeyRefused(p) {
		_ = writeErr(conn, 403, "403 Forbidden", sniKeyBody)
		return fmt.Errorf("%w: %s", ErrSNIKeyShape, CauseSNIKeyShape)
	}
	up := &upstream{b: b, dst: p.OrigDst, sni: p.SNI}
	if fake {
		// This is after the source check, so a connection from outside the
		// agent segment never reads the journal or writes a row. All causes get
		// one body. The agent learns nothing about which cause it was.
		name, cause := b.fakeAdmit(p)
		if cause != "" {
			_ = writeErr(conn, 403, "403 Forbidden", fakeipBody)
			return fmt.Errorf("%w: %s", ErrFakeIP, cause)
		}
		// dst stays unset until a dial resolves name. It is the real address
		// that the connection went to, never the fake one. An echo fixture
		// behind a fake address gets a local answer, as always, and resolves
		// nothing.
		up = &upstream{b: b, name: name, port: p.OrigDst.Port(), sni: p.SNI, ip: clientIP(p)}
	}
	defer up.close()
	// Pre-dial: the origin is fixed for this connection (OrigDst + SNI).
	// Thus start the origin handshake now, in parallel with the parse of the
	// first client request, not after it. Echo fixtures get a local answer
	// and must never dial. Paranoid refuses an unlisted SNI below. Thus
	// nothing predials for these. For a fake destination, the predial is
	// also the broker's own lookup. Thus the broker also does not
	// resolve a listed name, which admit refuses below.
	if !isEcho(p.OrigDst) && !echoHost(p.SNI, "") && (!b.paranoidFor(p) || b.forwardAllowed(p.SNI)) && (!fake || !b.Blocked.Has(p.SNI)) {
		up.startPredial(ctx)
	}
	for {
		cc.idleRead = false
		_ = conn.SetDeadline(time.Now().Add(idle))
		req, err := httpwire.ReadRequest(br)
		cc.idleRead = true
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			_ = writeErr(conn, 400, "400 Bad Request", "request\n")
			return err
		}
		expect := (req.ContentLength > 0 || req.Chunked) && headerToken(strings.Join(req.Values("Expect"), ","), "100-continue")
		if err := b.serve(ctx, cc, br, p, req, up, expect); err != nil {
			if errors.Is(err, errCloseDelimited) || errors.Is(err, errRefused) || errors.Is(err, errRefusedUnread) || errors.Is(err, errWSDone) {
				return nil
			}
			return err
		}
	}
}

// forwardAllowed is the paranoid refuse oracle. hostAllowed is not it.
// hostAllowed calls HostIn on a map that contains the merged core host
// names. Thus an exact core name like api.x.ai would open evil.api.x.ai
// by suffix (docs/paranoid_mode.md K9).
func (b *Broker) forwardAllowed(name string) bool {
	return b.Forward.Allowed(name, b.LabEcho)
}

// paranoidFor reports whether paranoid mode holds this connection. It is
// the posture of the agent network. A segment in FenceNets has its own
// PARANOID, in its resolver, and its own allowlist there.
func (b *Broker) paranoidFor(p *preamble.Preamble) bool {
	return b.Paranoid && (!b.AgentNet.IsValid() || b.AgentNet.Contains(p.Src.Addr()))
}

func (b *Broker) hostAllowed(host string) bool {
	if corepolicy.HostIn(host, b.AllowHosts) {
		return true
	}
	return b.Policy != nil && b.Policy.HostAllowed(host)
}

// RefusedBody and writeRefused are the one wall in front of the four
// substitution causes. No data about the cause goes into the response,
// so there is no variant of it to tell apart. The code, headers and
// bytes are the same when the slot is disabled, unknown, or empty, or
// when it targets a destination that must not carry its kind.
//
// 503 and not 403, because 503 is the safer of the two if it is wrong.
// A retry with no purpose is cheap and limits itself under Retry-After.
// But a 403 on a store that an operator will soon unlock makes an agent
// stop on a temporary condition.
// RefusedBody is exported so a test outside this package can assert the
// exact bytes that an agent gets. There is one definition because there
// is one response.
const RefusedBody = "pi-fortress: this request could not be completed\n"

func writeRefused(w io.Writer) error {
	resp := &httpwire.Response{Proto: "HTTP/1.1", Status: "503 Service Unavailable", Code: 503, Body: []byte(RefusedBody)}
	resp.SetInPlace("Content-Type", "text/plain")
	resp.SetInPlace("Retry-After", "60")
	resp.SetInPlace("Connection", "close")
	_, err := resp.WriteTo(w)
	return err
}

func writeErr(w io.Writer, code int, status, msg string) error {
	resp := &httpwire.Response{Proto: "HTTP/1.1", Status: status, Code: code, Body: []byte(msg)}
	resp.SetInPlace("Content-Type", "text/plain")
	resp.SetInPlace("Connection", "close")
	_, err := resp.WriteTo(w)
	return err
}

func (b *Broker) serves(src netip.AddrPort) bool {
	if !src.IsValid() {
		return false
	}
	if b.AgentNet.Contains(src.Addr()) {
		return true
	}
	for _, n := range b.FenceNets {
		if n.Contains(src.Addr()) {
			return true
		}
	}
	return false
}
