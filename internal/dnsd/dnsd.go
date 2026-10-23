// Package dnsd is the forwarding resolver that replaces the DNS half of
// dnsmasq. It forwards to one upstream per segment. It sinkholes a
// compiled list. It writes each resolved address into an nftables set
// before it answers. It logs in the format that internal/dnslog defines.
//
// This package exists because the policy knobs of dnsmasq (nftset=,
// server= and the sinkhole conf-file set) are process-global. Thus two
// segments with opposite postures need two processes, and N segments
// need N. Here a segment is a map entry.
//
// It is not a resolver: no recursion, no DNSSEC, no zones. It answers a
// query from the list, from the cache, or with the upstream reply verbatim.
package dnsd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/base"
	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/dnslog"
)

const (
	// These are the cache-size and max-cache-ttl of dnsmasq. They stay the
	// same, so the swap does not change what a client sees.
	defaultCacheSize = 2000
	defaultMaxTTL    = 3600 * time.Second
	// setTimeout is the timeout that internal/render gives each resolved_*
	// set (ruleset.go, "timeout 2h"). A cache hit does not add its addresses
	// again. Thus an entry must not live longer than the elements that its
	// miss put in (gate.go).
	setTimeout = 2 * time.Hour

	udpMin = 512
	udpMax = 4096
	// optType is the OPT record's RR type (RFC 6891).
	optType    = 41
	maxMsg     = 65535
	upstreamTO = 5 * time.Second
	// How long one upstream attempt waits before the query goes out again.
	// UDP drops datagrams. A forwarder that asks only one time changes a
	// single lost packet into a SERVFAIL. The client reads that SERVFAIL five
	// seconds later. This value is less than upstreamTO, so the budget holds
	// more than one attempt.
	udpRetryAfter = time.Second
	tcpReadTO     = 10 * time.Second
	typeHTTPS     = 65
	typeSVCB      = 64

	// Per segment, so a flood on one cannot starve another.
	udpInflight = 256
	tcpConns    = 64
	// tcpConnsPerSource is the number of tcpConns of a segment that one client
	// address may hold. Without this cap, one device took all 64 with
	// approximately seven new connections each second. It held each one to the
	// 10 s read deadline. Each other client on the segment that used TCP as the
	// fallback (a truncated answer, a large DNSSEC reply) was then refused.
	// A stub resolver opens one TCP connection for each truncated query and
	// then closes it. Thus eight is already generous for one host. The case
	// that this cap can pinch is a busy house NAT box behind one address (an
	// AP in router mode). That box still has UDP. The nft meter caps UDP, not
	// this code. The cap is per segment like tcpConns, so a device on the
	// house cannot spend the budget of the agent segment either. UDP has no
	// per-source cap in the daemon. A datagram holds a slot only for the
	// upstream round trip. The nft 200/s per-source meter already limits that
	// rate.
	tcpConnsPerSource = 8
)

// Segment is the policy of one interface. It holds each setting that
// dnsmasq could vary only per process.
type Segment struct {
	// Name tags records in the observe state; the agent segment is "".
	Name string
	// Iface is the interface on which queries arrive. The server drops
	// datagrams from anywhere else, with no reply.
	Iface string
	// IP is the address on which the segment answers. The server uses it to
	// match accepted TCP connections. These have no interface index to read.
	IP netip.Addr
	// Upstream is host:port. It is never a public resolver: the ruleset drops
	// port 53 traffic that leaves on any interface other than lo. Empty when
	// DoT is set.
	Upstream string
	// DoTName and DoTIPs replace Upstream with DNS over TLS. The server dials
	// the pinned addresses on 853. The certificate there must be valid for
	// DoTName. Set both or neither, and never together with Upstream. The
	// fields hold addresses, not a name, because a lookup of the resolver's
	// own name would be a loop.
	DoTName string
	DoTIPs  []netip.Addr
	// DoTIface binds the DoT dials to one interface (SO_BINDTODEVICE). This is
	// for the house stub under WireGuard. The dials then reach the house
	// provider through the tunnel. They never use the uplink when the tunnel
	// is down.
	DoTIface string
	// SNIQueue, when not 0, is the NFQUEUE in which the ruleset holds the
	// pending 443 flows of this segment (sni.go). SNIECHFile is the ranges to
	// which an ECH flow may go.
	SNIQueue   uint16
	SNIECHFile string
	// SNIOpaqueFile is the ranges to which a flow that is not TLS at all may
	// go (the WhatsApp chat protocol, Meta ranges). Empty refuses these flows.
	SNIOpaqueFile string
	// SinkholeFiles are dnsmasq address= files, merged. Missing is empty.
	SinkholeFiles []string
	// NFTSet is the set in NFTTable to which the server adds resolved
	// addresses before the answer goes out.
	NFTSet string
	// LogPath is the query log. Empty disables logging for the segment.
	LogPath string
	// Paranoid answers each name outside the forward set with the sinkhole
	// address. Thus the segment reaches only the names that policy names.
	// AllowPath is required with it. When CorePath is set, the forward set is
	// the agent set: allow.domains, the core.hosts host column and the echo
	// fixtures. When CorePath is empty, the forward set is the set of a plain
	// segment: its own allow.<segment>.domains and nothing else
	// (corepolicy.LoadAllow).
	//
	// The oracle is corepolicy.Forward, not a rule of this package. The
	// engine and the broker already make their decisions with that oracle. A
	// resolver with reasoning different from the fence would give out an
	// address. The fence would then refuse a connection to that address. The
	// operator would then read two policies to explain one failure.
	// It is also stricter than the dnsmasq conf that it replaces. That conf
	// wrote each forward name as "server=/name/#". Thus it also carried the
	// subdomains of exact core.hosts entries (docs/paranoid_mode.md K9).
	Paranoid  bool
	AllowPath string
	CorePath  string
	// LabEcho lets the pf-core-echo.test fixture pass, as it does for the
	// engine and the broker. Lab VM only.
	LabEcho bool
	// KeyRulesPath is the key_prefixes.rules file of the fence. When set, the
	// segment refuses a name that has a key of one of its shapes, or a
	// placeholder, before the name goes anywhere (keyshape.go). For the agent
	// segment.
	KeyRulesPath string
	// AddressOnly answers each type other than A here, with an empty answer.
	// It gives an A answer as addresses under the queried name and nothing
	// else (addronly.go). Reason: a TXT answer or a CNAME target is text that
	// comes back in to a segment that can use only an address. For the agent
	// segment. TypesAllowPath is dns_types.allow: the name and type pairs that
	// the segment forwards anyway. Empty is none.
	AddressOnly    bool
	TypesAllowPath string
	// ExtraTypes are DNS_TYPES: for any name on this segment, a client may ask
	// for these types despite AddressOnly. This is for a desk whose software
	// needs SRV or TXT. Only with AddressOnly.
	ExtraTypes []uint16
	// FakeIPNet and FakeIPJournal change the A answers of the segment to
	// fake-IP (fakeip.go). The segment answers each A query that passes the
	// checks from this pool, with one address per name. It journals each
	// address here, for the broker to map back. It never forwards these
	// queries. Set both or neither, and only with AddressOnly. For the agent
	// segment, under AGENT_DNS=fakeip.
	FakeIPNet     netip.Prefix
	FakeIPJournal string

	// Reload replaces the full value while queries read it. Thus the code
	// publishes it atomically and does not assign it. SIGHUP during traffic is
	// the ordinary case, not an edge case.
	local atomic.Pointer[hosts]
	// log uses atomic publication. CloseLogs removes it while query goroutines
	// may still read it. With an ordinary field, that is a data race with a
	// nil dereference that waits inside it.
	log atomic.Pointer[segLog]
	// fwd is the paranoid forward set. It uses atomic publication for the
	// same reason as local: allow.domains changes under a running daemon, and
	// SIGHUP applies the change.
	fwd atomic.Pointer[corepolicy.Forward]
	// keys is the key-shape check. It uses atomic publication like the lists:
	// the rules file changes with a ship, and SIGHUP applies the change. Nil
	// is off.
	keys atomic.Pointer[keyShapes]
	// types is dns_types.allow. It uses atomic publication like the forward
	// set, for the same reason: the operator edits it under a running daemon.
	types atomic.Pointer[typeAllow]
	// broken is the reason why the server does not serve this segment. It is
	// set when IsolateSegments let the segment start without its files. It is
	// nil after the files load.
	broken atomic.Pointer[string]
	// unbound is the reason why a transport of an isolated segment never
	// bound, udp then tcp. It is nil after the transport serves (serve.go
	// retry). It is separate from broken, which refuses each query. A segment
	// whose UDP bound but whose TCP did not still answers over UDP.
	unbound [2]atomic.Pointer[string]
	// logErr is the reason why the query log of an isolated segment did not
	// open. The segment answers without a log until a reload opens it (log.go
	// OpenLogs).
	logErr atomic.Pointer[string]
	// up is the upstream leg, chosen once in New.
	up exchanger
	// fake is the fake-IP pool, set in New when FakeIPNet is; nil is
	// forward mode.
	fake *fakeState
}

type Config struct {
	Segments []Segment
	// IsolateSegments is for the running daemon. If the files of a house or
	// plain segment do not load, the daemon answers REFUSED for that segment
	// alone. The DNS of the other networks stays up. -check leaves it off, so
	// apply still refuses a configuration with any file that it cannot read.
	// The agent listener and the loopback stubs are never isolated.
	IsolateSegments bool
	// NFTTable is the family and table the sets live in, "inet fortress".
	NFTTable string
	// Listen is the port to bind on every segment address.
	Listen int
	// CacheSize and MaxTTL default to dnsmasq's.
	CacheSize int
	MaxTTL    time.Duration
	// LogRate is the number of queries per second per source that reach the
	// query log. The lines of one query cost one token. LogBurst is the
	// bucket. Zero means 20 and 100. A negative rate logs each query. The
	// limit applies only to lines, never to answers.
	LogRate  float64
	LogBurst int
	// NFT writes set elements. Nil uses the nft command.
	NFT NFTWriter
	// Now is time.Now except in tests.
	Now func() time.Time
}

type Server struct {
	cfg   Config
	cache *cache
	nft   NFTWriter
	// gate is how long each element this process wrote into a gate set
	// has left (gate.go).
	gate gateLife
	// seen is what each name resolved to on a segment with the SNI check
	// (sniseen.go).
	seen seenAnswers

	udpSlots, tcpSlots int
	// tcpPerSource is tcpConnsPerSource as a field, so that a test can make it
	// small. 0 or less disables the per-source cap. Thus New sets it
	// explicitly and does not leave the zero value.
	tcpPerSource int
	logf         func(string, ...any)
	// bindGrace is how long a transport may fail its first bind before Run
	// stops the attempts for it. rebindWait is the pause between attempts.
	// Refer to the constants in serve.go.
	bindGrace, rebindWait time.Duration

	// queries counts the goroutines that each answer one query. Run can then
	// wait for them. Otherwise Run returns into a CloseLogs that removes the
	// log while the goroutines still use it.
	queries sync.WaitGroup

	mu   sync.Mutex
	segs []*Segment
}

// New validates cfg and loads the list of each segment. -check runs it, so
// nothing here may touch the network or bind a port.
func New(cfg Config) (*Server, error) {
	if err := cfg.fill(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:          cfg,
		cache:        newCache(cfg.CacheSize, cfg.Now),
		nft:          cfg.NFT,
		udpSlots:     udpInflight,
		tcpSlots:     tcpConns,
		tcpPerSource: tcpConnsPerSource,
		logf:         log.Printf,
		bindGrace:    bindGrace,
		rebindWait:   rebindWait,
	}
	if s.nft == nil {
		s.nft = &nftCmd{table: cfg.NFTTable}
	}
	seen := map[string]bool{}
	names := map[string]bool{}
	sets := map[string]bool{}
	for i := range cfg.Segments {
		seg := &cfg.Segments[i]
		if seg.Iface == "" {
			return nil, fmt.Errorf("segment %q: no interface", seg.Name)
		}
		if seen[seg.Iface] {
			return nil, fmt.Errorf("interface %s named twice", seg.Iface)
		}
		seen[seg.Iface] = true
		// The name is in the cache key, and the set is the gate. Two segments
		// that share either one answer one network from the lookups of the other.
		if names[seg.Name] {
			return nil, fmt.Errorf("segment %q named twice", seg.Name)
		}
		names[seg.Name] = true
		if seg.NFTSet != "" {
			if sets[seg.NFTSet] {
				return nil, fmt.Errorf("segment %q: nft set %s named twice", seg.Name, seg.NFTSet)
			}
			sets[seg.NFTSet] = true
		}
		leg, err := seg.upstreamLeg(cfg.Now)
		if err != nil {
			return nil, err
		}
		if err := seg.checkShape(); err != nil {
			return nil, err
		}
		if err := s.loadFiles(seg); err != nil {
			if !cfg.IsolateSegments || !seg.isolatable() {
				return nil, err
			}
			why := err.Error()
			seg.broken.Store(&why)
			s.logf("pf dns: segment %q answers REFUSED to everything until its files load (fix, then pf apply or SIGHUP): %v", seg.Name, err)
		}
		fk, err := seg.checkFake()
		if err != nil {
			return nil, err
		}
		seg.fake = fk
		if !seg.IP.Is4() {
			return nil, fmt.Errorf("segment %q: %q is not an IPv4 address to bind", seg.Name, seg.IP)
		}
		seg.up = leg
		s.segs = append(s.segs, seg)
	}
	return s, nil
}

// fill sets the defaults of cfg and refuses a value that no server can
// run with.
func (cfg *Config) fill() error {
	if len(cfg.Segments) == 0 {
		return errors.New("no segments")
	}
	if cfg.NFTTable == "" {
		return errors.New("no nft table")
	}
	if cfg.Listen == 0 {
		cfg.Listen = 53
	}
	// -check certifies a configuration without a bind. Thus it must refuse
	// here a port that no listener can ever take. If the bind finds the
	// problem, the refusal occurs inside the retry loop of a daemon that
	// already reported that it started. That is the one place where an
	// operator does not look.
	if cfg.Listen < 1 || cfg.Listen > 65535 {
		return fmt.Errorf("listen port %d is not a port", cfg.Listen)
	}
	if cfg.CacheSize == 0 {
		cfg.CacheSize = defaultCacheSize
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = defaultMaxTTL
	}
	if cfg.MaxTTL < 0 || cfg.MaxTTL > setTimeout {
		return fmt.Errorf("max ttl %v: must be positive and at most the gate set timeout %v", cfg.MaxTTL, setTimeout)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LogRate == 0 {
		cfg.LogRate = defaultLogRate
	}
	if cfg.LogBurst <= 0 {
		cfg.LogBurst = defaultLogBurst
	}
	return nil
}

// checkShape refuses a combination of segment fields that New must not
// accept. It reads no file.
func (seg *Segment) checkShape() error {
	// A loopback segment answers the box itself and dnsmasq. Their traffic
	// never crosses the gate, so the segment has no set to feed. For any
	// other segment, a missing set is a typo. That typo would silently stop
	// the writes to resolved_v4. The gate would then drop the connections
	// that its own answers invited.
	if seg.NFTSet == "" && !seg.IP.IsLoopback() {
		return fmt.Errorf("segment %q: no nft set", seg.Name)
	}
	// Refuse here, do not use a default. A paranoid segment with no named
	// forward set would answer 0.0.0.0 to all names. The segment would then
	// look sinkholed, not misconfigured. A core hosts file without an allow
	// list is the same mistake.
	if seg.Paranoid && seg.AllowPath == "" {
		return fmt.Errorf("segment %q: paranoid needs an allow list", seg.Name)
	}
	// An override list for a filter that is not on is a dns.json with an
	// error. If New accepted it, the operator would think that the segment is
	// filtered. But the segment forwards every type.
	if seg.TypesAllowPath != "" && !seg.AddressOnly {
		return fmt.Errorf("segment %q: dns_types_allow without address_only", seg.Name)
	}
	if len(seg.ExtraTypes) > 0 && !seg.AddressOnly {
		return fmt.Errorf("segment %q: dns_types without address_only", seg.Name)
	}
	return nil
}

// loadFiles reads and publishes every file a segment answers by: its
// lists, its paranoid forward set, its key shapes and its type overrides.
func (s *Server) loadFiles(seg *Segment) error {
	h, err := seg.readSink()
	if err != nil {
		return err
	}
	f, err := seg.readFwd()
	if err != nil {
		return err
	}
	k, err := seg.readKeys()
	if err != nil {
		return err
	}
	ty, err := seg.readTypes()
	if err != nil {
		return err
	}
	s.reportTypes(seg, ty)
	seg.local.Store(h)
	seg.fwd.Store(f)
	seg.keys.Store(k)
	seg.types.Store(ty)
	return nil
}

// isolatable is a segment whose failure may stay its own: the house and
// the plain segments. Apply names these segments. The agent listener has
// no name. The loopback stubs are the resolver of the box itself. A
// failure of either one is a failure of the box.
func (seg *Segment) isolatable() bool {
	return seg.Name != "" && !seg.IP.IsLoopback()
}

// isolates reports whether a failure of seg stays seg's own on this
// server: the running daemon's, and only for an isolatable segment.
func (s *Server) isolates(seg *Segment) bool {
	return s.cfg.IsolateSegments && seg.isolatable()
}

func transport(network string) int {
	if network == "tcp" {
		return 1
	}
	return 0
}

func (seg *Segment) unboundWhy(network string) *string {
	return seg.unbound[transport(network)].Load()
}

// setUnbound records why a transport does not serve, or clears the reason
// with nil. It reports whether this changed the marked state.
func (seg *Segment) setUnbound(network string, why *string) bool {
	old := seg.unbound[transport(network)].Swap(why)
	return (old == nil) != (why == nil)
}

// readSink reads the list of a segment but does not publish it. Thus a
// reload that will fail can fail first. No segment then answers by a list
// that the operator was told did not load.
func (seg *Segment) readSink() (*hosts, error) {
	h, err := loadHosts(seg.SinkholeFiles)
	if err != nil {
		return nil, fmt.Errorf("segment %q: %w", seg.Name, err)
	}
	return h, nil
}

// readFwd reads the paranoid forward set but does not publish it, the same
// bargain as readSink. A segment that is not paranoid has no set. The
// answer is then nil, not an empty set: an empty Forward allows nothing.
// Confusion of the two would black-hole the full segment.
func (seg *Segment) readFwd() (*corepolicy.Forward, error) {
	if !seg.Paranoid {
		return nil, nil
	}
	var f *corepolicy.Forward
	var err error
	if seg.CorePath == "" {
		f, err = corepolicy.LoadAllow(seg.AllowPath)
	} else {
		f, err = corepolicy.LoadForward(seg.AllowPath, seg.CorePath)
	}
	if err != nil {
		return nil, fmt.Errorf("segment %q paranoid forward set: %w", seg.Name, err)
	}
	return f, nil
}

// readKeys loads the key-shape check, or returns nil for a segment without
// one. A named rules file that does not load is an error, not an unchecked
// segment: the operator asked for the check.
func (seg *Segment) readKeys() (*keyShapes, error) {
	if seg.KeyRulesPath == "" {
		return nil, nil
	}
	k, err := loadKeyShapes(seg.KeyRulesPath)
	if err != nil {
		return nil, fmt.Errorf("segment %q key rules: %w", seg.Name, err)
	}
	return k, nil
}

// readTypes loads dns_types.allow, or returns nil for none. A named file
// that cannot be read is an error, for the reason that readKeys gives. The
// operator asked for those pairs. Without them, the segment would filter
// the pairs that the operator was promised it forwards. Nothing would say
// why.
func (seg *Segment) readTypes() (*typeAllow, error) {
	if seg.TypesAllowPath == "" {
		return nil, nil
	}
	ta, err := loadTypeAllow(seg.TypesAllowPath)
	if err != nil {
		return nil, fmt.Errorf("segment %q dns types allow: %w", seg.Name, err)
	}
	return ta, nil
}

// reportTypes says which dns_types.allow lines were skipped. -check and
// the journal show this. A skipped line filters a pair that the operator
// meant to forward. Nothing else would tell the operator why.
func (s *Server) reportTypes(seg *Segment, ta *typeAllow) {
	if ta == nil {
		return
	}
	for _, b := range ta.bad {
		s.logf("dns segment %q: %s", seg.Name, b)
	}
}

// forwards reports whether a paranoid segment may resolve name at all.
// Callers check seg.Paranoid first. If the set of a paranoid segment did
// not publish, the segment forwards nothing. That is the safe direction.
func (seg *Segment) forwards(name string) bool {
	return seg.fwd.Load().Allowed(name, seg.LabEcho)
}

// Segments reports what -check should print: one line per segment.
func (s *Server) Segments() []string {
	var out []string
	for _, seg := range s.segs {
		name := seg.Name
		if name == "" {
			name = "agent"
		}
		set := seg.NFTSet
		if set == "" {
			set = "-"
		}
		// The upstream field shows which leg is in use. Thus -check is sufficient
		// to tell an operator whether the box uses encryption.
		up := seg.Upstream
		if seg.DoTName != "" {
			up = fmt.Sprintf("dot:%s(%d)", seg.DoTName, len(seg.DoTIPs))
		}
		line := fmt.Sprintf("%s iface=%s ip=%s upstream=%s set=%s local=%d",
			name, seg.Iface, seg.IP, up, set, seg.local.Load().Len())
		// Only when armed. A "paranoid=0" on every ordinary line would
		// train the reader to skip the field that matters most.
		if f := seg.fwd.Load(); seg.Paranoid && f != nil {
			line += fmt.Sprintf(" paranoid=%d", len(f.Names()))
		}
		if seg.AddressOnly {
			line += fmt.Sprintf(" a_only=%d", seg.types.Load().Len())
		}
		if seg.fake != nil {
			line += " fakeip=" + seg.fake.prefix.String()
		}
		if why := seg.broken.Load(); why != nil {
			line += " BROKEN=refusing-all(" + *why + ")"
		}
		if why := seg.logErr.Load(); why != nil {
			line += " BROKEN=no-log(" + *why + ")"
		}
		var down []string
		for i, network := range []string{"udp", "tcp"} {
			if why := seg.unbound[i].Load(); why != nil {
				down = append(down, network+": "+*why)
			}
		}
		if len(down) > 0 {
			line += " BROKEN=not-serving(" + strings.Join(down, "; ") + ")"
		}
		out = append(out, line)
	}
	return out
}

// Reload reads the sinkhole list of each segment again and opens its log
// again. SIGHUP means this to dnsmasq and to the dns.reload of pf tui.
//
// Reload publishes nothing until all steps that can fail have succeeded.
// The old order loaded and published each segment in turn. Only then did
// it open the log again, and that step could still fail. Thus a reload
// that reported an error had already changed the policy of the resolver.
// That reload never reached the cache reset, so the answers of the
// previous list stayed live.
//
// The reset comes last, after the lists are published. Reason: a query
// that is already in flight gives its generation back at put. An increment
// of the generation after the swap makes each answer judged by the old
// list unwelcome in the new cache.
func (s *Server) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := make([]*hosts, len(s.segs))
	fwds := make([]*corepolicy.Forward, len(s.segs))
	keys := make([]*keyShapes, len(s.segs))
	types := make([]*typeAllow, len(s.segs))
	// An isolated segment whose files still do not load keeps what it had:
	// the old lists or REFUSED. The other segments reload without it.
	skip := make([]bool, len(s.segs))
	var isolated []string
	for i, seg := range s.segs {
		h, f, k, ty, err := seg.readAll()
		if err != nil {
			if !s.isolates(seg) {
				return err
			}
			skip[i] = true
			isolated = append(isolated, err.Error())
			continue
		}
		s.reportTypes(seg, ty)
		loaded[i], fwds[i], keys[i], types[i] = h, f, k, ty
	}
	// Reload opens each log before it swaps any log. Thus, if a reload fails
	// on the log of one segment, each segment continues to write where it
	// was. If the log of an isolated segment does not open, it stays as it
	// was (the old file, or none). The error names it, as for its lists.
	logs := make([]*segLog, len(s.segs))
	files := make([]*os.File, len(s.segs))
	fresh := make([]*segLog, len(s.segs))
	for i, seg := range s.segs {
		lg := seg.log.Load()
		var err error
		switch {
		case lg != nil:
			var f *os.File
			if f, err = lg.open(); err == nil {
				logs[i], files[i] = lg, f
			} else {
				err = fmt.Errorf("segment %q log: %w", seg.Name, err)
			}
		case seg.LogPath != "" && seg.logErr.Load() != nil:
			fresh[i], err = s.openLog(seg)
		}
		if err == nil {
			continue
		}
		if !s.isolates(seg) {
			for j := range s.segs {
				if files[j] != nil {
					_ = files[j].Close()
				}
				if fresh[j] != nil {
					_ = fresh[j].Close()
				}
			}
			return err
		}
		isolated = append(isolated, err.Error())
	}
	for i, seg := range s.segs {
		if logs[i] != nil {
			logs[i].swap(files[i])
		}
		if fresh[i] != nil {
			seg.log.Store(fresh[i])
			seg.logErr.Store(nil)
			s.logf("pf dns: segment %q query log open; logging again", seg.Name)
		}
		if skip[i] {
			continue
		}
		seg.local.Store(loaded[i])
		seg.fwd.Store(fwds[i])
		seg.keys.Store(keys[i])
		seg.types.Store(types[i])
		if seg.broken.Swap(nil) != nil {
			s.logf("pf dns: segment %q files loaded; served again", seg.Name)
		}
	}
	s.cache.reset()
	if len(isolated) > 0 {
		return fmt.Errorf("reloaded without %s", strings.Join(isolated, "; "))
	}
	return nil
}

// readAll reads every file a segment answers by, publishing nothing.
func (seg *Segment) readAll() (*hosts, *corepolicy.Forward, *keyShapes, *typeAllow, error) {
	h, err := seg.readSink()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	f, err := seg.readFwd()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	k, err := seg.readKeys()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ty, err := seg.readTypes()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return h, f, k, ty, nil
}

// answer makes the reply bytes for one query, or nil to send nothing.
// src is the client. Only the log line uses it.
func (s *Server) answer(ctx context.Context, seg *Segment, src netip.Addr, req []byte, maxUDP int) []byte {
	hdr, q, e, early, done := parseQuery(req)
	if done {
		return early
	}
	name := strings.TrimSuffix(q.Name.String(), ".")
	now := s.cfg.Now()
	// Sample the generation before the list, not after. Otherwise a reload
	// between the two could let an answer judged by the old list carry the
	// new generation and survive the reset.
	gen := s.cache.generation()
	// Use one snapshot of the list for the full query. Otherwise a reload
	// between the queried name and the chain below could judge the two halves
	// of one answer by different policies.
	local := seg.local.Load()
	a, listed := local.lookup(name)
	// The budget decision is made one time, for the query. Over budget, the
	// server logs neither the query nor its reply. A reply in the log
	// without its query could pair with a query of the same name from a
	// different source. A listed name and a tunnel-shaped query each pay
	// from their own budget.
	// Thus ordinary chatter cannot buy silence for either one.
	class := logOrdinary
	if listed {
		class = logListed
	} else if tunnelCandidate(name, uint16(q.Type)) {
		class = logCandidate
	}
	quiet := !seg.admitClass(now, src, class)

	// A segment that started without its files answers nothing that it cannot
	// judge. It logs no name: its key shapes may be the files that did not
	// load.
	if seg.broken.Load() != nil {
		return refuse(hdr, dnsmessage.RCodeRefused, &q, e)
	}
	// This check comes first, before each path that forwards, caches or logs
	// the name. The sinkhole and the filters do not forward, but they log the
	// full name. The log is not a correct location for a key either. This row
	// is always logged, over any budget: the alert is raised from this row.
	if k := seg.keys.Load(); k != nil {
		if rule := k.match(name); rule != "" {
			seg.event(now, dnslog.Event{
				Src: src.String(), Name: k.logName(name), QType: qtypeName(q.Type),
				Act: dnslog.ActRefused, Rule: rule,
			})
			return refuse(hdr, dnsmessage.RCodeRefused, &q, e)
		}
	}
	if q.Class != dnsmessage.ClassINET {
		return s.reply(seg, hdr, q, e, refuse(hdr, dnsmessage.RCodeNotImplemented, &q, e), src, verdict{act: dnslog.ActRefused}, quiet, maxUDP)
	}
	// filter-AAAA and filter-rr=HTTPS. They are unconditional here. dnsmasq
	// had them only if the build had them. The row says ActFiltered, not
	// "NODATA". "NODATA" is also what an empty upstream answer says. When the
	// two had the same spelling, deliberate policy suppression counted as
	// ordinary traffic that by chance did not resolve.
	if q.Type == dnsmessage.TypeAAAA || uint16(q.Type) == typeHTTPS || uint16(q.Type) == typeSVCB {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeSuccess, e), src, verdict{act: dnslog.ActFiltered}, quiet, maxUDP)
	}
	// Address-only: the server answers each other type here, empty, with the
	// same shape and the same word as the filter above. It never forwards
	// these types. TXT, NULL and ANY are how a client asks an LLM over DNS.
	// MX, SRV, CAA or a public PTR also bring text back in. This check comes
	// before the list, so the non-A answer for a listed name is the same in
	// both cases. A private reverse lookup is the one exception. It keeps the
	// bogus-priv NXDOMAIN below, which also forwards nothing. A client that
	// does reverse DNS on its LAN expects that answer.
	if seg.AddressOnly && q.Type != dnsmessage.TypeA && !bogusPriv(name, q.Type) && !seg.types.Load().allows(name, q.Type) && !slices.Contains(seg.ExtraTypes, uint16(q.Type)) {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeSuccess, e), src, verdict{act: dnslog.ActFiltered}, quiet, maxUDP)
	}
	if listed {
		return s.local(seg, hdr, q, src, a, e, quiet, maxUDP)
	}
	// domain-needed and bogus-priv: neither ever leaves the box.
	if q.Type == dnsmessage.TypeA && !strings.Contains(name, ".") {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeNameError, e), src, verdict{act: dnslog.ActNXDomain}, quiet, maxUDP)
	}
	if bogusPriv(name, q.Type) {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeNameError, e), src, verdict{act: dnslog.ActNXDomain}, quiet, maxUDP)
	}

	// Paranoid mode: nothing outside the forward set resolves. This check is
	// after the NXDOMAIN cases above. Those cases are for names that cannot be
	// forwarded at all, and they continue to say so. This check is before the
	// cache, so the cache cannot continue to answer a name that was removed
	// from allow.domains.
	//
	// The check judges the queried name, not the chain behind it. An allowed
	// name usually has a CNAME to a CDN that nobody would list. A refusal of
	// that CDN would also stop the entries of the forward set itself. The
	// chain is still judged against the blocklist further down, as for each
	// query.
	//
	// The answer goes through local with the unspecified address. Thus it is
	// the path of the sinkhole: "config NAME is 0.0.0.0" in the log. dnslog
	// and observe read that text as blocked.
	if seg.Paranoid && !seg.forwards(name) {
		return s.local(seg, hdr, q, src, netip.IPv4Unspecified(), e, quiet, maxUDP)
	}

	// Fake-IP: the pool answers the A query that got this far. This occurs
	// after each check above and in place of all steps below. Thus the name
	// never reaches the cache or the upstream. Each refusal keeps its place
	// and its answer. A key in the name is still refused before the pool sees
	// it. A listed name or fixture still gets its own address. Paranoid still
	// sinkholes what it does not forward. On a fake-IP segment, only A
	// arrives here, because New requires address-only. A dns_types.allow pair
	// of another type still forwards below.
	if seg.fake != nil && q.Type == dnsmessage.TypeA {
		return s.fakeAnswer(seg, hdr, q, name, e, src, quiet, maxUDP)
	}

	// handOut is what goes to the client after all checks of the full message
	// pass. That is the message itself, or, for an A query on an address-only
	// segment, only its addresses (flattenA). It is one place for the three
	// exits below, so a later exit cannot forget it.
	handOut := func(msg []byte) []byte {
		if !seg.AddressOnly || q.Type != dnsmessage.TypeA {
			return msg
		}
		if f := flattenA(hdr, q, msg, e); f != nil {
			return f
		}
		return empty(hdr, q, dnsmessage.RCodeServerFailure, e)
	}

	key := cacheKey{seg: seg.Name, name: strings.ToLower(name), qtype: uint16(q.Type)}
	if raw, age, ok := s.cache.get(key); ok {
		// Age the stored bytes into a copy of their own. The client then gets the
		// remaining life of the record, not the full life again. At put, the
		// entry was cut to the time that its gate elements had left. Thus the
		// aged TTLs also fit them.
		msg := ageTTLs(raw, age)
		setID(msg, hdr.ID)
		// Use the spelling of this asker, not of the first asker. A stub that
		// randomises case (0x20) drops an answer whose question differs.
		askersCase(msg, req)
		msg = handOut(withCallerOPT(msg, e))
		return s.reply(seg, hdr, q, e, msg, src, verdictOf(answerOf(msg)), quiet, maxUDP)
	}
	// The question goes upstream as the question of this resolver, not as
	// the client wrote it: refer to canonicalQuery. This code normalises each
	// item that the cache key does not hold. Such items must not differ
	// between the caller that filled the entry and the callers that read
	// it.
	upID, err := randomID()
	if err != nil {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	out := canonicalQuery(q, upID)
	if out == nil {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	raw, err := s.forward(ctx, seg, out, hdr.ID)
	if err != nil {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	// The name that the client asked is only the first name in the answer.
	// Judge the rest of the chain the same way, before the gate set admits any
	// of it or the cache holds it. A listed target gets the answer that it
	// would get if the client had asked for it. For the sinkhole, that is
	// 0.0.0.0 under the name that the client asked.
	names, ok := chainNames(raw)
	if !ok {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	for _, n := range names {
		if a, ok := local.lookup(n); ok {
			// The budget was charged before the answer came back. At that time,
			// nothing here knew that the name led to a block. Blocked lines have
			// their own reserved budget so that a flood cannot bury them. Thus that
			// budget now pays for the one line that matters. Otherwise the line is
			// lost to a bucket that the ordinary chatter had already emptied.
			if quiet && seg.admit(now, src, true) {
				quiet = false
			}
			return s.local(seg, hdr, q, src, a, e, quiet, maxUDP)
		}
	}
	addrs, ttl, ok := aRecords(raw)
	if !ok {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	// A public name with a local address in the answer is a rebind, or a
	// split-horizon name that looks exactly like one. The client gets the
	// answer, but the gate set never admits the address. Thus the gate treats
	// the address as a direct dial, which it is. Only this upstream path
	// filters. A fixture in the local list is the word of the operator. It
	// goes in as written.
	addrs = public(addrs)
	// The gate drops a connection to an address that is not yet in the set.
	// Thus the element must be in the set before the client can act on the
	// answer. Here the order is important, not the throughput. Also, the
	// answer must not live longer than the element. This applies to the cache
	// entry, which a hit serves without a new write to the set. It also
	// applies to the TTLs that the client gets.
	left, err := s.admitGate(seg, addrs, now)
	if err != nil {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	if seg.SNIQueue != 0 {
		s.seen.add(seg.Name, q.Name.String(), addrs, now)
	}
	if left < setTimeout {
		raw = capTTLs(raw, uint32(left/time.Second))
		ttl = min(ttl, uint32(left/time.Second))
	}
	// A truncated answer is a stub, not an answer. A cached stub would go to
	// each later asker. That includes the TCP retry, which exists to get past
	// the stub.
	bare, bareOK := stripOPT(raw)
	if ttl > 0 && raw[2]&0x02 == 0 && bareOK {
		s.cache.put(key, bare, minDur(minDur(time.Duration(ttl)*time.Second, s.cfg.MaxTTL), left), gen)
	}
	if !bareOK {
		// The upstream did not put OPT last. Answer this caller and cache
		// nothing. Do not store a message whose OPT cannot be removed for the
		// next caller.
		msg := handOut(patchID(raw, hdr.ID))
		return s.reply(seg, hdr, q, e, msg, src, verdictOf(answerOf(msg)), quiet, maxUDP)
	}
	msg := handOut(withCallerOPT(patchID(bare, hdr.ID), e))
	return s.reply(seg, hdr, q, e, msg, src, verdictOf(answerOf(msg)), quiet, maxUDP)
}

// parseQuery reads the one standard query in req. done is true when req
// is not one. reply is then the answer to send, or nil to send nothing.
func parseQuery(req []byte) (hdr dnsmessage.Header, q dnsmessage.Question, e ednsOPT, reply []byte, done bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		return hdr, q, e, nil, true
	}
	if hdr.Response {
		return hdr, q, e, nil, true
	}
	e = clientEDNS(req)
	// Only a standard query is implemented. Without this check, an opcode
	// that nothing here handles (an UPDATE, a NOTIFY) was read as if its
	// sections meant the same as the sections of a query. It was then
	// synthesised into an answer, forwarded upstream, or served from the
	// query cache, under whatever name the header had.
	if hdr.OpCode != 0 {
		return hdr, q, e, refuse(hdr, dnsmessage.RCodeNotImplemented, nil, e), true
	}
	q, err = p.Question()
	if err != nil {
		return hdr, q, e, refuse(hdr, dnsmessage.RCodeFormatError, nil, e), true
	}
	// A second question is legal to encode, but no resolver implements it. An
	// answer to the first question that ignores the others is how a cache
	// gets poisoned. An error that is not the end of the section is a third
	// case: QDCOUNT promised a question that the message does not have. That
	// is malformed, not single-question.
	if _, err := p.Question(); err == nil {
		return hdr, q, e, refuse(hdr, dnsmessage.RCodeNotImplemented, &q, e), true
	} else if !errors.Is(err, dnsmessage.ErrSectionDone) {
		return hdr, q, e, refuse(hdr, dnsmessage.RCodeFormatError, &q, e), true
	}
	// An EDNS version that we do not speak means that the client options were
	// not read. Thus the client must get that information. It must not get an
	// answer that looks as if the options were honoured.
	if e.present && e.version != 0 {
		return hdr, q, e, badVersion(hdr, q, e), true
	}
	return hdr, q, e, nil, false
}

// verdict is the result of a query, in the terms that both log formats
// need: the act in a transaction row, and the address when there is one.
type verdict struct {
	act    string
	answer string
}

// verdictOf reads a verdict from an answer that came back from a forwarder
// or the cache. There, the rcode is the only data available.
func verdictOf(answer string) verdict {
	return verdict{act: dnslog.ActOf(answer), answer: answer}
}

// reply logs the answer. It truncates the answer if the client cannot
// take it over UDP. The truncation makes the client retry over TCP.
func (s *Server) reply(seg *Segment, hdr dnsmessage.Header, q dnsmessage.Question, e ednsOPT, msg []byte, src netip.Addr, v verdict, quiet bool, maxUDP int) []byte {
	if msg == nil {
		// No response at all. The two-line format left a query line with no reply
		// after it. A reader could not tell that from a reply that had not
		// arrived yet.
		v.act = dnslog.ActDropped
	}
	if !quiet {
		seg.event(s.cfg.Now(), dnslog.Event{
			Src: src.String(), Name: strings.TrimSuffix(q.Name.String(), "."),
			QType: qtypeName(q.Type), Act: v.act, Answer: v.answer,
		})
	}
	if msg == nil {
		return nil
	}
	if maxUDP > 0 && len(msg) > maxUDP {
		return truncated(hdr, q, e)
	}
	return msg
}

func (s *Server) forward(ctx context.Context, seg *Segment, req []byte, clientID uint16) ([]byte, error) {
	resp, err := seg.up.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	return patchID(resp, clientID), nil
}

// local answers a name that the configuration names. dnsmasq logs this
// with "config", not "reply". The sinkhole is the usual case, and 0.0.0.0
// is only its address. A fixture that points to a real address uses the
// same path. Its address must reach the gate set. If not, the gate would
// drop the connection that the answer just invited.
func (s *Server) local(seg *Segment, hdr dnsmessage.Header, q dnsmessage.Question, src netip.Addr, a netip.Addr, e ednsOPT, quiet bool, maxUDP int) []byte {
	if q.Type != dnsmessage.TypeA {
		// A sinkholed name has no record of any other type either. That empty
		// answer is the list in action, not a missing record. Thus it is spelled
		// as policy, so the reader can count it as policy. A fixture that points
		// to a real address is the other case. Its empty answer is an ordinary
		// NODATA.
		v := verdict{act: dnslog.ActNodata}
		if a.IsUnspecified() {
			v.act = dnslog.ActFiltered
		}
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeSuccess, e), src, v, quiet, maxUDP)
	}
	if !a.IsUnspecified() {
		if _, err := s.admitGate(seg, []netip.Addr{a}, s.cfg.Now()); err != nil {
			return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
		}
	}
	b := newBuilder(hdr, q, dnsmessage.RCodeSuccess)
	if b == nil || b.StartAnswers() != nil {
		return nil
	}
	err := b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 0},
		dnsmessage.AResource{A: a.As4()},
	)
	if err != nil {
		return nil
	}
	msg := finish(b, e, dnsmessage.RCodeSuccess)
	if msg == nil {
		return nil
	}
	// The sinkhole and paranoid mode both answer with the unspecified
	// address, and both know that they block. Thus the row says so directly.
	// The reader does not have to infer it from 0.0.0.0.
	v := verdict{act: dnslog.ActResolved, answer: a.String()}
	if a.IsUnspecified() {
		v.act = dnslog.ActBlocked
	}
	return s.reply(seg, hdr, q, e, msg, src, v, quiet, maxUDP)
}

// admit reports whether a query from src goes to the log.
func (seg *Segment) admit(now time.Time, src netip.Addr, listed bool) bool {
	c := logOrdinary
	if listed {
		c = logListed
	}
	return seg.admitClass(now, src, c)
}

func (seg *Segment) admitClass(now time.Time, src netip.Addr, c logClass) bool {
	lg := seg.log.Load()
	if lg == nil || lg.lim == nil {
		return true
	}
	return lg.lim.takeClass(now, src, c)
}

// event appends one transaction. No validity rule can fail: unlike a text
// line, a row gives any name back as itself.
func (seg *Segment) event(now time.Time, ev dnslog.Event) {
	lg := seg.log.Load()
	if lg == nil {
		return
	}
	ev.T = now.UTC().Format(base.ISO)
	ev.Seg = seg.Name
	lg.line(dnslog.EventLine(ev))
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
