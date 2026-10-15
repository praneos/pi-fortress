package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"pi-fortress/internal/dest"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/keyshape"
	"pi-fortress/internal/preamble"
)

// Fake-IP (internal/fakeip): pf dns answers the A queries of the agent
// from a reserved pool. It records in a journal which name got which
// address. Thus the only thing that the agent can do with a name is open
// TLS to its fake address. In the broker, that address changes back into
// a name, and the name into a real origin. This occurs after each check
// that the fence runs on a connection. Thus DNS stops carrying data that
// the fence has not seen.
//
// The causes are refusals of the connection, not of a substitution. But
// they go to the strip log as the same row. That log is the operator
// channel for things that the fence blocks. The alerter and observe
// already tail it, and a distinct cause is all that either needs to tell
// them apart.
const (
	// CauseFakeIPNoSNI: a fake address with no SNI. The engine and the
	// preamble already refuse an empty SNI. Here the broker does not trust
	// either of them with the one field that fake-IP depends on.
	CauseFakeIPNoSNI fence.RefusalCause = "fakeip_no_sni"
	// CauseFakeIPUnmapped: a pool address for which the journal names
	// nothing. For example, an agent that cached an answer across a pf dns
	// wipe, or an agent that picked an address in the pool without a query.
	CauseFakeIPUnmapped fence.RefusalCause = "fakeip_unmapped"
	// CauseFakeIPSNIMismatch: the SNI is not the name that the address maps
	// to. This makes reuse of a full pool safe: the broker refuses an agent
	// that holds a stale answer, and does not send it to the new owner of
	// the address. It also prevents the use of a fake address as a relay to
	// any name.
	CauseFakeIPSNIMismatch fence.RefusalCause = "fakeip_sni_mismatch"
	// CauseFakeIPSegment: a pool address from outside the agent network.
	// pf dns gives pool addresses only to the agent network.
	CauseFakeIPSegment fence.RefusalCause = "fakeip_segment"
	// CauseFakeIPKeyShape: the SNI carries a key or a placeholder. The broker
	// refuses it before the lookup or resolve, because the lookup is the leak.
	CauseFakeIPKeyShape fence.RefusalCause = "fakeip_key_shape"
	// CauseFakeIPDestDenied: the name resolved, but to no address that the
	// broker is permitted to dial. This is a private or reserved address,
	// which is DNS rebinding toward the Pi's own networks, or an answer from
	// the fake pool.
	CauseFakeIPDestDenied fence.RefusalCause = "fakeip_dest_denied"
	// CauseFakeIPLiteral: the name is an address. A resolve of it gives back
	// the same literal. Thus a dial to it would be the direct-IP connection
	// that the agent gate is there to drop, laundered through a pool
	// address.
	CauseFakeIPLiteral fence.RefusalCause = "fakeip_ip_literal"
)

// ErrFakeIP is each fake-IP refusal before a dial. The agent gets one
// response for all of them (fakeipBody). The cause is in the error and in
// the strip log.
var ErrFakeIP = errors.New("broker: fake-ip destination refused")

const fakeipBody = "fakeip\n"

// ResolveFunc is how the broker resolves the name of a fake destination
// to A records. A test injects one. nil means the system resolver.
type ResolveFunc func(ctx context.Context, name string) ([]netip.Addr, error)

// NewResolver resolves through the DNS server at addr (host:port). It is
// for a broker that should not trust its system resolver with the names
// of the agent. Empty addr means the system resolver.
func NewResolver(addr string) ResolveFunc {
	r := net.DefaultResolver
	if addr != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	}
	return func(ctx context.Context, name string) ([]netip.Addr, error) {
		return r.LookupNetIP(ctx, "ip4", name)
	}
}

// maxFakeDials limits how many resolved addresses one connection tries.
// A name with a dozen A records that all fail is down. Each extra try is
// one more ten-second dial for the agent to wait through.
const maxFakeDials = 3

// resolveTimeout limits the broker's own lookup. The Handle context has
// no deadline of its own.
const resolveTimeout = 5 * time.Second

// isFake reports whether dst is a pool address: fake-IP is on and the
// agent connected to an address that pf dns gives out. With fake-IP off,
// this is false for all addresses. That keeps the old path of Handle
// intact.
func (b *Broker) isFake(dst netip.AddrPort) bool {
	return b.FakeIP != nil && dst.IsValid() && b.FakeIP.Contains(dst.Addr())
}

// fakeAdmit maps a fake destination back to its name and holds the SNI to
// it. It returns the name to resolve, or the cause of its refusal after
// it writes the strip row. Nothing here resolves or dials.
//
// The key check runs before all other checks. Thus the broker refuses a
// key-shaped SNI before its name gets into the row that another refusal
// would write.
func (b *Broker) fakeAdmit(p *preamble.Preamble) (string, fence.RefusalCause) {
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	row := jsonl.Refused{Where: "preamble", SNI: sni, ClientIP: clientIP(p)}
	var cause fence.RefusalCause
	rule := ""
	if sni != "" {
		rule = b.keyRule(p.SNI)
	}
	name, ok := "", false
	switch {
	case sni == "":
		cause = CauseFakeIPNoSNI
	case rule != "":
		// The SNI carries the key, so it stays off the log. The operator acts on
		// the zone and the rule.
		cause, row.SNI, row.Host, row.Kind = CauseFakeIPKeyShape, "", b.logZone(strings.TrimSuffix(p.SNI, ".")), rule
	case b.AgentNet.IsValid() && !b.AgentNet.Contains(p.Src.Addr()):
		cause = CauseFakeIPSegment
	case addrLiteral(sni):
		cause = CauseFakeIPLiteral
	default:
		if name, ok = b.FakeIP.Name(p.OrigDst.Addr()); !ok {
			cause = CauseFakeIPUnmapped
		} else if name != sni {
			cause, row.Host = CauseFakeIPSNIMismatch, name
		}
	}
	if cause == "" {
		return name, ""
	}
	row.Cause = string(cause)
	// A key in the SNI is the fence that catches a credential on its way
	// out, each time. The others are conditions that a stale cache repeats on
	// each retry. Thus they alert one time, as alertRefusal explains.
	row.Alert = cause == CauseFakeIPKeyShape || b.alertRefusal(cause)
	_ = b.Logs.Refused(row)
	return "", cause
}

// addrLiteral reports a name that is an address in any spelling that a
// resolver would give back unchanged: dotted or v6, bracketed, with a
// root dot or a zone. It also takes a name whose last label is all
// digits as an address. No TLD is numeric (RFC 3696 2), and "127.1" or
// "2130706433" are addresses to every inet_aton.
func addrLiteral(name string) bool {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	n = strings.TrimSuffix(strings.TrimPrefix(n, "["), "]")
	if n == "" {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return true
	}
	last := n[strings.LastIndexByte(n, '.')+1:]
	if last == "" {
		return false
	}
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return false
		}
	}
	return true
}

// keyRule names the rule for a key in an SNI, "placeholder" for a
// placeholder of the gateway, or "" for neither. It is the check of pf dns
// (keyshape.Match), with no prefilter. Thus the broker refuses each SNI
// that pf dns refuses as a name. The name stays as sent, not lower-cased,
// because the placeholder check is exact. A lowered pf_ spelling is not a
// placeholder of the gateway.
func (b *Broker) keyRule(name string) string {
	re := b.TokenRE
	if re == nil && b.Rules != nil {
		re = b.Rules.All()
	}
	return keyshape.Match(re, nil, name)
}

// logZone is what a key-shape row can say about the name, as logName of pf
// dns: the last two labels, the zone that an attacker had to register. If
// the key is also in those labels, it says nothing. The check runs on the
// name as sent, because the placeholder check is exact. The row keeps the
// zone in lower case, as it keeps the SNI.
func (b *Broker) logZone(name string) string {
	zone := keyshape.Tail(name)
	if b.keyRule(zone) != "" {
		return ""
	}
	return strings.ToLower(zone)
}

func (b *Broker) resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	if b.Resolve != nil {
		return b.Resolve(ctx, name)
	}
	return NewResolver("")(ctx, name)
}

// dialName resolves name and dials the first address that dest.Allowed
// accepts. On a dial error it tries the next address, to a maximum of
// maxFakeDials. Here it applies to each real address the check that the
// fake address skipped in Handle. Thus a name that resolves to 10.0.0.1
// gets the same refusal as an agent that connects to 10.0.0.1. It
// returns the address that connected. TLS still verifies against the SNI.
func (b *Broker) dialName(ctx context.Context, name string, port uint16, sni, ip string) (net.Conn, netip.AddrPort, error) {
	if addrLiteral(name) {
		b.refuseResolve(name, sni, ip, CauseFakeIPLiteral)
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %s is an address, not a name", ErrSSRF, name)
	}
	addrs, err := b.resolve(ctx, name)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("broker: resolve %s: %w", name, err)
	}
	var last error
	tried := 0
	for _, a := range addrs {
		dst := netip.AddrPortFrom(a.Unmap(), port)
		if !dst.Addr().Is4() || !dest.Allowed(dst) {
			continue
		}
		if tried == maxFakeDials {
			break
		}
		tried++
		c, err := b.dial(ctx, dst, sni)
		if err == nil {
			return c, dst, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if tried == 0 {
		b.refuseResolve(name, name, ip, CauseFakeIPDestDenied)
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %s resolved to no dialable address", ErrSSRF, name)
	}
	return nil, netip.AddrPort{}, last
}

// refuseResolve writes the strip row of a refusal at the resolve step.
func (b *Broker) refuseResolve(host, sni, ip string, cause fence.RefusalCause) {
	_ = b.Logs.Refused(jsonl.Refused{
		Host:     host,
		SNI:      sni,
		Where:    "resolve",
		Cause:    string(cause),
		ClientIP: ip,
		Alert:    b.alertRefusal(cause),
	})
}
