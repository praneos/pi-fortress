package dnsd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// reDNSName is the shape that internal/render already requires of
// DOT_AUTH_NAME. It is repeated here because a daemon validates its own
// arguments. It does not trust the code that built them.
var reDNSName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// reIfName is a Linux interface name: at most 15 bytes (IFNAMSIZ less
// the NUL), no slash, no space, no colon.
var reIfName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// exchanger is one query out and one answer back over the upstream leg
// of the segment, whatever that leg is. It exists so that New selects the
// plaintext UDP path or the DoT path in dot.go one time. Without it, the
// code would branch on this for each query.
//
// req has the id of the client. An implementation rerolls that id on the
// wire. The answer that it returns can have either id, because forward
// puts the client id back before the answer reaches the client.
type exchanger interface {
	exchange(ctx context.Context, req []byte) ([]byte, error)
}

// upstreamLeg validates the upstream settings of a segment and returns
// the leg that they describe. A plain upstream and DoT are mutually
// exclusive. One does not quietly win over the other, because a box with
// both would then seem to do whichever the operator hoped for.
func (seg *Segment) upstreamLeg(now func() time.Time) (exchanger, error) {
	if seg.DoTName == "" && len(seg.DoTIPs) == 0 {
		host, port, err := net.SplitHostPort(seg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("segment %q: upstream %q: %w", seg.Name, seg.Upstream, err)
		}
		// "10.64.0.1@wg0:53": the WireGuard house resolves at the far end of the
		// tunnel. The socket is bound to the tunnel, so when the tunnel is down
		// the query fails. It does not leave in plaintext by the default route of
		// the uplink (HouseDNSForward in render; first run on hardware
		// 2026-09-23, when this form was still refused).
		addr, iface, pinned := strings.Cut(host, "@")
		if !pinned {
			return udpExchanger{addr: seg.Upstream}, nil
		}
		if _, err := netip.ParseAddr(addr); err != nil {
			return nil, fmt.Errorf("segment %q: upstream %q: %q before the @ is not an address", seg.Name, seg.Upstream, addr)
		}
		if !reIfName.MatchString(iface) {
			return nil, fmt.Errorf("segment %q: upstream %q: %q after the @ is not an interface name", seg.Name, seg.Upstream, iface)
		}
		return udpExchanger{addr: net.JoinHostPort(addr, port), iface: iface}, nil
	}
	if seg.Upstream != "" {
		return nil, fmt.Errorf("segment %q: upstream %q is set alongside DoT; the pinned addresses are the upstream", seg.Name, seg.Upstream)
	}
	if seg.DoTName == "" {
		return nil, fmt.Errorf("segment %q: DoT addresses with no name to authenticate them against", seg.Name)
	}
	if len(seg.DoTIPs) == 0 {
		return nil, fmt.Errorf("segment %q: DoT name %q with no pinned address", seg.Name, seg.DoTName)
	}
	if !reDNSName.MatchString(seg.DoTName) {
		return nil, fmt.Errorf("segment %q: DoT name %q is not a DNS name", seg.Name, seg.DoTName)
	}
	// "9.9.9.9" matches the shape above, and an easy mistake is to paste a
	// pinned address into the name field. No real top level domain is all
	// digits. An address as the TLS ServerName would fail each handshake at
	// run time. This code refuses it here instead, while the operator still
	// watches.
	if last := seg.DoTName[strings.LastIndex(seg.DoTName, ".")+1:]; allDigits(last) {
		return nil, fmt.Errorf("segment %q: DoT name %q is an address; it has to be the name the certificate is valid for", seg.Name, seg.DoTName)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range seg.DoTIPs {
		// The output chain pins IPv4 addresses on 853. The daemon would dial a v6
		// upstream, and then the ruleset of the box would drop it.
		if !a.Is4() {
			return nil, fmt.Errorf("segment %q: DoT address %q is not IPv4", seg.Name, a)
		}
		if seen[a] {
			return nil, fmt.Errorf("segment %q: DoT address %q is listed twice", seg.Name, a)
		}
		seen[a] = true
	}
	if seg.DoTIface != "" && !reIfName.MatchString(seg.DoTIface) {
		return nil, fmt.Errorf("segment %q: dot_iface %q is not an interface name", seg.Name, seg.DoTIface)
	}
	d := newDoT(seg.DoTName, seg.DoTIPs, now)
	d.iface = seg.DoTIface
	return d, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// udpExchanger is the plaintext leg: one new socket for each query to a
// single resolver. All segments used it before DoT existed. A segment
// still gets it when it has no pinned DoT addresses.
type udpExchanger struct {
	addr  string // host:port
	iface string // SO_BINDTODEVICE when set: the WireGuard house's tunnel
}

// dialer binds to u.iface when it is set. The bind keeps the queries of a
// tunnelled segment off the uplink: a socket bound to a device that is
// gone cannot go to a different route.
func (u udpExchanger) dialer() *net.Dialer {
	d := &net.Dialer{}
	if u.iface != "" {
		d.Control = bindToDevice(u.iface)
	}
	return d
}

func (u udpExchanger) exchange(ctx context.Context, req []byte) ([]byte, error) {
	resp, err := u.overUDP(ctx, req)
	if err != nil {
		return nil, err
	}
	// An answer that does not fit in a datagram comes back as a stub with TC
	// set and no content. Without the retry here, the TCP retry of the client
	// reaches a forwarder whose upstream leg is still UDP, so it gets the
	// same stub. Then a large answer is unreachable through this resolver,
	// however the client asks. If the TCP attempt fails, the code keeps the
	// stub, because a client told to retry is better off than a client told
	// that the name does not resolve.
	if len(resp) >= 12 && resp[2]&0x02 != 0 {
		if full, err := u.overTCP(ctx, req); err == nil {
			return full, nil
		}
	}
	return resp, nil
}

func (u udpExchanger) overUDP(ctx context.Context, req []byte) ([]byte, error) {
	// A new socket for each query gives a new ephemeral source port, and the
	// code rerolls the id with it. These two together are the protection that
	// a forwarder has against an off-path answer.
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	out := patchID(req, id)
	c, err := u.dialer().DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	end := time.Now().Add(upstreamTO)
	_ = c.SetDeadline(end)
	// The buffer holds the largest datagram that a DNS message can be. If its
	// size was what we advertise, a larger answer would silently arrive
	// truncated at the end of the buffer. Its counts would promise records
	// that are not there. The completeness check below exists to refuse
	// exactly that message, but this one would come from our own read, not
	// from the upstream.
	buf := make([]byte, maxMsg)
	// The code keeps the id and the socket across attempts on purpose. A
	// duplicate query does no harm: DNS answers the same thing two times. If
	// the socket stays, an answer to the first ask that was only slow still
	// arrives in this read. Otherwise it arrives at a closed port after we
	// stopped the wait for it. A reroll of either would discard that answer
	// and wait for the next one.
	for {
		if _, err := c.Write(out); err != nil {
			return nil, err
		}
		// Wait for one attempt, not for the full budget, so there is time to ask
		// again. The last attempt gets the remainder.
		until := time.Now().Add(udpRetryAfter)
		last := !until.Before(end)
		if last {
			until = end
		}
		_ = c.SetReadDeadline(until)
		resp, err := readAnswer(c, buf, out, id)
		if err == nil {
			return resp, nil
		}
		// A timeout on a middle attempt means that the datagram or its answer
		// was lost: ask again. All other errors, and the deadline on the final
		// attempt, are the failure that the caller gets.
		var ne net.Error
		if last || !errors.As(err, &ne) || !ne.Timeout() {
			return nil, err
		}
	}
}

// readAnswer reads from c until it has the answer to out, or until the
// read deadline in force stops it.
func readAnswer(c net.Conn, buf, out []byte, id uint16) ([]byte, error) {
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 {
			continue
		}
		// The socket is connected, so only the upstream reaches it. The id must
		// still match, or the code would take a late answer to a previous query
		// for this one.
		if uint16(buf[0])<<8|uint16(buf[1]) != id {
			continue
		}
		if !isAnswerTo(out, buf[:n]) {
			continue
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		return resp, nil
	}
}

// overTCP asks the same upstream again over TCP. TCP is the transport
// that has no size limit that can truncate an answer. It uses the
// two-byte length prefix of RFC 1035, the same framing that the
// downstream listener uses.
func (u udpExchanger) overTCP(ctx context.Context, req []byte) ([]byte, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	out := patchID(req, id)
	c, err := u.dialer().DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(upstreamTO))
	frame := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(out)))
	copy(frame[2:], out)
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 12 || n > maxMsg {
		return nil, fmt.Errorf("upstream %s: tcp frame of %d bytes is not a message", u.addr, n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(resp[:2]) != id || !isAnswerTo(out, resp) {
		return nil, fmt.Errorf("upstream %s: tcp reply does not answer the question asked", u.addr)
	}
	return resp, nil
}

// isAnswerTo is everything that a datagram must be before this forwarder
// acts on it: an answer at all, to the opcode that was asked, to the
// question that was asked, and complete.
//
// A match of only the id and the question left three ways in. A query
// that comes back reflected has both, but is not an answer. A reply to a
// different opcode has both, but has a different meaning. A message whose
// header counts promise records that the bytes do not have parses far
// enough to look like an answer, and then stops. The forwarder then
// admits the records that did arrive to the gate set and caches them. But
// it never judges the records that the upstream meant to put after them,
// for example the rest of a CNAME chain.
func isAnswerTo(req, resp []byte) bool {
	if len(resp) < 12 || len(req) < 12 {
		return false
	}
	if resp[2]&0x80 == 0 {
		return false
	}
	if resp[2]>>3&0x0f != req[2]>>3&0x0f {
		return false
	}
	return sameQuestion(req, resp) && whole(resp)
}

// questionEnd is the offset immediately after the question section of a
// message with exactly one question. It is false for all other messages:
// no question, more than one, a name that goes past the end, or a
// compression pointer. The question is the first name in a message, so
// nothing is before it to point at, and a pointer there is malformed.
func questionEnd(m []byte) (int, bool) {
	if len(m) < 12 || uint16(m[4])<<8|uint16(m[5]) != 1 {
		return 0, false
	}
	i := 12
	for {
		if i >= len(m) {
			return 0, false
		}
		n := int(m[i])
		if n == 0 {
			i++
			break
		}
		if n&0xC0 != 0 {
			return 0, false
		}
		i += n + 1
	}
	// QTYPE and QCLASS.
	if i+4 > len(m) {
		return 0, false
	}
	return i + 4, true
}

// sameQuestion is true when the reply answers the question that was
// asked. A match of only the transaction id is not sufficient. Ids are 16
// bits, and we give them out again after a caller stops the wait. A late
// reply would then go to the next holder of that id, and its addresses
// would go into the nft set under the wrong name. The compare ignores
// case, because a resolver can echo the name in a different case. That
// is a correct answer, not a mismatched one.
func sameQuestion(req, resp []byte) bool {
	qe, ok := questionEnd(req)
	if !ok {
		return false
	}
	re, ok := questionEnd(resp)
	if !ok || re != qe {
		return false
	}
	for i := 12; i < qe; i++ {
		a, b := req[i], resp[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
