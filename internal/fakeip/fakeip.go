// Package fakeip is the address pool behind the resolver of the agent. pf dns
// no longer forwards the A queries of the agent. It answers each query with
// an address from a reserved pool, one name per address, and journals the
// pair. The agent then opens TLS to that address. The engine gives the
// address to the broker as OrigDst. The broker maps it back to the name,
// holds the SNI to it, and only then resolves the real origin server itself.
//
// The point is that DNS is no longer a data channel out of the agent. A
// name reaches an upstream resolver only when the agent actually opens TLS
// to it, and only after each check that the fence runs on a connection.
//
// Two processes share one file. The Pool is the writer, and is in pf dns.
// The Table is the reader, and is in the broker. They share no memory and
// no socket, only the journal. So the broker needs nothing from pf dns
// except read access to one file. A restart of either loses nothing that
// the other depends on.
package fakeip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

var (
	// ErrPrefix: the pool is not an IPv4 prefix of /8 to /24. A prefix
	// smaller than /24 is refused, because the pool gives out whole /24s
	// (see usable). A prefix larger than /8 is refused, because a pool that
	// wide would shadow a real share of the address space, and the broker
	// treats each address in the pool as fake.
	ErrPrefix = errors.New("fakeip: pool must be an IPv4 prefix from /8 to /24")
	// ErrHome: the pool is not wholly inside one of homes.
	ErrHome = errors.New("fakeip: pool must sit inside 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 or 198.18.0.0/15")
	// ErrName: the name is empty, longer than 253, or holds a byte the
	// journal cannot carry (a space, a control byte, anything past ASCII).
	ErrName = errors.New("fakeip: name is empty, longer than 253 bytes or not printable ascii")
	// ErrClosed: Assign after Close.
	ErrClosed = errors.New("fakeip: pool closed")
)

// maxName is the longest name DNS can carry in text form.
const maxName = 253

// homes are the ranges where a pool may be: RFC 1918, CGNAT and the
// benchmark block. Each one is inside the @reserved_v4 drop of the broker.
// So if a synthetic address is ever dialled for real, the Pi drops it, and
// it does not reach the holder of that address. A public pool would also
// shadow real space: each address in it is fake to the broker, so a real
// origin server there maps to nothing. It is fakeIPHomes of render, which
// checks FAKEIP_NET before apply. Loopback and link-local are left out on
// purpose, because both already have a meaning on the Pi.
var homes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// CheckPrefix is the validation that OpenPool applies. It is exported so
// that a flag can be refused at startup, and does not silently disable
// fake-IP. The -fakeip-net flags of the broker and of pf dns come here.
// render already refused a public FAKEIP_NET, but a flag typed by hand did
// not go through render.
func CheckPrefix(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 24 {
		return ErrPrefix
	}
	for _, h := range homes {
		if h.Bits() <= p.Bits() && h.Contains(p.Addr()) {
			return nil
		}
	}
	return ErrHome
}

// Normalise is the form in which a name is journalled and compared: lower
// case, no trailing dot. DNS names are case-insensitive, and the trailing
// dot is the root. So both spellings are one name, and must get one address.
func Normalise(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" || len(n) > maxName {
		return "", ErrName
	}
	// The journal is space separated and newline terminated. So a name
	// with either would forge a second field or a second line. No name that a
	// resolver should answer for holds them, or anything outside ASCII.
	for i := 0; i < len(n); i++ {
		if n[i] <= ' ' || n[i] > '~' {
			return "", ErrName
		}
	}
	return n, nil
}

// The pool gives out host .1 to .254 of each /24 in the prefix, never .0
// or .255. That drops the network and broadcast address of the prefix, and
// also the inner ones. Classful code still treats x.y.z.0 and x.y.z.255 as
// network and broadcast whatever the mask, and some stacks and middleboxes
// refuse to connect to them. Two addresses in 256 is a cheap price, so that
// nobody ever has to debug that on the laptop of a user.
const perBlock = 254

// usable is how many addresses the pool can give out.
func usable(p netip.Prefix) uint32 {
	return (uint32(1) << (32 - p.Bits()) / 256) * perBlock
}

// addrAt is the k-th usable address of p, k < usable(p).
func addrAt(p netip.Prefix, k uint32) netip.Addr {
	b4 := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b4[:]) + k/perBlock*256 + k%perBlock + 1
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

// offsetOf is the inverse of addrAt. It fails for an address outside p and
// for the excluded .0 and .255, so a journal line that names one is ignored.
func offsetOf(p netip.Prefix, a netip.Addr) (uint32, bool) {
	a = a.Unmap()
	if !a.Is4() || !p.Contains(a) {
		return 0, false
	}
	b4, a4 := p.Masked().Addr().As4(), a.As4()
	d := binary.BigEndian.Uint32(a4[:]) - binary.BigEndian.Uint32(b4[:])
	host := d % 256
	if host == 0 || host == 255 {
		return 0, false
	}
	return d/256*perBlock + host - 1, true
}

// line is one journal record: <unix-seconds> <addr> <name>\n.
func line(stamp int64, a netip.Addr, name string) []byte {
	b := strconv.AppendInt(nil, stamp, 10)
	b = append(b, ' ')
	b = a.AppendTo(b)
	b = append(b, ' ')
	b = append(b, name...)
	return append(b, '\n')
}

// parse reads one journal line without its newline. Both sides skip a line
// that does not parse, names an address outside the pool, or carries a
// name not in normal form. That is the line torn by a power cut, or a line
// from before the pool prefix was changed.
func parse(p netip.Prefix, s string) (stamp int64, a netip.Addr, off uint32, name string, ok bool) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return 0, netip.Addr{}, 0, "", false
	}
	stamp, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, netip.Addr{}, 0, "", false
	}
	// line writes the plain IPv4 form only. The mapped form
	// (::ffff:a.b.c.d) is a different map key for the same slot. Thus two
	// names could hold one address.
	a, err = netip.ParseAddr(f[1])
	if err != nil || !a.Is4() {
		return 0, netip.Addr{}, 0, "", false
	}
	off, ok = offsetOf(p, a)
	if !ok {
		return 0, netip.Addr{}, 0, "", false
	}
	if n, err := Normalise(f[2]); err != nil || n != f[2] {
		return 0, netip.Addr{}, 0, "", false
	}
	return stamp, a, off, f[2], true
}

// readLines gives fn each complete line that r holds, and returns the bytes
// that they took. It stops after the last newline. A line that the writer
// has not finished stays for the next read, and is not parsed half written.
func readLines(r io.Reader, fn func(string)) (int64, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var n int64
	for {
		s, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		n += int64(len(s))
		fn(s[:len(s)-1])
	}
}
