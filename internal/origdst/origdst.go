// Package origdst gets the destination of a connection before the redirect
// from the kernel. On Linux it uses SO_ORIGINAL_DST. Other systems are not
// supported. Only internal/engine calls it.
package origdst

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const soOriginalDst = 80

var (
	ErrIPv6   = errors.New("origdst: ipv6 disabled")
	ErrNotTCP = errors.New("origdst: not tcp")
	ErrShort  = errors.New("origdst: short sockaddr")
	ErrFamily = errors.New("origdst: not inet4")
)

const (
	afInet  = 2
	afInet6 = 10
)

func parseInet4(b []byte) (netip.AddrPort, error) {
	if len(b) < 8 {
		return netip.AddrPort{}, ErrShort
	}
	family := binary.NativeEndian.Uint16(b[0:2])
	if family == afInet6 {
		return netip.AddrPort{}, ErrIPv6
	}
	if family != afInet {
		return netip.AddrPort{}, ErrFamily
	}
	port := binary.BigEndian.Uint16(b[2:4])
	addr, ok := netip.AddrFromSlice(b[4:8])
	if !ok {
		return netip.AddrPort{}, ErrShort
	}
	return netip.AddrPortFrom(addr, port), nil
}
