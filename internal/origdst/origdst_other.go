//go:build !linux

package origdst

import (
	"errors"
	"net"
	"net/netip"
)

func Get(c *net.TCPConn) (netip.AddrPort, error) {
	_ = c
	return netip.AddrPort{}, errors.New("origdst: linux only")
}
