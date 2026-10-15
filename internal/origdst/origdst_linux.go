//go:build linux

package origdst

import (
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

func Get(c *net.TCPConn) (netip.AddrPort, error) {
	if c == nil {
		return netip.AddrPort{}, ErrNotTCP
	}
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP.To4() == nil {
		return netip.AddrPort{}, ErrIPv6
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.AddrPort
	var opErr error
	ctlErr := rc.Control(func(fd uintptr) {
		addr, opErr = getOrigDst(fd)
	})
	if ctlErr != nil {
		return netip.AddrPort{}, ctlErr
	}
	return addr, opErr
}

func getOrigDst(fd uintptr) (netip.AddrPort, error) {
	buf := make([]byte, 16)
	n := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(syscall.IPPROTO_IP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
		0,
	)
	if errno != 0 {
		return netip.AddrPort{}, errno
	}
	return parseInet4(buf[:n])
}
