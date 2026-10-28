package dnsd

import "syscall"

// bindToDevice pins an upstream socket to one interface before it
// connects. It is the dial half of what control in serve.go does for the
// listeners. The socket is new, and no device pins it yet. Linux 5.7 and
// later let a process with no capability set the option on such a socket.
// Thus pf dns runs without CAP_NET_RAW (vm/pi/dns-agent-go.service).
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}
}
