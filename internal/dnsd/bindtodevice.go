package dnsd

import "syscall"

// bindToDevice pins an upstream socket to one interface before it
// connects. It is the dial half of what control in serve.go does for the
// listeners. pf dns runs with CAP_NET_RAW (vm/pi/dns-agent-go.service).
// The option needs this capability.
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
