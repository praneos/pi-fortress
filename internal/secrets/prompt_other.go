//go:build !linux

package secrets

import "errors"

// echoOff refuses on systems other than Linux. A read with echo on would
// show the passphrase on the screen, so ReadPassphrase stops before it
// reads.
func echoOff(fd uintptr) (func(), error) {
	_ = fd
	return nil, errors.New("secrets: cannot turn off terminal echo on this system")
}
