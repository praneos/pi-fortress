module pi-fortress

go 1.27

toolchain go1.27.3

// Plain TCP for each listener and dial. Since Go 1.24 a listener uses
// MPTCP when the kernel has it, and no client of the box needs MPTCP.
godebug multipathtcp=0

require (
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
)
