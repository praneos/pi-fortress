package dnsd

import "net/netip"

// NFTWriter puts resolved addresses into an nftables set. It is an
// interface because the write is on the answer path. The gate drops a
// connection to an address that is not yet in the set. Thus tests must
// have a way to see the order without root.
type NFTWriter interface {
	Add(set string, addrs []netip.Addr) error
}

// discardNFT is for -check and the tests. It accepts every write, so the
// rest of the path can run without access to the kernel.
type discardNFT struct{}

func (discardNFT) Add(string, []netip.Addr) error { return nil }
