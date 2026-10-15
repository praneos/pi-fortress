package dnsd

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// NFTWriter puts resolved addresses into an nftables set. It is an
// interface because the write is on the answer path. The gate drops a
// connection to an address that is not yet in the set. Thus tests must
// have a way to see the order without root.
type NFTWriter interface {
	Add(set string, addrs []netip.Addr) error
}

// nftCmd runs the nft command. It makes one call per answer with all
// addresses in it, not one call per address.
//
// The cost is a fork per cache miss, measured at a few milliseconds on a
// Pi. This is the starting point intentionally. The order guarantee is
// the important property, and a subprocess makes it clear. A long-lived
// pipe or a netlink dependency would both need proof first. Replace it
// when a profile shows the need, not before.
type nftCmd struct {
	table string
}

const nftTimeout = 3 * time.Second

func (n *nftCmd) Add(set string, addrs []netip.Addr) error {
	elems := v4Elems(addrs)
	if elems == "" {
		return nil
	}
	// The set has its own timeout. Thus the code adds an element bare,
	// and the kernel expires it. nft is idempotent for an element that
	// is already present. A repeated answer causes that case.
	return n.run(fmt.Sprintf("add element %s %s { %s }", n.table, set, elems))
}

// Refresh restarts the timeout of each element, if it is in the set or
// not. On the kernels where this runs, an add of a present element does
// nothing. "destroy" is newer than their nft. Thus Refresh uses add,
// delete, add in one command line, and nft applies it as one transaction.
// The first add makes sure that the delete finds something. The second
// add puts the element back with the full timeout of the set. No packet
// sees the set without the element.
func (n *nftCmd) Refresh(set string, addrs []netip.Addr) error {
	elems := v4Elems(addrs)
	if elems == "" {
		return nil
	}
	el := fmt.Sprintf("element %s %s { %s }", n.table, set, elems)
	return n.run("add " + el + "; delete " + el + "; add " + el)
}

func v4Elems(addrs []netip.Addr) string {
	elems := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() {
			elems = append(elems, a.String())
		}
	}
	return strings.Join(elems, ", ")
}

func (n *nftCmd) run(arg string) error {
	cmd := exec.Command("nft", arg)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("nft %q: %w: %s", arg, err, strings.TrimSpace(errb.String()))
		}
		return nil
	case <-time.After(nftTimeout):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("nft %q: timed out", arg)
	}
}

// discardNFT is for -check and the tests. It accepts every write, so the
// rest of the path can run without access to the kernel.
type discardNFT struct{}

func (discardNFT) Add(string, []netip.Addr) error { return nil }
