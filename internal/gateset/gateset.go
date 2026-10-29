// Package gateset is the rules of a write to a gate set of the resolver:
// which sets are gate sets, which addresses may go in, how many go in
// one write, and the nft text of the write. pf dns decides what to
// write, and the process that holds CAP_NET_ADMIN does the write. Both
// use this package. Thus the two cannot disagree about these rules.
//
// It uses only the standard library.
package gateset

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// resolverSet names the sets with elements that the resolver fills:
// resolved_v4 of the agent, the set of the house, and one
// resolved_<segment>_v4 for each plain segment. A compiled set
// (blacklist_v4, direct_ip_v4, ssh_allow_v4) is not one of them.
var resolverSet = regexp.MustCompile(`^(resolved_v4|resolved_[a-z0-9_]+_v4)$`)

// IsResolverSet reports if name is a set that the resolver fills.
func IsResolverSet(name string) bool { return resolverSet.MatchString(name) }

// localV4 is what --stop-dns-rebind refused beyond what netip already
// names: this network, CGNAT, the benchmark range and class E.
var localV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Public drops each address that a gate set must not learn from an
// upstream: private, loopback, link-local, multicast, unspecified and the
// ranges in localV4. It filters the slice in place.
func Public(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0]
next:
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		for _, p := range localV4 {
			if p.Contains(a) {
				continue next
			}
		}
		out = append(out, a)
	}
	return out
}

// MaxA is the number of addresses that one answer can put in the gate
// set when the client gets the full answer: the house, and a type that
// dns_types.allow forwards. An address-only A answer uses maxFlatA of
// internal/dnsd, the number of addresses that the client gets. Each
// answer adds its addresses to a set with a size (render resolvedSetSize).
// Without a limit, one large answer over TCP (about 4000 A records) could
// use a large part of that size. 64 is four times maxFlatA. A client
// that connects to an address after the first 64 meets the gate drop,
// the same as for an address that this box did not resolve.
const MaxA = 64

// Cmd runs the nft command. It makes one call per answer with all
// addresses in it, not one call per address.
//
// The cost is a fork per cache miss, measured at a few milliseconds on a
// Pi. This is the starting point intentionally. The order guarantee is
// the important property, and a subprocess makes it clear. A long-lived
// pipe or a netlink dependency would both need proof first. Replace it
// when a profile shows the need, not before.
type Cmd struct {
	// Table is the family and table of the sets, "inet fortress".
	Table string
	// Run runs nft with one argument. Nil runs the nft command (Exec). A
	// test gives its own, so that it can read the text without root.
	Run func(arg string) error
}

// Timeout limits one nft call.
const Timeout = 3 * time.Second

// Add puts addrs into set. It skips each address that is not IPv4.
func (n *Cmd) Add(set string, addrs []netip.Addr) error {
	elems := v4Elems(addrs)
	if elems == "" {
		return nil
	}
	// The set has its own timeout. Thus the code adds an element bare,
	// and the kernel expires it. nft is idempotent for an element that
	// is already present. A repeated answer causes that case.
	return n.run(fmt.Sprintf("add element %s %s { %s }", n.Table, set, elems))
}

// Refresh restarts the timeout of each element, if it is in the set or
// not. On the kernels where this runs, an add of a present element does
// nothing. "destroy" is newer than their nft. Thus Refresh uses add,
// delete, add in one command line, and nft applies it as one transaction.
// The first add makes sure that the delete finds something. The second
// add puts the element back with the full timeout of the set. No packet
// sees the set without the element.
func (n *Cmd) Refresh(set string, addrs []netip.Addr) error {
	elems := v4Elems(addrs)
	if elems == "" {
		return nil
	}
	el := fmt.Sprintf("element %s %s { %s }", n.Table, set, elems)
	return n.run("add " + el + "; delete " + el + "; add " + el)
}

func (n *Cmd) run(arg string) error {
	if n.Run != nil {
		return n.Run(arg)
	}
	return Exec(arg)
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

// Exec runs nft with arg as its one argument, for a maximum of Timeout.
// The error has the text that nft wrote to stderr.
func Exec(arg string) error {
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
	case <-time.After(Timeout):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("nft %q: timed out", arg)
	}
}
