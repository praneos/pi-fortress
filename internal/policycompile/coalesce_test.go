package policycompile

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"testing"
	"time"
)

// coalesceIPv4Scan is CoalesceIPv4 as it was before the sort by address.
// For each prefix it scans all kept prefixes. The time is quadratic, but
// the output is the reference for the new code.
func coalesceIPv4Scan(items []string) []string {
	var nets []netip.Prefix
	for _, item := range items {
		p, ok := parsePrefix4(item)
		if !ok {
			continue
		}
		nets = append(nets, p)
	}
	sort.Slice(nets, func(i, j int) bool {
		if nets[i].Bits() != nets[j].Bits() {
			return nets[i].Bits() < nets[j].Bits()
		}
		return nets[i].Addr().Compare(nets[j].Addr()) < 0
	})
	var kept []netip.Prefix
	for _, n := range nets {
		covered := false
		for _, prev := range kept {
			if prefixContains(prev, n) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, n)
		}
	}
	collapsed := collapsePrefixes(kept)
	out := make([]string, 0, len(collapsed))
	for _, p := range collapsed {
		if p.Bits() == 32 {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out
}

func coalesceAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func coalesceU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// randomCoalesceItems makes n list items. The addresses are in a small
// space, so that many prefixes overlap. The items have nested, adjacent
// and duplicate prefixes, host bits, bare addresses and tokens that are
// not IPv4 prefixes.
func randomCoalesceItems(rng *rand.Rand, n int) []string {
	bases := []uint32{0x00000000, 0x0A000000, 0x0A080000, 0xC0000200, 0xFFFFFC00}
	junk := []string{"junk", "1.1.1.1/33", "2001:db8::/32", "::ffff:10.0.0.1", "10.0.0.256", "", "10.0.0.0/-1"}
	// A short list has prefixes of all lengths. A long list has long
	// prefixes in a larger space: a short prefix covers almost all other
	// items of a long list.
	minBits, spread := 16, uint32(0x3FF)
	if n >= 200 {
		minBits, spread = 20, 0xFFFFF
	}
	var made []netip.Prefix
	items := make([]string, 0, n)
	add := func(p netip.Prefix, s string) {
		made = append(made, p)
		items = append(items, s)
	}
	for len(items) < n {
		k := rng.IntN(12)
		if len(made) == 0 && k >= 2 && k < 9 {
			k = 0
		}
		switch {
		case k < 2:
			// A new prefix. A prefix shorter than /16 is rare.
			bits := minBits + rng.IntN(33-minBits)
			if n < 200 && rng.IntN(10) == 0 {
				bits = rng.IntN(16)
			}
			v := bases[rng.IntN(len(bases))] | rng.Uint32()&spread
			p, _ := coalesceAddr(v).Prefix(bits)
			add(p, p.String())
		case k < 4:
			// A prefix inside a prefix from before.
			outer := made[rng.IntN(len(made))]
			bits := outer.Bits() + rng.IntN(33-outer.Bits())
			v := coalesceU32(outer.Addr())
			if host := 32 - outer.Bits(); host > 0 {
				v |= rng.Uint32() & (1<<host - 1)
			}
			p, _ := coalesceAddr(v).Prefix(bits)
			add(p, p.String())
		case k < 6:
			// The sibling of a prefix from before, or the next prefix of
			// the same length.
			p := made[rng.IntN(len(made))]
			if p.Bits() == 0 {
				continue
			}
			step := uint32(1) << (32 - p.Bits())
			v := coalesceU32(p.Addr())
			if rng.IntN(2) == 0 {
				v ^= step
			} else {
				v += step
			}
			q := netip.PrefixFrom(coalesceAddr(v), p.Bits())
			add(q, q.String())
		case k < 7:
			// A duplicate, in the same form.
			items = append(items, items[rng.IntN(len(items))])
		case k < 9:
			// A prefix from before, with host bits set or as a bare
			// address.
			p := made[rng.IntN(len(made))]
			v := coalesceU32(p.Addr())
			if host := 32 - p.Bits(); host > 0 {
				v |= rng.Uint32() & (1<<host - 1)
			}
			if p.Bits() == 32 || rng.IntN(3) == 0 {
				items = append(items, coalesceAddr(v).String())
			} else {
				items = append(items, netip.PrefixFrom(coalesceAddr(v), p.Bits()).String())
			}
		case k < 10:
			items = append(items, junk[rng.IntN(len(junk))])
		default:
			// A bare host address.
			v := bases[rng.IntN(len(bases))] | rng.Uint32()&spread
			add(netip.PrefixFrom(coalesceAddr(v), 32), coalesceAddr(v).String())
		}
	}
	rng.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	return items
}

// The sort by address gives the same output as the scan of all kept
// prefixes, for many random lists.
func TestCoalesceIPv4SameAsScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(31, 32))
	for round := range 3000 {
		n := rng.IntN(120)
		if round%100 == 0 {
			n = 2000 + rng.IntN(2000)
		}
		items := randomCoalesceItems(rng, n)
		want := coalesceIPv4Scan(slices.Clone(items))
		got := CoalesceIPv4(slices.Clone(items))
		if !slices.Equal(got, want) {
			t.Fatalf("round %d: CoalesceIPv4(%q)\n got %q\nwant %q", round, items, got, want)
		}
	}
}

// 80,000 hosts that do not overlap and do not join take much less than one
// second. The old scan of all kept prefixes took about 19 s.
func TestCoalesceIPv4ManyHostsIsFast(t *testing.T) {
	const n = 80000
	items := make([]string, 0, n)
	for i := range n {
		items = append(items, coalesceAddr(0x0A000000+uint32(2*i)).String())
	}
	start := time.Now()
	out := CoalesceIPv4(items)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("CoalesceIPv4 of %d hosts took %v", n, d)
	}
	if len(out) != n {
		t.Errorf("got %d items, want %d", len(out), n)
	}
}
