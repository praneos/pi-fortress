package srclimit

import (
	"net"
	"net/netip"
	"testing"
)

func tcp(s string) net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

func TestPerSourceCapsOneAddressNotOthers(t *testing.T) {
	p := New(2)
	var rel []func()
	for i, port := range []string{"1001", "1002"} {
		r, ok := p.Acquire(tcp("10.0.0.5:" + port))
		if !ok {
			t.Fatalf("conn %d refused under the cap", i)
		}
		rel = append(rel, r)
	}
	if _, ok := p.Acquire(tcp("10.0.0.5:1003")); ok {
		t.Fatal("third conn from one address admitted over a cap of 2")
	}
	r, ok := p.Acquire(tcp("10.0.0.6:1001"))
	if !ok {
		t.Fatal("another address refused while the first was full")
	}
	r()
	rel[0]()
	rel[0]()
	if got := p.Count(netip.MustParseAddr("10.0.0.5")); got != 1 {
		t.Fatalf("count after one release (called twice) = %d, want 1", got)
	}
	if _, ok := p.Acquire(tcp("10.0.0.5:1004")); !ok {
		t.Fatal("slot not returned on release")
	}
}

func TestPerSourceZeroIsOff(t *testing.T) {
	p := New(0)
	for i := 0; i < 100; i++ {
		if _, ok := p.Acquire(tcp("10.0.0.5:1")); !ok {
			t.Fatal("cap 0 refused a connection")
		}
	}
	var nilP *PerSource
	if _, ok := nilP.Acquire(tcp("10.0.0.5:1")); !ok {
		t.Fatal("nil counter refused a connection")
	}
}

func TestPerSourceDeletesAtZero(t *testing.T) {
	p := New(4)
	r, _ := p.Acquire(tcp("10.0.0.5:1"))
	r()
	if p.Len() != 0 {
		t.Fatalf("map kept %d entries after the last release", p.Len())
	}
}

func TestPerSourceV4MappedIsSameKey(t *testing.T) {
	p := New(1)
	if _, ok := p.Acquire(tcp("10.0.0.5:1")); !ok {
		t.Fatal("first refused")
	}
	if _, ok := p.Acquire(tcp("[::ffff:10.0.0.5]:2")); ok {
		t.Fatal("v4-mapped form of the same address got a second slot")
	}
}

func TestPerSourceUnparsedAdmitted(t *testing.T) {
	p := New(1)
	u := &net.UnixAddr{Name: "@x", Net: "unix"}
	for i := 0; i < 3; i++ {
		if _, ok := p.Acquire(u); !ok {
			t.Fatal("unix address refused")
		}
	}
}
