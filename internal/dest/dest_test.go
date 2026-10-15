package dest

import (
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		dst  string
		want bool
	}{
		{"8.8.8.8:443", true},
		{"160.79.104.10:443", true},
		{"192.0.2.2:443", true},
		{"192.0.2.3:443", true},
		{"192.168.1.1:443", false},
		{"10.77.0.1:443", false},
		{"127.0.0.1:443", false},
		{"169.254.1.1:443", false},
		{"100.64.0.1:443", false},
		{"172.16.0.5:443", false},
		{"0.0.0.0:443", false},
		{"224.0.0.1:443", false},
		{"192.0.0.9:443", false},
		{"198.18.0.1:443", false},
		{"198.51.100.7:443", false},
		{"203.0.113.7:443", false},
		{"240.0.0.1:443", false},
		{"255.255.255.255:443", false},
		{"192.0.2.100:443", false},
		{"192.0.2.1:443", false},
		{"192.0.2.0:443", false},
		{"192.0.2.4:443", false},
		{"192.0.2.255:443", false},
		{"[::ffff:192.0.2.2]:443", true},
		{"[::ffff:192.0.2.1]:443", false},
		{"192.0.2.2:80", false},
	}
	for _, c := range cases {
		got := Allowed(ap(c.dst))
		if got != c.want {
			t.Fatalf("%s: got %v want %v", c.dst, got, c.want)
		}
	}
	if Allowed(netip.AddrPort{}) {
		t.Fatal("invalid")
	}
}
