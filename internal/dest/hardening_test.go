package dest

import "testing"

func TestPortAndMappedV6(t *testing.T) {
	cases := []struct {
		dst  string
		want bool
	}{
		{"8.8.8.8:80", false},
		{"8.8.8.8:8443", false},
		{"192.0.2.2:80", false},
		{"[::ffff:8.8.8.8]:443", true},
		{"[::ffff:10.0.0.1]:443", false},
		{"[::ffff:127.0.0.1]:443", false},
		{"[::ffff:169.254.1.1]:443", false},
		{"[::ffff:192.168.1.1]:443", false},
		{"[::ffff:0.0.0.0]:443", false},
		{"[::1]:443", false},
		{"[fe80::1]:443", false},
		{"[2001:db8::1]:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"[64:ff9b::808:808]:443", false},
	}
	for _, c := range cases {
		if got := Allowed(ap(c.dst)); got != c.want {
			t.Fatalf("%s: got %v want %v", c.dst, got, c.want)
		}
	}
}
