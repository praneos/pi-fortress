//go:build vagrant

package itest

import (
	"net"
	"testing"
)

func TestUplinkParsers(t *testing.T) {
	in := "\t\tiifname \"eth1\" udp sport 68 udp dport 67 accept\n" +
		"\t\tiifname \"wlan0\" udp sport 67 udp dport 68 accept\n"
	if got := uplinkIF(in); got != "wlan0" {
		t.Errorf("uplinkIF = %q, want wlan0", got)
	}
	if got := uplinkIF("\t\tiifname \"eth1\" udp sport 68 udp dport 67 accept\n"); got != "" {
		t.Errorf("uplinkIF took the house rule: %q", got)
	}

	addr := "3: wlan0    inet 192.168.1.242/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0\\       valid_lft 3000sec"
	if got := inetAddr(addr); got != "192.168.1.242" {
		t.Errorf("inetAddr = %q", got)
	}
	if got := inetAddr(""); got != "" {
		t.Errorf("inetAddr of nothing = %q", got)
	}

	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)},
	}
	for ip, want := range map[string]bool{
		"192.168.1.242": true,
		"10.79.0.1":     false,
		"192.168.1.10":  false,
		"127.0.0.2":     false,
	} {
		if got := onLink(addrs, net.ParseIP(ip)); got != want {
			t.Errorf("onLink(%s) = %v, want %v", ip, got, want)
		}
	}
}
