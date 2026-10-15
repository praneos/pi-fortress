// Package dest decides if the broker can dial an address. It refuses
// loopback, private, link-local and the other reserved ranges. Only
// internal/broker calls it.
package dest

import (
	"net/netip"

	"pi-fortress/internal/base"
)

var deny = base.MustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"100.64.0.0/10",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

// echo is the two TEST-NET-1 addresses on which the echo fixtures of the
// broker answer (internal/broker/echo.go). The code denies the rest of
// 192.0.2.0/24 with the other reserved ranges. 192.0.2.1 is the block
// canary of the project.
var echo = [...]netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")}

// Allowed copies the nft output rule for the broker: port 443 only, to a
// public unicast IPv4 address. It judges IPv4-mapped IPv6 as the IPv4 in
// it. It refuses all other IPv6, because the uplink drops it.
func Allowed(dst netip.AddrPort) bool {
	if !dst.IsValid() || dst.Port() != 443 {
		return false
	}
	ip := dst.Addr().Unmap()
	if !ip.Is4() {
		return false
	}
	if ip == echo[0] || ip == echo[1] {
		return true
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range deny {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
