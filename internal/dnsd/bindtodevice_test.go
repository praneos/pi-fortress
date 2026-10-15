package dnsd

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The upstream of the WireGuard house, as render writes it, becomes a leg
// that is bound to the tunnel. The address that the leg dials has no
// suffix.
func TestAnInterfacePinnedUpstreamBindsTheLeg(t *testing.T) {
	seg := &Segment{Name: "house", Upstream: "10.64.0.1@wg0:53"}
	leg, err := seg.upstreamLeg(time.Now)
	if err != nil {
		t.Fatalf("the WireGuard house upstream was refused: %v", err)
	}
	u, ok := leg.(udpExchanger)
	if !ok || u.addr != "10.64.0.1:53" || u.iface != "wg0" {
		t.Fatalf("leg %#v, want udp to 10.64.0.1:53 bound to wg0", leg)
	}
	plain, err := (&Segment{Name: "agent", Upstream: "9.9.9.9:53"}).upstreamLeg(time.Now)
	if err != nil || plain.(udpExchanger).iface != "" {
		t.Fatalf("a plain upstream came back bound: %#v %v", plain, err)
	}
}

// When bound to the interface of the upstream, the query goes through.
// When bound to an interface that does not exist, it fails. The second
// half is the purpose: when the tunnel is down, the house query must not
// go through the uplink route. An unbound socket would do that.
func TestABoundUpstreamGoesOnlyThroughItsInterface(t *testing.T) {
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "bound.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	ctx, cancel := context.WithTimeout(context.Background(), upstreamTO+2*time.Second)
	defer cancel()

	u := udpExchanger{addr: up.addr(), iface: "lo"}
	if _, err := u.exchange(ctx, wire(t, "bound.test", dnsmessage.TypeA, 0x1111)); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("SO_BINDTODEVICE needs CAP_NET_RAW on this kernel; pf dns has it, this test process does not")
		}
		t.Fatalf("a socket bound to lo could not reach an upstream on lo: %v", err)
	}

	gone := udpExchanger{addr: up.addr(), iface: "pf-absent0"}
	if _, err := gone.exchange(ctx, wire(t, "bound.test", dnsmessage.TypeA, 0x2222)); err == nil {
		t.Fatal("a socket bound to an interface that does not exist reached the upstream anyway")
	}
}

// The DoT provider of the house under WireGuard: the stub config names the
// tunnel, and the leg binds each dial to it. A bound dial to an interface
// that does not exist fails. It does not use the uplink. Thus the kill
// switch also holds for DNS.
func TestADoTLegTakesItsInterface(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{"listen": 53, "segments": [{"name": "stub-house", "iface": "lo", "ip": "127.0.0.2", "dot_name": "abc123.dns.controld.com", "dot_ips": ["76.76.2.22"], "dot_iface": "wg0"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	leg, err := cfg.Segments[0].upstreamLeg(time.Now)
	if err != nil {
		t.Fatalf("a DoT leg with an interface was refused: %v", err)
	}
	if d, ok := leg.(*dotClient); !ok || d.iface != "wg0" {
		t.Fatalf("leg %#v, want DoT bound to wg0", leg)
	}
	bad := &Segment{Name: "stub-house", DoTName: "abc123.dns.controld.com", DoTIPs: cfg.Segments[0].DoTIPs, DoTIface: "wg0; rm"}
	if _, err := bad.upstreamLeg(time.Now); err == nil {
		t.Fatal("a dot_iface that is not an interface name was accepted")
	}

	gone := newDoT("bound.test", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, time.Now)
	gone.iface = "pf-absent0"
	ctx, cancel := context.WithTimeout(context.Background(), dotDialTO+time.Second)
	defer cancel()
	if _, err := gone.exchange(ctx, wire(t, "bound.test", dnsmessage.TypeA, 0x3333)); err == nil {
		t.Fatal("a DoT dial bound to an interface that does not exist went out anyway")
	}
}
