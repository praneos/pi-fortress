package dnsd

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// twoSegments is the layout of the box since the house moved to pf dns:
// one daemon, two segments, and a gate set for each segment. The two
// segments share the upstream and the NFT writer, so a test can see
// which segment reached them.
func twoSegments(t *testing.T, table map[string][4]byte) (*Server, *fakeNFT, *upstream) {
	t.Helper()
	dir := t.TempDir()
	up := newUpstream(t, table, nil, 60)
	nft := &fakeNFT{}
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   0,
		NFT:      nft,
		Now:      func() time.Time { return now },
		Segments: []Segment{
			{
				Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"),
				Upstream: up.addr(), NFTSet: "resolved_v4",
				LogPath: filepath.Join(dir, "agent.log"),
			},
			{
				Name: "house", Iface: "lo-house", IP: netip.MustParseAddr("127.0.0.2"),
				Upstream: up.addr(), NFTSet: "resolved_house_v4",
				LogPath: filepath.Join(dir, "house.log"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	return srv, nft, up
}

func askSeg(t *testing.T, srv *Server, seg int, name, src string) {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{
		Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp := srv.answer(ctx, srv.segs[seg], netip.MustParseAddr(src), req, 0); resp == nil {
		t.Fatalf("segment %d got no answer for %s", seg, name)
	}
}

// setsFed is which gate sets saw a write, in order.
func setsFed(f *fakeNFT) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sets...)
}

// The lab house VM found this bug. The cache key was only the name and
// the qtype. Thus a name that one segment already resolved was a hit for
// the other segment. A hit returns before the address goes into the gate
// set of the segment that asks. The house got an answer, and then a drop
// stopped its connection to that same address. The symptom is "the house
// cannot reach sites that the agents visited", and it expires by itself.
func TestASecondSegmentFeedsItsOwnGate(t *testing.T) {
	srv, nft, up := twoSegments(t, map[string][4]byte{"good.test": {1, 2, 3, 4}})

	askSeg(t, srv, 0, "good.test", "10.77.0.10")
	askSeg(t, srv, 1, "good.test", "10.78.0.20")

	want := []string{"resolved_v4", "resolved_house_v4"}
	if got := setsFed(nft); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("gate sets fed %v, want %v", got, want)
	}
	// Both segments went to the upstream, because a segment must not answer
	// from the entry of the other segment. A segment can have its own
	// provider (HOUSE_DNS_UPSTREAM, HOUSE_DOT_*). That is half the reason
	// that this daemon exists instead of dnsmasq.
	if n := up.asked.Load(); n != 2 {
		t.Fatalf("upstream asked %d times, want 2 -- one segment answered out of the other's cache", n)
	}
}

// The cache must still work as a cache. With a key for each segment, a
// repeat on the same segment is still a hit: no second upstream query,
// and no second write to a set that already holds the address.
func TestTheSameSegmentStillHitsItsCache(t *testing.T) {
	srv, nft, up := twoSegments(t, map[string][4]byte{"good.test": {1, 2, 3, 4}})

	askSeg(t, srv, 0, "good.test", "10.77.0.10")
	askSeg(t, srv, 0, "good.test", "10.77.0.11")

	if n := up.asked.Load(); n != 1 {
		t.Fatalf("upstream asked %d times, want 1 -- the cache stopped working", n)
	}
	if got := setsFed(nft); len(got) != 1 {
		t.Fatalf("gate written %d times for one cached name: %v", len(got), got)
	}
}

// Two segments with one name share a cache key. Two segments with one
// set share a gate: an address that one network resolved opens the gate
// of the other. New refuses both, as it already refused one interface
// that has two entries.
func TestNewRefusesASegmentNameOrSetTwice(t *testing.T) {
	seg := func(name, iface, ip, set string) Segment {
		return Segment{Name: name, Iface: iface, IP: netip.MustParseAddr(ip), Upstream: "127.0.0.1:9", NFTSet: set}
	}
	cases := []struct {
		name string
		segs []Segment
		want string
	}{
		{"two houses", []Segment{seg("house", "eth1", "10.78.0.1", "resolved_house_v4"), seg("house", "eth2", "10.80.0.1", "resolved_house2_v4")}, `segment "house" named twice`},
		{"two agents", []Segment{seg("", "eth0", "10.77.0.1", "resolved_v4"), seg("", "eth3", "10.81.0.1", "resolved_a_v4")}, `segment "" named twice`},
		{"a-b and a_b share a set", []Segment{seg("a-b", "eth1", "10.78.0.1", "resolved_a_b_v4"), seg("a_b", "eth2", "10.80.0.1", "resolved_a_b_v4")}, "nft set resolved_a_b_v4 named twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, Segments: c.segs})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("New: %v, want %q", err, c.want)
			}
		})
	}
	if _, err := New(Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, Segments: []Segment{
		seg("", "eth0", "10.77.0.1", "resolved_v4"), seg("house", "eth1", "10.78.0.1", "resolved_house_v4"), seg("desk", "eth2", "10.79.0.1", "resolved_desk_v4"),
	}}); err != nil {
		t.Fatalf("distinct segments refused: %v", err)
	}
}
