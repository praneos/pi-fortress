package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Reload replaces the sinkhole list while queries read it. This is the
// usual case: SIGHUP and the dns.reload of pf tui both come here while
// the resolver serves. It was an unsynchronized write to a plain field.
// Thus this test is a race regression test. It has a meaning only under
// -race.
func TestReloadRacesWithQueries(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.hosts")
	if err := os.WriteFile(sink, []byte("address=/blocked.example/0.0.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      discardNFT{},
		Segments: []Segment{{
			Name: "t", Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"),
			Upstream: "127.0.0.1:65535", SinkholeFiles: []string{sink},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	seg := srv.segs[0]
	// The fixture has the format that loadHosts reads, so each lookup has a
	// list entry to find. If a reload ever publishes an empty list, even for
	// a short time, the test shows a miss.
	if _, ok := seg.local.Load().lookup("blocked.example"); !ok {
		t.Fatal("the fixture's name is not on the list")
	}
	var misses atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			if _, ok := seg.local.Load().lookup("blocked.example"); !ok {
				misses.Add(1)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			if err := srv.Reload(); err != nil {
				return
			}
		}
	}()
	wg.Wait()
	if n := misses.Load(); n != 0 {
		t.Fatalf("%d lookups missed the listed name during reloads", n)
	}
}

// If a reload fails on the log of one segment, each segment must continue
// to write to the file that it had open. When the reload reopened the
// logs one at a time, the segments before the failed one moved to the
// rotated path. At the same time, the reload reported failure and kept
// the old lists.
func TestAFailedReloadMovesNoLog(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.hosts")
	if err := os.WriteFile(sink, []byte("address=/blocked.example/0.0.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "b.jsonl")
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      discardNFT{},
		Segments: []Segment{
			{
				Name: "a", Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"),
				Upstream: "127.0.0.1:65535", SinkholeFiles: []string{sink}, LogPath: first,
			},
			{
				Name: "b", Iface: "eth1.20", IP: netip.MustParseAddr("10.77.0.1"), NFTSet: "resolved_v4",
				Upstream: "127.0.0.1:65535", SinkholeFiles: []string{sink}, LogPath: second,
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
	rotated := first + ".1"
	if err := os.Rename(first, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err == nil {
		t.Fatal("a reload whose log could not be reopened reported success")
	}
	srv.segs[0].log.Load().line("after")
	if b, _ := os.ReadFile(rotated); string(b) != "after\n" {
		t.Fatalf("a reload that failed moved the first segment's log: %q in the file it had open", b)
	}
}
