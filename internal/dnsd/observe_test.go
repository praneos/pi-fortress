package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/observe"
)

// TestObserveReadsWhatWeWrite is the end of the log-format contract.
// internal/dnslog round-trips its own writer against its own reader.
// internal/observe always had tests against literal dnsmasq lines. But
// before this test, nothing put the two together. The resolver could
// write a log that the reader silently skipped. The symptom would be that
// DNS records no longer appear, not a failure.
func TestObserveReadsWhatWeWrite(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/webhook.site/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "dns.jsonl")
	up := newUpstream(t, map[string][4]byte{"example.com": {93, 184, 216, 34}}, nil, 300)
	srv, err := New(Config{
		NFTTable: "inet fortress", NFT: discardNFT{}, Now: time.Now,
		Segments: []Segment{{
			IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo",
			Upstream: up.addr(), SinkholeFiles: []string{sink},
			NFTSet: "resolved_v4", LogPath: logPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	h := &harness{srv: srv, nft: &fakeNFT{}, up: up, log: logPath}

	h.ask(t, "example.com", dnsmessage.TypeA)
	h.ask(t, "webhook.site", dnsmessage.TypeA)
	// A source outside the agent net must not be recorded. The reader
	// applies this filter to the third field of the line.
	h.askFrom(t, "elsewhere.test", netip.MustParseAddr("8.8.8.8"))
	srv.CloseLogs()

	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &observe.Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		JSONLPath:  filepath.Join(dir, "observe.jsonl"),
		DNSLog:     logPath,
		OffsetPath: filepath.Join(dir, "dns.offset"),
		CTPath:     filepath.Join(dir, "no-conntrack"),
		CTCmd:      []string{"true"},
		NetEnvPath: []string{netEnv},
		// No house.env, so the house half stays out of it.
		HouseEnvPath: []string{filepath.Join(dir, "no-house.env")},
		Now:          time.Now,
	}
	st := o.Snapshot()

	rec, ok := st.DNS["example.com"]
	if !ok {
		t.Fatalf("observe did not read a forwarded answer; it holds %d names", len(st.DNS))
	}
	if rec.Src != "10.77.0.10" || rec.Sinkholed {
		t.Fatalf("forwarded record %+v", rec)
	}
	if len(rec.Qtypes) != 1 || rec.Qtypes[0] != "A" {
		t.Fatalf("qtypes %v, want the A the resolver logged", rec.Qtypes)
	}
	sunk, ok := st.DNS["webhook.site"]
	if !ok {
		t.Fatal("observe did not read a sinkholed answer")
	}
	if !sunk.Sinkholed {
		t.Fatalf("sinkholed record not marked: %+v", sunk)
	}
	if _, ok := st.DNS["elsewhere.test"]; ok {
		t.Fatal("a query from outside the agent net was recorded")
	}

	// The offset is the resume point. observe rewrites it on every pass.
	// A second pass over an unchanged log must add nothing.
	before := len(st.DNS)
	if got := len(o.Snapshot().DNS); got != before {
		t.Fatalf("a second pass over the same log holds %d names, was %d", got, before)
	}
}
