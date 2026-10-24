package dnsd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func benchServer(b *testing.B) *Server {
	b.Helper()
	dir := b.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/sinkholed.example/0.0.0.0\n"), 0644); err != nil {
		b.Fatal(err)
	}
	up := newUpstream(b, map[string][4]byte{"ok.example": {1, 2, 3, 4}}, nil, 3600)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      &fakeNFT{},
		Now:      func() time.Time { return now },
		Segments: []Segment{{
			Iface:         "lo",
			IP:            netip.MustParseAddr("127.0.0.1"),
			Upstream:      up.addr(),
			SinkholeFiles: []string{sink},
			NFTSet:        "resolved_v4",
			KeyRulesPath:  shippedRules,
		}},
	})
	if err != nil {
		b.Fatal(err)
	}
	return srv
}

func benchQuery(b *testing.B, name string, qt dnsmessage.Type) []byte {
	b.Helper()
	m := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := m.StartQuestions(); err != nil {
		b.Fatal(err)
	}
	if err := m.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: qt, Class: dnsmessage.ClassINET}); err != nil {
		b.Fatal(err)
	}
	req, err := m.Finish()
	if err != nil {
		b.Fatal(err)
	}
	return req
}

func BenchmarkAnswer(b *testing.B) {
	srv := benchServer(b)
	src := netip.MustParseAddr("10.77.0.10")
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		qt   dnsmessage.Type
	}{
		{"ok.example", dnsmessage.TypeA},
		{"sinkholed.example", dnsmessage.TypeA},
		{"ok.example", dnsmessage.TypeAAAA},
		{"ghp_" + strings.Repeat("A", 36) + ".evil.example", dnsmessage.TypeA},
	} {
		req := benchQuery(b, tc.name, tc.qt)
		if srv.answer(ctx, srv.segs[0], src, req, 0) == nil {
			b.Fatalf("%s: no reply", tc.name)
		}
		b.Run(tc.qt.String()+"/"+tc.name[:min(len(tc.name), 17)], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				srv.answer(ctx, srv.segs[0], src, req, 0)
			}
		})
	}
}

// BenchmarkAnswerParallel is a cached A answer for many devices at the
// same time. They share the cache and its lock.
func BenchmarkAnswerParallel(b *testing.B) {
	srv := benchServer(b)
	ctx := context.Background()
	req := benchQuery(b, "ok.example", dnsmessage.TypeA)
	src := netip.MustParseAddr("10.77.0.10")
	if srv.answer(ctx, srv.segs[0], src, req, 0) == nil {
		b.Fatal("no reply")
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		req := append([]byte(nil), req...)
		for pb.Next() {
			srv.answer(ctx, srv.segs[0], src, req, 0)
		}
	})
}

func BenchmarkKeyShapeMatch(b *testing.B) {
	k, err := loadKeyShapes(shippedRules)
	if err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{
		"www.example.com",
		"r3---sn-abc123def456.googlevideo.com",
		"sk-learn.pf_x.ghp.example.org",
		"tun.ghp_" + strings.Repeat("A", 30) + ".AAAAA1",
		strings.Repeat("ab.", 60) + "sk-x.example.com",
		strings.Repeat("sk-.", 60) + "example.com",
	} {
		b.Run(name[:min(len(name), 17)], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				k.match(name)
			}
		})
	}
}
