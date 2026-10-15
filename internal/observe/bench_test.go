package observe

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkTrackTunnelAt(b *testing.B) {
	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprintf("host%d.cdn%d.example.com", i, i%4)
	}
	long := make([]string, 64)
	for i := range long {
		long[i] = fmt.Sprintf("%040d.t.evil.example", i)
	}
	at := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, seg, qtype string
		names            []string
	}{
		{"house", "house", "A", names},
		{"agent-long", "", "TXT", long},
	} {
		b.Run(tc.name, func(b *testing.B) {
			o := &Observer{TunnelNames: 120}
			st := &State{}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				o.trackTunnelAt(st, tc.seg, tc.names[i%len(tc.names)], "10.77.0.10", tc.qtype, at)
				i++
			}
		})
	}
}
