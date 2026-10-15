package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzIngestDNS: arbitrary query log text never panics, never records a
// name with control bytes, never records a source outside the agent net,
// and stays under the table cap.
func FuzzIngestDNS(f *testing.F) {
	f.Add(rows(resolved("10.77.0.10", "example.com", "93.184.216.34")))
	f.Add(rows(blocked("192.168.1.1", "x.test"), filtered("10.77.0.10", "x.test", "AAAA")))
	f.Add(rows(suppressed("10.77.0.10", 5, false), suppressed("10.77.0.10", 3, true), suppressed("untracked", 9, false)))
	// The shape that dnsmasq wrote, which nothing reads now: it must be
	// discarded, without a panic and without a partial parse.
	f.Add("Sep  5 10:00:00 dnsmasq[1]: query[A] example.com from 10.77.0.10\nreply example.com is 93.184.216.34\n")
	f.Fuzz(func(t *testing.T, log string) {
		dir := t.TempDir()
		o := &Observer{
			DNSLog:     filepath.Join(dir, "dns.jsonl"),
			OffsetPath: filepath.Join(dir, "dns.offset"),
			JSONLPath:  filepath.Join(dir, "observe.jsonl"),
			Now:        time.Now,
		}
		if err := os.WriteFile(o.DNSLog, []byte(log), 0644); err != nil {
			t.Fatal(err)
		}
		st := &State{DNS: map[string]*DNSRec{}, Flows: map[string]*FlowRec{}}
		o.ingestDNS(st, "10.77.0.0/24")
		if len(st.DNS) > maxDNS {
			t.Fatalf("dns table %d over cap", len(st.DNS))
		}
		for name, rec := range st.DNS {
			if strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(rec.Src, "\r\n\x00") {
				t.Fatalf("control bytes recorded: %q %q", name, rec.Src)
			}
			if !InNet(rec.Src, "10.77.0.0/24") {
				t.Fatalf("source %q outside agent net recorded for %q", rec.Src, name)
			}
		}
	})
}
