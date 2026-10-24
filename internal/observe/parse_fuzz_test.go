package observe

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// FuzzParseNeigh: `ip neigh` and /proc/net/arp name hosts that a LAN
// device can claim. No text makes the parsers panic. Each key and MAC is
// one token of the input, the MAC is in lower case, and the zero MAC is
// never kept.
func FuzzParseNeigh(f *testing.F) {
	f.Add("10.78.0.20 dev eth1 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n10.78.0.21 dev eth1 FAILED\n")
	f.Add("10.78.0.22 dev eth1 lladdr 00:00:00:00:00:00 STALE\nlladdr lladdr lladdr\n x lladdr\n")
	f.Add("IP address HW type Flags HW address Mask Device\n10.77.0.10 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n10.77.0.11 0x1 0x0 00:00:00:00:00:00 * eth0\n")
	f.Fuzz(func(t *testing.T, text string) {
		lines := strings.Count(text, "\n") + 1
		for name, m := range map[string]map[string]string{"neigh": parseNeigh(text), "arp": parseARP(text)} {
			if len(m) > lines {
				t.Fatalf("%s: %d entries from %d lines", name, len(m), lines)
			}
			for ip, mac := range m {
				if ip == "" || mac == "" || strings.ContainsAny(ip+mac, " \t\n\r\v\f") {
					t.Fatalf("%s: bad entry %q -> %q", name, ip, mac)
				}
				if mac != strings.ToLower(mac) || mac == "00:00:00:00:00:00" {
					t.Fatalf("%s: bad MAC %q", name, mac)
				}
			}
		}
	})
}

var prefixRe = regexp.MustCompile(`^[a-z0-9._-]+-[a-z0-9]+$`)

// FuzzParseNftLog: no journal line makes parseNftLog panic. A line that it
// takes has a prefix of the nft rule grammar, and a source and destination
// that are single tokens. The protocol is in lower case. The stamp is UTC
// or zero. A token ends at the space class of RE2 (\s), which does not
// hold \v. The TUI and the alert text replace control bytes later.
func FuzzParseNftLog(f *testing.F) {
	f.Add(`2026-09-15T00:02:56+0530 pi kernel: pi-fortress agent-blacklist: IN=eth0 OUT= SRC=10.77.0.10 DST=192.0.2.1 PROTO=TCP DPT=443`)
	f.Add(`2026-09-15T00:02:56+05:30 pi kernel: pi-fortress agent-doh: SRC=10.77.0.10 DST=8.8.8.8 PROTO=UDP DPT=443`)
	f.Add(`[  123.4] pi-fortress house-killswitch: SRC= DST=1.2.3.4 SRC=a PROTO=ICMP`)
	f.Add(`pi-fortress a-b: XSRC=1 SRC=1 DST=2 DST=3`)
	f.Fuzz(func(t *testing.T, line string) {
		l, ok := parseNftLog(line)
		if !ok {
			if l != (nftLog{}) {
				t.Fatalf("refused line left fields: %+v", l)
			}
			return
		}
		if !prefixRe.MatchString(l.Prefix) {
			t.Fatalf("prefix %q", l.Prefix)
		}
		if l.Src == "" || l.Dst == "" {
			t.Fatalf("empty address: %+v", l)
		}
		for _, s := range []string{l.Src, l.Dst, l.Proto, l.Dport} {
			if strings.ContainsAny(s, " \t\n\r\f") {
				t.Fatalf("field with whitespace: %q", s)
			}
		}
		if l.Proto != strings.ToLower(l.Proto) {
			t.Fatalf("proto %q", l.Proto)
		}
		if !l.T.IsZero() && l.T.Location() != time.UTC {
			t.Fatalf("stamp not UTC: %v", l.T)
		}
	})
}

// FuzzIngestCT: no conntrack text makes ingestCT panic. It records only
// flows whose source is on the net of the segment, never the Pi itself,
// and it keeps the flow table under its cap.
func FuzzIngestCT(f *testing.F) {
	f.Add(ctLine("10.77.0.10", "93.184.216.34", 900, 100))
	f.Add(ctLinePort("udp", "10.77.0.10", "8.8.8.8", 5353, 53) + "\n" + ctLine("10.77.0.1", "1.1.1.1", 1, 1))
	f.Add("ipv4 2 tcp 6 src=10.77.0.10 dst=1.2.3.4 sport=1 dport=99999999999999999999 bytes=99999999999999999999 bytes=9223372036854775807")
	f.Add("ipv4 2 icmp 1 src=10.77.0.10 dst=1.2.3.4 type=8\nsrc=10.77.0.300 dst=1.2.3.4 sport=1 dport=2")
	f.Fuzz(func(t *testing.T, raw string) {
		o := &Observer{Now: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }}
		st := o.empty()
		seen := map[string]int64{}
		o.ingestCT(st, raw, "", "10.77.0.0/24", "10.77.0.1", []string{"10.0.2.0/24"}, seen)
		if len(st.Flows) > maxFlows {
			t.Fatalf("flow table %d over cap", len(st.Flows))
		}
		for k, fl := range st.Flows {
			if !InNet(fl.Src, "10.77.0.0/24") || fl.Src == "10.77.0.1" {
				t.Fatalf("flow %q from %q recorded", k, fl.Src)
			}
			if InNet(fl.Dst, "10.0.2.0/24") || fl.Dst == "10.77.0.1" {
				t.Fatalf("flow %q to skipped %q recorded", k, fl.Dst)
			}
		}
	})
}
