package render

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateEnvKeys = flag.Bool("update-envkeys", false, "rewrite testdata/envkeys.golden from the current code")

// TestEnvKeysPinned records, for each key of house.env and segments.d and a
// fixed list of values, the exact refusal or the full Config that Load gives.
// It also records the connection limit refusals and the DNS forward choice.
// A change to any of them, including a change to the text of a refusal, fails here.
func TestEnvKeysPinned(t *testing.T) {
	var out strings.Builder
	pinHouseKeys(t, &out)
	pinSegmentKeys(t, &out)
	pinSegmentDirs(t, &out)
	pinConnLimits(&out)
	pinDNSForward(t, &out)
	got := out.String()
	golden := filepath.Join("testdata", "envkeys.golden")
	if *updateEnvKeys {
		if err := os.WriteFile(golden, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("line %d drifted:\n got: %s\nwant: %s", i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("output length drifted: got %d lines, want %d", len(gl), len(wl))
	}
}

var pinValues = []string{
	"", "on", "off", "yes", "no", "strict", "audit", "open", "eth1", "eth1;x",
	"10.78.0.0/24", "10.78.0.5", "10.77.0.10", "10.77.0.10-10.77.0.12", "10.77.0.12-10.77.0.10", "10.77.0.10-10.78.0.5", "'q'", `"dns.quad9.net"`,
	"0x2", "0x0", "tcp:27015 udp:3000-3010", "tcp:0443", "'SRV txt'", "TYPE65", "50/200", "1000/5000", "200", "0",
}

func pinResult(dir string, c *Config, err error) string {
	if err != nil {
		return "ERR " + strings.ReplaceAll(err.Error(), dir, "$DIR")
	}
	return strings.ReplaceAll(fmt.Sprintf("%+v", *c), dir, "$DIR")
}

func pinHouseKeys(t *testing.T, out *strings.Builder) {
	keys := []string{"HOUSE_IF", "HOUSE_NET", "HOUSE_IP", "HOUSE_DHCP_START", "HOUSE_DHCP_END", "HOUSE_ADMIN_IP",
		"HOUSE_DNS_UPSTREAM", "HOUSE_SSH_TO", "HOUSE_DOT_AUTH_NAME", "HOUSE_DOT_IPS", "HOUSE_BLOCK_DIRECT_IP",
		"HOUSE_BLOCK_HTTP", "HOUSE_BLOCK_VPN", "HOUSE_PRIVATE_DNS", "HOUSE_EGRESS", "HOUSE_ALLOW_WIFI_CALLING",
		"HOUSE_ALLOW_CALL_UDP", "HOUSE_ALLOW_WHATSAPP", "HOUSE_ALLOW_PORTS", "HOUSE_DEV_MODE", "WG_IF",
		"WG_BYPASS_MARK", "BOGUS"}
	dir := t.TempDir()
	for _, prefix := range []string{"", "HOUSE_IF=eth1\n"} {
		for _, k := range keys {
			for _, v := range pinValues {
				house := write(t, dir, "house.env", prefix+k+"="+v+"\n")
				c, err := Load(Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"})
				fmt.Fprintf(out, "house %q %s=%s: %s\n", prefix, k, v, pinResult(dir, c, err))
			}
		}
	}
}

func pinSegmentKeys(t *testing.T, out *strings.Builder) {
	keys := []string{"IF", "NET", "IP", "ADMIN", "SSH_TO", "BLOCK_DIRECT_IP", "EGRESS", "ALLOW_PORTS", "SSH_FROM",
		"DNS_TYPES", "PARANOID", "DHCP", "DHCP_START", "DHCP_END", "CONN_PER_IP", "NEW_PER_IP", "CONN_TOTAL",
		"NEW_TOTAL", "NTP", "BOGUS"}
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	base := "IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n"
	for _, k := range keys {
		for _, v := range pinValues {
			write(t, segs, "one.env", base+k+"="+v+"\n")
			c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent", SegmentsDir: segs})
			fmt.Fprintf(out, "segment %s=%s: %s\n", k, v, pinResult(dir, c, err))
		}
	}
	extra := []string{
		"SSH_FROM=10.77.0.5\n", "SSH_FROM=10.80.0.9\n", "SSH_FROM=10.78.0.9\n",
		"DHCP=on\nDHCP_START=10.80.0.100\nDHCP_END=10.80.0.199\n",
		"DHCP_START=10.80.0.100\n", "CONN_PER_IP=200\nCONN_TOTAL=100\n", "NEW_PER_IP=500/600\nNEW_TOTAL=300/600\n",
		"ADMIN=yes\nSSH_TO=10.77.0.10\n", "IF=\n", "NTP=redirect\n", "NTP=pass\n",
	}
	for _, e := range extra {
		write(t, segs, "one.env", base+e)
		c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent", SegmentsDir: segs})
		fmt.Fprintf(out, "segment extra %q: %s\n", e, pinResult(dir, c, err))
	}
	write(t, segs, "one.env", base+"PARANOID=on\n")
	write(t, dir, "allow.one.domains", "github.com\n")
	c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent", SegmentsDir: segs})
	fmt.Fprintf(out, "segment paranoid with allow: %s\n", pinResult(dir, c, err))
}

func pinSegmentDirs(t *testing.T, out *strings.Builder) {
	base := "IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n"
	cases := []struct {
		name  string
		setup func(dir, segs string)
	}{
		{"absent", func(dir, segs string) { os.Remove(segs) }},
		{"a file", func(dir, segs string) { os.Remove(segs); write(t, dir, "segments.d", "x") }},
		{"empty", func(dir, segs string) {}},
		{"not env", func(dir, segs string) { write(t, segs, "one.conf", base) }},
		{"env dir", func(dir, segs string) { os.Mkdir(filepath.Join(segs, "one.env"), 0755) }},
		{"bad name", func(dir, segs string) { write(t, segs, "One.env", base) }},
		{"reserved", func(dir, segs string) { write(t, segs, "house.env", base) }},
		{"nft clash", func(dir, segs string) {
			write(t, segs, "a-b.env", base)
			write(t, segs, "a_b.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n")
		}},
		{"two", func(dir, segs string) {
			write(t, segs, "b.env", base)
			write(t, segs, "a.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\nSSH_FROM=10.80.0.7\n")
		}},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		if err := os.Mkdir(segs, 0755); err != nil {
			t.Fatal(err)
		}
		tc.setup(dir, segs)
		c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent", SegmentsDir: segs})
		fmt.Fprintf(out, "segdir %s: %s\n", tc.name, pinResult(dir, c, err))
	}
}

func pinConnLimits(out *strings.Builder) {
	vals := []string{"", "0", "4", "5", "16", "64", "99", "100", "128", "131072", "131073", "0128", "+5",
		"5/5", "5/4", "100/100", "100000/1000000", "100001/100001", "50/1000001", "50/", "/50", "50/200/1", "x"}
	for _, class := range []string{"AGENT", "HOUSE", "SEG", "X"} {
		for _, suffix := range []string{"_CONN_PER_IP", "_NEW_PER_IP", "_CONN_TOTAL", "_NEW_TOTAL", "_OTHER"} {
			for _, v := range vals {
				n, m, err := parseConnValue(class+suffix, v, 7, 9)
				fmt.Fprintf(out, "conn %s%s=%s: %d %d %v\n", class, suffix, v, n, m, err)
			}
		}
	}
}

func pinDNSForward(t *testing.T, out *strings.Builder) {
	dir := t.TempDir()
	for _, dot := range []bool{false, true} {
		for _, house := range []string{"", "HOUSE_IF=eth1\n", "HOUSE_IF=eth1\nWG_IF=wg0\n", "WG_IF=wg0\n"} {
			for _, extra := range []string{"", "HOUSE_DNS_UPSTREAM=1.1.1.1\n", "HOUSE_DOT_AUTH_NAME=dns.quad9.net\nHOUSE_DOT_IPS=9.9.9.10\n"} {
				n := lab
				if dot {
					n.DoTAuthName, n.DoTIPs = "dns.quad9.net", "9.9.9.9"
				}
				h := write(t, dir, "house.env", house+extra)
				c, err := Load(Options{Net: n, HouseEnv: h, SegmentsDir: "/nonexistent"})
				res := "ERR "
				if err == nil {
					res = c.DNSForward + " " + c.HouseDNSForward + " " + fmt.Sprint(c.HouseDNSExplicit) + " "
				}
				fmt.Fprintf(out, "dns dot=%v %q: %s%v\n", dot, house+extra, res, err)
			}
		}
	}
}

func TestExplainNoIF(t *testing.T) {
	(&Config{}).explainNoIF(nil)
	var b strings.Builder
	c := &Config{Net: Net{PiIP: "10.77.0.1"}}
	c.explainNoIF(&b)
	for _, want := range []string{
		"pi-fortress: no interface holds PI_IP=10.77.0.1, so INT_IF is empty.",
		"pi-fortress: no default route, so WAN_IF is empty.",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	c.IntIF = "eth0"
	c.explainNoIF(&b)
	if strings.Contains(b.String(), "INT_IF is empty") || !strings.Contains(b.String(), "WAN_IF is empty") {
		t.Errorf("only WAN_IF is empty, got:\n%s", b.String())
	}
}
