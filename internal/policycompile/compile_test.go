package policycompile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

func policyDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(testsupport.RepoRoot(t), "vm", "policy")
}

func TestNeverDomainProtectsSuffix(t *testing.T) {
	never := map[string]struct{}{"google.com": {}}
	if !IsNeverDomain("dns.google.com", never) {
		t.Fatal("never_block google.com would protect dns.google.com")
	}
	if IsNeverDomain("google.com.evil.example", never) {
		t.Fatal("suffix-flip")
	}
}

func TestNeverBlockIPsHasNoPublicResolvers(t *testing.T) {
	got, err := LoadTokens(filepath.Join(policyDir(t), "never_block.ips"), "ips")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("never_block.ips has public resolvers: %v", got)
	}
}

func TestCompileDoH(t *testing.T) {
	tmp := t.TempDir()
	sum, err := Compile(policyDir(t), Out{
		NFT:    filepath.Join(tmp, "elements.nft"),
		DNS:    filepath.Join(tmp, "blocked.domains"),
		DoHNFT: filepath.Join(tmp, "doh.nft"),
		DoHDNS: filepath.Join(tmp, "doh.domains"),
	})
	if err != nil {
		t.Fatal(err)
	}
	line := sum.Line()
	if !strings.Contains(line, "doh_ips") || !strings.Contains(line, "doh_domains") {
		t.Fatal(line)
	}
	dohNFT, err := os.ReadFile(filepath.Join(tmp, "doh.nft"))
	if err != nil {
		t.Fatal(err)
	}
	nft := string(dohNFT)
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		if !strings.Contains(nft, ip) {
			t.Fatalf("doh.nft missing %s:\n%s", ip, nft)
		}
	}
	dohDNS, err := os.ReadFile(filepath.Join(tmp, "doh.domains"))
	if err != nil {
		t.Fatal(err)
	}
	dns := string(dohDNS)
	if !strings.Contains(dns, "address=/cloudflare-dns.com/0.0.0.0") {
		t.Fatal(dns)
	}
	if !strings.Contains(dns, "address=/dns.google/0.0.0.0") {
		t.Fatal(dns)
	}
	blocked, err := os.ReadFile(filepath.Join(tmp, "blocked.domains"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blocked), "address=/cloudflare-dns.com/0.0.0.0") {
		t.Fatal("doh names left to never_block path")
	}
}

func TestParseIPv4RejectsPrivate(t *testing.T) {
	for _, bad := range []string{"10.0.0.1", "127.0.0.1", "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "8.0.0.0/7", "192.0.0.0/8", "172.0.0.0/8", "100.0.0.0/8", "198.0.0.0/8", "203.0.0.0/8", "224.0.0.0/3", "169.254.1.0/24", "100.64.1.1", "198.18.0.1", "255.255.255.255"} {
		if got, ok := ParseIPv4(bad); ok {
			t.Fatalf("%s accepted as %q", bad, got)
		}
	}
	for in, want := range map[string]string{"1.1.1.1": "1.1.1.1", "9.9.9.9": "9.9.9.9", "8.0.0.0/8": "8.0.0.0/8", "1.2.3.0/24": "1.2.3.0/24", "192.0.2.1": "192.0.2.1"} {
		if got, ok := ParseIPv4(in); !ok || got != want {
			t.Fatalf("%s -> %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestParseDomainWildcard(t *testing.T) {
	got, ok := ParseDomain("*.dns.google.com")
	if !ok || got != "dns.google.com" {
		t.Fatalf("%q %v", got, ok)
	}
}

// A leading dot reads as "*.": the name and all names below it. Before, the
// parser refused ".example.com", and the line compiled to nothing with no
// warning. Only one dot goes.
func TestParseDomainLeadingDot(t *testing.T) {
	for in, want := range map[string]string{".example.com": "example.com", ".Evil.Example.": "evil.example"} {
		if got, ok := ParseDomain(in); !ok || got != want {
			t.Errorf("ParseDomain(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"..example.com", "*..example.com", ".*.example.com", ".", ".com"} {
		if got, ok := ParseDomain(bad); ok {
			t.Errorf("ParseDomain(%q) accepted as %q", bad, got)
		}
	}
}

func TestParseDomainLengthLimits(t *testing.T) {
	if _, ok := ParseDomain(strings.Repeat("a", 64) + ".example.com"); ok {
		t.Fatal("label over 63 accepted")
	}
	if got, ok := ParseDomain(strings.Repeat("a", 63) + ".example.com"); !ok || got != strings.Repeat("a", 63)+".example.com" {
		t.Fatalf("%q %v", got, ok)
	}
	long := strings.TrimSuffix(strings.Repeat("abcdefghij.", 24), ".") + ".com"
	if len(long) <= 253 {
		t.Fatalf("test name too short: %d", len(long))
	}
	if _, ok := ParseDomain(long); ok {
		t.Fatal("name over 253 accepted")
	}
}

func TestCompileHouseDNS(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "generated"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "never_block.domains"), []byte("keep.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "never_block.ips"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(dir, "blacklist.domains"), []byte("untrusted.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "blacklist.ips"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(dir, "house_never_block.domains"), []byte("# family\nfamily.example\n"), 0644)
	// Shipped defaults: one unique, one duplicated by the feed, one the
	// operator has never-blocked, one under a shared-never_block apex.
	_ = os.WriteFile(filepath.Join(dir, "house_default.domains"), []byte("# shipped\ndefault-ad.example\nads.example\nfamily.example\napi.keep.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "generated", "house.domains"), []byte("ads.example\nkeep.example\ncdn.family.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "house.domains"), []byte("# local\nlocal-ad.example\nads.example\nfamily.example\n"), 0644)
	out := t.TempDir()
	sum, err := Compile(dir, Out{
		NFT:      filepath.Join(out, "e.nft"),
		DNS:      filepath.Join(out, "blocked.domains"),
		HouseDNS: filepath.Join(out, "house.domains"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.HouseDomains != 5 || !strings.Contains(sum.Line(), "5 house_domains") {
		t.Fatalf("%+v %s", sum, sum.Line())
	}
	house, _ := os.ReadFile(filepath.Join(out, "house.domains"))
	got := string(house)
	// The shared never_block does not apply to the house list
	// (keep.example and api.keep.example stay). The house never_block
	// applies, with subdomains (family.example and cdn.family.example
	// go). It also disables a shipped default the same way.
	for _, want := range []string{"address=/default-ad.example/0.0.0.0\n", "address=/api.keep.example/0.0.0.0\n", "address=/ads.example/0.0.0.0\n", "address=/local-ad.example/0.0.0.0\n", "address=/keep.example/0.0.0.0\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("house list missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "family.example") || strings.Contains(got, "untrusted.example") {
		t.Fatalf("house list wrong membership:\n%s", got)
	}
	if strings.Count(got, "address=/ads.example/") != 1 {
		t.Fatalf("ads.example not deduped across sources:\n%s", got)
	}
	if strings.Index(got, "address=/default-ad.example/") > strings.Index(got, "address=/ads.example/") {
		t.Fatalf("shipped defaults must lead the compiled file:\n%s", got)
	}
	shared, _ := os.ReadFile(filepath.Join(out, "blocked.domains"))
	if strings.Contains(string(shared), "ads.example") || strings.Contains(string(shared), "default-ad.example") {
		t.Fatal("house domain leaked into the shared sinkhole")
	}
	// Without HouseDNS, the compiler writes nothing and the summary does not change.
	sum2, err := Compile(dir, Out{NFT: filepath.Join(out, "e2.nft"), DNS: filepath.Join(out, "b2.domains")})
	if err != nil || sum2.HouseDomains != 0 || strings.Contains(sum2.Line(), "house") {
		t.Fatalf("%v %+v", err, sum2)
	}
	// A Pi that does not have the defaults file yet still compiles.
	_ = os.Remove(filepath.Join(dir, "house_default.domains"))
	sum3, err := Compile(dir, Out{NFT: filepath.Join(out, "e3.nft"), DNS: filepath.Join(out, "b3.domains"), HouseDNS: filepath.Join(out, "h3.domains")})
	if err != nil || sum3.HouseDomains != 3 {
		t.Fatalf("%v %+v", err, sum3)
	}
}

// HOUSE_PRIVATE_DNS removes the secure-DNS providers of the operator from
// the house DoH sinkhole, and only from that one. The shared sinkhole and
// DoH set keep them. The exemption is house-only and apply controls it. It
// is never a hole for the agent segment. The compiler writes the house copy
// each time a caller asks. Thus the key decides which file the house
// resolver serves (apply.sh), not what the compiler compiles.
func TestCompileHousePrivateDNS(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "generated"), 0755)
	for _, f := range []string{"never_block.domains", "never_block.ips", "blacklist.domains", "blacklist.ips"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(""), 0644)
	}
	_ = os.WriteFile(filepath.Join(dir, "doh.domains"), []byte("dns.google\nfreedns.controld.com\ncloudflare-dns.com\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "doh.ips"), []byte("8.8.8.8\n76.76.2.22\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "house_private_dns.domains"), []byte("# the operator's own profile\nabc123.dns.controld.com\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "house_private_dns.ips"), []byte("76.76.2.22\n76.76.10.22/32\n"), 0644)
	out := t.TempDir()
	o := Out{
		NFT:                filepath.Join(out, "e.nft"),
		DNS:                filepath.Join(out, "b.domains"),
		DoHNFT:             filepath.Join(out, "doh.nft"),
		DoHDNS:             filepath.Join(out, "doh.domains"),
		HouseDoHDNS:        filepath.Join(out, "house-doh.domains"),
		HousePrivateDNSNFT: filepath.Join(out, "private.nft"),
	}
	sum, err := Compile(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if sum.HousePrivateDNS != 2 || !strings.Contains(sum.Line(), "2 house_private_dns") {
		t.Fatalf("%+v %s", sum, sum.Line())
	}
	got, _ := os.ReadFile(filepath.Join(out, "house-doh.domains"))
	// The endpoint of the operator gets an answer from here with its pin. All
	// other profiles of the provider are sinkholed with their parent zone. The
	// usual DoH sinkhole does not change.
	for _, want := range []string{
		"address=/abc123.dns.controld.com/76.76.2.22\n",
		"address=/dns.controld.com/0.0.0.0\n",
		"address=/freedns.controld.com/0.0.0.0\n",
		"address=/dns.google/0.0.0.0\n",
		"address=/cloudflare-dns.com/0.0.0.0\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("house DoH sinkhole lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "address=/controld.com/") {
		t.Fatalf("the provider's whole domain was sinkholed:\n%s", got)
	}
	private, _ := os.ReadFile(filepath.Join(out, "private.nft"))
	if !strings.Contains(string(private), "76.76.2.22") || !strings.Contains(string(private), "76.76.10.22") || strings.Contains(string(private), "/24") {
		t.Fatalf("the firewall set is not the endpoint's own pins:\n%s", private)
	}

	// A range would also open the public resolvers of the provider. A name
	// whose parent is a registrable domain would sinkhole that domain. An
	// endpoint with no pin has no address for the answer.
	for name, c := range map[string][2]string{
		"a provider range":          {"abc123.dns.controld.com\n", "76.76.2.0/24\n"},
		"a parent that is a domain": {"dns.controld.com\n", "76.76.2.22\n"},
		"an endpoint with no pin":   {"abc123.dns.controld.com\n", ""},
	} {
		_ = os.WriteFile(filepath.Join(dir, "house_private_dns.domains"), []byte(c[0]), 0644)
		_ = os.WriteFile(filepath.Join(dir, "house_private_dns.ips"), []byte(c[1]), 0644)
		if _, err := Compile(dir, o); err == nil {
			t.Errorf("%s was compiled", name)
		}
	}
	// Without the two outputs, the compiler reads nothing and the summary is silent.
	sum2, err := Compile(dir, Out{NFT: filepath.Join(out, "e2.nft"), DNS: filepath.Join(out, "b2.domains")})
	if err != nil || sum2.HousePrivateDNS != 0 || strings.Contains(sum2.Line(), "private") {
		t.Fatalf("%v %+v", err, sum2)
	}
}

// The shipped defaults are a checked claim. They are not a file that someone
// can empty or move to the agent segment. The exact-set assertion must
// fail when a default is added or removed. Update the list here in the same
// commit. Do not change it to a count.
// The house segment promises that it never sinkholes these ad hosts, so
// browsers continue to work. static.doubleclick.net comes from the hagezi
// feed, and only house_never_block frees it (2026-09-14: it resolved to
// 0.0.0.0 on the Pi). A parent frees its children.
func TestHouseNeverBlocksDoubleclick(t *testing.T) {
	toks, err := LoadTokens(filepath.Join(policyDir(t), "house_never_block.domains"), "domains")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]struct{}{}
	for _, d := range toks {
		set[d] = struct{}{}
	}
	for _, name := range []string{"static.doubleclick.net", "googleads.g.doubleclick.net", "googleadservices.com"} {
		if !IsNeverDomain(name, set) {
			t.Fatalf("house_never_block.domains does not free %s", name)
		}
	}
}

func TestHouseDefaultsShipped(t *testing.T) {
	policy := policyDir(t)
	want := []string{"youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com", "googlevideo.com", "youtubei.googleapis.com", "chess.com", "chesscomfiles.com", "soundcloud.com", "sndcdn.com"}
	got, err := LoadTokens(filepath.Join(policy, "house_default.domains"), "domains")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(want)
	sorted := slices.Clone(got)
	slices.Sort(sorted)
	if !slices.Equal(sorted, want) {
		t.Fatalf("shipped house defaults drifted:\n got %v\nwant %v", sorted, want)
	}
	for _, file := range []string{"house_never_block.domains", "blacklist.domains"} {
		toks, err := LoadTokens(filepath.Join(policy, file), "domains")
		if err != nil {
			t.Fatal(err)
		}
		set := map[string]struct{}{}
		for _, d := range toks {
			set[d] = struct{}{}
		}
		for _, d := range got {
			if IsNeverDomain(d, set) {
				t.Fatalf("%s lists %s: a default cancelled at the source (never-block) or pushed onto the agent segment (blacklist)", file, d)
			}
		}
	}
}

// direct_ip.allow and ssh_allow.ips compile the same way: coalesce,
// remove each prefix wider than the allow cap, count the remaining prefixes.
func TestIPAllowLists(t *testing.T) {
	for _, tc := range []struct {
		name  string
		file  string
		body  string
		out   string
		nft   func(*Out, string)
		count func(Summary) int
		label string
	}{
		{
			name:  "direct_ip",
			file:  "direct_ip.allow",
			body:  "# seat\n93.184.216.0/26\n93.184.216.40\n151.101.1.9\n151.0.0.0/8\n",
			out:   "direct.nft",
			nft:   func(o *Out, p string) { o.DirectIPNFT = p },
			count: func(s Summary) int { return s.DirectIPs },
			label: "direct_ips",
		},
		{
			name:  "house_direct_ip",
			file:  "house_direct_ip.allow",
			body:  "# tv\n93.184.216.0/26\n93.184.216.40\n151.101.1.9\n151.0.0.0/8\n",
			out:   "house-direct.nft",
			nft:   func(o *Out, p string) { o.HouseDirectIPNFT = p },
			count: func(s Summary) int { return s.HouseDirectIPs },
			label: "house_direct_ips",
		},
		{
			name:  "ssh_allow",
			file:  "ssh_allow.ips",
			body:  "# forge\n93.184.216.0/26\n93.184.216.40\n151.101.1.9\n",
			out:   "ssh.nft",
			nft:   func(o *Out, p string) { o.SSHAllowNFT = p },
			count: func(s Summary) int { return s.SSHAllows },
			label: "ssh_allows",
		},
	} {
		compile := func(t *testing.T, dir string) (Summary, string) {
			t.Helper()
			out := t.TempDir()
			o := Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")}
			tc.nft(&o, filepath.Join(out, tc.out))
			sum, err := Compile(dir, o)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(filepath.Join(out, tc.out))
			return sum, string(raw)
		}

		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.body), 0644)
			sum, got := compile(t, dir)
			// .40 is inside the /26, and coalescence removes it. The single /32 stays.
			if !strings.Contains(got, "93.184.216.0/26") || !strings.Contains(got, "151.101.1.9") || strings.Contains(got, "93.184.216.40") {
				t.Fatalf("%s=%q", tc.out, got)
			}
			if tc.count(sum) != 2 || !strings.Contains(sum.Line(), "2 "+tc.label) {
				t.Fatalf("summary=%+v line=%q", sum, sum.Line())
			}
		})

		t.Run(tc.name+" absent", func(t *testing.T) {
			sum, got := compile(t, t.TempDir())
			if strings.TrimSpace(got) != "" || tc.count(sum) != 0 || strings.Contains(sum.Line(), tc.label) {
				t.Fatalf("absent file produced %q, summary %+v", got, sum)
			}
		})
	}
}

// An allow list opens what the drops close. Thus its cap is /24, while a
// deny list still accepts prefixes as wide as /8.
func TestParseAllowIPv4CapsWidth(t *testing.T) {
	for _, bad := range []string{"8.0.0.0/8", "76.76.0.0/16", "1.2.0.0/23", "10.0.0.0/24"} {
		if got, ok := ParseAllowIPv4(bad); ok {
			t.Fatalf("%s accepted on an allow list as %s", bad, got)
		}
	}
	for in, want := range map[string]string{"76.76.2.0/24": "76.76.2.0/24", "93.184.216.0/26": "93.184.216.0/26", "9.9.9.9": "9.9.9.9"} {
		if got, ok := ParseAllowIPv4(in); !ok || got != want {
			t.Fatalf("%s: got %q ok=%v", in, got, ok)
		}
	}
}

// An allow list refuses a prefix with host bits, as ssh_allow.ips does. A
// mask would open the full range where the operator possibly meant one
// host. The warning gives the network.
func TestAllowListsSkipHostBitPrefixes(t *testing.T) {
	for _, bad := range []string{"93.184.216.40/24", "151.101.1.9/31"} {
		if got, ok := ParseAllowIPv4(bad); ok {
			t.Errorf("ParseAllowIPv4(%q) accepted as %q", bad, got)
		}
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"direct_ip.allow":       "93.184.216.40/24\n151.101.1.9\n",
		"house_direct_ip.allow": "76.76.2.9/24\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	o := Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf"),
		DirectIPNFT: filepath.Join(out, "direct.nft"), HouseDirectIPNFT: filepath.Join(out, "house-direct.nft")}
	sum, err := Compile(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	direct, _ := os.ReadFile(o.DirectIPNFT)
	if sum.DirectIPs != 1 || sum.HouseDirectIPs != 0 || strings.Contains(string(direct), "93.184.216.0/24") {
		t.Fatalf("direct.nft=%q summary=%+v", direct, sum)
	}
	want := [][]string{
		{`direct_ip.allow line 1: "93.184.216.40/24"`, "host bits", "93.184.216.0/24"},
		{`house_direct_ip.allow line 1: "76.76.2.9/24"`, "host bits", "76.76.2.0/24"},
	}
	if len(sum.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", sum.Warnings, len(want))
	}
	for i, w := range want {
		for _, s := range w {
			if !strings.Contains(sum.Warnings[i], s) {
				t.Errorf("warning %d %q lacks %q", i, sum.Warnings[i], s)
			}
		}
	}
}

// The house VPN feed compiles to its own file. house_never_block applies.
// The file does not repeat a name that the house sinkhole already carries.
// Thus the file is exactly what HOUSE_BLOCK_VPN adds.
func TestCompileHouseVPN(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "generated"), 0755)
	for _, f := range []string{"never_block.domains", "never_block.ips", "blacklist.domains", "blacklist.ips"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(""), 0644)
	}
	_ = os.WriteFile(filepath.Join(dir, "house_never_block.domains"), []byte("family-vpn.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "generated", "house.domains"), []byte("tracker.example\nboth.example\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, HouseVPNFile), []byte("vpn.example\nboth.example\nfamily-vpn.example\n"), 0644)
	out := t.TempDir()
	o := Out{
		NFT:         filepath.Join(out, "e.nft"),
		DNS:         filepath.Join(out, "b.domains"),
		HouseDNS:    filepath.Join(out, "house.domains"),
		HouseVPNDNS: filepath.Join(out, "house-vpn.domains"),
	}
	if _, err := Compile(dir, o); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(o.HouseVPNDNS)
	if string(got) != dnsLines([]string{"vpn.example"}) {
		t.Fatalf("house VPN list:\n%s", got)
	}
	house, _ := os.ReadFile(o.HouseDNS)
	if strings.Contains(string(house), "/vpn.example/") || !strings.Contains(string(house), "/both.example/") {
		t.Fatalf("house sinkhole took the VPN list:\n%s", house)
	}
}

// A line in a hand-kept address list can be a value that is not an address
// that the list accepts. The compiler skips that line with a warning that
// Line prints, not silently. Before, github.com in ssh_allow.ips compiled
// to nothing and gave no message. It is a warning, not an error. Thus a
// file that already holds a name does not stop an apply that passed before.
// Lists from feeds (doh.ips here) continue to skip junk silently.
func TestHandKeptListsWarnOnSkippedLines(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("ssh_allow.ips", "github.com  # forge\n10.0.0.5\n\n# only a comment\n93.184.216.40\n")
	write("direct_ip.allow", "151.0.0.0/8\n151.101.1.9\n")
	write("house_direct_ip.allow", "tv.example\n")
	write("doh.ips", "not-an-ip\n")
	out := t.TempDir()
	sum, err := Compile(dir, Out{
		NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf"),
		SSHAllowNFT: filepath.Join(out, "ssh.nft"), DirectIPNFT: filepath.Join(out, "direct.nft"),
		HouseDirectIPNFT: filepath.Join(out, "house-direct.nft"), DoHNFT: filepath.Join(out, "doh.nft"),
	})
	if err != nil {
		t.Fatalf("a skipped line stopped the compile: %v", err)
	}
	if sum.SSHAllows != 1 || sum.DirectIPs != 1 || sum.HouseDirectIPs != 0 {
		t.Fatalf("counts %+v", sum)
	}
	want := []struct{ has, hasNot []string }{
		{[]string{`direct_ip.allow line 1: "151.0.0.0/8"`, "/24 or narrower"}, []string{"a name"}},
		{[]string{`ssh_allow.ips line 1: "github.com"`, "a name is not accepted"}, nil},
		{[]string{`ssh_allow.ips line 2: "10.0.0.5"`, "public IPv4"}, []string{"a name"}},
		{[]string{`house_direct_ip.allow line 1: "tv.example"`, "a name is not accepted"}, nil},
	}
	if len(sum.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", sum.Warnings, len(want))
	}
	for i, w := range want {
		for _, s := range w.has {
			if !strings.Contains(sum.Warnings[i], s) {
				t.Errorf("warning %d %q lacks %q", i, sum.Warnings[i], s)
			}
		}
		for _, s := range w.hasNot {
			if strings.Contains(sum.Warnings[i], s) {
				t.Errorf("warning %d %q has %q", i, sum.Warnings[i], s)
			}
		}
	}
	line := sum.Line()
	if !strings.HasPrefix(line, "compile: ") || strings.Count(line, "\ncompile: warning: ") != len(want) ||
		!strings.Contains(line, "\ncompile: warning: ssh_allow.ips line 1:") {
		t.Fatalf("Line does not print the warnings:\n%s", line)
	}
	if strings.Contains(line, "not-an-ip") {
		t.Fatal("a feed-fed list's junk line was warned about")
	}

	write("ssh_allow.ips", "93.184.216.40\n")
	write("direct_ip.allow", "151.101.1.9\n")
	write("house_direct_ip.allow", "")
	sum, err = Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
	if err != nil || len(sum.Warnings) != 0 || strings.Contains(sum.Line(), "warning") {
		t.Fatalf("clean lists: warnings %q err %v", sum.Warnings, err)
	}
}

// never_block.domains and core.hosts shield a name and each name below it.
// Thus a line of the operator in blacklist.domains can compile to nothing.
// The compiler then gives a warning that names the entry and the two files.
// A feed entry that a shield removes gets no warning: the shield is there
// for the feeds.
func TestShieldedBlacklistLineWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"never_block.domains":         "example.com\n",
		"core.hosts":                  "api.anthropic.com CLAUDE_OAT\n",
		"blacklist.domains":           "www.example.com\nanthropic.com\nevil.example\nwww.example.com\n",
		"generated/blacklist.domains": "cdn.example.com\napi.anthropic.com\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	sum, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
	if err != nil {
		t.Fatal(err)
	}
	dns, _ := os.ReadFile(filepath.Join(out, "d.conf"))
	if string(dns) != dnsLines([]string{"evil.example"}) || sum.Domains != 1 {
		t.Fatalf("d.conf=%q summary=%+v", dns, sum)
	}
	want := [][]string{
		{`blacklist.domains: "www.example.com"`, "never_block.domains"},
		{`blacklist.domains: "anthropic.com"`, "core.hosts"},
	}
	if len(sum.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", sum.Warnings, len(want))
	}
	for i, w := range want {
		for _, s := range w {
			if !strings.Contains(sum.Warnings[i], s) {
				t.Errorf("warning %d %q lacks %q", i, sum.Warnings[i], s)
			}
		}
	}
	if line := sum.Line(); strings.Contains(line, "cdn.example.com") || !strings.Contains(line, "\ncompile: warning: blacklist.domains:") {
		t.Fatalf("Line:\n%s", line)
	}
}
