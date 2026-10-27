package policycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMap(t *testing.T) {
	cases := []struct {
		name, text string
		want       map[string]string
	}{
		{"plain", "evil.example\turlhaus-domains-online\n192.0.2.0/24\tspamhaus-drop\n",
			map[string]string{"evil.example": "urlhaus-domains-online", "192.0.2.0/24": "spamhaus-drop"}},
		{"first feed wins", "a.example\tx\na.example\ty\n", map[string]string{"a.example": "x"}},
		{"blank and malformed skipped", "\n \nnofeed\n\tnoitem\na.example\tx\n", map[string]string{"a.example": "x"}},
		{"padding trimmed", "  a.example \t x \r\n", map[string]string{"a.example": "x"}},
		{"empty", "", map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseMap(c.text)
			if len(got) != len(c.want) {
				t.Fatalf("%v", got)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("%v", got)
				}
			}
		})
	}
}

func TestCompileEmitsFeedMaps(t *testing.T) {
	pol := t.TempDir()
	gen := filepath.Join(pol, "generated")
	if err := os.MkdirAll(gen, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"generated/blacklist.domains": "evil.example\nstale.example\n",
		"generated/blacklist.ips":     "192.0.2.0/24\n192.0.2.64/26\n",
		"generated/house.domains":     "ads.example\n",
		"generated/feeds.map":         "evil.example\turlhaus-domains-online\n192.0.2.0/24\tspamhaus-drop\n192.0.2.64/26\tfeodo-tracker\nads.example\thagezi-pro\n",
		"blacklist.domains":           "mine.example\n",
		"blacklist.ips":               "192.0.2.7\n",
		"house.domains":               "house.example\n",
		"never_block.domains":         "",
		"never_block.ips":             "",
		"house_never_block.domains":   "",
		"house_default.domains":       "",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(pol, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	tmp := t.TempDir()
	out := Out{
		NFT:       filepath.Join(tmp, "elements.nft"),
		DNS:       filepath.Join(tmp, "blocked.domains"),
		HouseDNS:  filepath.Join(tmp, "house.domains"),
		DomainMap: filepath.Join(tmp, "blocked-domains.map"),
		IPMap:     filepath.Join(tmp, "blocked-ips.map"),
	}
	if _, err := Compile(pol, out); err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	wantDomains := "evil.example\turlhaus-domains-online\nstale.example\tlocal\nmine.example\tlocal\n" + MapHouseMark + "\nads.example\thagezi-pro\nhouse.example\tlocal\n"
	if got := read(out.DomainMap); got != wantDomains {
		t.Fatalf("domain map:\n%s", got)
	}
	// The map carries every prefix as fed; the nft set coalesces them.
	wantIPs := "192.0.2.0/24\tspamhaus-drop\n192.0.2.64/26\tfeodo-tracker\n192.0.2.7\tlocal\n"
	if got := read(out.IPMap); got != wantIPs {
		t.Fatalf("ip map:\n%s", got)
	}
	if nft := read(out.NFT); strings.Contains(nft, "192.0.2.64/26") {
		t.Fatalf("the map changed the set:\n%s", nft)
	}
	// Without a feeds.map, every item is local and the lists are the same.
	before := read(out.DNS) + read(out.NFT)
	if err := os.Remove(filepath.Join(gen, "feeds.map")); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(pol, out); err != nil {
		t.Fatal(err)
	}
	if got := read(out.DomainMap); strings.Contains(got, "urlhaus") || !strings.HasPrefix(got, "evil.example\tlocal\n") {
		t.Fatalf("no feeds.map:\n%s", got)
	}
	if after := read(out.DNS) + read(out.NFT); after != before {
		t.Fatal("feeds.map changed the compiled lists")
	}
}

// An item that the operator lists is "local" in the maps, also when a feed
// lists it too. The operator line is the reason for the block. The feed
// label is for an item that only a feed carries.
func TestFeedMapsLabelOperatorEntriesLocal(t *testing.T) {
	pol := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pol, "generated"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"generated/blacklist.domains": "both.example\nfeed.example\n",
		"generated/blacklist.ips":     "192.0.2.7\n",
		"generated/house.domains":     "ads.example\n",
		"generated/feeds.map":         "both.example\turlhaus-domains-online\nfeed.example\turlhaus-domains-online\n192.0.2.7\tspamhaus-drop\nads.example\thagezi-pro\n",
		"blacklist.domains":           "both.example\n",
		"blacklist.ips":               "192.0.2.7\n",
		"house.domains":               "ads.example\n",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(pol, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	tmp := t.TempDir()
	out := Out{
		NFT:       filepath.Join(tmp, "elements.nft"),
		DNS:       filepath.Join(tmp, "blocked.domains"),
		HouseDNS:  filepath.Join(tmp, "house.domains"),
		DomainMap: filepath.Join(tmp, "blocked-domains.map"),
		IPMap:     filepath.Join(tmp, "blocked-ips.map"),
	}
	if _, err := Compile(pol, out); err != nil {
		t.Fatal(err)
	}
	dm, _ := os.ReadFile(out.DomainMap)
	if want := "both.example\tlocal\nfeed.example\turlhaus-domains-online\n" + MapHouseMark + "\nads.example\tlocal\n"; string(dm) != want {
		t.Fatalf("domain map:\n%s", dm)
	}
	im, _ := os.ReadFile(out.IPMap)
	if want := "192.0.2.7\tlocal\n"; string(im) != want {
		t.Fatalf("ip map:\n%s", im)
	}
}

// An IPv4 address on a domain list of the agent, from a feed or from the
// operator, goes to the IP list: nft drops it. It is not a name in the
// sinkhole. The IP map keeps its feed, or "local" for an operator line.
// never_block.ips still applies to it, and an address that the IP list
// refuses (private, reserved) compiles to nothing. For a line of the
// operator, the compile gives a warning.
func TestAddressOnDomainListBlocksAsAddress(t *testing.T) {
	pol := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pol, "generated"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"generated/blacklist.domains": "evil.example\n192.0.2.10\n0.0.0.0\n",
		"generated/feeds.map":         "evil.example\turlhaus-domains-online\n192.0.2.10\turlhaus-domains-online\n",
		"blacklist.domains":           "mine.example\n192.0.2.20\n10.0.0.1\n192.0.2.30\n",
		"never_block.ips":             "192.0.2.30\n",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(pol, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	tmp := t.TempDir()
	out := Out{
		NFT:       filepath.Join(tmp, "elements.nft"),
		DNS:       filepath.Join(tmp, "blocked.domains"),
		DomainMap: filepath.Join(tmp, "blocked-domains.map"),
		IPMap:     filepath.Join(tmp, "blocked-ips.map"),
	}
	sum, err := Compile(pol, out)
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if got := read(out.DNS); got != dnsLines([]string{"evil.example", "mine.example"}) {
		t.Fatalf("sinkhole:\n%s", got)
	}
	if got := read(out.NFT); got != nftElements([]string{"192.0.2.10", "192.0.2.20"})+"\n" {
		t.Fatalf("nft:\n%s", got)
	}
	if got, want := read(out.IPMap), "192.0.2.10\turlhaus-domains-online\n192.0.2.20\tlocal\n"; got != want {
		t.Fatalf("ip map:\n%s", got)
	}
	if got := read(out.DomainMap); strings.Contains(got, "192.0.2.") {
		t.Fatalf("domain map:\n%s", got)
	}
	if sum.IPs != 2 || sum.Domains != 2 {
		t.Fatalf("summary %+v", sum)
	}
}
