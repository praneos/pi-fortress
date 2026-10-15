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
	wantDomains := "evil.example\turlhaus-domains-online\nstale.example\tlocal\nmine.example\tlocal\nads.example\thagezi-pro\nhouse.example\tlocal\n"
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
