package policycompile

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// feedDir is localDir with subdirectories: a name can be generated/....
func feedDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["core.hosts"] = "gitlab.com GITLAB_TOKEN\n"
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readOut(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAtSharedParent(t *testing.T) {
	shared := SharedParents([]string{"github.io", "s3.amazonaws.com", "co.uk"})
	for _, d := range []string{"github.io", "s3.amazonaws.com", "amazonaws.com", "co.uk"} {
		if !AtSharedParent(d, shared) {
			t.Errorf("%s compiles from a feed", d)
		}
	}
	for _, d := range []string{"bad.github.io", "bucket.s3.amazonaws.com", "ec2.amazonaws.com", "bad.co.uk", "example.com"} {
		if AtSharedParent(d, shared) {
			t.Errorf("%s does not compile from a feed", d)
		}
	}
}

// A feed entry at a shared parent does not compile, in the agent list and
// in the two house lists. An entry under it does. The same name in a list
// of the operator compiles as written.
func TestCompileDropsAFeedEntryAtASharedParent(t *testing.T) {
	dir := feedDir(t, map[string]string{
		SharedParentsFile:             "github.io\nvercel.app\nworkers.dev\nblogspot.com\nco.uk\n",
		"generated/blacklist.domains": "github.io\nbad.github.io\n*.vercel.app\nco.uk\n",
		"blacklist.domains":           "blogspot.com\n",
		"generated/house.domains":     "vercel.app\nads.vercel.app\n",
		"house.domains":               "github.io\n",
		"generated/house_vpn.domains": "workers.dev\nproxy.workers.dev\n",
	})
	out := t.TempDir()
	o := Out{
		NFT:         filepath.Join(out, "e.nft"),
		DNS:         filepath.Join(out, "d.conf"),
		HouseDNS:    filepath.Join(out, "house.conf"),
		HouseVPNDNS: filepath.Join(out, "vpn.conf"),
	}
	sum, err := Compile(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	line := func(d string) string { return "address=/" + d + "/0.0.0.0\n" }
	for path, want := range map[string]struct{ in, out []string }{
		o.DNS:         {[]string{"bad.github.io", "blogspot.com"}, []string{"github.io", "vercel.app", "co.uk"}},
		o.HouseDNS:    {[]string{"ads.vercel.app", "github.io"}, []string{"vercel.app"}},
		o.HouseVPNDNS: {[]string{"proxy.workers.dev"}, []string{"workers.dev"}},
	} {
		got := readOut(t, path)
		for _, d := range want.in {
			if !strings.Contains(got, line(d)) {
				t.Errorf("%s: no %s:\n%s", filepath.Base(path), d, got)
			}
		}
		for _, d := range want.out {
			if strings.Contains(got, line(d)) {
				t.Errorf("%s: %s compiled:\n%s", filepath.Base(path), d, got)
			}
		}
	}
	if want := []string{"co.uk", "github.io", "vercel.app", "workers.dev"}; !slices.Equal(sum.SharedParents, want) {
		t.Fatalf("SharedParents %v, want %v", sum.SharedParents, want)
	}
	if l := sum.Line(); !strings.Contains(l, "skipped 4 feed entries at a shared parent") || !strings.Contains(l, "github.io") {
		t.Fatalf("summary does not report the skipped entries:\n%s", l)
	}
}

// With no shared_parents.domains (a box with no tree, before a ship), each
// feed entry compiles as before.
func TestCompileWithoutSharedParentsKeepsTheFeed(t *testing.T) {
	dir := feedDir(t, map[string]string{"generated/blacklist.domains": "github.io\n"})
	out := t.TempDir()
	sum, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Domains != 1 || len(sum.SharedParents) != 0 {
		t.Fatalf("domains %d, skipped %v; want 1 and none", sum.Domains, sum.SharedParents)
	}
}

// The shipped list must not hold a name that a shipped feed is for: the
// house VPN feed blocks tunnel services on purpose.
func TestShippedSharedParentsAreNotTunnels(t *testing.T) {
	names, err := LoadTokens(filepath.Join("..", "..", "vm", "policy", SharedParentsFile), "domains")
	if err != nil || len(names) == 0 {
		t.Fatalf("no shipped %s: %v", SharedParentsFile, err)
	}
	for _, n := range names {
		for _, tunnel := range []string{"ngrok", "trycloudflare", "loca.lt", "localtunnel"} {
			if strings.Contains(n, tunnel) {
				t.Errorf("%s lists %s", SharedParentsFile, n)
			}
		}
	}
}

// A fetched IP feed adds no prefix wider than the floor. blacklist.ips of
// the operator keeps the /8 floor.
func TestCompileDropsAWideFeedPrefix(t *testing.T) {
	for _, tc := range []struct {
		sources string
		floor   int
		skipped []string
	}{
		{"", FeedMinBits, []string{"5.0.0.0/11", "6.0.0.0/8"}},
		{`{"min_ip_prefix":16,"feeds":[]}`, 16, []string{"42.128.0.0/12", "5.0.0.0/11", "6.0.0.0/8"}},
		{`{"min_ip_prefix":8,"feeds":[]}`, 8, nil},
		{`{"min_ip_prefix":4,"feeds":[]}`, FeedMinBits, []string{"5.0.0.0/11", "6.0.0.0/8"}},
		{`{not json`, FeedMinBits, []string{"5.0.0.0/11", "6.0.0.0/8"}},
	} {
		files := map[string]string{
			"generated/blacklist.ips": "6.0.0.0/8\n5.0.0.0/11\n42.128.0.0/12\n9.9.9.9\n",
			"blacklist.ips":           "13.0.0.0/8\n",
		}
		if tc.sources != "" {
			files["sources.json"] = tc.sources
		}
		dir := feedDir(t, files)
		out := t.TempDir()
		o := Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf"), IPMap: filepath.Join(out, "ip.map")}
		sum, err := Compile(dir, o)
		if err != nil {
			t.Fatal(err)
		}
		if sum.FeedFloor != tc.floor || !slices.Equal(sum.WidePrefixes, tc.skipped) {
			t.Fatalf("%q: floor /%d, skipped %v; want /%d and %v", tc.sources, sum.FeedFloor, sum.WidePrefixes, tc.floor, tc.skipped)
		}
		nft, ipMap := readOut(t, o.NFT), readOut(t, o.IPMap)
		for _, p := range []string{"6.0.0.0/8", "5.0.0.0/11", "42.128.0.0/12", "9.9.9.9", "13.0.0.0/8"} {
			want := !slices.Contains(tc.skipped, p)
			if strings.Contains(nft, p) != want || strings.Contains(ipMap, p) != want {
				t.Errorf("%q: %s compiled is %v, want %v:\n%s", tc.sources, p, !want, want, nft)
			}
		}
		if len(tc.skipped) > 0 && !strings.Contains(sum.Line(), fmt.Sprintf("skipped %d feed entries wider than /%d", len(tc.skipped), tc.floor)) {
			t.Fatalf("summary does not report the skipped prefixes:\n%s", sum.Line())
		}
	}
}
