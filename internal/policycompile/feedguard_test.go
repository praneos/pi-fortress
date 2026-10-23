package policycompile

import (
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
