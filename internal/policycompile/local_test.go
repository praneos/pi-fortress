package policycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// localDir is a policy dir with a core.hosts and the given files.
func localDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["core.hosts"] = "gitlab.com GITLAB_TOKEN\n"
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// doh.ips and doh.domains ship, and an upgrade or a provision replaces
// them. The resolvers that the operator adds are in the .local files,
// and compile pins both sets.
func TestCompileDoHAddsTheLocalLists(t *testing.T) {
	dir := localDir(t, map[string]string{
		"doh.ips":           "8.8.8.8\n",
		"doh.ips.local":     "# mine\n94.140.14.14\n8.8.8.8\n",
		"doh.domains":       "dns.google\n",
		"doh.domains.local": "# mine\ndns.adguard-dns.com\ndns.google\n",
	})
	out := t.TempDir()
	sum, err := Compile(dir, Out{
		NFT:    filepath.Join(out, "e.nft"),
		DNS:    filepath.Join(out, "d.conf"),
		DoHNFT: filepath.Join(out, "doh.nft"),
		DoHDNS: filepath.Join(out, "doh.domains"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.DoHIPs != 2 || sum.DoHDomains != 2 {
		t.Fatalf("doh_ips %d, doh_domains %d; want 2 and 2 (a token in both files counts one time)", sum.DoHIPs, sum.DoHDomains)
	}
	nft, _ := os.ReadFile(filepath.Join(out, "doh.nft"))
	for _, ip := range []string{"8.8.8.8", "94.140.14.14"} {
		if !strings.Contains(string(nft), ip) {
			t.Fatalf("doh.nft has no %s:\n%s", ip, nft)
		}
	}
	dns, _ := os.ReadFile(filepath.Join(out, "doh.domains"))
	for _, d := range []string{"dns.google", "dns.adguard-dns.com"} {
		if !strings.Contains(string(dns), "address=/"+d+"/0.0.0.0") {
			t.Fatalf("doh.domains has no %s:\n%s", d, dns)
		}
	}
}

// key_prefixes.rules.local compiles to nothing. apply appends it to the
// shipped rules. compile loads it as the broker does, so that a rule the
// broker cannot use stops pf apply before anything installs.
func TestCompileChecksTheLocalKeyRules(t *testing.T) {
	run := func(local string) error {
		dir := localDir(t, map[string]string{"key_prefixes.rules.local": local})
		out := t.TempDir()
		_, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
		return err
	}
	for _, ok := range []string{
		"",
		"# only comments\n#\n",
		"# mine\nacme\tacme_[A-Za-z0-9]{32,}\tACME_TOKEN\n",
	} {
		if err := run(ok); err != nil {
			t.Fatalf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"acme\tacme_[A-Za-z0-9{32,}\n",
		"acme\t[A-Za-z0-9]{40,}\n",
	} {
		err := run(bad)
		if err == nil || !strings.Contains(err.Error(), "key_prefixes.rules.local") || !strings.Contains(err.Error(), "acme") {
			t.Fatalf("%q accepted or not named: %v", bad, err)
		}
	}
}
