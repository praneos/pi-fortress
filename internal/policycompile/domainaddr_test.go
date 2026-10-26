package policycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// compileAll writes the policy files, compiles them with each output set,
// and gives the summary and the outputs.
func compileAll(t *testing.T, files map[string]string) (Summary, Out) {
	t.Helper()
	dir, tmp := t.TempDir(), t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := Out{}
	for name, p := range map[string]*string{
		"e.nft": &out.NFT, "d.conf": &out.DNS, "doh.nft": &out.DoHNFT, "doh.conf": &out.DoHDNS,
		"h.conf": &out.HouseDNS, "hvpn.conf": &out.HouseVPNDNS, "hdoh.conf": &out.HouseDoHDNS,
		"hpriv.nft": &out.HousePrivateDNSNFT, "direct.nft": &out.DirectIPNFT,
		"hdirect.nft": &out.HouseDirectIPNFT, "wa.nft": &out.HouseWhatsAppNFT, "ssh.nft": &out.SSHAllowNFT,
		"d.map": &out.DomainMap, "ip.map": &out.IPMap,
	} {
		*p = filepath.Join(tmp, name)
	}
	sum, err := Compile(dir, out)
	if err != nil {
		t.Fatal(err)
	}
	return sum, out
}

// hasWarning says if one warning holds each of the parts.
func hasWarning(warnings []string, parts ...string) bool {
	for _, w := range warnings {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(w, p)
		}
		if all {
			return true
		}
	}
	return false
}

// An address on a domain list blocks as an address. never_block.domains and
// core.hosts shield it as they shield a name. They shield the IP half as
// never_block.ips does: an entry that overlaps the address goes. A line of
// the operator that a shield removes gets a warning.
func TestShieldsKeepAnAddressOnADomainList(t *testing.T) {
	for _, tc := range []struct {
		shield, body, file, token string
	}{
		{"never_block.domains", "192.0.2.1", "blacklist.domains", "192.0.2.1"},
		{"core.hosts", "192.0.2.1 CLAUDE_OAT", "blacklist.domains", "192.0.2.1"},
		{"never_block.domains", "192.0.2.1", "generated/blacklist.domains", "192.0.2.1"},
		{"core.hosts", "192.0.2.1 CLAUDE_OAT", "generated/blacklist.domains", "192.0.2.1"},
		{"core.hosts", "192.0.2.1 CLAUDE_OAT", "blacklist.ips", "192.0.2.0/24"},
		{"never_block.domains", "192.0.2.1", "generated/blacklist.ips", "192.0.2.0/24"},
	} {
		t.Run(tc.shield+"/"+tc.file, func(t *testing.T) {
			sum, out := compileAll(t, map[string]string{tc.shield: tc.body + "\n", tc.file: tc.token + "\n"})
			if nft := readOut(t, out.NFT); strings.Contains(nft, "192.0.2.") {
				t.Fatalf("%s did not shield the address:\n%s", tc.shield, nft)
			}
			if !strings.HasPrefix(tc.file, "generated/") && !hasWarning(sum.Warnings, tc.file+`: "`+tc.token+`"`, tc.shield) {
				t.Fatalf("no warning names the line and %s: %q", tc.shield, sum.Warnings)
			}
		})
	}
}
