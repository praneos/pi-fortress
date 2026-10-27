package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/policycompile"
)

// The seat and pf compile read a list line by the same rule. A value that
// the seat adds compiles with no warning. A value that the seat refuses
// gives a warning or an error in pf compile. Thus a value that compiles
// can be added at the seat. The test tries each value on each list.
func TestSeatTakesWhatCompileTakes(t *testing.T) {
	values := []string{
		"example.com", "*.example.com", "pi-fortress-block.test", "abc123.dns.controld.example",
		"192.0.2.1", "192.0.2.0/24", "192.0.2.5/24", "10.0.0.1", "10.0.0.0/8", "2.0.0.0/7", "203.0.113.9",
		"..x.example", "-bad-.example", "a+b.example", "münchen.de", "com", "bad!token",
	}
	for _, seg := range policycompile.Segments {
		for _, l := range seg.Lists() {
			for _, v := range values {
				got, verr := ValidateToken(l.Name, v)
				line := v
				if verr == nil {
					line = got
				}
				loud := compileIsLoud(t, l.Name, line)
				switch {
				case verr == nil && loud != "":
					t.Errorf("%s: the seat takes %q as %q, but pf compile says: %s", l.Name, v, got, loud)
				case verr != nil && loud == "":
					t.Errorf("%s: pf compile takes %q, but the seat refuses it: %v", l.Name, v, verr)
				}
			}
		}
	}
}

// compileIsLoud compiles a policy whose file list holds the one line, and
// gives the warning or the error that names the file, or "".
func compileIsLoud(t *testing.T, list, line string) string {
	t.Helper()
	dir, tmp := t.TempDir(), t.TempDir()
	files := map[string]string{list: line + "\n"}
	if list == "house_private_dns.domains" {
		files["house_private_dns.ips"] = "192.0.2.53\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := policycompile.Out{}
	for name, p := range map[string]*string{
		"e.nft": &out.NFT, "d.conf": &out.DNS, "doh.nft": &out.DoHNFT, "doh.conf": &out.DoHDNS,
		"h.conf": &out.HouseDNS, "hvpn.conf": &out.HouseVPNDNS, "hdoh.conf": &out.HouseDoHDNS,
		"hpriv.nft": &out.HousePrivateDNSNFT, "direct.nft": &out.DirectIPNFT,
		"hdirect.nft": &out.HouseDirectIPNFT, "ssh.nft": &out.SSHAllowNFT,
	} {
		*p = filepath.Join(tmp, name)
	}
	sum, err := policycompile.Compile(dir, out)
	if err != nil {
		return err.Error()
	}
	for _, w := range sum.Warnings {
		if strings.HasPrefix(w, list+" line ") || strings.HasPrefix(w, list+": ") {
			return w
		}
	}
	return ""
}
