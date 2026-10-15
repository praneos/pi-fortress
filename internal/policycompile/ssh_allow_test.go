package policycompile

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ssh_allow.ips opens a path past the fence. Thus it uses the floor of an
// allow list (/16). The parser refuses a prefix with host bits. It does not
// mask it into a wider hole than the operator possibly meant.
func TestParseSSHIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"140.82.112.0/20": "140.82.112.0/20",
		"93.184.0.0/16":   "93.184.0.0/16",
		"151.101.1.9":     "151.101.1.9",
		"151.101.1.9/32":  "151.101.1.9",
	} {
		if got, ok := ParseSSHIPv4(in); !ok || got != want {
			t.Errorf("ParseSSHIPv4(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"151.0.0.0/8", "93.0.0.0/15", "140.82.114.4/20", "93.184.216.40/24", "10.0.0.5", "github.com", ""} {
		if got, ok := ParseSSHIPv4(bad); ok {
			t.Errorf("ParseSSHIPv4(%q) accepted as %q", bad, got)
		}
	}
}

func TestSSHAllowSkipsWideAndHostBitPrefixesByLine(t *testing.T) {
	dir := t.TempDir()
	body := "151.0.0.0/8\n140.82.114.4/20\n140.82.112.0/20\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh_allow.ips"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	sum, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf"), SSHAllowNFT: filepath.Join(out, "ssh.nft")})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(out, "ssh.nft"))
	if sum.SSHAllows != 1 || !strings.Contains(string(raw), "140.82.112.0/20") || strings.Contains(string(raw), "151.0.0.0") {
		t.Fatalf("ssh.nft=%q summary=%+v", raw, sum)
	}
	if len(sum.Warnings) != 2 ||
		!strings.Contains(sum.Warnings[0], `ssh_allow.ips line 1: "151.0.0.0/8"`) || !strings.Contains(sum.Warnings[0], "/16 or narrower") ||
		!strings.Contains(sum.Warnings[1], `ssh_allow.ips line 2: "140.82.114.4/20"`) || !strings.Contains(sum.Warnings[1], "host bits") || !strings.Contains(sum.Warnings[1], "140.82.112.0/20") {
		t.Fatalf("warnings %q", sum.Warnings)
	}
}

func FuzzParseSSHIPv4(f *testing.F) {
	f.Add("140.82.112.0/20")
	f.Add("140.82.114.4/20")
	f.Add("151.101.1.9")
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := ParseSSHIPv4(s)
		if !ok {
			return
		}
		p, ok := parsePrefix4(out)
		if !ok || p.Bits() < sshMinBits {
			t.Fatalf("accepted %q -> %q", s, out)
		}
		if in, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil && in != p {
			t.Fatalf("accepted %q as a different prefix %q", s, out)
		}
		for _, block := range Reserved {
			if p.Overlaps(block) {
				t.Fatalf("accepted reserved %q -> %q", s, out)
			}
		}
	})
}
