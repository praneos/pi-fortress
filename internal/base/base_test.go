package base

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNowISOUsesTheInjectedClockInUTC(t *testing.T) {
	east := time.FixedZone("east", 5*3600)
	got := NowISO(func() time.Time { return time.Date(2026, 9, 8, 15, 4, 5, 0, east) })
	if want := "2026-09-08T10:04:05Z"; got != want {
		t.Fatalf("NowISO = %q, want %q", got, want)
	}
	if NowISO(nil) == "" {
		t.Fatal("NowISO(nil) is empty")
	}
	if _, err := ParseISO(got); err != nil {
		t.Fatalf("ParseISO(%q): %v", got, err)
	}
}

func TestParseEnvSkipsBlanksCommentsAndBareLines(t *testing.T) {
	got := ParseEnv([]byte("" +
		"# a comment\n" +
		"\n" +
		"  PI_IP = 10.77.0.1  \n" +
		"AGENT_NET=\"10.77.0.0/24\"\n" +
		"no equals sign\n" +
		"EMPTY=\n" +
		"WITH=a=b\n"))
	want := map[string]string{
		"PI_IP":     "10.77.0.1",
		"AGENT_NET": "10.77.0.0/24",
		"EMPTY":     "",
		"WITH":      "a=b",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseEnvStripsQuotesLikeShellSourcing(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		{"double quoted", `DOT_IPS="9.9.9.9 149.112.112.112"`, "9.9.9.9 149.112.112.112"},
		{"single quoted", `DOT_IPS='9.9.9.9 149.112.112.112'`, "9.9.9.9 149.112.112.112"},
		{"unquoted", `DOT_IPS=9.9.9.9`, "9.9.9.9"},
		{"trailing spaces", `DOT_IPS=9.9.9.9   `, "9.9.9.9"},
		{"hash in quoted value", `RULE="a#b"`, "a#b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseEnv([]byte(tc.line))
			key, _, _ := strings.Cut(tc.line, "=")
			if got[key] != tc.want {
				t.Fatalf("ParseEnv(%q) = %q, want %q", tc.line, got[key], tc.want)
			}
		})
	}
}

func TestLoadEnvFirstStopsAtTheFirstReadableFile(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "a.env"), filepath.Join(dir, "b.env")
	if err := os.WriteFile(second, []byte("WHO=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadEnvFirst([]string{first, second})["WHO"]; got != "b" {
		t.Fatalf("unreadable head not skipped: WHO = %q", got)
	}
	if err := os.WriteFile(first, []byte("WHO=a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadEnvFirst([]string{first, second})["WHO"]; got != "a" {
		t.Fatalf("second file won: WHO = %q", got)
	}
	if got := LoadEnvFirst(nil); len(got) != 0 {
		t.Fatalf("LoadEnvFirst(nil) = %v, want empty", got)
	}
	if got := LoadEnv(filepath.Join(dir, "missing.env")); len(got) != 0 {
		t.Fatalf("LoadEnv(missing) = %v, want empty", got)
	}
}

func TestMustPrefixes(t *testing.T) {
	got := MustPrefixes("10.0.0.0/8", "::1/128")
	if len(got) != 2 || got[0].String() != "10.0.0.0/8" || got[1].String() != "::1/128" {
		t.Fatalf("MustPrefixes = %v", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustPrefixes accepted a bad CIDR")
		}
	}()
	MustPrefixes("10.0.0.0/33")
}

// www and the engine use the same bind rule: one unicast address, never the
// wildcard.
func TestCheckBindHost(t *testing.T) {
	for _, h := range []string{"10.77.0.1", "127.0.0.1", "localhost", "fe80::1", "::1"} {
		if err := CheckBindHost(h); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
	for _, h := range []string{"", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "pi.example"} {
		if err := CheckBindHost(h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestPolicyDirResolvesLikeApply(t *testing.T) {
	root := t.TempDir()
	lab, opt, etc := filepath.Join(root, "vagrant"), filepath.Join(root, "opt"), filepath.Join(root, "etc")
	tree := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "vm", "pi"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "vm", "policy"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vm", "pi", "net.env"), []byte("PI_IP=10.77.0.1\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	trees := []string{lab, opt}
	if got := policyDirFrom("", trees, etc); got != etc {
		t.Fatalf("no tree: %q, want %q", got, etc)
	}
	// A policy directory alone is not a tree that apply would compile from.
	os.MkdirAll(filepath.Join(opt, "vm", "policy"), 0755)
	if got := policyDirFrom("", trees, etc); got != etc {
		t.Fatalf("vm/policy without vm/pi/net.env: %q, want %q", got, etc)
	}
	tree(opt)
	if got, want := policyDirFrom("", trees, etc), filepath.Join(opt, "vm", "policy"); got != want {
		t.Fatalf("pf install box: %q, want %q", got, want)
	}
	tree(lab)
	if got, want := policyDirFrom("", trees, etc), filepath.Join(lab, "vm", "policy"); got != want {
		t.Fatalf("lab: %q, want %q", got, want)
	}
	if got := policyDirFrom(" /srv/policy ", trees, etc); got != "/srv/policy" {
		t.Fatalf("PI_FORTRESS_POLICY: %q", got)
	}
}
