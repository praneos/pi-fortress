package gateset

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// The text of each write, from a fake runner: the add is bare, the
// refresh is one transaction (add so that the delete finds the element,
// delete, add back with the whole timeout), and an address that is not
// IPv4 never reaches nft.
func TestCmdTextGolden(t *testing.T) {
	var got []string
	n := &Cmd{Table: "inet fortress", Run: func(arg string) error { got = append(got, arg); return nil }}
	in := addrs("93.184.216.34", "2001:db8::1", "1.1.1.1")
	if err := n.Add("resolved_v4", in); err != nil {
		t.Fatal(err)
	}
	if err := n.Refresh("resolved_house_v4", in); err != nil {
		t.Fatal(err)
	}
	el := "element inet fortress resolved_house_v4 { 93.184.216.34, 1.1.1.1 }"
	want := []string{
		"add element inet fortress resolved_v4 { 93.184.216.34, 1.1.1.1 }",
		"add " + el + "; delete " + el + "; add " + el,
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("nft text:\n%q\nwant:\n%q", got, want)
	}
	// No IPv4 address: no call at all.
	got = nil
	if err := n.Add("resolved_v4", addrs("2001:db8::1")); err != nil || len(got) != 0 {
		t.Fatalf("an IPv6-only add ran nft %q (%v)", got, err)
	}
	if err := n.Refresh("resolved_v4", nil); err != nil || len(got) != 0 {
		t.Fatalf("an empty refresh ran nft %q (%v)", got, err)
	}
	// The error of the runner is the error of the write.
	boom := errors.New("boom")
	n.Run = func(string) error { return boom }
	if err := n.Add("resolved_v4", addrs("1.1.1.1")); !errors.Is(err, boom) {
		t.Fatalf("Add returned %v, want the runner error", err)
	}
}

// The refresh is one nft invocation, so one transaction: add (so the
// delete finds the element), delete, add (back with the whole timeout).
// This runs the real Exec against a fake nft on PATH.
func TestCmdRefreshIsOneCommandLine(t *testing.T) {
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >>"+argv+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	n := &Cmd{Table: "inet fortress"}
	in := addrs("93.184.216.34", "2001:db8::1", "1.1.1.1")
	if err := n.Refresh("resolved_v4", in); err != nil {
		t.Fatal(err)
	}
	if err := n.Add("resolved_v4", in); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	el := "element inet fortress resolved_v4 { 93.184.216.34, 1.1.1.1 }"
	want := "add " + el + "; delete " + el + "; add " + el + "\nadd " + el + "\n"
	if string(raw) != want {
		t.Fatalf("nft argv:\n%s\nwant:\n%s", raw, want)
	}
}

// An nft that fails gives its stderr in the error.
func TestExecErrorHasStderr(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\necho 'Error: set full' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	err := Exec("add element inet fortress resolved_v4 { 1.1.1.1 }")
	if err == nil || !strings.Contains(err.Error(), "Error: set full") {
		t.Fatalf("Exec error %v, want the stderr of nft in it", err)
	}
}

func TestPublic(t *testing.T) {
	in := addrs("8.8.8.8", "172.16.0.1", "::ffff:10.0.0.1", "100.64.0.1", "198.18.0.1", "240.0.0.1",
		"0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.2", "1.1.1.1", "192.168.1.1")
	got := Public(in)
	want := addrs("8.8.8.8", "192.0.2.2", "1.1.1.1")
	if len(got) != len(want) {
		t.Fatalf("Public = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Public = %v, want %v", got, want)
		}
	}
	// A mapped public address comes back as plain IPv4.
	if got := Public(addrs("::ffff:8.8.4.4")); len(got) != 1 || !got[0].Is4() {
		t.Fatalf("Public of a mapped address = %v", got)
	}
}

func TestIsResolverSet(t *testing.T) {
	for _, name := range []string{"resolved_v4", "resolved_house_v4", "resolved_desk_v4", "resolved_my_seg_2_v4"} {
		if !IsResolverSet(name) {
			t.Errorf("%s is a resolver set", name)
		}
	}
	for _, name := range []string{"", "blacklist_v4", "direct_ip_v4", "ssh_allow_v4", "resolved__v4", "resolved_v4 ", "resolved_House_v4",
		"resolved_v4; flush ruleset", "resolved_x_v4\n", "house_direct_ip_v4"} {
		if IsResolverSet(name) {
			t.Errorf("%q is not a resolver set", name)
		}
	}
}
