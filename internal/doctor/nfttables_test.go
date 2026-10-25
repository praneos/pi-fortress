package doctor

import (
	"errors"
	"io/fs"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestNftTablesRung(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		err       error
		st        Status
		want      []string
		not       []string
	}{
		{
			name: "only pf",
			out:  "table inet fortress\n",
			st:   OK,
			want: []string{"inet fortress"},
		},
		{
			name: "empty ruleset",
			out:  "",
			st:   OK,
		},
		{
			// Docker with iptables-nft, and the fail2ban nftables action.
			name: "foreign tables",
			out:  "table inet fortress\ntable ip nat\ntable ip filter\ntable inet f2b-table\n",
			st:   Warn,
			want: []string{"ip nat", "ip filter", "inet f2b-table", "next apply", "boot"},
			not:  []string{"inet fortress"},
		},
		{
			name: "firewalld",
			out:  "table inet firewalld\n",
			st:   Warn,
			want: []string{"inet firewalld"},
		},
		{
			name: "not root",
			out:  "",
			err:  errors.New("Error: Could not process rule: Operation not permitted"),
			st:   Warn,
			want: []string{"cannot", "Operation not permitted", "sudo pf doctor"},
		},
		{
			name: "no nft",
			err:  exec.ErrNotFound,
			st:   Warn,
			want: []string{"cannot", "not installed"},
		},
		{
			// The fixed path is the fallback when nft is not in PATH.
			name: "no /usr/sbin/nft",
			err:  &fs.PathError{Op: "fork/exec", Path: "/usr/sbin/nft", Err: syscall.ENOENT},
			st:   Warn,
			want: []string{"cannot", "not installed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NftTablesRung(tc.out, tc.err)
			if r.Status != tc.st {
				t.Fatalf("status = %v, want %v (%q)", r.Status, tc.st, r.Detail)
			}
			if r.Rung != "nft" || r.Where != "pi" {
				t.Fatalf("rung = %q %q, want nft pi", r.Rung, r.Where)
			}
			for _, w := range tc.want {
				if !strings.Contains(r.Detail, w) {
					t.Errorf("detail %q does not name %q", r.Detail, w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(r.Detail, n) {
					t.Errorf("detail %q names %q", r.Detail, n)
				}
			}
		})
	}
}
