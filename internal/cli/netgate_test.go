package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/netgate"
)

func TestNetgateVerbs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, netgateUsage},
		{[]string{"bogus"}, 2, netgateUsage},
		{[]string{"ping", "bogus"}, 2, "bogus"},
		{[]string{"run", "-config", filepath.Join(t.TempDir(), "missing.json")}, 1, "missing.json"},
	} {
		var stderr bytes.Buffer
		code := runNetgate(tc.args, io.Discard, &stderr)
		if code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("pf netgate %q: code %d, stderr %q; want %d and %q", tc.args, code, stderr.String(), tc.code, tc.want)
		}
	}
}

// A fault in the setup of observe stops only ct.sock. A fault in the
// account of the agent resolver stops netgate.
func TestNetgateConfigWithoutObserve(t *testing.T) {
	dc := netgate.DNSConfig{Table: "inet fortress", Sets: []string{"resolved_v4"}}
	peers := map[string]netgate.Peer{netgate.DNSUser: {UID: 101, GID: 201}, netgate.CTUser: {UID: 102, GID: 202}}
	groups := map[string]int{netgate.CTGroup: 203}
	peer := func(account, _ string) (netgate.Peer, error) {
		p, ok := peers[account]
		if !ok {
			return netgate.Peer{}, errors.New("user: unknown user " + account)
		}
		return p, nil
	}
	group := func(name string) (int, error) {
		g, ok := groups[name]
		if !ok {
			return 0, errors.New("group: unknown group " + name)
		}
		return g, nil
	}
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }

	cfg, err := netgateConfig(dc, peer, group, logf)
	if err != nil || cfg.NoCT || cfg.CT != peers[netgate.CTUser] || cfg.CTGroup != 203 || cfg.DNS != peers[netgate.DNSUser] || cfg.DNSGroup != 201 {
		t.Fatalf("all accounts there: %+v %v", cfg, err)
	}
	delete(groups, netgate.CTGroup)
	if cfg, err := netgateConfig(dc, peer, group, logf); err != nil || !cfg.NoCT || cfg.DNS != peers[netgate.DNSUser] {
		t.Fatalf("no pf-ctgate: %+v %v", cfg, err)
	}
	delete(peers, netgate.CTUser)
	if cfg, err := netgateConfig(dc, peer, group, logf); err != nil || !cfg.NoCT {
		t.Fatalf("no pf-observe: %+v %v", cfg, err)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "unknown group "+netgate.CTGroup) || !strings.Contains(lines[1], "unknown user "+netgate.CTUser) {
		t.Fatalf("log %q, want one line for each fault", lines)
	}
	delete(peers, netgate.DNSUser)
	if _, err := netgateConfig(dc, peer, group, logf); err == nil || !strings.Contains(err.Error(), "agent resolver") {
		t.Fatalf("no pf-dns: %v", err)
	}
}
