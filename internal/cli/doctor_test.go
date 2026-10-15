package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/doctor"
)

// A unit that starts on the third look passes. A unit that never starts
// fails when the window closes. The sleeps show that the ladder did not
// stop early.
func TestSettleRetriesUntilTheWindowCloses(t *testing.T) {
	looks := 0
	cfg := doctor.PostUpgradeConfig{Units: []string{"pi-fortress-broker.service"}, UnitActive: func(string) bool {
		looks++
		return looks >= 3
	}}
	var slept time.Duration
	sleep := func(d time.Duration) { slept += d }
	if rs := settle(cfg, 90*time.Second, sleep); rs[0].Status != doctor.OK || looks != 3 {
		t.Fatalf("looks %d, %+v", looks, rs)
	}
	cfg.UnitActive = func(string) bool { return false }
	slept = 0
	if rs := settle(cfg, 20*time.Second, sleep); rs[0].Status != doctor.Fail || slept != 20*time.Second {
		t.Fatalf("slept %v, %+v", slept, rs)
	}
}

func TestLoadUnitsRequired(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "units.required")
	if units, src := loadUnitsRequired(p); units != nil || !strings.Contains(src, p) {
		t.Fatalf("missing file: units=%v src=%q", units, src)
	}
	if err := os.WriteFile(p, []byte("\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if units, src := loadUnitsRequired(p); units != nil || src == "" {
		t.Fatalf("blank file: units=%v src=%q", units, src)
	}
	body := "pi-fortress-broker.service\npi-fortress-engine.service\n\npi-fortress-dns-agent-go.service\n"
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	units, src := loadUnitsRequired(p)
	if src != "" {
		t.Fatalf("src = %q, want empty on success", src)
	}
	want := []string{"pi-fortress-broker.service", "pi-fortress-engine.service", "pi-fortress-dns-agent-go.service"}
	if len(units) != len(want) {
		t.Fatalf("units = %v, want %v", units, want)
	}
	for i, u := range want {
		if units[i] != u {
			t.Fatalf("units[%d] = %q, want %q", i, units[i], u)
		}
	}
}

func TestUpstreamResolver(t *testing.T) {
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	if got := upstreamResolver(netEnv); got != "" {
		t.Fatalf("missing net.env: %q", got)
	}
	if err := os.WriteFile(netEnv, []byte("PI_IP=10.77.0.1\nDNS_UPSTREAM=9.9.9.9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := upstreamResolver(netEnv); got != "9.9.9.9" {
		t.Fatalf("got %q, want 9.9.9.9", got)
	}
	// net.env.local, the operator overlay apply reads after net.env, wins.
	if err := os.WriteFile(netEnv+".local", []byte("DNS_UPSTREAM=1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := upstreamResolver(netEnv); got != "1.1.1.1" {
		t.Fatalf("got %q, want the .local override 1.1.1.1", got)
	}
	// DoT on: the output chain refuses plain DNS to the upstream. Thus the
	// doctor asks the local stub.
	if err := os.WriteFile(netEnv+".local", []byte("DNS_UPSTREAM=1.1.1.1\nDOT_IPS=\"76.76.2.22\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := upstreamResolver(netEnv); got != "127.0.0.1" {
		t.Fatalf("got %q, want the DoT stub 127.0.0.1", got)
	}
}
