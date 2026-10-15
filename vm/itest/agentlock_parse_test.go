//go:build vagrant

package itest

import "testing"

func TestAgentLockParsers(t *testing.T) {
	const prerouting = `table inet fortress {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0.20" tcp dport 443 redirect to :8080
	}
}`
	if got := agentIFOf(prerouting); got != "eth0.20" {
		t.Errorf("agentIFOf = %q, want eth0.20", got)
	}
	if got := agentIFOf("table inet fortress {\n}"); got != "" {
		t.Errorf("agentIFOf with no redirect = %q", got)
	}

	const raw = `		iifname "eth0.20" udp dport 443 counter packets 7 bytes 210 drop
		iifname "eth0.20" tcp dport 80 ip daddr != 10.77.0.1 counter packets 3 bytes 180 drop
		iifname "eth1" udp dport 443 counter packets 99 bytes 2970 drop
		iifname "eth0.79" oifname "eth0.20" ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept
		iifname "eth0.79" oifname "eth0.20" counter packets 12 bytes 720 drop`
	for rule, want := range map[string]int{
		`iifname "eth0.20" udp dport 443`:                      7,
		`iifname "eth0.20" tcp dport 80 ip daddr != 10.77.0.1`: 3,
		`iifname "eth0.79" oifname "eth0.20"`:                  12,
	} {
		if got, err := ruleCount(raw, rule); err != nil || got != want {
			t.Errorf("ruleCount(%q) = %d, %v; want %d", rule, got, err, want)
		}
	}
	// Two matching rules (raw and forward both drop the udp/443 of the
	// agent) and no matching rule are both refusals, never a guess.
	if _, err := ruleCount(raw+"\n\t\tiifname \"eth0.20\" udp dport 443 counter packets 1 bytes 30 drop", `iifname "eth0.20" udp dport 443`); err == nil {
		t.Error("ruleCount took one of two matching rules")
	}
	if _, err := ruleCount(raw, `iifname "eth9" udp dport 443`); err == nil {
		t.Error("ruleCount found a rule that is not there")
	}
}
