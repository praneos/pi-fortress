//go:build vagrant

package itest

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The agent VM has its own output lock (agent_lock, vm/agent/routes.sh
// and setup.sh): DNS only to the Pi, no 853, no QUIC, no 80 except to the
// Pi, no IPv6. A probe of the Pi drops that the lock already refuses never
// leaves the VM. Thus it proves the table of the VM, and says nothing
// about the Pi. liftAgentLock removes the lock for the length of one
// subtest. There, the Pi itself must be seen to drop the probe (kernLog,
// or a counter of piRuleCount).
const (
	agentLockSaved = "/run/pf-itest-agent-lock.nft"
	agentLockToken = "/run/pf-itest-agent-lock.tok"
	// agentLockDeadman is how long the lock may stay off if this process
	// dies before its cleanup runs. Then a background job on the agent puts
	// it back. Much longer than any probe window.
	agentLockDeadman = 120
)

// agentLockMu keeps the windows of parallel subtests apart. Two lifts at
// the same time would each save the missing table of the other, and
// restore nothing.
var agentLockMu sync.Mutex

// liftAgentLock saves and then deletes the agent_lock table of the agent.
// It registers the restore on t, so the lock comes back if the subtest
// passes, fails or is skipped. A deadman on the agent also restores it if
// the run is killed. A token stops an old deadman from firing inside a
// later window.
func liftAgentLock(t *testing.T) {
	t.Helper()
	agentLockMu.Lock()
	// Until the cleanup owns it. A sudo refusal skips the subtest from
	// inside ssh, and a mutex that stays held would hang all later lifts.
	held := true
	defer func() {
		if held {
			agentLockMu.Unlock()
		}
	}()
	tok := strconv.FormatInt(time.Now().UnixNano(), 36)
	script := strings.Join([]string{
		"set -e",
		"nft list table inet agent_lock > " + agentLockSaved + ".new",
		"mv -f " + agentLockSaved + ".new " + agentLockSaved,
		"echo " + tok + " > " + agentLockToken,
		"setsid -f sh -c 'sleep " + strconv.Itoa(agentLockDeadman) + "; [ \"$(cat " + agentLockToken + " 2>/dev/null)\" = " + tok + " ] || exit 0; nft list table inet agent_lock >/dev/null 2>&1 || nft -f " + agentLockSaved + "' >/dev/null 2>&1 </dev/null",
		"nft delete table inet agent_lock",
	}, "; ")
	if out, err := ssh(t, 30*time.Second, "agent", "sudo sh -c "+shellQuote(script)); err != nil {
		t.Fatalf("could not lift the agent's own lock for the probe: %v\n%s", err, out)
	}
	held = false
	t.Cleanup(func() {
		defer agentLockMu.Unlock()
		restoreAgentLock(t)
	})
}

// restoreAgentLock loads the saved lock again, and fails the test unless
// agent_lock is in place with policy drop after that. The saved copy
// first. If that fails, the files from which routes.sh and setup.sh
// install the lock.
func restoreAgentLock(t *testing.T) {
	t.Helper()
	script := strings.Join([]string{
		"rm -f " + agentLockToken,
		"nft list table inet agent_lock >/dev/null 2>&1 || nft -f " + agentLockSaved + " || nft -f /usr/local/lib/pi-fortress/agent-lock.nft || nft -f /etc/nftables.conf",
		"nft list chain inet agent_lock output",
	}, "; ")
	out, err := ssh(t, 30*time.Second, "agent", "sudo sh -c "+shellQuote(script))
	if err != nil || !strings.Contains(out, "policy drop") {
		t.Errorf("the agent's own lock (agent_lock) did not come back after the probe; reload it on the agent (sudo nft -f %s): %v\n%s", agentLockSaved, err, out)
	}
}

// piAgentIF is INT_IF as the ruleset of the Pi names it: the one
// interface whose 443 is redirected to the engine.
func piAgentIF(t *testing.T) string {
	t.Helper()
	ifc := agentIFOf(pi(t, "sudo nft list chain inet fortress prerouting"))
	if ifc == "" {
		t.Fatal("no agent 443 redirect in the Pi's nat prerouting; cannot tell which interface is the agent's")
	}
	return ifc
}

var reAgentRedirect = regexp.MustCompile(`iifname "([^"]+)" tcp dport 443 redirect to :8080`)

func agentIFOf(listing string) string {
	if m := reAgentRedirect.FindStringSubmatch(listing); m != nil {
		return m[1]
	}
	return ""
}

// piRuleCount is the packet counter of the rule in chain on the Pi (of
// table inet fortress) that is rule followed by its counter. Exactly one
// rule must match. If not, the count could belong to a different rule.
func piRuleCount(t *testing.T, chain, rule string) int {
	t.Helper()
	n, err := ruleCount(pi(t, "sudo nft list chain inet fortress "+chain), rule)
	if err != nil {
		t.Fatalf("the Pi's %s chain: %v", chain, err)
	}
	return n
}

// ruleCount is piRuleCount over a listing already read.
func ruleCount(listing, rule string) (int, error) {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(rule) + ` counter packets (\d+) bytes \d+`)
	ms := re.FindAllStringSubmatch(listing, -1)
	if len(ms) != 1 {
		return 0, fmt.Errorf("%d rules match %q, want exactly one", len(ms), rule)
	}
	return strconv.Atoi(ms[0][1])
}

// piDropsGrow fails unless the counter on the Pi for rule in chain
// increased while probe ran.
func piDropsGrow(t *testing.T, chain, rule string, probe func()) {
	t.Helper()
	before := piRuleCount(t, chain, rule)
	probe()
	eventually(t, 10*time.Second, func() string {
		if after := piRuleCount(t, chain, rule); after <= before {
			return "the Pi's counter on `" + rule + "` did not move (" + strconv.Itoa(before) + " -> " + strconv.Itoa(after) + "): the probe never reached that drop"
		}
		return ""
	})
}

// piV6Discards is the Ip6InDiscards of the Pi on ifc, or -1 when the
// kernel keeps no IPv6 statistics for it.
func piV6Discards(t *testing.T, ifc string) int {
	t.Helper()
	out, _ := ssh(t, 5*time.Second, "pi", "cat /proc/net/dev_snmp6/"+ifc+" 2>/dev/null || true")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "Ip6InDiscards" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return n
			}
		}
	}
	return -1
}

// piV6DropsGrow fails unless IPv6 from the agent was dropped on the Pi
// while probe ran. With disable_ipv6 set on the interface, the kernel
// discards the packet before the nft prerouting hook. Thus its rule
// never counts it, but the Ip6InDiscards of the interface does.
func piV6DropsGrow(t *testing.T, ifc string, probe func()) {
	t.Helper()
	rule := `iifname "` + ifc + `" meta nfproto ipv6`
	nftBefore, discBefore := piRuleCount(t, "filter_prerouting", rule), piV6Discards(t, ifc)
	probe()
	eventually(t, 10*time.Second, func() string {
		nftAfter, discAfter := piRuleCount(t, "filter_prerouting", rule), piV6Discards(t, ifc)
		if nftAfter > nftBefore || (discBefore >= 0 && discAfter > discBefore) {
			return ""
		}
		return fmt.Sprintf("no IPv6 drop on the Pi: nft counter on `%s` %d -> %d, %s Ip6InDiscards %d -> %d; the probe never reached the Pi", rule, nftBefore, nftAfter, ifc, discBefore, discAfter)
	})
}
