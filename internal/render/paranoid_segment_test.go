package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	deskWebGate  = `iifname "eth0.79" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 ip daddr != 10.77.0.10-10.77.0.12`
	deskEnvLines = "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\n"
)

// paranoidDesk is segGoldenDir with the desk armed and its allowlist
// next to segments.d, where SegmentAllowPath looks.
func paranoidDesk(t *testing.T) string {
	t.Helper()
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"PARANOID=on\n")
	write(t, filepath.Dir(segs), "allow.desk.domains", "# the desk's own\ngithub.com\n")
	return segs
}

// The resolver of a segment enforces its PARANOID, with the gate that it
// already has. The ruleset does not change. The test proves this against
// the golden rendered before the key existed, for on and for an explicit off.
func TestParanoidSegmentLeavesTheRulesetAlone(t *testing.T) {
	golden, err := os.ReadFile("testdata/nft.segments.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := load(t, Options{Net: lab, SegmentsDir: paranoidDesk(t)}).Ruleset(labElements); got != string(golden) {
		t.Fatalf("PARANOID=on changed the ruleset:\n%s", got)
	}
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"PARANOID=off\n")
	c := load(t, Options{Net: lab, SegmentsDir: segs})
	if got := c.Ruleset(labElements); got != string(golden) {
		t.Fatalf("PARANOID=off drifted from the golden:\n%s", got)
	}
	if env := c.EnvFile(); !strings.Contains(env, "SEG_PARANOID=('off' 'off')\n") || !strings.Contains(env, "SEG_ALLOW=('' '')\n") {
		t.Fatalf("apply.env:\n%s", env)
	}
}

func TestParanoidSegmentEnvFileCarriesTheCheckedPath(t *testing.T) {
	segs := paranoidDesk(t)
	env := load(t, Options{Net: lab, SegmentsDir: segs}).EnvFile()
	allow := filepath.Join(filepath.Dir(segs), "allow.desk.domains")
	for _, want := range []string{"SEG_NAME=('desk' 'guest')\n", "SEG_PARANOID=('on' 'off')\n", "SEG_ALLOW=('" + allow + "' '')\n", "PARANOID='0'\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("apply.env lacks %q:\n%s", want, env)
		}
	}
}

// The shipped seed is a usable allowlist alone. A desk armed with the
// unedited seed renders, so Claude Code continues to work on the desk.
func TestParanoidSegmentAcceptsTheShippedSeed(t *testing.T) {
	seed, err := os.ReadFile("../../vm/pi/allow.segment.domains.example")
	if err != nil {
		t.Fatal(err)
	}
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"PARANOID=on\n")
	write(t, filepath.Dir(segs), "allow.desk.domains", string(seed))
	load(t, Options{Net: lab, SegmentsDir: segs})
}

// The refusals. Each names the file to fix and changes nothing.
func TestParanoidSegmentRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, env, allow string
		mode             os.FileMode
		want             []string
	}{
		{"bad value", "PARANOID=yes\n", "github.com\n", 0644, []string{"desk.env", "PARANOID is not on or off"}},
		{"empty value", "PARANOID=\n", "github.com\n", 0644, []string{"PARANOID is not on or off"}},
		{"agent spelling", "PARANOID=1\n", "github.com\n", 0644, []string{"PARANOID is not on or off"}},
		{"missing allowlist", "PARANOID=on\n", "", 0, []string{"desk.env", "allow.desk.domains is missing or unreadable", "Nothing was changed"}},
		{"comments only", "PARANOID=on\n", "# later\n\n", 0644, []string{"allow.desk.domains has no usable name"}},
		{"star lines only", "PARANOID=on\n", "*.github.com\n", 0644, []string{"allow.desk.domains has no usable name"}},
		{"not readable by pf dns", "PARANOID=on\n", "github.com\n", 0600, []string{"not readable by pf dns", "chmod 0644"}},
		{"gate turned off", "PARANOID=on\nBLOCK_DIRECT_IP=off\n", "github.com\n", 0644, []string{"PARANOID=on needs the resolved-address gate", "BLOCK_DIRECT_IP=off"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs := segGoldenDir(t)
			write(t, segs, "desk.env", deskEnvLines+tc.env)
			if tc.mode != 0 {
				p := write(t, filepath.Dir(segs), "allow.desk.domains", tc.allow)
				if err := os.Chmod(p, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Load(Options{Net: lab, SegmentsDir: segs})
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q: %v", w, err)
				}
			}
		})
	}
}

// The allow.domains of the agent is not the list of the desk. A box with
// only the list of the agent next to segments.d still refuses the armed desk.
func TestParanoidSegmentIgnoresTheAgentList(t *testing.T) {
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"PARANOID=on\n")
	write(t, filepath.Dir(segs), "allow.domains", "github.com\n")
	if _, err := Load(Options{Net: lab, SegmentsDir: segs}); err == nil || !strings.Contains(err.Error(), "allow.desk.domains") {
		t.Fatalf("the desk took the agent's list: %v", err)
	}
}

// lines is every rule line naming iface, in order.
func lines(nft, iface string) string {
	var out []string
	for _, l := range strings.Split(nft, "\n") {
		if strings.Contains(l, `"`+iface+`"`) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// The two toggles are independent. All four combinations render. The
// PARANOID of the agent changes only the agent gate and never a segment
// line. The PARANOID of the desk never changes an agent line. apply.env
// carries each on its own key.
func TestAgentAndSegmentParanoidAreIndependent(t *testing.T) {
	segsOff := segGoldenDir(t)
	segsOn := paranoidDesk(t)
	render := func(agent bool, segs string) *Config {
		return load(t, Options{Net: labFwd, SegmentsDir: segs, Paranoid: agent})
	}
	const agentOff = `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != @resolved_v4 counter drop`
	const agentOn = `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @resolved_v4 counter drop`
	nft := map[[2]bool]string{}
	for _, agent := range []bool{false, true} {
		for _, desk := range []bool{false, true} {
			segs := segsOff
			if desk {
				segs = segsOn
			}
			c := render(agent, segs)
			n := c.Ruleset(labElements)
			nft[[2]bool{agent, desk}] = n
			if got := strings.Contains(n, agentOn); got != agent {
				t.Errorf("agent=%v desk=%v: agent paranoid gate present=%v", agent, desk, got)
			}
			if got := strings.Contains(n, agentOff); got == agent {
				t.Errorf("agent=%v desk=%v: agent carve-out present=%v", agent, desk, got)
			}
			if !strings.Contains(n, deskWebGate+" counter drop") {
				t.Errorf("agent=%v desk=%v: the desk lost its gate", agent, desk)
			}
			env := c.EnvFile()
			wantAgent, wantDesk := "PARANOID='0'\n", "SEG_PARANOID=('off' 'off')\n"
			if agent {
				wantAgent = "PARANOID='1'\n"
			}
			if desk {
				wantDesk = "SEG_PARANOID=('on' 'off')\n"
			}
			if !strings.Contains(env, wantAgent) || !strings.Contains(env, wantDesk) {
				t.Errorf("agent=%v desk=%v: apply.env:\n%s", agent, desk, env)
			}
		}
	}
	for _, desk := range []bool{false, true} {
		for _, iface := range []string{"eth0.79", "eth2"} {
			if lines(nft[[2]bool{false, desk}], iface) != lines(nft[[2]bool{true, desk}], iface) {
				t.Errorf("the agent's PARANOID changed %s's rules (desk=%v)", iface, desk)
			}
		}
	}
	for _, agent := range []bool{false, true} {
		if nft[[2]bool{agent, false}] != nft[[2]bool{agent, true}] {
			t.Errorf("the desk's PARANOID changed the ruleset (agent=%v)", agent)
		}
	}
}
