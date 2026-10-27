package render

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// INSPECT off, absent or explicit, renders the golden of the segments as
// it was before the key existed.
func TestInspectOffLeavesTheRulesetAlone(t *testing.T) {
	golden, err := os.ReadFile("testdata/nft.segments.golden")
	if err != nil {
		t.Fatal(err)
	}
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"INSPECT=off\n")
	c := load(t, Options{Net: lab, SegmentsDir: segs})
	if got := c.Ruleset(labElements); got != string(golden) {
		t.Fatalf("INSPECT=off drifted from the golden:\n%s", got)
	}
	if env := c.EnvFile(); !strings.Contains(env, "SEG_INSPECT=('off' 'off')\n") {
		t.Fatalf("apply.env:\n%s", env)
	}
}

func inspectedDesk(t *testing.T) *Config {
	t.Helper()
	segs := segGoldenDir(t)
	write(t, segs, "desk.env", deskEnvLines+"INSPECT=on\n")
	return load(t, Options{Net: lab, SegmentsDir: segs})
}

// The desk gets what the agent network has: 443 to the engine, the engine
// port open on its own interface, and a budget for those local flows. The
// guest next to it does not change.
func TestInspectOnSendsTheDeskToTheEngine(t *testing.T) {
	c := inspectedDesk(t)
	nft := c.Ruleset(labElements)
	for _, want := range []string{
		"    iifname \"eth0\" tcp dport 443 redirect to :8080\n    iifname \"eth0.79\" tcp dport 443 redirect to :8080\n",
		`iifname "eth0.79" tcp dport 8080 ct state new add @seg_desk_fence_conn_v4 { ip saddr ct count over 128 } jump seg_desk_fence_connlimit`,
		`iifname "eth0.79" tcp dport 8080 accept`,
		"chain seg_desk_fence_connlimit {",
		`log prefix "pi-fortress desk-connlimit: "`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	if n := strings.Count(nft, "redirect to :8080"); n != 2 {
		t.Errorf("%d redirects, want the agent and the desk", n)
	}
	if strings.Contains(nft, `iifname "eth2" tcp dport 8080`) || strings.Contains(nft, `iifname "eth2" tcp dport 443 redirect`) {
		t.Error("the guest segment got the fence")
	}
	desk := lines(nft, "eth0.79")
	accept := strings.Index(desk, "tcp dport 8080 accept")
	drop := strings.Index(desk, `log prefix "pi-fortress desk-drop: "`)
	if accept < 0 || drop < 0 || accept > drop {
		t.Errorf("the engine accept is not before the drop of the desk:\n%s", desk)
	}
	if env := c.EnvFile(); !strings.Contains(env, "SEG_INSPECT=('on' 'off')\n") {
		t.Errorf("apply.env:\n%s", env)
	}
}

func TestInspectRefusals(t *testing.T) {
	for _, tc := range []struct{ name, env, want string }{
		{"bad value", "INSPECT=yes\n", "INSPECT is not on or off"},
		{"gate turned off", "INSPECT=on\nBLOCK_DIRECT_IP=off\n", "INSPECT=on needs the resolved-address gate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs := segGoldenDir(t)
			write(t, segs, "desk.env", deskEnvLines+tc.env)
			_, err := Load(Options{Net: lab, SegmentsDir: segs})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	_, err := houseVLAN(t, "HOUSE_IF=eth2\n", "", nil, iotBase+"INSPECT=on\n")
	if err == nil || !strings.Contains(err.Error(), "INSPECT=on would let it use the credentials of the fence") || !strings.HasSuffix(err.Error(), "Nothing was changed.") {
		t.Fatalf("INSPECT=on on the house cable: %v", err)
	}
}

// The fence keeps keys off the desk. An SSH key for the Pi on that desk
// would give them back, so the render says so, and does not refuse.
func TestInspectWithAdminWarns(t *testing.T) {
	for _, tc := range []struct {
		admin string
		warn  bool
	}{{"yes", true}, {"no", false}} {
		segs := segGoldenDir(t)
		write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nINSPECT=on\nADMIN="+tc.admin+"\n")
		var stderr bytes.Buffer
		if _, err := Load(Options{Net: lab, SegmentsDir: segs, Stderr: &stderr}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(stderr.String(), "INSPECT=on and ADMIN=yes"); got != tc.warn {
			t.Errorf("ADMIN=%s: warning %v, want %v: %q", tc.admin, got, tc.warn, stderr.String())
		}
	}
}
