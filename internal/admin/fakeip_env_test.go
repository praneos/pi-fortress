package admin

import (
	"os"
	"strings"
	"testing"
)

// AGENT_DNS and FAKEIP_NET go through the seat as the DoT keys do. The
// validator refuses what render cannot parse. Render refuses a pool that
// collides with a network that the Pi is on. A refused edit does not write
// net.env.local.
func TestSetNetEnvFakeIPKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		kv   map[string]string
		want string
	}{
		{"mode", map[string]string{"AGENT_DNS": "fake"}, "AGENT_DNS: want forward or fakeip"},
		{"pool not a prefix", map[string]string{"FAKEIP_NET": "198.18.0.0"}, "FAKEIP_NET: is not an IPv4 CIDR"},
		{"pool too small", map[string]string{"FAKEIP_NET": "198.18.0.0/25"}, "is a /25"},
		{"pool too large", map[string]string{"FAKEIP_NET": "198.18.0.0/15"}, "is a /15"},
		{"pool public", map[string]string{"FAKEIP_NET": "8.8.0.0/16"}, "is not inside"},
		{"pool on the agents", map[string]string{"AGENT_DNS": "fakeip", "FAKEIP_NET": "10.77.0.0/16"}, "overlaps AGENT_NET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := netConfig(t)
			_, err := c.SetNetEnv(tc.kv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want one mentioning %q", err, tc.want)
			}
			if _, err := os.Stat(c.NetEnvLocal); err == nil {
				t.Fatal("a refused edit wrote the overlay anyway")
			}
		})
	}
	c := netConfig(t)
	if warn, err := c.SetNetEnv(map[string]string{"AGENT_DNS": "fakeip", "FAKEIP_NET": "100.64.0.0/16"}); err != nil || warn != "" {
		t.Fatalf("warn=%q err=%v", warn, err)
	}
	if c.Net["AGENT_DNS"] != "fakeip" || c.Net["FAKEIP_NET"] != "100.64.0.0/16" {
		t.Fatalf("the overlay does not read back: %+v", c.Net)
	}
}
