package admin

import (
	"strings"
	"testing"
)

// Plain segments default to the 300/600 segment total of the agent. Thus
// the seat refuses a per-device rate above 300, as render refuses it. It
// does not refuse the 300 of the agent itself.
func TestSetNetEnvSegRateAgainstAgentTotal(t *testing.T) {
	c := netConfig(t)
	if _, err := c.SetNetEnv(map[string]string{"SEG_NEW_PER_IP": "301/600"}); err == nil || !strings.Contains(err.Error(), "SEG_NEW_TOTAL") {
		t.Fatalf("SEG_NEW_PER_IP=301/600: err=%v, want one mentioning SEG_NEW_TOTAL", err)
	}
	if _, err := netConfig(t).SetNetEnv(map[string]string{"SEG_NEW_PER_IP": "300/600"}); err != nil {
		t.Fatalf("SEG_NEW_PER_IP=300/600 equals the default total: %v", err)
	}
}
