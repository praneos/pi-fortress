package admin

import (
	"strings"
	"testing"
)

const segDestState = `{"dns":{},"flows":{},"dests":{
"desk":{
"api.example.com:443/tcp":{"first_seen":"2026-10-04T10:00:00Z","last_seen":"2026-10-04T10:05:00Z","src":"10.79.0.2","dst":"93.184.216.34","name":"api.example.com","dport":443,"proto":"tcp"},
"203.0.113.9:22/tcp":{"first_seen":"2026-10-04T10:01:00Z","last_seen":"2026-10-04T10:01:00Z","src":"10.79.0.2","dst":"203.0.113.9","dport":22,"proto":"tcp"}},
"lab":{
"198.51.100.1:443/tcp":{"first_seen":"2026-10-04T10:02:00Z","last_seen":"2026-10-04T10:02:00Z","src":"10.80.0.2","dst":"198.51.100.1","dport":443,"proto":"tcp"}}},
"started":"2026-10-04T09:00:00Z"}`

// If a request for the first-seen log gives the name of a plain segment,
// the log is the new destinations of that segment, oldest first, with name
// and address. Without a name, the log is the log of the agent, as before.
func TestSegmentFirstSeen(t *testing.T) {
	c := testConfig(t)
	write(t, c.ObservePath, segDestState)
	v, err := c.Call(RoleAdmin, "logs", Args{Log: LogFirstSeen, N: 10, Name: "desk"})
	if err != nil {
		t.Fatal(err)
	}
	lines := v.([]string)
	if len(lines) != 2 || !strings.Contains(lines[0], "api.example.com (93.184.216.34):443/tcp") || !strings.Contains(lines[1], "203.0.113.9:22/tcp") {
		t.Fatalf("desk %q", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "198.51.100.1") {
			t.Fatalf("another segment's row: %q", l)
		}
	}
	if v, _ := c.Call(RoleAdmin, "logs", Args{Log: LogFirstSeen, N: 1, Name: "desk"}); len(v.([]string)) != 1 || !strings.Contains(v.([]string)[0], "203.0.113.9") {
		t.Fatalf("newest one: %q", v)
	}
	agent, err := c.Call(RoleAdmin, "logs", Args{Log: LogFirstSeen, N: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.([]string)) != 0 {
		t.Fatalf("the agent's first-seen log took plain-segment rows: %q", agent)
	}
}
