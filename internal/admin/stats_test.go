package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/observe"
)

func TestStatsFromState(t *testing.T) {
	names := map[string]uint32{}
	for i := 0; i < 30; i++ {
		names[fmt.Sprintf("n%02d.example", i)] = uint32(i)
	}
	t0 := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	st := &observe.State{
		Clients: map[string]*observe.Client{
			"house/10.78.0.101": {Segment: "house", IP: "10.78.0.101", MAC: "aa:bb:cc:dd:ee:02", Name: "phone",
				LastSeen: "2026-09-13T10:00:00Z", Queries: 5, Flows: 2, Blocked: 1, Names: names,
				Dests: map[string]uint32{"1.2.3.4:443": 2, "5.6.7.8:53": 9}},
			"agent/10.77.0.10":  {Segment: "agent", IP: "10.77.0.10", LastSeen: "bad", Queries: 7},
			"house/10.78.0.102": {Segment: "house", IP: "10.78.0.102", Queries: 5},
		},
	}
	for i := 0; i < 250; i++ {
		st.Events = append(st.Events, observe.Event{T: t0.Add(time.Duration(i) * time.Second), Segment: "house",
			Src: "10.78.0.101", Dst: fmt.Sprintf("d%d", i), Threat: "local"})
	}
	st.Events = append(st.Events, observe.Event{T: t0.Add(time.Hour), Segment: "agent", Src: "10.77.0.10", Dst: "x", Threat: "credential_strip", Detail: "r1"})

	s := statsFrom(st)
	ips := []string{}
	for _, c := range s.Clients {
		ips = append(ips, c.IP)
	}
	if fmt.Sprint(ips) != "[10.77.0.10 10.78.0.101 10.78.0.102]" {
		t.Fatal(ips)
	}
	ph := s.Clients[1]
	if !ph.LastSeen.Equal(t0) || len(ph.TopNames) != statsTop || ph.TopNames[0].Name != "n29.example" || ph.TopNames[19].Count != 10 {
		t.Fatalf("%+v", ph.TopNames)
	}
	if fmt.Sprint(ph.TopDests) != "[{5.6.7.8:53 9} {1.2.3.4:443 2}]" {
		t.Fatal(ph.TopDests)
	}
	if !s.Clients[0].LastSeen.IsZero() || s.Clients[0].TopNames == nil {
		t.Fatal(s.Clients[0])
	}
	if len(s.Events) != statsEvents || s.Events[0].Threat != "credential_strip" || s.Events[0].Name != "" || s.Events[0].Detail != "r1" || s.Events[0].Hits != 1 {
		t.Fatalf("%d %+v", len(s.Events), s.Events[0])
	}
	if e := s.Events[1]; e.Dst != "d249" || e.Name != "phone" || !e.T.After(s.Events[2].T) {
		t.Fatalf("%+v", e)
	}

	raw, err := json.Marshal(statsFrom(&observe.State{}))
	if err != nil || !strings.HasPrefix(string(raw), `{"clients":[],"events":[],"series":{"agent":[{"day":"`) ||
		strings.Count(string(raw), `"day"`) != 14 || !strings.Contains(string(raw), `"house":[{"day":"`) {
		t.Fatal(string(raw), err)
	}
	var m map[string]any
	raw, _ = json.Marshal(s)
	_ = json.Unmarshal(raw, &m)
	c0 := m["clients"].([]any)[1].(map[string]any)
	for _, k := range []string{"segment", "ip", "mac", "name", "queries", "flows", "blocked", "last_seen", "top_names", "top_dests"} {
		if _, ok := c0[k]; !ok {
			t.Fatal("missing", k)
		}
	}
	e0 := m["events"].([]any)[0].(map[string]any)
	for _, k := range []string{"t", "segment", "src", "name", "dst", "threat", "detail"} {
		if _, ok := e0[k]; !ok {
			t.Fatal("missing", k)
		}
	}
}

// TestStatsSeriesLocalDays rolls UTC hours into Kolkata days. 18:30Z is
// already the next day there. A day with no hours is a zero row. A segment
// with no hours still gets its seven rows.
func TestStatsSeriesLocalDays(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Skip(err)
	}
	st := &observe.State{Series: map[string][]observe.Bucket{"house": {
		{Hour: "2026-09-06T10", Queries: 1},
		{Hour: "2026-09-10T18", Queries: 2, Flows: 1, Blocked: 1},
		{Hour: "2026-09-10T19", Queries: 4, Blocked: 2},
		{Hour: "2026-09-12T18", Queries: 8},
		{Hour: "2026-09-12T19", Queries: 16, Flows: 3, Blocked: 4},
		{Hour: "2026-09-13T05", Queries: 32, Blocked: 8},
	}}}
	s := statsAt(st, time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC), loc)
	got, _ := json.Marshal(s.Series["house"])
	want := `[{"day":"09-07","queries":0,"flows":0,"blocked":0},{"day":"09-08","queries":0,"flows":0,"blocked":0},` +
		`{"day":"09-09","queries":0,"flows":0,"blocked":0},{"day":"09-10","queries":2,"flows":1,"blocked":1},` +
		`{"day":"09-11","queries":4,"flows":0,"blocked":2},{"day":"09-12","queries":8,"flows":0,"blocked":0},` +
		`{"day":"09-13","queries":48,"flows":3,"blocked":12}]`
	if string(got) != want {
		t.Fatalf("%s\nwant %s", got, want)
	}
	if a := s.Series["agent"]; len(a) != 7 || a[0].Day != "09-07" || a[6] != (observe.Day{Day: "09-13"}) {
		t.Fatalf("%+v", a)
	}
}

func TestStatsVerbReadsObserveFile(t *testing.T) {
	c := testConfig(t)
	write(t, c.ObservePath, `{"clients":{"house/10.78.0.20":{"segment":"house","ip":"10.78.0.20","name":"mac","queries":3,"last_seen":"2026-01-01T00:00:00Z"}}}`)
	v, err := c.Call(RoleOperator, "stats", Args{})
	if err != nil {
		t.Fatal(err)
	}
	s := v.(Stats)
	if len(s.Clients) != 1 || s.Clients[0].Name != "mac" || len(s.Events) != 0 {
		t.Fatalf("%+v", s)
	}
	write(t, c.ObservePath, "not json")
	if v, err := c.Call(RoleAdmin, "stats", Args{}); err != nil || len(v.(Stats).Clients) != 0 {
		t.Fatal(v, err)
	}
}

// Before plain segments had a resolver, all rows not from the house were
// from the agent, and Device split the DNS rows two ways on that basis.
// Now the desk resolves through this box. Thus that else-branch reported a
// desk lookup as an agent lookup. Also, through the source set behind
// AgentIP, it could show the address of a desk client as the address of
// the agent. A number that looks right is worse than a missing number.
func TestAPlainSegmentIsNotCountedAsTheAgent(t *testing.T) {
	st := &observe.State{DNS: map[string]*observe.DNSRec{
		"example.com":     {Segment: "", Src: "10.77.0.10", Count: 3},
		"house/h.example": {Segment: "house", Src: "10.78.0.20", Count: 4},
		"desk/d.example":  {Segment: "desk", Src: "10.79.0.2", Count: 5},
		"guest/g.example": {Segment: "guest", Src: "10.80.0.9", Count: 6},
	}}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "observe.json")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	c := &Config{ObservePath: path}
	d := c.Device()
	if d.DNSNames != 1 || d.DNSQueries != 3 {
		t.Errorf("agent counters took another segment's rows: names=%d queries=%d, want 1 and 3", d.DNSNames, d.DNSQueries)
	}
	if d.HouseNames != 1 {
		t.Errorf("house names = %d, want 1", d.HouseNames)
	}
	// 10.79.0.2 sorts below 10.80.0.9 and would win the lowest-address pick.
	// Thus this assertion catches a desk client that shows as the agent.
	if d.AgentIP == "10.79.0.2" || d.AgentIP == "10.80.0.9" {
		t.Errorf("AgentIP is a plain segment's client: %s", d.AgentIP)
	}
}
