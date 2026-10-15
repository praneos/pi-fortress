package admin

import (
	"sort"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/observe"
)

const (
	statsTop    = 20
	statsEvents = 200
)

type NameCount struct {
	Name  string `json:"name"`
	Count uint32 `json:"count"`
}

type DestCount struct {
	Dest  string `json:"dest"`
	Count uint32 `json:"count"`
}

type ClientStat struct {
	Segment  string      `json:"segment"`
	IP       string      `json:"ip"`
	MAC      string      `json:"mac"`
	Name     string      `json:"name"`
	Queries  uint32      `json:"queries"`
	Flows    uint32      `json:"flows"`
	Blocked  uint32      `json:"blocked"`
	LastSeen time.Time   `json:"last_seen"`
	TopNames []NameCount `json:"top_names"`
	TopDests []DestCount `json:"top_dests"`
}

// EventStat is an observe.Event with the client's name joined in.
type EventStat struct {
	T       time.Time `json:"t"`
	Segment string    `json:"segment"`
	Src     string    `json:"src"`
	Name    string    `json:"name"`
	Dst     string    `json:"dst"`
	Threat  string    `json:"threat"`
	Detail  string    `json:"detail"`
	Hits    uint32    `json:"hits"`
	// Alert is a row that the Pi only saw, and did not stop. It goes on the
	// same ring. Thus a screen that shows them together must say which is
	// which. If not, it credits the box with a claim that it never refused.
	Alert bool `json:"alert,omitempty"`
}

// Stats is the per-device model,
// read from observe.json as last flushed: clients by queries desc,
// events newest first, series as seven local days per segment.
type Stats struct {
	Clients []ClientStat             `json:"clients"`
	Events  []EventStat              `json:"events"`
	Series  map[string][]observe.Day `json:"series"`
}

func (c *Config) Stats() Stats {
	return statsFrom(loadObserve(c.ObservePath))
}

func statsFrom(st *observe.State) Stats {
	return statsAt(st, time.Now(), time.Local)
}

func statsAt(st *observe.State, now time.Time, loc *time.Location) Stats {
	out := Stats{Clients: []ClientStat{}, Events: []EventStat{}, Series: observe.Days(st, now, loc)}
	names := map[string]string{}
	for key, cl := range st.Clients {
		if cl == nil {
			continue
		}
		last, _ := base.ParseISO(cl.LastSeen)
		cs := ClientStat{Segment: cl.Segment, IP: Printable(cl.IP), MAC: Printable(cl.MAC), Name: Printable(cl.Name),
			Queries: cl.Queries, Flows: cl.Flows, Blocked: cl.Blocked, LastSeen: last,
			TopNames: []NameCount{}, TopDests: []DestCount{}}
		for _, kv := range top(cl.Names) {
			cs.TopNames = append(cs.TopNames, NameCount{Printable(kv.k), kv.n})
		}
		for _, kv := range top(cl.Dests) {
			cs.TopDests = append(cs.TopDests, DestCount{Printable(kv.k), kv.n})
		}
		out.Clients = append(out.Clients, cs)
		if cl.Name != "" {
			names[key] = Printable(cl.Name)
		}
	}
	sort.Slice(out.Clients, func(i, j int) bool {
		a, b := out.Clients[i], out.Clients[j]
		if a.Queries != b.Queries {
			return a.Queries > b.Queries
		}
		if a.Segment != b.Segment {
			return a.Segment < b.Segment
		}
		return a.IP < b.IP
	})
	for i := len(st.Events) - 1; i >= 0 && len(out.Events) < statsEvents; i-- {
		ev := st.Events[i]
		out.Events = append(out.Events, EventStat{T: ev.T, Segment: ev.Segment, Src: Printable(ev.Src),
			Name: names[ev.Segment+"/"+ev.Src], Dst: Printable(ev.Dst), Threat: Printable(ev.Threat), Detail: Printable(ev.Detail),
			Hits: ev.Hits(), Alert: ev.Alert()})
	}
	return out
}

type kv struct {
	k string
	n uint32
}

// top orders by count desc then key, and keeps statsTop.
func top(m map[string]uint32) []kv {
	out := make([]kv, 0, len(m))
	for k, n := range m {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	if len(out) > statsTop {
		out = out[:statsTop]
	}
	return out
}
