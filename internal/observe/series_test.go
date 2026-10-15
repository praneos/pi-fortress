package observe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBucketPlacement(t *testing.T) {
	st := &State{}
	h0 := time.Date(2026, 9, 13, 11, 59, 59, 0, time.UTC)
	bucket(st, "house", h0).Queries++
	bucket(st, "house", h0.Add(time.Second)).Queries++
	bucket(st, "house", h0.Add(time.Second)).Flows++
	s := st.Series["house"]
	if len(s) != 2 || s[0] != (Bucket{Hour: "2026-09-13T11", Queries: 1}) || s[1] != (Bucket{Hour: "2026-09-13T12", Queries: 1, Flows: 1}) {
		t.Fatalf("%+v", s)
	}
	// A late line for an earlier hour lands in order, in its own bucket.
	bucket(st, "house", h0.Add(-3*time.Hour)).Blocked++
	bucket(st, "house", h0.Add(-3*time.Hour)).Blocked++
	if s = st.Series["house"]; len(s) != 3 || s[0] != (Bucket{Hour: "2026-09-13T08", Blocked: 2}) || s[2].Hour != "2026-09-13T12" {
		t.Fatalf("%+v", s)
	}
	// Older than the window before the newest hour: counted nowhere.
	bucket(st, "house", h0.Add(-seriesHours*time.Hour-time.Hour)).Queries++
	if s = st.Series["house"]; len(s) != 3 {
		t.Fatalf("%+v", s)
	}
	bucket(st, "", h0).Queries++
	if _, ok := st.Series[""]; ok || len(st.Series) != 1 {
		t.Fatalf("%v", st.Series)
	}
	// In a local zone the key is still the UTC hour.
	st = &State{}
	bucket(st, "agent", h0.In(time.FixedZone("x", 5*3600+1800)))
	if st.Series["agent"][0].Hour != "2026-09-13T11" {
		t.Fatal(st.Series)
	}
}

func TestSeriesCapAndExpiry(t *testing.T) {
	st := &State{}
	h0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < seriesHours+5; i++ {
		bucket(st, "agent", h0.Add(time.Duration(i)*time.Hour)).Queries++
	}
	s := st.Series["agent"]
	if len(s) != seriesHours || s[0].Hour != h0.Add(5*time.Hour).Format(hourKey) {
		t.Fatalf("%d %s", len(s), s[0].Hour)
	}
	// Full and contiguous: an older hour inside the window goes in, and
	// then the limit pushes it out. Thus it counts against nothing.
	bucket(st, "agent", h0.Add(4*time.Hour)).Queries++
	if s = st.Series["agent"]; len(s) != seriesHours || s[0].Hour != h0.Add(5*time.Hour).Format(hourKey) || s[0].Queries != 1 {
		t.Fatalf("%d %+v", len(s), s[0])
	}
	st.Series["house"] = []Bucket{{Hour: "2026-08-01T00"}}
	expireSeries(st, h0.Add((seriesHours+10)*time.Hour))
	if s = st.Series["agent"]; len(s) != seriesHours-5 || s[0].Hour != h0.Add(10*time.Hour).Format(hourKey) {
		t.Fatalf("%d %s", len(s), s[0].Hour)
	}
	if _, ok := st.Series["house"]; ok {
		t.Fatal("empty segment kept")
	}
}

func TestSeriesCountedAtSourceAndLoaded(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	o := &Observer{Now: func() time.Time { return now }, StatePath: filepath.Join(dir, "observe.json")}
	if err := os.WriteFile(o.StatePath, []byte(`{"dns":{},"flows":{},"started":"2026-09-13T00:00:00Z"}`), 0644); err != nil {
		t.Fatal(err)
	}
	st := o.Load()
	if st.Series == nil || len(st.Series) != 0 {
		t.Fatalf("%v", st.Series)
	}
	o.touchDNSSeg(st, "house", "ads.example", "10.78.0.5", "A", true)
	o.touchDNSSeg(st, "house", "ok.example", "10.78.0.5", "A", false)
	o.touchFlow(st, "", "10.77.0.10", "1.2.3.4", 443, "tcp", 10, true)
	o.touchFlow(st, "", "10.77.0.10", "1.2.3.4", 443, "tcp", 20, false)
	o.event(st, Event{T: now.Add(-time.Hour), Segment: "agent", Threat: "credential_strip"})
	if s := st.Series["house"]; len(s) != 1 || s[0] != (Bucket{Hour: "2026-09-13T12", Queries: 2, Blocked: 1}) {
		t.Fatalf("%+v", s)
	}
	if s := st.Series["agent"]; len(s) != 2 || s[0] != (Bucket{Hour: "2026-09-13T11", Blocked: 1}) || s[1] != (Bucket{Hour: "2026-09-13T12", Flows: 1}) {
		t.Fatalf("%+v", s)
	}
	if err := o.Save(st); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.StatePath)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m["series"] == nil {
		t.Fatalf("%v %s", err, raw)
	}
	if again := o.Load(); len(again.Series["agent"]) != 2 || again.Series["house"][0].Queries != 2 {
		t.Fatalf("%v", again.Series)
	}
	var out bytes.Buffer
	o.Stdout = &out
	o.Show(st)
	days := Days(st, now, time.Local)["house"]
	if want := "  " + days[6].Day + " house q=2 f=0 b=1\n"; !strings.Contains(out.String(), "SERIES 7d") || strings.Count(out.String(), " house q=") != 7 || !strings.Contains(out.String(), want) {
		t.Fatalf("%s", out.String())
	}
}

func TestDaysRollupLocal(t *testing.T) {
	loc := time.FixedZone("ist", 5*3600+1800)
	st := &State{Series: map[string][]Bucket{"agent": {
		{Hour: "2026-09-12T18", Blocked: 1},
		{Hour: "2026-09-12T19", Blocked: 2, Queries: 5},
		{Hour: "2026-09-01T00", Blocked: 99},
	}}}
	d := Days(st, time.Date(2026, 9, 13, 3, 0, 0, 0, time.UTC), loc)
	a, h := d["agent"], d["house"]
	if len(a) != 7 || len(h) != 7 || a[0].Day != "09-07" || h[6] != (Day{Day: "09-13"}) {
		t.Fatalf("%+v %+v", a, h)
	}
	if a[5] != (Day{Day: "09-12", Blocked: 1}) || a[6] != (Day{Day: "09-13", Blocked: 2, Queries: 5}) {
		t.Fatalf("%+v", a)
	}
}

func TestSaveKeepsStatePrivate(t *testing.T) {
	dir := t.TempDir()
	o := &Observer{StatePath: filepath.Join(dir, "observe.json")}
	if err := os.WriteFile(o.StatePath, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := o.Save(o.Load()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Fatalf("observe.json mode %v, want 0640 whatever the umask", st.Mode().Perm())
	}
}
