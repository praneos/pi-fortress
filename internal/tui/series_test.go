package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/observe"
)

// seriesFixture is 50 house events plus two house hours: three blocks
// an hour ago, one two days back.
func seriesFixture(t *testing.T, c *admin.Config) time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	hour := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02T15") }
	evs := []string{}
	for i := 0; i < 50; i++ {
		evs = append(evs, fmt.Sprintf(`{"t":%q,"segment":"house","src":"10.78.0.101","dst":"d%d","threat":"local"}`,
			now.Add(-time.Duration(i)*time.Minute).Format("2006-01-02T15:04:05Z"), i))
	}
	body := fmt.Sprintf(`{"events":[%s],"series":{"house":[{"hour":%q,"blocked":1},{"hour":%q,"queries":12345,"flows":2,"blocked":3}]}}`,
		strings.Join(evs, ","), hour(49*time.Hour), hour(time.Hour))
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return now
}

func TestActivityBarRows(t *testing.T) {
	for _, tc := range []struct{ lang, floor, peak string }{{"en_IN.UTF-8", "▁", "█"}, {"C", "_", "#"}} {
		t.Setenv("LANG", tc.lang)
		t.Setenv("LC_ALL", "")
		c, _ := testConfig(t)
		now := seriesFixture(t, c)
		days := observe.Days(&observe.State{}, now, time.Local)["house"]
		// The Activity of each network carries its own week and no other week.
		agentView := run(t, c, NewFake(80, 24).Type(keys(netAgent, secActivity))).Last()
		last := run(t, c, NewFake(80, 24).Type(keys(netHouse, secActivity))).Last()
		screen := strings.Split(last, "\n")
		agent, house := lineWith(agentView, "agent  blocked 7d"), lineWith(last, "house  blocked 7d")
		if agent == "" || house == "" || len(screen) != 24 || strings.Contains(last, "agent  blocked") || strings.Contains(agentView, "house  blocked") {
			t.Fatalf("%s\n%s", agentView, last)
		}
		want := "agent  blocked 7d  "
		for i, d := range days {
			if i > 0 {
				want += " "
			}
			want += day(d.Day) + " " + tc.floor
		}
		want += "  max 0"
		if got := strings.TrimRight(contentOf(agent), " "); got != want {
			t.Fatalf("%q want %q", got, want)
		}
		if strings.Count(house, tc.peak) != 1 || !strings.HasSuffix(strings.TrimRight(house, " "), "max 3") {
			t.Fatalf("%q", house)
		}
		i := 0
		for screen[i] != house {
			i++
		}
		q, fl := screen[i+1], screen[i+2]
		if !strings.Contains(q, "queries") || !strings.Contains(q, " 12k") || !strings.Contains(fl, "flows") || !strings.Contains(fl, "   2") || len([]rune(q)) > 80 {
			t.Fatalf("%q\n%q", q, fl)
		}
		// 24 rows: title, sections, tabs, header, events, blank, three
		// bar rows, status.
		if n := strings.Count(last, "local"); n != 15 {
			t.Fatalf("%d event rows\n%s", n, last)
		}
	}
}

func TestBarScale(t *testing.T) {
	for _, tc := range []struct {
		v, peak uint32
		want    int
	}{{0, 0, 0}, {5, 0, 0}, {0, 9, 0}, {1, 8, 0}, {1, 3, 2}, {3, 3, 7}, {4, 8, 3}, {9, 9, 7}} {
		if got := bar(tc.v, tc.peak, 8); got != tc.want {
			t.Errorf("bar(%d,%d) = %d want %d", tc.v, tc.peak, got, tc.want)
		}
	}
	for n, want := range map[uint32]string{9999: "9999", 12345: "12k", 9999999: "9999k", 12000000: "12M"} {
		if got := compact(n); got != want {
			t.Errorf("compact(%d) = %q want %q", n, got, want)
		}
	}
}
