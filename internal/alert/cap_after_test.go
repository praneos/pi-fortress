package alert

import (
	"reflect"
	"testing"
	"time"
)

func TestCapAfterKeepsWhatArrivedDuringTheSummary(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cur := webhookCap{start: now.Add(-time.Hour), posted: 9, keyPosted: 4, suppressed: 5, by: map[string]int{"a": 3, "b": 1}}
	snap := webhookCap{suppressed: 2, by: map[string]int{"a": 1, "b": 1}}
	want := webhookCap{start: now, posted: 1, suppressed: 3, by: map[string]int{"a": 2}}
	if got := cur.after(snap, now); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got := cur.after(cur, now); got.by != nil || got.suppressed != 0 || got.posted != 1 {
		t.Fatalf("got %+v", got)
	}
}
