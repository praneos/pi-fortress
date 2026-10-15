package observe

import (
	"slices"
	"testing"
)

// prune drops the oldest entries first, ties by key, and returns them in
// that order.
func TestPruneOrder(t *testing.T) {
	table := map[string]string{"e": "3", "d": "1", "c": "2", "b": "1", "a": "4"}
	dropped := prune(table, 2, func(v string) string { return v })
	if want := []string{"b", "d", "c"}; !slices.Equal(dropped, want) {
		t.Fatalf("dropped %v, want %v", dropped, want)
	}
	if len(table) != 2 || table["a"] != "4" || table["e"] != "3" {
		t.Fatalf("table %v", table)
	}
	if got := prune(table, 2, func(v string) string { return v }); got != nil {
		t.Fatalf("a table at its limit dropped %v", got)
	}
}
