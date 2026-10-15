package alert

import (
	"fmt"
	"testing"
	"time"
)

func TestDebounce(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := Debounce{Window: 10 * time.Second, Now: func() time.Time { return now }}
	if !d.OK("", "r", "h", "example.com") {
		t.Fatal("first")
	}
	if d.OK("", "r", "h", "example.com") {
		t.Fatal("debounced")
	}
	if !d.OK("", "r", "h", "other.com") {
		t.Fatal("other host")
	}
	now = now.Add(11 * time.Second)
	if !d.OK("", "r", "h", "example.com") {
		t.Fatal("after window")
	}
}

func TestDebounceRemembersInterleavedIncidents(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := Debounce{Window: 10 * time.Second, Now: func() time.Time { return now }}
	if !d.OK("", "r", "h", "a.example") {
		t.Fatal("first a")
	}
	if !d.OK("", "r", "h", "b.example") {
		t.Fatal("first b")
	}
	now = now.Add(time.Second)
	if d.OK("", "r", "h", "a.example") {
		t.Fatal("a posted twice inside its window because b evicted it")
	}
	if d.OK("", "r", "h", "b.example") {
		t.Fatal("b posted twice inside its window because a evicted it")
	}
}

func TestDebounceSeparatesCanaryFromOrdinary(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := Debounce{Window: 10 * time.Second, Now: func() time.Time { return now }}
	if !d.OK("", "", "header", "evil.example") {
		t.Fatal("ordinary refusal")
	}
	if !d.OK("canary", "", "header", "evil.example") {
		t.Fatal("canary suppressed by an ordinary refusal it shares a key with")
	}
}

func TestDebounceTableIsBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := Debounce{Window: 10 * time.Second, Now: func() time.Time { return now }}
	for i := range debounceMax * 4 {
		now = now.Add(time.Millisecond)
		d.OK("", "r", "h", fmt.Sprintf("h%d.example", i))
	}
	if len(d.at) > debounceMax {
		t.Fatalf("debounce table grew to %d, past the %d cap", len(d.at), debounceMax)
	}
}
