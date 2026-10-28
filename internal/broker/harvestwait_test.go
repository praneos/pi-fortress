package broker

import (
	"testing"
	"time"
)

// A stop waits for a token refresh in flight, and for max at most.
func TestWaitHarvests(t *testing.T) {
	b := &Broker{}
	if !b.WaitHarvests(0) {
		t.Fatal("no refresh in flight, but the wait says one is left")
	}
	b.harvesting.Add(1)
	start := time.Now()
	if b.WaitHarvests(50 * time.Millisecond) {
		t.Fatal("a refresh in flight, but the wait says none is left")
	}
	if d := time.Since(start); d < 50*time.Millisecond || d > 2*time.Second {
		t.Fatalf("the wait took %v, not its max", d)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		b.harvesting.Add(-1)
	}()
	if !b.WaitHarvests(5 * time.Second) {
		t.Fatal("the refresh ended, but the wait gave up")
	}
}
