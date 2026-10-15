package alert

import (
	"strings"
	"testing"
	"time"
)

// A canary row is posted each time, also when the same canary row came
// in the debounce window.
func TestCanaryRepeatIsPostedInDebounceWindow(t *testing.T) {
	r := newCapRig(t)
	r.strips(t, 0, 1, "canary")
	r.strips(t, 0, 1, "canary")
	r.strips(t, 0, 1, "")
	r.strips(t, 0, 1, "")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 3 || !strings.HasPrefix(posts[0], "CANARY ") || !strings.HasPrefix(posts[1], "CANARY ") || strings.HasPrefix(posts[2], "CANARY ") {
		t.Fatalf("posts %q; want two canary posts and one strip post", posts)
	}
}

func queueCanaries(q []pending) int {
	n := 0
	for _, p := range q {
		if p.canary {
			n++
		}
	}
	return n
}

// A canary post stays in a full queue that has no ordinary post. Overflow
// drops a key post before a canary post.
func TestQueueOverflowKeepsCanaryBeforeKeyPosts(t *testing.T) {
	a := &Alerter{Now: func() time.Time { return time.Unix(1700000000, 0) }}
	a.enqueue(pending{msg: "canary", kind: "canary", keep: true, canary: true})
	for range queueMax - 1 {
		a.enqueue(pending{msg: "key", kind: "dns_key", keep: true})
	}
	a.enqueue(pending{msg: "key2", kind: "dns_key", keep: true})
	a.enqueue(pending{msg: "tunnel", kind: "dns_tunnel"})
	if len(a.queue) != queueMax || a.queue[0].msg != "canary" {
		t.Fatalf("queue %d head %q", len(a.queue), a.queue[0].msg)
	}
	if a.cap.suppressed != 2 || a.cap.by["dns_key"] != 2 {
		t.Fatalf("drop not counted: %+v", a.cap)
	}
}

// When the queue holds canary posts only, a new post that is not a canary
// goes to the summary count. No canary post goes. A new canary post
// replaces the oldest canary post, and the summary counts that one. The
// queue never grows above queueMax.
func TestQueueFullOfCanariesStaysBounded(t *testing.T) {
	a := &Alerter{Now: func() time.Time { return time.Unix(1700000000, 0) }}
	for i := range queueMax {
		a.enqueue(pending{msg: "canary" + string(rune('a'+i%26)), kind: "canary", keep: true, canary: true})
	}
	first := a.queue[0].id
	a.enqueue(pending{msg: "key", kind: "dns_key", keep: true})
	a.enqueue(pending{msg: "tunnel", kind: "dns_tunnel"})
	if len(a.queue) != queueMax || queueCanaries(a.queue) != queueMax || a.queue[0].id != first {
		t.Fatalf("queue %d canaries %d head %d", len(a.queue), queueCanaries(a.queue), a.queue[0].id)
	}
	if a.cap.suppressed != 2 || a.cap.by["dns_key"] != 1 || a.cap.by["dns_tunnel"] != 1 {
		t.Fatalf("drop not counted: %+v", a.cap)
	}
	a.enqueue(pending{msg: "new canary", kind: "canary", keep: true, canary: true})
	if len(a.queue) != queueMax || a.queue[0].id == first || a.queue[len(a.queue)-1].msg != "new canary" {
		t.Fatalf("queue %d head %d tail %q", len(a.queue), a.queue[0].id, a.queue[len(a.queue)-1].msg)
	}
	if a.cap.suppressed != 3 || a.cap.by["canary"] != 1 || a.cap.start.IsZero() {
		t.Fatalf("drop not counted: %+v", a.cap)
	}
}
