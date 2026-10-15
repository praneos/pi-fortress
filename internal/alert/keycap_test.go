package alert

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Junk tunnel notices spend the general budget. A leaked key, a marked
// refusal and a key in a DNS name still post on their own budget. The
// summary names what was suppressed.
func TestKeyAlertsHaveTheirOwnCap(t *testing.T) {
	r := newCapRig(t)
	r.a.CapPosts = 3
	r.strips(t, 0, 5, "dns_tunnel")
	f, err := os.OpenFile(r.log, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		`{"ev":"strip","rule":"secret:d0d1_OPENAI","where":"body","host":"k1.example"}`,
		`{"ev":"substitution_refused","cause":"slot_unknown","slot":"d0","kind":"OPENAI","host":"k2.example","where":"header","alert":true}`,
		`{"threat":"dns_key","where":"agent","client_ip":"10.77.0.10","host":"k3.example","detail":"refused"}`,
		`{"ev":"strip","rule":"secret:d0d1_OPENAI","where":"body","host":"k4.example"}`,
	} {
		fmt.Fprintln(f, row)
	}
	_ = f.Close()
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 6 {
		t.Fatalf("posts %q; want three tunnel notices and three key alerts", posts)
	}
	for i, want := range []string{"k1.example", "k2.example", "k3.example"} {
		if !strings.Contains(posts[3+i], want) {
			t.Fatalf("post %d %q, want %s", 3+i, posts[3+i], want)
		}
	}
	r.now = r.now.Add(capWindow + time.Second)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts = r.got()
	sum := posts[len(posts)-1]
	if len(posts) != 7 || !strings.Contains(sum, "3 alerts suppressed") || !strings.Contains(sum, "dns_tunnel 2") || !strings.Contains(sum, "strip 1") {
		t.Fatalf("summary %q", sum)
	}
}
