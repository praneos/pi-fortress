//go:build vagrant

package itest

import (
	"strings"
	"testing"
	"time"
)

func stripTests(t *testing.T) {
	fake := "ghp_" + strings.Repeat("A", 36)
	pi(t, "sudo mkdir -p /var/log/pi-fortress; sudo touch /var/log/pi-fortress/strip.jsonl; sudo chown pf-broker:pf-fortress /var/log/pi-fortress/strip.jsonl 2>/dev/null || true; sudo chmod 0644 /var/log/pi-fortress/strip.jsonl; sudo truncate -s 0 /var/log/pi-fortress/strip.jsonl")

	_, _ = ssh(t, 20*time.Second, "agent", "curl -sS -o /dev/null --max-time 15 -H 'Authorization: Bearer "+fake+"' https://example.com/")
	n1 := grepCount(t, "/var/log/pi-fortress/strip.jsonl", "github_classic")
	if n1 < 1 {
		t.Fatalf("header strip count=%d", n1)
	}

	_, _ = ssh(t, 20*time.Second, "agent", `curl -sS -o /dev/null --max-time 15 -H 'Content-Type: application/json' --data-raw '{"token":"`+fake+`"}' https://example.com/`)
	n2 := grepCount(t, "/var/log/pi-fortress/strip.jsonl", "github_classic")
	if n2 <= n1 {
		t.Fatalf("body strip n1=%d n2=%d", n1, n2)
	}

	_, _ = ssh(t, 20*time.Second, "agent", "curl -sS -o /dev/null --max-time 15 'https://example.com/?k="+fake+"'")
	n3 := grepCount(t, "/var/log/pi-fortress/strip.jsonl", "github_classic")
	if n3 <= n2 {
		t.Fatalf("url strip n2=%d n3=%d", n2, n3)
	}

	_, _ = ssh(t, 20*time.Second, "agent", "curl -sS -o /dev/null --max-time 15 -H 'PRIVATE-TOKEN: "+fake+"' https://example.com/")
	n4 := grepCount(t, "/var/log/pi-fortress/strip.jsonl", "github_classic")
	if n4 <= n3 {
		t.Fatalf("any-header strip n3=%d n4=%d", n3, n4)
	}

	show := pi(t, "sudo /usr/local/sbin/pf alert show")
	if !contains(show, "github_classic") {
		t.Fatal(show)
	}
}
