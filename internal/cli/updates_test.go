package cli

import (
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/doctor"
)

func TestDecideUpdates(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	kernel := doctor.Update{Key: "kernel:6.18.55+rpt-rpi-2712", Text: "kernel 6.18.55+rpt-rpi-2712 is installed but 6.18.50+rpt-rpi-2712 runs; reboot"}
	pkg := doctor.Update{Key: "pkg:openssl=3.5.1-1+deb13u2", Text: "openssl 3.5.1-1+deb13u2", Wait: doctor.PackageWait}

	// Nothing pending, nothing posted before: no post.
	msg, _, kept := decideUpdates(nil, parseUpdState(""), t0)
	if msg != "" {
		t.Fatalf("empty: %q", msg)
	}

	// A new kernel: post at once. The package waits.
	msg, posted, kept := decideUpdates([]doctor.Update{kernel, pkg}, kept, t0)
	if !strings.HasPrefix(msg, "UPDATES: kernel 6.18.55") || strings.Contains(msg, "openssl") {
		t.Fatalf("kernel: %q", msg)
	}
	if kept.posted != nil {
		t.Fatalf("a failed post must not record the keys: %v", kept.posted)
	}
	// The state goes through the file.
	st := parseUpdState(posted.String())

	// The same set a day later: no post.
	if msg, _, _ := decideUpdates([]doctor.Update{kernel, pkg}, st, t0.Add(24*time.Hour)); msg != "" {
		t.Fatalf("same set: %q", msg)
	}
	// After the wait, the package joins: a new set, so a post.
	msg, posted, _ = decideUpdates([]doctor.Update{kernel, pkg}, st, t0.Add(doctor.PackageWait))
	if !strings.Contains(msg, "1 automatic updates are not installed after 36h: openssl 3.5.1-1+deb13u2") {
		t.Fatalf("package: %q", msg)
	}
	st = parseUpdState(posted.String())
	// A week later with no change: a reminder.
	msg, posted, _ = decideUpdates([]doctor.Update{kernel, pkg}, st, t0.Add(doctor.PackageWait+updatesRemind))
	if !strings.HasPrefix(msg, "UPDATES (still waiting): ") {
		t.Fatalf("reminder: %q", msg)
	}
	st = parseUpdState(posted.String())
	// The reboot clears all: one post that says so, then silence.
	msg, posted, _ = decideUpdates(nil, st, t0.Add(9*24*time.Hour))
	if !strings.Contains(msg, "nothing waits now") {
		t.Fatalf("cleared: %q", msg)
	}
	if msg, _, _ := decideUpdates(nil, parseUpdState(posted.String()), t0.Add(10*24*time.Hour)); msg != "" {
		t.Fatalf("after clear: %q", msg)
	}
}

func TestDecideUpdatesFailedPostKeepsWait(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	pkg := doctor.Update{Key: "pkg:a=1", Text: "a 1", Wait: doctor.PackageWait}
	_, _, kept := decideUpdates([]doctor.Update{pkg}, parseUpdState(""), t0)
	st := parseUpdState(kept.String())
	if st.first["pkg:a=1"] != t0.Unix() {
		t.Fatalf("first seen not kept: %v", st.first)
	}
	// A package that left the list and comes back starts its wait again.
	_, _, kept = decideUpdates(nil, st, t0.Add(time.Hour))
	if _, ok := parseUpdState(kept.String()).first["pkg:a=1"]; ok {
		t.Fatal("a gone package keeps its first-seen time")
	}
}
