package alert

import (
	"strings"
	"testing"
	"time"
)

func TestParseWGShow(t *testing.T) {
	st := ParseWGShow("pubkey\t1757280000\n", "pubkey\t146.70.1.2:51820\n")
	if st.Never || st.Handshake.Unix() != 1757280000 || st.Endpoint != "146.70.1.2:51820" {
		t.Fatalf("%+v", st)
	}
	st = ParseWGShow("pubkey\t0\n", "pubkey\t146.70.1.2:51820\n")
	if !st.Never || st.Endpoint != "146.70.1.2:51820" {
		t.Fatalf("never: %+v", st)
	}
}

func TestWGTransition(t *testing.T) {
	now := time.Unix(1757280000, 0)
	max := 3 * time.Minute
	fresh := WGStatus{Handshake: now.Add(-30 * time.Second), Endpoint: "146.70.1.2:51820"}
	stale := WGStatus{Handshake: now.Add(-4 * time.Minute), Endpoint: "146.70.1.2:51820"}
	never := WGStatus{Never: true, Endpoint: "146.70.1.2:51820"}

	_, msg, write := WGTransition("wg0", "", fresh, now, max)
	if msg != "" || write != "up\n" {
		t.Fatalf("healthy boot: msg=%q write=%q", msg, write)
	}

	_, msg, write = WGTransition("wg0", "", never, now, max)
	if !strings.Contains(msg, "no handshake ever") || !strings.HasPrefix(write, "down ") {
		t.Fatalf("dead boot: msg=%q write=%q", msg, write)
	}

	_, msg, write = WGTransition("wg0", "up\n", stale, now, max)
	if !strings.Contains(msg, "no handshake for 4m0s") || !strings.Contains(msg, "146.70.1.2:51820") {
		t.Fatalf("down: msg=%q", msg)
	}
	if !strings.HasPrefix(write, "down ") {
		t.Fatalf("write=%q", write)
	}

	_, msg, _ = WGTransition("wg0", "up\n", fresh, now, max)
	if msg != "" {
		t.Fatalf("still up: %q", msg)
	}

	downAt := now.Add(-9 * time.Minute)
	_, msg, write = WGTransition("wg0", FormatWGLast("down", downAt), fresh, now, max)
	if msg != "WG wg0 handshake back after 9m0s" || write != "up\n" {
		t.Fatalf("recovery: msg=%q write=%q", msg, write)
	}

	_, msg, write = WGTransition("wg0", "down 1\n", stale, now, max)
	if msg != "" || write != "" {
		t.Fatalf("still down: msg=%q write=%q", msg, write)
	}
}

// A config with two peers. The tunnel is up if either peer has a recent
// handshake, whichever line wg prints first. The endpoint named is the
// endpoint of the live peer.
func TestParseWGShowTwoPeers(t *testing.T) {
	eps := "peerA\t146.70.1.2:51820\npeerB\t[2001:db8::7]:51820\n"
	for _, latest := range []string{
		"peerA\t0\npeerB\t1757280000\n",
		"peerB\t1757280000\npeerA\t0\n",
	} {
		st := ParseWGShow(latest, eps)
		if st.Never || st.Handshake.Unix() != 1757280000 || st.Endpoint != "[2001:db8::7]:51820" {
			t.Fatalf("latest %q: %+v", latest, st)
		}
	}
	for _, latest := range []string{
		"peerA\t1757270000\npeerB\t1757280000\n",
		"peerB\t1757280000\npeerA\t1757270000\n",
	} {
		st := ParseWGShow(latest, eps)
		if st.Handshake.Unix() != 1757280000 || st.Endpoint != "[2001:db8::7]:51820" {
			t.Fatalf("latest %q: %+v", latest, st)
		}
	}
	st := ParseWGShow("peerA\t0\npeerB\t0\n", "peerA\t(none)\npeerB\t146.70.1.2:51820\n")
	if !st.Never || st.Endpoint != "146.70.1.2:51820" {
		t.Fatalf("no handshake anywhere: %+v", st)
	}
	if st := ParseWGShow("", ""); !st.Never {
		t.Fatalf("empty: %+v", st)
	}
}
