//go:build nfqlive

package nfq

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestLive runs against a real kernel: as root, in a temporary network
// namespace that has a dummy interface on 192.0.2.254/24 and has this
// table loaded (the script in the checklist sets it up):
//
//	table inet nfqlive {
//	  counter ok { }
//	  chain out {
//	    type filter hook output priority filter; policy accept;
//	    meta mark and 0x00f00000 == 0x00200000 counter name "ok" accept
//	    ip daddr 192.0.2.1 udp dport 9 queue num 7
//	  }
//	}
//
// The test queues a datagram to the canary, reads it back, and repeats
// it with the ok bits in its mark. The repeat must go into the ok
// counter. A verdict drops a second datagram. It must not go there.
func TestLive(t *testing.T) {
	q, err := Open(7)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	send := func(msg string) {
		c, err := net.Dial("udp4", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(msg))
	}
	got := make(chan Packet, 4)
	go func() {
		for {
			p, err := q.Recv()
			if err != nil {
				return
			}
			got <- p
		}
	}()
	recv := func() Packet {
		select {
		case p := <-got:
			return p
		case <-time.After(3 * time.Second):
			t.Fatal("nothing queued")
		}
		return Packet{}
	}
	send("repeat-me")
	p := recv()
	if len(p.Payload) < 28 || net.IP(p.Payload[16:20]).String() != "192.0.2.1" || !strings.HasSuffix(string(p.Payload), "repeat-me") {
		t.Fatalf("queued packet %x", p.Payload)
	}
	m := p.Mark | 0x00200000
	if err := q.Verdict(p.ID, Repeat, &m); err != nil {
		t.Fatal(err)
	}
	send("drop-me")
	p2 := recv()
	if err := q.Verdict(p2.ID, Drop, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	out, err := exec.Command("nft", "list", "counter", "inet", "nfqlive", "ok").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "packets 1 ") {
		t.Fatalf("the repeated packet did not come back with its mark (want exactly 1):\n%s", out)
	}
}
