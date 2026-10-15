package admin

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"pi-fortress/internal/secrets"
)

// fakeBroker answers one line to each request. It stands in for the
// root-only admin socket of the broker.
func fakeBroker(t *testing.T, reply string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte(reply + "\n"))
			c.Close()
		}
	}()
	return sock
}

func TestSlotHours(t *testing.T) {
	c := &Config{BrokerAdmin: fakeBroker(t, "a1b2 12 3456 c3d4 1 0")}
	got, err := c.SlotHours(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got["a1b2"] != (SlotHour{Requests: 12, Bytes: 3456}) || got["c3d4"] != (SlotHour{Requests: 1}) {
		t.Fatalf("%+v", got)
	}
	// Nothing spent is an empty line, not an error.
	empty := &Config{BrokerAdmin: fakeBroker(t, "")}
	if got, err := empty.SlotHours(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

// A broker that does not run has no hour to give. The slot list must say
// this, and not show all slots as idle. An operator who reads zero there no
// longer watches. The list itself still comes, because the code reads it
// from the store, and the store is on disk.
func TestSlotsWithoutABroker(t *testing.T) {
	c := testConfig(t)
	c.BrokerAdmin = filepath.Join(t.TempDir(), "nothing.sock")
	if _, err := c.SlotHours(context.Background()); err == nil {
		t.Fatal("a missing socket answered")
	}
	write(t, c.SecretsPath, secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN")+"=lab_fence_github\n")
	slots, err := c.Slots()
	if err != nil || len(slots) != 1 {
		t.Fatalf("%+v %v", slots, err)
	}
	if slots[0].HourKnown {
		t.Fatalf("a dead broker reported an hour: %+v", slots[0])
	}
}

// With the broker up, the hour goes on the slot that the store listed.
func TestSlotsCarryTheHour(t *testing.T) {
	c := testConfig(t)
	c.BrokerAdmin = fakeBroker(t, "a1b2c3d4e5f67890 12 3456")
	write(t, c.SecretsPath, secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN")+"=lab_fence_github\n")
	slots, err := c.Slots()
	if err != nil || len(slots) != 1 {
		t.Fatalf("%+v %v", slots, err)
	}
	if !slots[0].HourKnown || slots[0].Hour != (SlotHour{Requests: 12, Bytes: 3456}) {
		t.Fatalf("%+v", slots[0])
	}
}

// The minute-long deadline of the unlock is for scrypt. A status read must
// not inherit it. If it does, a wedged broker freezes the screen that would
// tell the operator that the broker is wedged.
func TestBrokerAskHonoursAShortDeadline(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Accept and answer nothing. This is the wedged broker.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	c := &Config{BrokerAdmin: sock}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.SlotHours(ctx); err == nil {
		t.Fatal("a silent broker answered")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("waited %v on a silent broker", took)
	}
}
