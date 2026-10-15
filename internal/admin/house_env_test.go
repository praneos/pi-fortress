package admin

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// unreadableHouseEnv gives the box a house on 192.168.50.0/24. Then it
// removes the permission to read it. Thus all code that falls back to the
// built-in 10.78.0.0/24 defaults gives answers about a network that this
// box is not on.
func unreadableHouseEnv(t *testing.T, c *Config) {
	t.Helper()
	// Mode 0 stops all readers except root, which ignores it. The box runs pf
	// as root. Thus on the box the read succeeds, and this test cannot stage
	// the fault at all.
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file regardless")
	}
	write(t, c.HouseEnv, "HOUSE_IF=eth1\nHOUSE_NET=192.168.50.0/24\nHOUSE_IP=192.168.50.1\n"+
		"HOUSE_DHCP_START=192.168.50.100\nHOUSE_DHCP_END=192.168.50.199\n")
	if err := os.Chmod(c.HouseEnv, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(c.HouseEnv, 0o644) })
}

// House() answers "nothing is configured" for a house.env that it could not
// read. The defaults that it then fills in describe a valid house on a
// network that the box is not on. NextFreeIP gives an address from that
// invented network, and Reserve commits it. The reason is that house.hosts
// reads correctly even when house.env does not.
func TestReserveRefusesWhenHouseEnvCannotBeRead(t *testing.T) {
	c := testConfig(t)
	before, err := os.ReadFile(c.HouseHosts)
	if err != nil {
		t.Fatal(err)
	}
	unreadableHouseEnv(t, c)

	r, err := c.Reserve("aa:bb:cc:dd:ee:09", "", "newbox")
	if err == nil {
		t.Fatalf("reserved %s out of an invented network against a house.env that could not be read", r.IP)
	}
	if !strings.Contains(err.Error(), c.HouseEnv) {
		t.Fatalf("the refusal does not name the file it could not read: %v", err)
	}
	after, rerr := os.ReadFile(c.HouseHosts)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(after) != string(before) {
		t.Fatalf("house.hosts was written anyway:\n%s", after)
	}
}

// The code also validates an explicit address against HOUSE_NET. Thus the
// same read failure lets a reservation outside the real network through.
func TestReserveOfAnExplicitAddressRefusesWhenHouseEnvCannotBeRead(t *testing.T) {
	c := testConfig(t)
	unreadableHouseEnv(t, c)
	if r, err := c.Reserve("aa:bb:cc:dd:ee:0a", "10.78.0.42", "newbox"); err == nil {
		t.Fatalf("reserved %s against a house.env that could not be read", r.IP)
	}
}

// The test holds the edit lock for its full length. Thus each call that
// reaches the write path gets a lock error. The gate must refuse before
// that. Before the fix, the code validated the tuple against the invented
// defaults. The tuple passed, and the call continued to the writer.
func TestSetHouseEnvRefusesBeforeEditingWhenItCannotReadTheTuple(t *testing.T) {
	c := testConfig(t)
	unreadableHouseEnv(t, c)
	l, err := TryLock(c.editLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()

	// 10.78.0.1 is the gateway of the built-in defaults. It is far from the
	// 192.168.50.0/24 that this box runs.
	err = c.SetHouseEnv("HOUSE_IP", "10.78.0.1")
	if err == nil {
		t.Fatal("accepted a house address validated against an unreadable house.env")
	}
	if errors.Is(err, ErrLocked) {
		t.Fatalf("the tuple passed validation against an invented house and went on to the writer: %v", err)
	}
	if !strings.Contains(err.Error(), c.HouseEnv) {
		t.Fatalf("the refusal does not name the file it could not read: %v", err)
	}
}

// A house.env that is absent is still a configuration, not a fault. The
// defaults apply, and an edit creates the file.
func TestSetHouseEnvStillWorksWithoutAHouseEnv(t *testing.T) {
	c := testConfig(t)
	if err := os.Remove(c.HouseEnv); err != nil {
		t.Fatal(err)
	}
	if err := c.SetHouseEnv("HOUSE_IP", "10.78.0.1"); err != nil {
		t.Fatalf("absent house.env refused: %v", err)
	}
	raw, err := os.ReadFile(c.HouseEnv)
	if err != nil || !strings.Contains(string(raw), "HOUSE_IP=10.78.0.1") {
		t.Fatalf("%q, %v", raw, err)
	}
}
