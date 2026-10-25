package tui

import (
	"os"
	"strings"
	"testing"
)

// A device chooses its own name. Thus the Blocked table shows the address
// of the source, and the name only beside it. Before, the name replaced the
// address, and a device could show itself as a different one.
func TestBlockedTableShowsTheAddressBesideTheName(t *testing.T) {
	c, _ := testConfig(t)
	statsFixture(t, c)
	last := run(t, c, NewFake(100, 24).Type(keys(netHouse, secActivity))).Last()
	if row := lineWith(last, "ads.example"); !strings.Contains(row, "10.78.0.101") || !strings.Contains(row, "phone") {
		t.Fatalf("the source is not its address with its name beside it: %q\n%s", row, last)
	}
	// At 80 columns the name has no space. The address stays, and the
	// destination is not cut.
	last = run(t, c, NewFake(80, 24).Type(keys(netHouse, secActivity))).Last()
	if row := lineWith(last, "ads.example"); !strings.Contains(row, "10.78.0.101") || strings.Contains(row, "~") {
		t.Fatalf("at 80 columns the source is not its address: %q\n%s", row, last)
	}
}

// A name that is not plain ASCII can look like a different name. The
// Devices table shows each such character as '?', as it does for the name
// that a lease gives, with the address beside it.
func TestDevicesNameThatIsNotASCIIShowsAsASCII(t *testing.T) {
	c, _ := testConfig(t)
	// The second letter is a Cyrillic o.
	if err := os.WriteFile(c.HouseHosts, []byte("aa:bb:cc:dd:ee:01,10.78.0.20,pоrinter\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(100, 24).Type(keys(netHouse, secDevices))).Last()
	row := lineWith(last, "10.78.0.20")
	if !strings.Contains(row, "p?rinter") || strings.ContainsRune(row, 'о') {
		t.Fatalf("the name is not shown as plain ASCII: %q\n%s", row, last)
	}
}
