package fakeip

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	pool16 = netip.MustParsePrefix("198.18.0.0/16")
	pool24 = netip.MustParsePrefix("198.18.7.0/24")
	t0     = time.Unix(1_800_000_000, 0)
)

func journal(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "fakeip.journal")
}

func open(t *testing.T, prefix netip.Prefix, path string) *Pool {
	t.Helper()
	p, err := OpenPool(prefix, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func assign(t *testing.T, p *Pool, name string, now time.Time) netip.Addr {
	t.Helper()
	a, err := p.Assign(name, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStableAssignment(t *testing.T) {
	p := open(t, pool16, journal(t))
	a := assign(t, p, "api.github.com", t0)
	if !pool16.Contains(a) {
		t.Fatalf("%s outside the pool", a)
	}
	for _, spelling := range []string{"api.github.com", "API.GitHub.com.", "api.github.com."} {
		if got := assign(t, p, spelling, t0.Add(time.Hour)); got != a {
			t.Fatalf("%q got %s, want %s", spelling, got, a)
		}
	}
	if b := assign(t, p, "example.com", t0); b == a {
		t.Fatalf("two names share %s", a)
	}
}

func TestRejects(t *testing.T) {
	for _, s := range []string{"198.18.0.0/25", "2001:db8::/64", "10.0.0.0/7"} {
		if _, err := OpenPool(netip.MustParsePrefix(s), journal(t)); err == nil {
			t.Errorf("prefix %s accepted", s)
		}
	}
	p := open(t, pool16, journal(t))
	for _, n := range []string{"", ".", strings.Repeat("a", 254), "a b.example", "a\nb.example"} {
		if _, err := p.Assign(n, t0); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

// The pool is only where the broker is already dropped, and nothing real
// is shadowed. A public, loopback or link-local pool, or a pool that
// straddles the edge of a home, is refused at the flag.
func TestCheckPrefixHomes(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "10.200.3.0/24", "100.64.0.0/10", "100.127.255.0/24",
		"172.16.0.0/12", "172.31.0.0/16", "192.168.0.0/16", "198.18.0.0/15", "198.19.0.0/16"} {
		if err := CheckPrefix(netip.MustParsePrefix(s)); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	for _, s := range []string{"8.8.0.0/16", "1.0.0.0/8", "203.0.113.0/24", "127.0.0.0/8", "127.1.0.0/16",
		"169.254.0.0/16", "240.0.0.0/8", "100.0.0.0/8", "172.0.0.0/8", "198.16.0.0/13", "192.0.0.0/8"} {
		if err := CheckPrefix(netip.MustParsePrefix(s)); err != ErrHome {
			t.Errorf("%s: %v, want ErrHome", s, err)
		}
		if _, err := OpenPool(netip.MustParsePrefix(s), journal(t)); err == nil {
			t.Errorf("OpenPool took %s", s)
		}
	}
	if err := CheckPrefix(netip.MustParsePrefix("10.0.0.0/7")); err != ErrPrefix {
		t.Errorf("/7: %v, want ErrPrefix", err)
	}
}

// Every usable address of a /24 is .1 to .254: the network, the
// broadcast and nothing else.
func TestExcludedAddresses(t *testing.T) {
	p := open(t, pool24, journal(t))
	seen := map[netip.Addr]bool{}
	for i := range int(p.size) {
		a := assign(t, p, fmt.Sprintf("n%d.example", i), t0)
		last := a.As4()[3]
		if last == 0 || last == 255 || seen[a] {
			t.Fatalf("handed out %s", a)
		}
		seen[a] = true
	}
	if len(seen) != 254 {
		t.Fatalf("%d addresses, want 254", len(seen))
	}
	for _, s := range []string{"198.18.1.0", "198.18.0.255"} {
		if _, ok := offsetOf(pool16, netip.MustParseAddr(s)); ok {
			t.Errorf("%s is usable", s)
		}
	}
	if a := addrAt(pool16, 254); a != netip.MustParseAddr("198.18.1.1") {
		t.Errorf("offset 254 is %s, want 198.18.1.1", a)
	}
}

func TestRestartReload(t *testing.T) {
	path := journal(t)
	p := open(t, pool16, path)
	a := assign(t, p, "api.github.com", t0)
	b := assign(t, p, "example.com", t0)
	p.Close()
	q := open(t, pool16, path)
	if got := assign(t, q, "api.github.com", t0); got != a {
		t.Fatalf("after restart %s, want %s", got, a)
	}
	c := assign(t, q, "new.example", t0)
	if c == a || c == b {
		t.Fatalf("restart reused %s for a new name while the pool had room", c)
	}
}

// A full pool reuses the least recently assigned address, and a
// re-assign counts as use.
func TestLRUReuseWhenFull(t *testing.T) {
	p := open(t, pool24, journal(t))
	addr := map[string]netip.Addr{}
	for i := range 254 {
		n := fmt.Sprintf("n%d.example", i)
		addr[n] = assign(t, p, n, t0.Add(time.Duration(i)*time.Second))
	}
	assign(t, p, "n0.example", t0.Add(time.Hour))
	got := assign(t, p, "late.example", t0.Add(time.Hour))
	if got != addr["n1.example"] {
		t.Fatalf("reused %s, want n1's %s", got, addr["n1.example"])
	}
	if assign(t, p, "n0.example", t0.Add(time.Hour)) != addr["n0.example"] {
		t.Fatal("the refreshed name lost its address")
	}
	tab := NewTable(pool24, p.path)
	if n, _ := tab.Name(got); n != "late.example" {
		t.Fatalf("reader says %q for the reused address", n)
	}
}

// A refresh inside refreshLine writes nothing; past it, one line.
func TestRefreshLine(t *testing.T) {
	path := journal(t)
	p := open(t, pool16, path)
	assign(t, p, "a.example", t0)
	assign(t, p, "a.example", t0.Add(30*time.Second))
	if n := lines(t, path); n != 1 {
		t.Fatalf("%d lines, want 1", n)
	}
	assign(t, p, "a.example", t0.Add(2*time.Minute))
	if n := lines(t, path); n != 2 {
		t.Fatalf("%d lines, want 2", n)
	}
}

func lines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func TestJournalMode(t *testing.T) {
	path := journal(t)
	open(t, pool16, path)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640", st.Mode().Perm())
	}
}

// Past compactFactor lines per address, the journal is rewritten with the
// live mappings only, and a reader that holds the old file reloads.
func TestCompactionReaderReload(t *testing.T) {
	path := journal(t)
	p := open(t, pool24, path)
	tab := NewTable(pool24, path)
	first := assign(t, p, "n0.example", t0)
	if n, ok := tab.Name(first); !ok || n != "n0.example" {
		t.Fatalf("reader: %q %v", n, ok)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Distinct names churn the full pool until the line count trips.
	var last netip.Addr
	var name string
	for i := 1; ; i++ {
		if i > 2*compactFactor*254 {
			t.Fatal("never compacted")
		}
		name = fmt.Sprintf("n%d.example", i)
		last = assign(t, p, name, t0.Add(time.Duration(i)*time.Second))
		if st, _ := os.Stat(path); !os.SameFile(st, before) {
			break
		}
	}
	if n := lines(t, path); n > 254 {
		t.Fatalf("compacted journal has %d lines", n)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("compacted mode %v", st.Mode().Perm())
	}
	if n, ok := tab.Name(last); !ok || n != name {
		t.Fatalf("reader after compaction: %q %v, want %s", n, ok, name)
	}
	p.Close()
	r := open(t, pool24, path)
	if got := assign(t, r, name, t0); got != last {
		t.Fatalf("reload after compaction: %s, want %s", got, last)
	}
	after := assign(t, r, "after.example", t0.Add(time.Hour))
	if n, ok := tab.Name(after); !ok || n != "after.example" {
		t.Fatalf("reader missed a line after compaction: %q %v", n, ok)
	}
}

// A reader created before a line was written still finds it.
func TestReaderSeesLaterLine(t *testing.T) {
	path := journal(t)
	tab := NewTable(pool16, path)
	if _, ok := tab.Name(netip.MustParseAddr("198.18.0.1")); ok {
		t.Fatal("mapped before any journal")
	}
	p := open(t, pool16, path)
	a := assign(t, p, "later.example", t0)
	if n, ok := tab.Name(a); !ok || n != "later.example" {
		t.Fatalf("got %q %v", n, ok)
	}
	if !tab.Contains(netip.MustParseAddr("198.18.255.255")) || tab.Contains(netip.MustParseAddr("198.19.0.1")) {
		t.Fatal("Contains is not the prefix")
	}
}

// A torn last line (power cut in the middle of an append) is skipped, and
// the next append does not glue onto it.
func TestTornLine(t *testing.T) {
	path := journal(t)
	if err := os.WriteFile(path, []byte("1800000000 198.18.0.1 a.example\n1800000000 198.18.0.2 b.exa"), 0o640); err != nil {
		t.Fatal(err)
	}
	p := open(t, pool16, path)
	c := assign(t, p, "c.example", t0)
	tab := NewTable(pool16, path)
	if n, _ := tab.Name(netip.MustParseAddr("198.18.0.1")); n != "a.example" {
		t.Fatalf("a: %q", n)
	}
	if n, _ := tab.Name(c); n != "c.example" {
		t.Fatalf("c: %q", n)
	}
}

// A journal line with the mapped form of a pool address is skipped. It
// does not give a second name the address that a first name holds.
func TestJournalSkipsMappedAddress(t *testing.T) {
	path := journal(t)
	if err := os.WriteFile(path, []byte("1800000000 198.18.0.1 a.example\n1800000000 ::ffff:198.18.0.1 b.example\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	p := open(t, pool16, path)
	held := netip.MustParseAddr("198.18.0.1")
	if b := assign(t, p, "b.example", t0); !b.Is4() || b == held {
		t.Fatalf("b.example got %v", b)
	}
	if n, _ := NewTable(pool16, path).Name(held); n != "a.example" {
		t.Fatalf("%v names %q", held, n)
	}
}

// A name with two trailing dots is refused. Its journal line would not
// read back, so its address would go to another name after a restart.
func TestAssignRefusesDoubleTrailingDot(t *testing.T) {
	p := open(t, pool24, journal(t))
	for _, name := range []string{"a.example..", "..", "a.."} {
		if _, err := p.Assign(name, t0); !errors.Is(err, ErrName) {
			t.Fatalf("%q: err %v, want ErrName", name, err)
		}
	}
	if n, err := Normalise("a.example."); err != nil || n != "a.example" {
		t.Fatalf("one trailing dot: %q %v", n, err)
	}
}

func TestConcurrentAssignName(t *testing.T) {
	path := journal(t)
	p := open(t, pool24, path)
	tab := NewTable(pool24, path)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range 200 {
				n := fmt.Sprintf("w%d-%d.example", w, i%40)
				a, err := p.Assign(n, t0.Add(time.Duration(i)*time.Minute))
				if err != nil {
					t.Error(err)
					return
				}
				if got, ok := tab.Name(a); ok && !strings.HasSuffix(got, ".example") {
					t.Errorf("reader got %q", got)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 200 {
				tab.Name(addrAt(pool24, uint32(i%254)))
			}
		}()
	}
	wg.Wait()
}

// An address asked as a name gets no pool address from any caller: the
// broker would map it back and dial the literal.
func TestAssignRefusesAnAddress(t *testing.T) {
	p := open(t, pool16, journal(t))
	for _, n := range []string{"203.0.114.9", "203.0.114.9.", "::1", "2001:db8::7"} {
		if _, err := p.Assign(n, t0); !errors.Is(err, ErrName) {
			t.Errorf("%q: %v, want ErrName", n, err)
		}
	}
	assign(t, p, "203.0.114.9.example", t0)
}
