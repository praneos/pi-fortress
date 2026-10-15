package admin

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// An edit reads the full list, changes one line, and writes the full list
// back. Nothing holds the file across the three steps. Thus two edits that
// overlap each write back the list that they read, and the second edit
// erases the first. On a blocklist, a block that an operator added is then
// gone, and nothing says so: both edits reported success. The shared
// staging name makes it worse. Each writer unlinks the temp file of the
// other before it creates its own. Thus a rename can publish a file that
// belongs to the other edit.
func TestConcurrentListEditsBothSurvive(t *testing.T) {
	c := testConfig(t)
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.ListAdd("blacklist.domains", "added"+string(rune('a'+i))+".test")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("ListAdd %d: %v", i, err)
		}
	}
	got, err := c.List("blacklist.domains")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tok := range got {
		have[tok] = true
	}
	var lost []string
	for i := 0; i < n; i++ {
		if tok := "added" + string(rune('a'+i)) + ".test"; !have[tok] {
			lost = append(lost, tok)
		}
	}
	if len(lost) > 0 {
		t.Fatalf("%d of %d accepted edits were erased by a concurrent one: %v (list %v)", len(lost), n, lost, got)
	}
	if !have["pi-fortress-block.test"] {
		t.Fatalf("the original entry was lost: %v", got)
	}
}

// readLines answers "no lines" for a file that it cannot read. It gives the
// same answer for a file that does not exist. An edit then writes back a
// list that holds only what the edit added, and the write succeeds. Thus a
// transient read failure becomes a blocklist with one entry and a green
// report. The only safe answer is to refuse the edit.
func TestListEditRefusesWhenTheCurrentListCannotBeRead(t *testing.T) {
	c := testConfig(t)
	p := filepath.Join(c.PolicyDir, "blacklist.domains")
	const before = "evil.test\nworse.test\n"
	write(t, p, before)
	if err := os.Chmod(p, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0644) })

	err := c.ListAdd("blacklist.domains", "newer.test")
	os.Chmod(p, 0644)
	if err == nil {
		t.Fatal("ListAdd reported success against a list it could not read")
	}
	got, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != before {
		t.Fatalf("an unreadable list was replaced by what the edit added:\n got %q\nwant %q", got, before)
	}
}

// The same answer for the house reservations: an unreadable house.hosts
// must not become a file that holds one reservation.
func TestReserveRefusesWhenTheReservationsCannotBeRead(t *testing.T) {
	c := testConfig(t)
	before, err := os.ReadFile(c.HouseHosts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.HouseHosts, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(c.HouseHosts, 0644) })

	_, rerr := c.Reserve("aa:bb:cc:dd:ee:09", "10.78.0.40", "tv")
	os.Chmod(c.HouseHosts, 0644)
	if rerr == nil {
		t.Fatal("Reserve reported success against reservations it could not read")
	}
	got, err := os.ReadFile(c.HouseHosts)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(before) {
		t.Fatalf("unreadable reservations were replaced:\n got %q\nwant %q", got, before)
	}
}

// WriteFile stages through path + ".tmp" and unlinks it first. Thus its
// exclusive create gives no protection against a different copy of
// itself. Two writers of the same file each remove the staging file of the
// other. The rename that occurs last can publish bytes that the other
// writer wrote. The staging name must be one that only this writer knows.
func TestWriteFileStagesUnderAnUnpredictableName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sources.json")
	if err := WriteFile(p, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A symlink at the staging name that is easy to guess: the old code removed
	// it and continued. This shows that an attacker can own the name.
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), p+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("{\"feeds\":[]}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p + ".tmp"); err != nil {
		t.Fatalf("WriteFile removed a path it does not own: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".sources.json.") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}
}
