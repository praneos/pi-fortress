package tailer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeInPlace changes the content of path and keeps its inode. Thus the
// test can make a file with the same dev:ino as the file in which the old
// offset was counted.
func writeInPlace(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func inode(t *testing.T, path string) fileID {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return idOf(fi)
}

// The log rotates while the sidecar is stopped, and the new log gets the
// inode number of the old one. The saved offset then names the right
// dev:ino and the wrong file. The new tail must read the new file from the
// start. It must not skip the records before the old offset.
func TestRestartReadsFromStartWhenInodeHoldsAnotherFile(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := inode(t, log)
	var first []string
	one := &Tail{Path: log, OffsetPath: off}
	drainInto(t, one, &first)
	if err := one.Drain(false); err != nil {
		t.Fatal(err)
	}
	one.shut()
	raw, err := os.ReadFile(off)
	if err != nil {
		t.Fatal(err)
	}

	want := "{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n"
	writeInPlace(t, log, want)
	if inode(t, log) != before {
		t.Fatal("test set-up: the inode changed")
	}
	var second []string
	two := &Tail{Path: log, OffsetPath: off}
	drainInto(t, two, &second)
	if err := two.Drain(false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(second, ""); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if f := strings.Fields(string(raw)); len(f) != 3 || len(f[2]) != headSumLen {
		t.Errorf("offset record has no head sum: %q", raw)
	}
}

// The same file grew while the sidecar was stopped. The head sum matches,
// so the new tail resumes at the saved offset and reads only the new lines.
func TestRestartResumesWhenSameFileGrew(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var first []string
	one := &Tail{Path: log, OffsetPath: off}
	drainInto(t, one, &first)
	if err := one.Drain(false); err != nil {
		t.Fatal(err)
	}
	one.shut()

	f, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"n\":3}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var second []string
	two := &Tail{Path: log, OffsetPath: off}
	drainInto(t, two, &second)
	if err := two.Drain(false); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(second, ""), "{\"n\":3}\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The head sum covers at most headSpan bytes. A log longer than that
// still resumes at its offset after a restart.
func TestRestartResumesPastHeadSpan(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	line := "{\"pad\":\"" + strings.Repeat("x", 100) + "\"}\n"
	if err := os.WriteFile(log, []byte(strings.Repeat(line, 2*headSpan/len(line))), 0644); err != nil {
		t.Fatal(err)
	}
	one := &Tail{Path: log, OffsetPath: off}
	if err := one.Drain(false); err != nil {
		t.Fatal(err)
	}
	one.shut()
	f, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"n\":9}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var second []string
	two := &Tail{Path: log, OffsetPath: off}
	drainInto(t, two, &second)
	if err := two.Drain(false); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(second, ""), "{\"n\":9}\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// An offset record from an older pf has no head sum. The tail trusts its
// dev:ino as before. It does not send the full log again. The next save
// adds the head sum.
func TestRestartReadsRecordWithoutHeadSum(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	old := "16 " + inode(t, log).String()
	if err := os.WriteFile(off, []byte(old+strings.Repeat(" ", 64-len(old))+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off}
	drainInto(t, tl, &seen)
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(seen, ""), "{\"n\":3}\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	raw, err := os.ReadFile(off)
	if err != nil {
		t.Fatal(err)
	}
	if f := strings.Fields(string(raw)); len(f) != 3 || f[0] != "24" || len(f[2]) != headSumLen {
		t.Fatalf("offset record %q", raw)
	}
}
