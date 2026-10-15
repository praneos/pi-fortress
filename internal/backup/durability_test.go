package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// manifestOf builds an archive whose manifest is exactly what the caller
// says, not what the bodies deserve. Each check in Read that is worth
// having is a check that the two disagree.
func manifestOf(t *testing.T, man Manifest, bodies map[string]string) []byte {
	t.Helper()
	mj, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name, body string) {
		t.Helper()
		h := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0644, Size: int64(len(body)), Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write(ManifestName, string(mj))
	names := make([]string, 0, len(bodies))
	for n := range bodies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		write(n, bodies[n])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func row(name, body string) File {
	sum := sha256.Sum256([]byte(body))
	return File{Name: name, Size: int64(len(body)), Mode: 0644, SHA256: hex.EncodeToString(sum[:])}
}

// The digest check used to compare set sizes, and then find each manifest
// row in the body map. If the archive names one file twice, the counts
// agree, but a second body stays that no row ever hashes. Plan writes from
// the bodies, not from the manifest. So that unverified file is the one
// that lands on the box.
func TestReadRefusesAManifestThatDoesNotCoverEveryFile(t *testing.T) {
	kept := "INT_IF=eth0\n"
	smuggled := "HOUSE_IF=eth1\n"
	man := Manifest{Schema: Schema, Files: []File{row("etc/net.env", kept), row("etc/net.env", kept)}}
	raw := manifestOf(t, man, map[string]string{"etc/net.env": kept, "etc/house.env": smuggled})
	if _, err := Read(bytes.NewReader(raw)); !errors.Is(err, ErrDigest) {
		t.Fatalf("Read accepted an archive holding an unhashed file: err %v", err)
	}
}

// Size is in the manifest, so an operator can read the account of the
// archive about itself. A row whose size does not agree with its body
// means that the manifest was edited. The hash alone does not show this
// when the editor kept the hash in place.
func TestReadRefusesAManifestSizeThatDisagrees(t *testing.T) {
	body := "INT_IF=eth0\n"
	f := row("etc/net.env", body)
	f.Size = 9999
	raw := manifestOf(t, Manifest{Schema: Schema, Files: []File{f}}, map[string]string{"etc/net.env": body})
	if _, err := Read(bytes.NewReader(raw)); !errors.Is(err, ErrDigest) {
		t.Fatalf("Read accepted a manifest row whose size was wrong: err %v", err)
	}
}

// The size budget used to apply only to the entries that Read keeps.
// archive/tar still reads past the declared body of each other header for
// us. So an archive of only unknown-type entries costs the dry run all of
// those bytes, but the budget counts none of them.
func TestReadBudgetsTheEntriesItSkips(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	man := []byte(`{"schema":1}`)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: ManifestName, Mode: 0600, Size: int64(len(man)), Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(man); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, maxFile+1)
	h := &tar.Header{Typeflag: 'Z', Name: "etc/net.env", Mode: 0644, Size: int64(len(body)), Format: tar.FormatPAX}
	if err := tw.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(buf.Bytes())); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Read walked past an oversized entry it did not keep: err %v", err)
	}
}

// Entry count is its own budget. Each header costs a read and a name
// check, whether or not the entry passes them. So an archive of only
// headers must stop at some point.
func TestReadBudgetsTheEntryCount(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	man := []byte(`{"schema":1}`)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: ManifestName, Mode: 0600, Size: int64(len(man)), Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(man); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxEntries+1; i++ {
		h := &tar.Header{Typeflag: tar.TypeDir, Name: "etc/d/", Mode: 0755, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(buf.Bytes())); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Read walked an unbounded number of headers: err %v", err)
	}
}

// A restore that returns without an error has told the operator that the
// box is back. The contents, and the directory entry that names them, can
// still be only in the page cache. Then a power loss between the restore
// and the apply gives back a file that is empty, partly old, or fully
// gone. The operator has no reason to look, because the restore said that it wrote.
func TestApplySyncsWhatItWrote(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	pol := filepath.Join(dir, "policy")
	body := "INT_IF=eth0\n"
	raw := manifestOf(t, Manifest{Schema: Schema, Files: []File{row("etc/net.env", body)}}, map[string]string{"etc/net.env": body})
	arc, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := arc.Plan(etc, pol)
	if err != nil {
		t.Fatal(err)
	}
	synced := map[string]bool{}
	testHookSynced = func(p string) { synced[p] = true }
	t.Cleanup(func() { testHookSynced = nil })
	if _, err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	testHookSynced = nil
	target := filepath.Join(etc, "net.env")
	if !synced[target] {
		t.Errorf("restore did not flush %s before reporting success", target)
	}
	if !synced[etc] {
		t.Errorf("restore did not flush the directory entry for %s", target)
	}
}

// files() gives the same answer for a stat failure and for a file that is
// absent on purpose. So it omits a list that the operator cannot read, and
// the backup still reports success. The archive then does not have a
// policy file, and nothing in it tells this.
func TestWriteRefusesWhenASourceCannotBeStatted(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	pol := filepath.Join(dir, "policy")
	for _, d := range []string{etc, pol} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "net.env"), []byte("INT_IF=eth0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A symlink that points at itself: stat fails with ELOOP. That is not
	// "not there", and it is not a thing that a backup should hide.
	loop := filepath.Join(pol, "blacklist.domains")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	c := Config{EtcDir: etc, PolicyDir: pol, Host: "pi"}
	if _, err := c.Write(&bytes.Buffer{}); err == nil {
		t.Fatal("backup reported success while a policy file it could not stat was silently omitted")
	}
}

// The mode in the manifest is the word of the archive, and the archive has
// been on a laptop. A restore takes a maximum of 0644 from it, and a
// maximum of 0600 for the env files and alert.url, whatever it asks for.
func TestApplyClampsArchiveModes(t *testing.T) {
	bodies := map[string]string{
		"policy/blacklist.domains": "evil.test\n",
		"policy/alert.url":         "https://hooks.example/T0/secret\n",
		"etc/net.env":              "INT_IF=eth0\n",
		"etc/segments.d/lab.env":   "IF=eth2\n",
	}
	asked := map[string]uint32{
		"policy/blacklist.domains": 0777,
		"policy/alert.url":         0666,
		"etc/net.env":              04755,
		"etc/segments.d/lab.env":   0640,
	}
	want := map[string]os.FileMode{
		"policy/blacklist.domains": 0644,
		"policy/alert.url":         0600,
		"etc/net.env":              0600,
		"etc/segments.d/lab.env":   0600,
	}
	var files []File
	for n, b := range bodies {
		f := row(n, b)
		f.Mode = asked[n]
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	a, err := Read(bytes.NewReader(manifestOf(t, Manifest{Schema: Schema, Files: files}, bodies)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	etc, pol := filepath.Join(root, "etc"), filepath.Join(root, "policy")
	p, err := a.Plan(etc, pol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Apply(); err != nil {
		t.Fatal(err)
	}
	for n, m := range want {
		dest, _ := p.dest(n)
		st, err := os.Stat(dest)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != m {
			t.Errorf("%s restored %v, want %v (archive asked for %o)", n, got, m, asked[n])
		}
	}
}
