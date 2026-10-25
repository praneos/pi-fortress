package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

var (
	ErrSchema   = errors.New("archive is from a newer pf than this one")
	ErrNoMan    = errors.New("archive has no manifest")
	ErrPath     = errors.New("archive names a path outside the backup set")
	ErrDigest   = errors.New("archive content does not match its manifest")
	ErrTooLarge = errors.New("archive is larger than a config backup can be")
)

// maxFile and maxTotal bound a decompressed archive. The lists are text,
// and the largest of them is the domains of one feed. So these limits are
// generous by an order of magnitude, and still refuse a gzip bomb before
// any part of it is written.
const (
	maxFile  = 64 << 20
	maxTotal = 256 << 20
)

// maxEntries bounds how many headers a restore will walk. Each header
// costs a read and a name check, whether or not the entry passes them. So
// an archive of only headers is work with no ceiling.
const maxEntries = 4096

// testHookSynced names a file or directory whose contents were just
// flushed. Durability has no other effect that is visible from inside
// the process. Without this hook, there would be no way to catch a
// restore that reports success without a flush.
var testHookSynced func(path string)

// Archive is a read backup: the manifest and the contents of each file,
// verified against it. It is read whole into memory before any disk
// write, so a truncated or wrong archive cannot leave a half-restored box
// behind.
type Archive struct {
	Manifest Manifest
	Body     map[string][]byte
}

// safeName is the full path defence. Each entry must be one of the names
// that this version of the tool would itself have written. That is
// strictly narrower than "no .. and no leading /". So an archive cannot
// add a path at all. It can only fill one in.
func safeName(name string) bool {
	if name != path.Clean(name) || path.IsAbs(name) || strings.Contains(name, "..") {
		return false
	}
	if name == ManifestName {
		return true
	}
	if rest, ok := strings.CutPrefix(name, "policy/"); ok {
		for _, n := range PolicyFiles() {
			if rest == n {
				return true
			}
		}
		return false
	}
	rest, ok := strings.CutPrefix(name, "etc/")
	if !ok {
		return false
	}
	for _, n := range EtcFiles {
		if rest == n {
			return true
		}
	}
	if segAllowName.MatchString(rest) || segHostsName.MatchString(rest) {
		return true
	}
	seg, ok := strings.CutPrefix(rest, SegmentsDir+"/")
	return ok && seg != "" && !strings.Contains(seg, "/") && filepath.Ext(seg) == ".env"
}

func Read(r io.Reader) (*Archive, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	a := &Archive{Body: map[string][]byte{}}
	var total int64
	entries := 0
	haveMan := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > maxEntries {
			return nil, ErrTooLarge
		}
		// The budget is charged from the header, before the typeflag
		// decides whether this entry is wanted. archive/tar reads past the
		// declared body of a skipped entry for us in both cases. When the
		// count was only of what passed the filter, an archive of only
		// unknown-type entries cost the dry run each of those bytes, but
		// the budget counted none of them.
		if h.Size < 0 || h.Size > maxFile {
			return nil, fmt.Errorf("%w: %s", ErrTooLarge, h.Name)
		}
		total += h.Size
		if total > maxTotal {
			return nil, ErrTooLarge
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if !safeName(h.Name) {
			return nil, fmt.Errorf("%w: %q", ErrPath, h.Name)
		}
		raw, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) > maxFile {
			return nil, ErrTooLarge
		}
		if h.Name == ManifestName {
			if err := json.Unmarshal(raw, &a.Manifest); err != nil {
				return nil, err
			}
			if a.Manifest.Schema > Schema {
				return nil, fmt.Errorf("%w: schema %d", ErrSchema, a.Manifest.Schema)
			}
			haveMan = true
			continue
		}
		a.Body[h.Name] = raw
	}
	if !haveMan {
		return nil, ErrNoMan
	}
	if err := a.verify(); err != nil {
		return nil, err
	}
	return a, nil
}

// verify compares the bodies with the manifest. Each file must have a
// description, and each description must be met, so an archive edited
// after it was written does not restore. A count
// of the two sets is not enough for that. If the archive names one file
// twice, the counts agree, but a body stays that no row ever hashes. Plan
// writes from the bodies, not from the manifest. So that unverified file
// is exactly the one that would land on the box.
func (a *Archive) verify() error {
	seen := map[string]bool{}
	for _, f := range a.Manifest.Files {
		if seen[f.Name] {
			return fmt.Errorf("%w: %s is listed twice", ErrDigest, f.Name)
		}
		seen[f.Name] = true
		raw, ok := a.Body[f.Name]
		if !ok {
			return fmt.Errorf("%w: %s is in the manifest and not the archive", ErrDigest, f.Name)
		}
		if f.Size != int64(len(raw)) {
			return fmt.Errorf("%w: %s is %d bytes and the manifest says %d", ErrDigest, f.Name, len(raw), f.Size)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("%w: %s", ErrDigest, f.Name)
		}
	}
	for n := range a.Body {
		if !seen[n] {
			return fmt.Errorf("%w: %s is in the archive and not the manifest", ErrDigest, n)
		}
	}
	return nil
}

// Change is what a restore would do to one file.
type Change struct {
	Name string
	Path string
	Kind string // "new", "changed", "same"
}

// Plan is a restore that has not occurred. Restore is the one action in
// this product that can quietly undo a security decision: a removed
// never_block entry, a list from before a threat was added, PARANOID set
// back to off. It does this with a write of files that look exactly like
// the files that an operator wrote. So the diff comes first, and the write
// is a second, separate step.
type Plan struct {
	Archive   *Archive
	EtcDir    string
	PolicyDir string
	Changes   []Change
	// Warnings are the reasons to look twice: interfaces or a hostname
	// that do not match the box. Age is not one of them. The timestamp and
	// revision of the archive are printed for the operator to judge, and
	// nothing compares them with what is installed.
	Warnings []string
}

func (a *Archive) Plan(etcDir, policyDir string) (*Plan, error) {
	p := &Plan{Archive: a, EtcDir: etcDir, PolicyDir: policyDir}
	names := make([]string, 0, len(a.Body))
	for n := range a.Body {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		top, rel, err := p.split(n)
		if err != nil {
			return nil, err
		}
		dest := filepath.Join(top, rel)
		kind := "new"
		if cur, err := readUnder(top, rel); err == nil {
			kind = "changed"
			if string(cur) == string(a.Body[n]) {
				kind = "same"
			}
		}
		p.Changes = append(p.Changes, Change{Name: n, Path: dest, Kind: kind})
	}
	p.Warnings = a.warnings(etcDir)
	return p, nil
}

func (p *Plan) dest(name string) (string, error) {
	top, rel, err := p.split(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(top, rel), nil
}

// split gives the target root of an archive name (PolicyDir or EtcDir)
// and the path of the file below that root. Apply writes each file
// through an os.Root that it opens on that root.
func (p *Plan) split(name string) (top, rel string, err error) {
	if rest, ok := strings.CutPrefix(name, "policy/"); ok {
		return p.PolicyDir, filepath.FromSlash(rest), nil
	}
	if rest, ok := strings.CutPrefix(name, "etc/"); ok {
		return p.EtcDir, filepath.FromSlash(rest), nil
	}
	return "", "", fmt.Errorf("%w: %q", ErrPath, name)
}

// readUnder reads rel below the root top. It does not follow a symlink
// out of top. So the diff in Plan describes the file that Apply would
// replace, and not a file in some other location.
func readUnder(top, rel string) ([]byte, error) {
	r, err := os.OpenRoot(top)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.ReadFile(rel)
}

// warnings compares the archive with the box where it is about to land.
// Neither of these refuses the restore: an intentional move to new
// hardware is the main reason for a backup. They exist so that the same
// move by accident is loud.
func (a *Archive) warnings(etcDir string) []string {
	var out []string
	now := envValues(Ifaces, texts(etcDir, "net.env", "net.env.local", "house.env")...)
	var keys []string
	for k := range a.Manifest.Ifaces {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		was, is := a.Manifest.Ifaces[k], now[k]
		if is != "" && was != is {
			out = append(out, fmt.Sprintf("%s was %q when this backup was taken and is %q here; apply refuses a profile pinned to an interface that is not present", k, was, is))
		}
	}
	if host, _ := os.Hostname(); host != "" && a.Manifest.Host != "" && host != a.Manifest.Host {
		out = append(out, fmt.Sprintf("taken on %q, restoring onto %q", a.Manifest.Host, host))
	}
	return out
}

// Changed reports the entries a restore would actually write.
func (p *Plan) Changed() []Change {
	var out []Change
	for _, c := range p.Changes {
		if c.Kind != "same" {
			out = append(out, c)
		}
	}
	return out
}

// Apply writes the plan. Each file is staged beside its target and renamed
// over it. So a restore that stops part way leaves whole files on both
// sides of the point where it stopped, not one truncated file.
//
// The rename is only half of that promise. Until the contents and the
// directory entry that names them are on the medium, a power loss between
// the restore and the next apply can give back a file that is empty,
// partly the old file, or missing. The operator has no reason to look,
// because the restore said that it wrote. So each staged file is flushed
// before the rename, and each touched directory once at the end. pf uses
// the same order for the secrets store.
//
// Each write goes through an os.Root on EtcDir or PolicyDir. A directory
// below that root can be a symlink. If it points out of the root, the
// write fails and nothing is written there. The root directories are the
// choice of the operator, so they are opened as they are.
func (p *Plan) Apply() ([]Change, error) {
	done := []Change{}
	roots := map[string]*os.Root{}
	defer func() {
		for _, r := range roots {
			r.Close()
		}
	}()
	type dirRef struct {
		root     *os.Root
		top, rel string
	}
	dirs := []dirRef{}
	seenDir := map[string]bool{}
	for _, c := range p.Changed() {
		mode := fs.FileMode(0644)
		for _, f := range p.Archive.Manifest.Files {
			if f.Name == c.Name && f.Mode != 0 {
				mode = fs.FileMode(f.Mode).Perm()
			}
		}
		mode = restoreMode(c.Name, mode)
		top, rel, err := p.split(c.Name)
		if err != nil {
			return done, err
		}
		r, ok := roots[top]
		if !ok {
			if err := os.MkdirAll(top, 0755); err != nil {
				return done, err
			}
			if r, err = os.OpenRoot(top); err != nil {
				return done, err
			}
			roots[top] = r
		}
		if err := writeUnder(r, rel, p.Archive.Body[c.Name], mode); err != nil {
			return done, err
		}
		if testHookSynced != nil {
			testHookSynced(c.Path)
		}
		if d := filepath.Join(top, filepath.Dir(rel)); !seenDir[d] {
			seenDir[d] = true
			dirs = append(dirs, dirRef{root: r, top: top, rel: filepath.Dir(rel)})
		}
		done = append(done, c)
	}
	for _, d := range dirs {
		if err := syncDir(d.root, d.top, d.rel); err != nil {
			return done, err
		}
	}
	return done, nil
}

// writeUnder stages body beside rel in the root r, flushes it, and
// renames it over rel. All of the steps use the root, so none of them
// follows a symlink out of it.
func writeUnder(r *os.Root, rel string, body []byte, mode fs.FileMode) error {
	dir := filepath.Dir(rel)
	if err := r.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".pf-restore-"+rand.Text())
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Chmod(mode)
	}
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = r.Rename(tmp, rel)
	}
	if werr != nil {
		r.Remove(tmp)
		return werr
	}
	return nil
}

// restoreMode clamps the mode that an archive asks for. The archive is a
// file that has been on a laptop, and its manifest can say 0777 as easily
// as 0644. Nothing that it restores is executable, or writable by a user
// other than root. The env files, alert.url (a webhook whose path is its
// bearer token) and all files named secret are for root alone. Root keeps
// read and write whatever the archive says, so apply can always read a
// restored file.
func restoreMode(name string, archived fs.FileMode) fs.FileMode {
	ceiling := fs.FileMode(0644)
	base := path.Base(name)
	if strings.HasSuffix(base, ".env") || strings.HasSuffix(base, ".env.local") || base == "alert.url" || strings.Contains(base, "secret") {
		ceiling = 0600
	}
	return (archived.Perm() | 0600) & ceiling
}

// syncDir flushes a directory, so the renames in it are on the medium and
// not only in the page cache. A restore reports how many files it wrote.
// Without this, that count describes the cache. The directory is rel in
// the root r, and top is the path of that root.
func syncDir(r *os.Root, top, rel string) error {
	dir := filepath.Join(top, rel)
	d, err := r.Open(rel)
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return serr
	}
	if cerr != nil {
		return cerr
	}
	if testHookSynced != nil {
		testHookSynced(dir)
	}
	return nil
}
