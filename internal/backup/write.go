package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Config names the two directories that a backup comes from. PolicyDir is
// where apply resolved POLICY to. On a shipped Pi, that is not under
// /etc/pi-fortress.
type Config struct {
	EtcDir    string
	PolicyDir string
	Host      string
	Now       func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type entry struct {
	arc  string
	path string
}

// files resolves the set against the disk. It skips a named file that is
// not there, and that is not an error. never_block.ips is absent on a box
// where nobody has written one. A backup that refuses to run until each
// optional file exists is a backup that nobody takes.
//
// But absence is the only excuse. Each other stat failure (a permission
// the operator lost, a symlink loop, an I/O error on the SD card) used to
// read as "deliberately not there". So the archive was incomplete, and
// still reported success. A backup without a policy file is discovered at
// the restore, and by then the original is gone.
func (c Config) files() ([]entry, error) {
	var out []entry
	keep := func(p string) (bool, error) {
		st, err := os.Stat(p)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return st.Mode().IsRegular(), nil
	}
	for _, n := range EtcFiles {
		p := etcPath(c.EtcDir, n)
		ok, err := keep(p)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, entry{archiveEtc(n), p})
		}
	}
	segs, err := os.ReadDir(filepath.Join(c.EtcDir, SegmentsDir))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range segs {
		if e.IsDir() || filepath.Ext(e.Name()) != ".env" {
			continue
		}
		n := SegmentsDir + "/" + e.Name()
		out = append(out, entry{archiveEtc(n), filepath.Join(c.EtcDir, SegmentsDir, e.Name())})
		seg := strings.TrimSuffix(e.Name(), ".env")
		for _, side := range []struct {
			name string
			re   *regexp.Regexp
		}{{segAllowFile(seg), segAllowName}, {segHostsFile(seg), segHostsName}} {
			if !side.re.MatchString(side.name) {
				continue
			}
			ok, err := keep(etcPath(c.EtcDir, side.name))
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, entry{archiveEtc(side.name), etcPath(c.EtcDir, side.name)})
			}
		}
	}
	for _, n := range PolicyFiles() {
		p := filepath.Join(c.PolicyDir, n)
		ok, err := keep(p)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, entry{archivePolicy(n), p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].arc < out[j].arc })
	return out, nil
}

// Write streams a gzipped tar to w. The format is intentionally ordinary:
// tar tzf and tar xzf must work, because at the time a backup is
// necessary, the tool that wrote it may be the thing that died.
func (c Config) Write(w io.Writer) (Manifest, error) {
	ents, err := c.files()
	if err != nil {
		return Manifest{}, err
	}
	host := c.Host
	if host == "" {
		host, _ = os.Hostname()
	}
	rev, dirty := revision()
	man := Manifest{
		Schema:    Schema,
		Taken:     c.now().UTC().Format(time.RFC3339),
		Host:      host,
		Revision:  rev,
		Dirty:     dirty,
		EtcDir:    c.EtcDir,
		PolicyDir: c.PolicyDir,
		Excluded:  Exclusions(),
	}

	// Read each file once, at the start. The manifest carries a digest per
	// file, and it must be the first entry in the stream so that a partial
	// extract is cheap.
	bodies := make([][]byte, len(ents))
	for i, e := range ents {
		raw, err := os.ReadFile(e.path)
		if err != nil {
			return Manifest{}, err
		}
		st, err := os.Stat(e.path)
		if err != nil {
			return Manifest{}, err
		}
		sum := sha256.Sum256(raw)
		bodies[i] = raw
		man.Files = append(man.Files, File{
			Name:   e.arc,
			Size:   int64(len(raw)),
			Mode:   uint32(st.Mode().Perm()),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	man.Ifaces = envValues(Ifaces, texts(c.EtcDir, "net.env", "net.env.local", "house.env")...)

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	mj, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	mj = append(mj, '\n')
	if err := writeFile(tw, ManifestName, mj, 0600, c.now()); err != nil {
		return Manifest{}, err
	}
	for i, e := range ents {
		if err := writeFile(tw, e.arc, bodies[i], fs.FileMode(man.Files[i].Mode), c.now()); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}
	return man, gz.Close()
}

func writeFile(tw *tar.Writer, name string, body []byte, mode fs.FileMode, now time.Time) error {
	h := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     int64(mode.Perm()),
		Size:     int64(len(body)),
		ModTime:  now,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func texts(dir string, names ...string) []string {
	var out []string
	for _, n := range names {
		if raw, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			out = append(out, string(raw))
		}
	}
	return out
}
