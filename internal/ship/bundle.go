package ship

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// BundleOptions mirror the rsync flags that pi-sync used. ExcludeNames
// are base names skipped at any depth (.git, .vagrant). Keep are paths
// not shipped whose Pi copy is carried over (generated/, alert.url). Seed
// are shipped, but the Pi copy wins when present (the PI_OWNED lists).
// Omit are paths that are not shipped (the bundle itself).
type BundleOptions struct {
	Version      int64
	SHA          string
	ExcludeNames []string
	Keep         []string
	Seed         []string
	Omit         []string
}

// Build walks root and writes the bundle to w.
func Build(w io.Writer, root string, opt BundleOptions) (*Manifest, error) {
	m := &Manifest{
		Version: opt.Version, SHA: opt.SHA,
		Keep:     append(slices.Clone(opt.Keep), opt.Seed...),
		StateMin: StateMin, StateMax: StateMax,
	}
	var dirs []string
	skip := append(slices.Clone(opt.Keep), opt.Omit...)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// The floor stamp is installer state that a tree carries, never
		// release content. If not skipped, a build from a live Pi tree
		// would put the floor of one release in the manifest of another.
		// The stamp that the install then writes would make the live tree
		// disagree with the manifest that it came from. Skipped here, not
		// left to the -exclude of the caller, which can be forgotten.
		if d.Name() == stampName {
			return nil
		}
		if slices.Contains(opt.ExcludeNames, d.Name()) || slices.Contains(skip, rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !CleanRel(rel) || rel == ManifestName {
			return fmt.Errorf("%s: path not allowed in a bundle", rel)
		}
		switch t := d.Type(); {
		case t.IsDir():
			dirs = append(dirs, rel)
		case t.IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			sum, n, err := hashFile(p)
			if err != nil {
				return err
			}
			m.Files = append(m.Files, File{Path: rel, SHA256: sum, Size: n, Exec: info.Mode()&0111 != 0})
		default:
			return fmt.Errorf("%s: %s; bundles carry regular files and directories only", rel, t)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := m.Validate(DefaultLimits); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	mtime := time.Unix(opt.Version, 0)
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0644, Size: int64(len(raw)), ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(raw); err != nil {
		return nil, err
	}
	for _, d := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/", Mode: 0755, ModTime: mtime, Typeflag: tar.TypeDir}); err != nil {
			return nil, err
		}
	}
	for _, f := range m.Files {
		mode := int64(0644)
		if f.Exec {
			mode = 0755
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.Path, Mode: mode, Size: f.Size, ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if err := copyChecked(tw, filepath.Join(root, filepath.FromSlash(f.Path)), f); err != nil {
			return nil, err
		}
	}
	return m, tw.Close()
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// copyChecked reads a file again into the tar, and fails if it changed
// after the hash. It does not ship a bundle that the Pi will refuse.
func copyChecked(w io.Writer, p string, f File) error {
	src, err := os.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()
	var buf bytes.Buffer
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(&buf, h), io.LimitReader(src, f.Size+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%s changed while bundling", f.Path)
	}
	_, err = w.Write(buf.Bytes())
	return err
}
