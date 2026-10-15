package ship

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrRollback = errors.New("rollback")

// Extract unpacks a bundle into dst, which must not exist. The manifest
// comes first and is checked against minVersion before anything is written.
// Only regular files listed in the manifest, and directories, are accepted.
// Sizes and hashes must match, and modes are 0644 or 0755. On any error, dst
// is removed, and the manifest, if one was read, is still returned for the log.
func Extract(r io.Reader, dst string, lim Limits, minVersion int64) (m *Manifest, err error) {
	if err := os.Mkdir(dst, 0755); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dst)
		}
	}()
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if hdr.Name != ManifestName || !regular(hdr.Typeflag) || hdr.Size > lim.MaxManifest {
		return nil, fmt.Errorf("bundle: first entry must be %s", ManifestName)
	}
	if m, err = ReadManifest(tr, lim); err != nil {
		return nil, err
	}
	if m.Version <= minVersion {
		return m, fmt.Errorf("%w: version %d is not newer than installed %d", ErrRollback, m.Version, minVersion)
	}
	want := make(map[string]File, len(m.Files))
	for _, f := range m.Files {
		want[f.Path] = f
	}
	done := make(map[string]bool, len(m.Files))
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, fmt.Errorf("bundle: %w", err)
		}
		if entries++; entries > 2*lim.MaxFiles {
			return m, fmt.Errorf("bundle: over %d entries", 2*lim.MaxFiles)
		}
		name := hdr.Name
		switch {
		case hdr.Typeflag == tar.TypeDir:
			name = strings.TrimSuffix(name, "/")
			if !CleanRel(name) || name == ManifestName {
				return m, fmt.Errorf("bundle: bad dir name %q", hdr.Name)
			}
			if _, isFile := want[name]; isFile {
				return m, fmt.Errorf("bundle: %s is a file in the manifest", name)
			}
			if err := os.MkdirAll(filepath.Join(dst, name), 0755); err != nil {
				return m, err
			}
		case regular(hdr.Typeflag):
			if !CleanRel(name) {
				return m, fmt.Errorf("bundle: bad name %q", name)
			}
			f, ok := want[name]
			if !ok {
				return m, fmt.Errorf("bundle: %s is not in the manifest", name)
			}
			if done[name] {
				return m, fmt.Errorf("bundle: %s twice", name)
			}
			if hdr.Size != f.Size {
				return m, fmt.Errorf("bundle: %s: size %d, manifest %d", name, hdr.Size, f.Size)
			}
			if total += f.Size; total > lim.MaxTotal {
				return m, fmt.Errorf("bundle: total size over %d", lim.MaxTotal)
			}
			if err := writeFile(filepath.Join(dst, name), tr, f); err != nil {
				return m, fmt.Errorf("bundle: %s: %w", name, err)
			}
			done[name] = true
		default:
			return m, fmt.Errorf("bundle: %s: entry type %q is not allowed", name, hdr.Typeflag)
		}
	}
	if len(done) != len(want) {
		for _, f := range m.Files {
			if !done[f.Path] {
				return m, fmt.Errorf("bundle: %s is in the manifest but not the tar", f.Path)
			}
		}
	}
	return m, nil
}

func regular(t byte) bool { return t == tar.TypeReg || t == '\x00' }

func writeFile(p string, r io.Reader, f File) error {
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	mode := os.FileMode(0644)
	if f.Exec {
		mode = 0755
	}
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, f.Size+1))
	if err == nil {
		err = out.Chmod(mode)
	}
	// The tree that this writes becomes live in one rename, and the
	// reboot that a ship usually causes follows soon after. Close only
	// gives the bytes to the page cache. Without this, the exchange can
	// publish a tree of empty or half-written files that no later run
	// examines. The caller flushes the directories that name them.
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Size {
		return fmt.Errorf("size %d, manifest %d", n, f.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("sha256 %s, manifest %s", got, f.SHA256)
	}
	return nil
}
