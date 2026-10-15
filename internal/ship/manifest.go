// Package ship builds, verifies and installs a signed release bundle: a tar
// of the tree that pf apply reads, with a first manifest that names each
// file, its sha256 and a monotonic version. The desktop builds and signs it.
// The Pi verifies the signature, refuses rollbacks, extracts strictly and
// swaps the tree in (docs/signed_ship.md).
package ship

import (
	"archive/tar"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// ManifestName is the tar's first entry.
const ManifestName = "pf-ship.json"

// Limits bound what a bundle may unpack to. The tree is ~25 MiB today.
type Limits struct {
	MaxFile     int64
	MaxTotal    int64
	MaxFiles    int
	MaxManifest int64
}

var DefaultLimits = Limits{
	MaxFile:     128 << 20,
	MaxTotal:    384 << 20,
	MaxFiles:    20000,
	MaxManifest: 4 << 20,
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Exec   bool   `json:"exec,omitempty"`
}

type Manifest struct {
	Version int64  `json:"version"`
	SHA     string `json:"sha"`
	Files   []File `json:"files"`
	// Keep names paths whose copy on the Pi wins over the bundle copy: the
	// policy lists that the operator edits (shipped as seeds), generated/
	// and alert.url (not shipped at all).
	Keep []string `json:"keep"`
	// StateMin and StateMax are the on-disk state versions (state.go)
	// that the binary of this bundle can read. A bundle built before this
	// field existed carries neither. EffectiveStateMax treats that as 1:
	// the only state version that a build that old could have produced
	// (docs/signed_ship.md, "State version").
	StateMin int64 `json:"state_min,omitempty"`
	StateMax int64 `json:"state_max,omitempty"`
	// Format increases only for a field that an older installer must
	// refuse, not skip. It is omitted while it is 1. Thus installers from
	// before it existed can still read a bundle.
	Format int64 `json:"format,omitempty"`
}

// ManifestFormat is the highest Format this installer understands.
const ManifestFormat = 1

// legacyStateMax is what a manifest predating StateMin/StateMax is
// treated as declaring.
const legacyStateMax = 1

// EffectiveStateMax is m.StateMax, or legacyStateMax when the bundle
// predates the field.
func (m *Manifest) EffectiveStateMax() int64 {
	if m.StateMax == 0 {
		return legacyStateMax
	}
	return m.StateMax
}

// CleanRel reports whether p is a relative, slash-separated path with no
// empty, "." or ".." component and no NUL or backslash.
func CleanRel(p string) bool {
	if p == "" || len(p) > 1024 || strings.ContainsAny(p, "\x00\\") || p[0] == '/' {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	for c := range strings.SplitSeq(p, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

func (m *Manifest) Validate(lim Limits) error {
	if m.Version <= 0 {
		return fmt.Errorf("manifest: version %d", m.Version)
	}
	if len(m.Files) == 0 || len(m.Files) > lim.MaxFiles {
		return fmt.Errorf("manifest: %d files", len(m.Files))
	}
	seen := make(map[string]bool, len(m.Files))
	var total int64
	for _, f := range m.Files {
		if !CleanRel(f.Path) || f.Path == ManifestName {
			return fmt.Errorf("manifest: bad path %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("manifest: %s listed twice", f.Path)
		}
		seen[f.Path] = true
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("manifest: %s: bad sha256", f.Path)
		}
		if f.Size < 0 || f.Size > lim.MaxFile {
			return fmt.Errorf("manifest: %s: size %d", f.Path, f.Size)
		}
		total += f.Size
		if total > lim.MaxTotal {
			return fmt.Errorf("manifest: total size over %d", lim.MaxTotal)
		}
	}
	for _, k := range m.Keep {
		if !CleanRel(k) {
			return fmt.Errorf("manifest: bad keep path %q", k)
		}
	}
	if m.StateMin < 0 || m.StateMax < 0 {
		return fmt.Errorf("manifest: negative state version")
	}
	if m.StateMin != 0 && m.StateMax != 0 && m.StateMin > m.StateMax {
		return fmt.Errorf("manifest: state_min %d > state_max %d", m.StateMin, m.StateMax)
	}
	return nil
}

// PeekManifest reads only the first manifest entry of a bundle tar. It
// does not extract or verify anything else. pf rollback reads the
// declared state version of the kept release before it touches the live tree.
func PeekManifest(path string, lim Limits) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if hdr.Name != ManifestName {
		return nil, fmt.Errorf("%s: first entry is %q, not %s", path, hdr.Name, ManifestName)
	}
	return ReadManifest(tr, lim)
}

func ReadManifest(r io.Reader, lim Limits) (*Manifest, error) {
	raw, err := io.ReadAll(io.LimitReader(r, lim.MaxManifest+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > lim.MaxManifest {
		return nil, fmt.Errorf("manifest over %d bytes", lim.MaxManifest)
	}
	// Unknown fields are read past, not refused. Before, a refusal made
	// each new field (state_min, 2026-09-27) a wall that no deployed
	// installer could climb over: the box had to be upgraded out of band
	// first. A field that an older installer must not skip raises Format
	// in its place, and the installer refuses that by name.
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format > ManifestFormat {
		return nil, fmt.Errorf("manifest format %d needs a newer installer than this one (%d): ship once with make pi-ship-sudo, or pf install the bundle", m.Format, ManifestFormat)
	}
	if err := m.Validate(lim); err != nil {
		return nil, err
	}
	return &m, nil
}
