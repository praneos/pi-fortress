package ship

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name string
	typ  byte
	body string
	link string
	mode int64
	size int64
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func manifestFor(version int64, files map[string]string, exec ...string) Manifest {
	m := Manifest{Version: version, SHA: "abc"}
	for p, body := range files {
		f := File{Path: p, SHA256: sum(body), Size: int64(len(body))}
		for _, e := range exec {
			f.Exec = f.Exec || e == p
		}
		m.Files = append(m.Files, f)
	}
	return m
}

func mkTar(t testing.TB, m *Manifest, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if m != nil {
		raw, _ := json.Marshal(m)
		ents = append([]ent{{name: ManifestName, typ: tar.TypeReg, body: string(raw)}}, ents...)
	}
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode}
		if h.Mode == 0 {
			h.Mode = 0644
		}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
			if e.size != 0 {
				h.Size = e.size
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("header %q: %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	files := map[string]string{"vm/pi/apply.sh": "#!/bin/bash\n", "vm/policy/x.domains": "a.example\n"}
	good := manifestFor(10, files, "vm/pi/apply.sh")
	reg := func(name, body string) ent { return ent{name: name, typ: tar.TypeReg, body: body} }
	both := []ent{{name: "vm/", typ: tar.TypeDir}, reg("vm/pi/apply.sh", files["vm/pi/apply.sh"]), reg("vm/policy/x.domains", files["vm/policy/x.domains"])}
	with := func(extra ...ent) []ent { return append(append([]ent{}, both...), extra...) }
	withFile := func(p, body string) Manifest {
		m := manifestFor(10, map[string]string{p: body})
		return m
	}
	evil := withFile("evil", "x")
	cases := []struct {
		name string
		m    *Manifest
		ents []ent
		min  int64
		want string
	}{
		{"ok", &good, both, 9, ""},
		{"manifest not first", nil, append(both, reg(ManifestName, "{}")), 0, "first entry"},
		{"absolute", &good, with(reg("/etc/evil", "x")), 0, "bad name"},
		{"dotdot", &good, with(reg("vm/../../evil", "x")), 0, "bad name"},
		{"leading dotdot", &good, with(reg("../evil", "x")), 0, "bad name"},
		{"dot", &good, with(reg("./vm/pi/apply.sh", "x")), 0, "bad name"},
		{"dotdot dir", &good, with(ent{name: "../d/", typ: tar.TypeDir}), 0, "bad dir"},
		{"symlink", &good, with(ent{name: "vm/l", typ: tar.TypeSymlink, link: "/etc"}), 0, "not allowed"},
		{"hardlink", &good, with(ent{name: "vm/h", typ: tar.TypeLink, link: "vm/pi/apply.sh"}), 0, "not allowed"},
		{"char device", &good, with(ent{name: "vm/c", typ: tar.TypeChar}), 0, "not allowed"},
		{"fifo", &good, with(ent{name: "vm/f", typ: tar.TypeFifo}), 0, "not allowed"},
		{"unlisted", &good, with(reg("vm/extra", "x")), 0, "not in the manifest"},
		{"twice", &good, with(reg("vm/pi/apply.sh", files["vm/pi/apply.sh"])), 0, "twice"},
		{"hash mismatch", &good, []ent{reg("vm/pi/apply.sh", "#!/bin/bosh\n"), reg("vm/policy/x.domains", files["vm/policy/x.domains"])}, 0, "sha256"},
		{"size mismatch", &good, []ent{reg("vm/pi/apply.sh", "#!/bin/bash\nX"), reg("vm/policy/x.domains", files["vm/policy/x.domains"])}, 0, "size"},
		{"missing file", &good, both[:2], 0, "not the tar"},
		{"rollback equal", &good, both, 10, "rollback"},
		{"rollback older", &good, both, 11, "rollback"},
		{"dir over manifest file", &evil, []ent{{name: "evil/", typ: tar.TypeDir}, reg("evil", "x")}, 0, "is a file"},
		{"setuid masked", &evil, []ent{{name: "evil", typ: tar.TypeReg, body: "x", mode: 04777}}, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "new")
			m, err := Extract(bytes.NewReader(mkTar(t, c.m, c.ents...)), dst, DefaultLimits, c.min)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				checkTree(t, dst, m)
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if strings.HasPrefix(c.name, "rollback") && !errors.Is(err, ErrRollback) {
				t.Fatalf("not ErrRollback: %v", err)
			}
			if _, err := os.Lstat(dst); err == nil {
				t.Fatal("dst left behind after a refusal")
			}
		})
	}
}

func TestExtractCapsAndManifest(t *testing.T) {
	lim := Limits{MaxFile: 8, MaxTotal: 12, MaxFiles: 2, MaxManifest: 1 << 12}
	cases := []struct {
		name string
		m    Manifest
		want string
	}{
		{"per-file cap", manifestFor(1, map[string]string{"a": "123456789"}), "size 9"},
		{"total cap", manifestFor(1, map[string]string{"a": "12345678", "b": "12345678"}), "total"},
		{"file count", manifestFor(1, map[string]string{"a": "1", "b": "2", "c": "3"}), "3 files"},
		{"zero version", manifestFor(0, map[string]string{"a": "1"}), "version"},
		{"bad keep", func() Manifest {
			m := manifestFor(1, map[string]string{"a": "1"})
			m.Keep = []string{"../etc"}
			return m
		}(), "keep"},
		{"bad sha", func() Manifest {
			m := manifestFor(1, map[string]string{"a": "1"})
			m.Files[0].SHA256 = "zz"
			return m
		}(), "sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "new")
			_, err := Extract(bytes.NewReader(mkTar(t, &c.m)), dst, lim, 0)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// A field that this installer does not know is read past, so a newer
	// bundle still installs. A bundle that raises the format is refused.
	t.Run("unknown field", func(t *testing.T) {
		raw := `{"version":1,"files":[{"path":"a","sha256":"` + sum("1") + `","size":1}],"added_later":"x"}`
		dst := filepath.Join(t.TempDir(), "new")
		if _, err := Extract(bytes.NewReader(mkTar(t, nil, ent{name: ManifestName, typ: tar.TypeReg, body: raw}, ent{name: "a", typ: tar.TypeReg, body: "1"})), dst, lim, 0); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("newer format", func(t *testing.T) {
		raw := `{"version":1,"format":2,"files":[{"path":"a","sha256":"` + sum("1") + `","size":1}]}`
		dst := filepath.Join(t.TempDir(), "new")
		_, err := Extract(bytes.NewReader(mkTar(t, nil, ent{name: ManifestName, typ: tar.TypeReg, body: raw}, ent{name: "a", typ: tar.TypeReg, body: "1"})), dst, lim, 0)
		if err == nil || !strings.Contains(err.Error(), "newer installer") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("dst exists", func(t *testing.T) {
		m := manifestFor(1, map[string]string{"a": "1"})
		if _, err := Extract(bytes.NewReader(mkTar(t, &m, ent{name: "a", typ: tar.TypeReg, body: "1"})), t.TempDir(), lim, 0); err == nil {
			t.Fatal("extracted over an existing directory")
		}
	})
}

// checkTree: only dirs and regular files, each file listed, hash and mode
// as the manifest says.
func checkTree(t testing.TB, dst string, m *Manifest) {
	t.Helper()
	want := map[string]File{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	n := 0
	filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(dst, p)
		info, _ := d.Info()
		switch {
		case d.IsDir():
			if info.Mode().Perm() != 0755 {
				t.Fatalf("%s: dir mode %v", rel, info.Mode())
			}
		case d.Type().IsRegular():
			f, ok := want[filepath.ToSlash(rel)]
			if !ok {
				t.Fatalf("%s: not in manifest", rel)
			}
			raw, _ := os.ReadFile(p)
			if sum(string(raw)) != f.SHA256 {
				t.Fatalf("%s: hash", rel)
			}
			mode := os.FileMode(0644)
			if f.Exec {
				mode = 0755
			}
			if info.Mode() != mode {
				t.Fatalf("%s: mode %v, want %v", rel, info.Mode(), mode)
			}
			n++
		default:
			t.Fatalf("%s: type %v", rel, d.Type())
		}
		return nil
	})
	if n != len(m.Files) {
		t.Fatalf("%d files on disk, manifest %d", n, len(m.Files))
	}
}

func FuzzShipExtract(f *testing.F) {
	files := map[string]string{"a/b": "hello", "c": "x"}
	m := manifestFor(5, files, "c")
	f.Add(mkTar(f, &m, ent{name: "a/", typ: tar.TypeDir}, ent{name: "a/b", typ: tar.TypeReg, body: "hello"}, ent{name: "c", typ: tar.TypeReg, body: "x"}))
	f.Add(mkTar(f, &m, ent{name: "a/b", typ: tar.TypeSymlink, link: "../../x"}, ent{name: "c", typ: tar.TypeReg, body: "x"}))
	f.Add(mkTar(f, &m, ent{name: "../a/b", typ: tar.TypeReg, body: "hello"}))
	f.Add([]byte{})
	lim := Limits{MaxFile: 1 << 16, MaxTotal: 1 << 18, MaxFiles: 32, MaxManifest: 1 << 14}
	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dst := filepath.Join(parent, "new")
		m, err := Extract(bytes.NewReader(data), dst, lim, 1)
		ents, _ := os.ReadDir(parent)
		if err != nil {
			if len(ents) != 0 {
				t.Fatalf("refused bundle left %d entries", len(ents))
			}
			return
		}
		if len(ents) != 1 || m.Version <= 1 {
			t.Fatalf("entries %d version %d", len(ents), m.Version)
		}
		checkTree(t, dst, m)
	})
}
