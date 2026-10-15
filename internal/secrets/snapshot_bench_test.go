package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func benchStore(b *testing.B) *Store {
	b.Helper()
	dir := b.TempDir()
	path := filepath.Join(dir, "secrets.env")
	var body, off, exp strings.Builder
	for i := range 32 {
		id := fmt.Sprintf("%016x", 0xa1b2c3d4e5f60000+uint64(i))
		body.WriteString(EnvKey(id, "CLAUDE_OAT") + "=sk-ant-oat01-" + id + "\n")
		body.WriteString(EnvKey(id, "CLAUDE_ORT") + "=sk-ant-ort01-" + id + "\n")
		if i%4 == 0 {
			off.WriteString(id + " 1700000000\n")
		}
		if i%3 == 0 {
			exp.WriteString(fmt.Sprintf("%s %d\n", id, time.Now().Add(time.Hour).Unix()))
		}
	}
	if err := os.WriteFile(path, []byte(body.String()), 0600); err != nil {
		b.Fatal(err)
	}
	st := Open(path)
	if err := os.WriteFile(st.DisabledPath(), []byte(off.String()), 0640); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(st.ExpiresPath(), []byte(exp.String()), 0640); err != nil {
		b.Fatal(err)
	}
	return st
}

func BenchmarkSnapshotCached(b *testing.B) {
	st := benchStore(b)
	if _, err := st.Snapshot(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := st.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSnapshotReload(b *testing.B) {
	st := benchStore(b)
	b.ReportAllocs()
	for b.Loop() {
		st.mu.Lock()
		st.cache = nil
		st.mu.Unlock()
		if _, err := st.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}
