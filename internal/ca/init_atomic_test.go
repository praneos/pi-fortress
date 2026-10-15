package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestInitRaceKeepsOneRoot starts more than one initialiser at the same time
// on one pair of paths. Only one root can exist. An initialiser that loses the
// race must adopt the bundle of the winner. It must not publish its own on
// top. The cert that each initialiser leaves must be the root that is really
// in the bundle.
func TestInitRaceKeepsOneRoot(t *testing.T) {
	const rounds = 10
	const writers = 8
	for r := 0; r < rounds; r++ {
		dir := t.TempDir()
		bundle := filepath.Join(dir, "ca.pem")
		cert := filepath.Join(dir, "ca-cert.pem")

		start := make(chan struct{})
		serials := make([]string, writers)
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				if err := Init(bundle, cert); err != nil {
					errs[w] = err
					return
				}
				s, err := Load(bundle)
				if err != nil {
					errs[w] = err
					return
				}
				serials[w] = s.Root().SerialNumber.String()
			}(w)
		}
		close(start)
		wg.Wait()

		for w, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", r, w, err)
			}
		}
		for w, got := range serials {
			if got != serials[0] {
				t.Fatalf("round %d: writer %d saw root %s, writer 0 saw %s: initialisers replaced each other's CA", r, w, got, serials[0])
			}
		}
		s, err := Load(bundle)
		if err != nil {
			t.Fatalf("round %d: bundle unreadable after race: %v", r, err)
		}
		got, err := os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, s.CertPEM()) {
			t.Fatalf("round %d: published cert is not the root in the bundle", r)
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 2 {
			names := make([]string, len(ents))
			for i, e := range ents {
				names[i] = e.Name()
			}
			t.Fatalf("round %d: staging files left behind: %v", r, names)
		}
	}
}

// TestInitRefusesPlantedSymlink tests the same missing exclusive creation
// from the other side. Stat cannot see a dangling symlink at the bundle path.
// Thus an Init that only writes the file follows it and puts the CA private
// key where the link points.
func TestInitRefusesPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "ca-cert.pem")
	target := filepath.Join(t.TempDir(), "stolen.pem")
	if err := os.Symlink(target, bundle); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Init(bundle, cert); err == nil {
		t.Fatal("Init reported success through a planted symlink")
	}
	if _, err := os.Stat(target); err == nil {
		b, _ := os.ReadFile(target)
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatal("Init wrote the CA private key through a planted symlink")
		}
		t.Fatal("Init created the symlink target")
	}
}
