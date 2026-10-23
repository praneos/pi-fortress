package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return out
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

func publish(t *testing.T, bundle string) []*x509.Certificate {
	t.Helper()
	if err := Init(bundle, CertPath(bundle)); err != nil {
		t.Fatal(err)
	}
	if err := Publish(bundle, TrustPath(bundle)); err != nil {
		t.Fatal(err)
	}
	return readCerts(t, TrustPath(bundle))
}

func engineRoot(t *testing.T, bundle string) *x509.Certificate {
	t.Helper()
	s, err := Load(bundle)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := s.LeafFor("example.com", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Leaf.CheckSignatureFrom(s.Root()); err != nil {
		t.Fatal(err)
	}
	return s.Root()
}

// The link must carry the key of the new root and verify only from the
// root before it. That is all that an agent checks before it adds the
// new root.
func checkLink(t *testing.T, link, from, to *x509.Certificate) {
	t.Helper()
	if err := link.CheckSignatureFrom(from); err != nil {
		t.Fatalf("link is not signed by %q: %v", from.Subject.CommonName, err)
	}
	if !bytes.Equal(link.RawSubjectPublicKeyInfo, to.RawSubjectPublicKeyInfo) {
		t.Fatal("link does not carry the key of the new root")
	}
	if !link.IsCA || link.Subject.String() == to.Subject.String() {
		t.Fatalf("link must be a CA cert with a subject of its own: %q", link.Subject)
	}
}

func TestRotatePromoteRetire(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	set := publish(t, bundle)
	first := engineRoot(t, bundle)
	cert, _ := os.ReadFile(CertPath(bundle))
	trust, _ := os.ReadFile(TrustPath(bundle))
	if !bytes.Equal(cert, trust) || len(set) != 1 {
		t.Fatal("without a rotation the trust set must be the same bytes as the cert, so that a pin stays correct")
	}

	if err := Rotate(bundle, time.Now()); err != nil {
		t.Fatal(err)
	}
	set = publish(t, bundle)
	if len(set) != 3 || !set[0].Equal(first) {
		t.Fatalf("after rotate the set must be current, next, link; got %d certs", len(set))
	}
	next := set[1]
	checkLink(t, set[2], first, next)
	if !engineRoot(t, bundle).Equal(first) {
		t.Fatal("rotate changed the root that the engine signs with")
	}
	if err := Rotate(bundle, time.Now()); err == nil {
		t.Fatal("a second rotate replaced the next root")
	}
	if mode := fileMode(t, NextPath(bundle)); mode != 0600 {
		t.Fatalf("next bundle mode %o, want 0600", mode)
	}

	if err := Promote(bundle); err != nil {
		t.Fatal(err)
	}
	set = publish(t, bundle)
	if !engineRoot(t, bundle).Equal(next) {
		t.Fatal("promote did not make the engine sign with the next root")
	}
	if len(set) != 3 || !set[0].Equal(next) || !set[1].Equal(first) {
		t.Fatalf("after promote the set must be new, old, link; got %d certs", len(set))
	}
	checkLink(t, set[2], first, next)
	if c := readCerts(t, CertPath(bundle)); len(c) != 1 || !c[0].Equal(next) {
		t.Fatal("promote did not write the new root to the cert file")
	}
	if err := Rotate(bundle, time.Now()); err == nil {
		t.Fatal("rotate ran while the old root is still in the set")
	}
	roots, err := Status(bundle)
	if err != nil || len(roots) != 2 || roots[0].Role != "current" || roots[1].Role != "old" {
		t.Fatalf("status after promote: %v %v", roots, err)
	}

	if err := Retire(bundle); err != nil {
		t.Fatal(err)
	}
	set = publish(t, bundle)
	if len(set) != 1 || !set[0].Equal(next) {
		t.Fatalf("after retire the set must hold only the new root; got %d certs", len(set))
	}
	if err := Retire(bundle); err == nil {
		t.Fatal("retire with nothing to retire succeeded")
	}
}

func TestRetireBeforePromoteStopsTheRotation(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	publish(t, bundle)
	first := engineRoot(t, bundle)
	if err := Rotate(bundle, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Retire(bundle); err != nil {
		t.Fatal(err)
	}
	set := publish(t, bundle)
	if len(set) != 1 || !set[0].Equal(first) || !engineRoot(t, bundle).Equal(first) {
		t.Fatal("retire before promote must leave only the current root")
	}
	for _, p := range []string{NextPath(bundle), LinkPath(bundle)} {
		if exists(p) {
			t.Fatalf("%s is still there", p)
		}
	}
}

func TestPromoteNeedsANextRoot(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	publish(t, bundle)
	if err := Promote(bundle); err == nil {
		t.Fatal("promote without a next root succeeded")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
