package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"pi-fortress/internal/testsupport"
	"strings"
	"testing"
	"time"
)

func writeRSA(t *testing.T, dir string) (string, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testsupport.CATemplate(serial, "pi-fortress-test-ca")
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return path, root
}

func TestMintAndVerify(t *testing.T) {
	path, root := writeRSA(t, t.TempDir())
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.LeafFor("example.com", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatal("leaf is not ecdsa")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatal(err)
	}
	again, err := s.LeafFor("example.com", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if again != cert {
		t.Fatal("lru miss")
	}
}

func TestIPSAN(t *testing.T) {
	path, root := writeRSA(t, t.TempDir())
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.10")
	cert, err := s.LeafFor("", ip)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("ips=%v", cert.Leaf.IPAddresses)
	}
}

func TestInitDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "ca-cert.pem")
	if err := Init(bundle, cert); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "BEGIN CERTIFICATE") || !strings.Contains(string(first), "BEGIN PRIVATE KEY") {
		t.Fatal(string(first))
	}
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(certPEM), "PRIVATE KEY") {
		t.Fatal("agent cert must not include key")
	}
	s, err := Load(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LeafFor("example.com", netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := Init(bundle, cert); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("init overwrote existing CA")
	}
}

func TestInitRefreshesCertOnly(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "ca-cert.pem")
	if err := Init(bundle, cert); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, []byte("stale\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Init(bundle, cert); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") || strings.Contains(string(got), "stale") || strings.Contains(string(got), "PRIVATE KEY") {
		t.Fatal(string(got))
	}
}

func TestNoName(t *testing.T) {
	path, _ := writeRSA(t, t.TempDir())
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.LeafFor("", netip.Addr{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLeafRemintedBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := Init(path, ""); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.LeafFor("api.anthropic.com", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.LeafFor("api.anthropic.com", netip.Addr{}); again != first {
		t.Fatal("fresh leaf must be served from cache")
	}
	first.Leaf.NotAfter = time.Now().Add(time.Hour)
	second, err := s.LeafFor("api.anthropic.com", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if second == first || time.Until(second.Leaf.NotAfter) < 6*24*time.Hour {
		t.Fatal("leaf within renewBefore of expiry must be re-minted")
	}
	if s.ll.Len() != 1 {
		t.Fatalf("cache holds %d entries for one host", s.ll.Len())
	}
}
