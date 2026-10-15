package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned builds a loadable bundle from the template that it gets. Thus
// each test can make a cert that is wrong in exactly one way, while the key
// pair stays matched and parseable.
func selfSigned(t *testing.T, tmpl *x509.Certificate) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
}

func goodRoot() *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "pf-validate-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// TestLoadPEMRejectsUnusableRoot: a bundle with a matching key pair is not
// always a CA. Each cert that this store mints chains to the bundle content.
// Thus the load must refuse a leaf put into the bundle path, a cert that
// cannot sign certs, or a cert outside its validity window. Each agent must
// not find it later as an untrusted chain.
func TestLoadPEMRejectsUnusableRoot(t *testing.T) {
	leaf := goodRoot()
	leaf.IsCA = false
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	noCertSign := goodRoot()
	noCertSign.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign

	noConstraints := goodRoot()
	noConstraints.BasicConstraintsValid = false

	expired := goodRoot()
	expired.NotBefore = time.Now().Add(-48 * time.Hour)
	expired.NotAfter = time.Now().Add(-time.Hour)

	future := goodRoot()
	future.NotBefore = time.Now().Add(24 * time.Hour)
	future.NotAfter = time.Now().Add(48 * time.Hour)

	cases := []struct {
		name string
		tmpl *x509.Certificate
		want string
	}{
		{"leaf in the bundle path", leaf, "not a ca"},
		{"no cert-signing key usage", noCertSign, "sign certificates"},
		{"no basic constraints", noConstraints, "not a ca"},
		{"expired root", expired, "expired"},
		{"root not yet valid", future, "not valid until"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPEM(selfSigned(t, tc.tmpl))
			if err == nil {
				t.Fatal("LoadPEM accepted an unusable root")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%q, want it to say %q plainly", err, tc.want)
			}
		})
	}
}

// TestLoadPEMAcceptsGoodRoot is the control: the checks above must not break
// the ordinary case.
func TestLoadPEMAcceptsGoodRoot(t *testing.T) {
	if _, err := LoadPEM(selfSigned(t, goodRoot())); err != nil {
		t.Fatal(err)
	}
}

// TestInitRefusesUnusableBundle: Init uses each bundle already on disk as the
// root that it adopts. If that bundle is not a usable CA, Init must tell this.
// If not, an engine that starts on an expired root fails all connections.
func TestInitRefusesUnusableBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "ca-cert.pem")
	expired := goodRoot()
	expired.NotBefore = time.Now().Add(-48 * time.Hour)
	expired.NotAfter = time.Now().Add(-time.Hour)
	if err := os.WriteFile(bundle, selfSigned(t, expired), 0600); err != nil {
		t.Fatal(err)
	}
	err := Init(bundle, cert)
	if err == nil {
		t.Fatal("Init adopted an expired root")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "expired") {
		t.Fatalf("err=%q, want it to name the expiry", err)
	}
	if _, serr := os.Stat(cert); serr == nil {
		t.Fatal("Init published a cert for a root it refused")
	}
}
