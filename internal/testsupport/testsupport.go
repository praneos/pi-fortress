// Package testsupport holds helpers that the package tests share. Nothing
// in the shipped binaries imports it.
package testsupport

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// RepoRoot is the checkout root, resolved from the file that calls it.
// Each caller is two directories below the root.
func RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// ReadFile is os.ReadFile as a string, fatal on error.
func ReadFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// CATemplate is the self-signed CA that the tests sign for themselves. The
// caller gives the key. Thus the caller selects the algorithm.
func CATemplate(serial *big.Int, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}
