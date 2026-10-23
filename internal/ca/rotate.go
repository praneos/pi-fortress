package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A rotation keeps its files beside the bundle that the engine loads. The
// names come from the name of the bundle. For ca.pem they are:
//
//	ca-cert.pem   the cert of the bundle (Init writes it)
//	ca-next.pem   cert and key of the next root (Rotate writes it)
//	ca-link.pem   the key of the newest root, signed by the root before it
//	ca-old.pem    the cert of the root that Promote replaced
//	ca-trust.pem  the certs that agents trust (Publish writes it)
//
// The engine reads only the bundle. Thus it signs with one root at all
// times. Agents fetch the trust set. During a rotation the set holds two
// roots and the link. An agent adds a new root only when a root that it
// already trusts signed the link to the key of that root (vm/agent/routes.sh
// pick_ca). Thus a device that answers for the Pi on the agent cable cannot
// add a root of its own to the same file.
func sibling(bundlePath, role string) string {
	ext := filepath.Ext(bundlePath)
	return strings.TrimSuffix(bundlePath, ext) + "-" + role + ext
}

func CertPath(bundlePath string) string  { return sibling(bundlePath, "cert") }
func NextPath(bundlePath string) string  { return sibling(bundlePath, "next") }
func LinkPath(bundlePath string) string  { return sibling(bundlePath, "link") }
func OldPath(bundlePath string) string   { return sibling(bundlePath, "old") }
func TrustPath(bundlePath string) string { return sibling(bundlePath, "trust") }

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// firstCert reads the first certificate in a PEM file. It does not do the
// checks of Load: Status and Publish must also show a root that expired.
func firstCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return nil, fmt.Errorf("ca: %s holds no certificate", path)
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// Rotate makes a next root and a link to it, signed by the current root.
// The engine continues to sign with the current root. Publish then adds
// the two to the trust set.
func Rotate(bundlePath string, now time.Time) error {
	cur, err := Load(bundlePath)
	if err != nil {
		return err
	}
	if exists(NextPath(bundlePath)) {
		return errors.New("ca: a next root exists already: promote it, or retire it to stop the rotation")
	}
	if exists(OldPath(bundlePath)) {
		return errors.New("ca: the old root is still in the trust set: retire it first")
	}
	cn := "pi-fortress " + now.UTC().Format("2006-01-02 15:04:05")
	der, bundle, key, err := newRoot(cn, now)
	if err != nil {
		return err
	}
	next, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	// The link has its own subject. Thus no chain to a leaf goes through it,
	// also when an agent puts it in its trust store with the roots.
	notAfter := next.NotAfter
	if cur.caCert.NotAfter.Before(notAfter) {
		notAfter = cur.caCert.NotAfter
	}
	link := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn + " (link)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	linkDER, err := x509.CreateCertificate(rand.Reader, link, cur.caCert, &key.PublicKey, cur.caKey)
	if err != nil {
		return err
	}
	// The link first. If the run stops between the two writes, the link is
	// alone, and no agent finds a root with its key.
	if err := writeFile(LinkPath(bundlePath), certPEM(linkDER), 0644); err != nil {
		return err
	}
	return writeFile(NextPath(bundlePath), bundle, 0600)
}

// Promote makes the next root the root of the engine. The replaced root
// stays in the trust set as the old root until Retire. The engine uses the
// new root after its next start.
func Promote(bundlePath string) error {
	next := NextPath(bundlePath)
	if !exists(next) {
		return errors.New("ca: no next root: run pf engine ca rotate first")
	}
	if _, err := Load(next); err != nil {
		return err
	}
	cur, err := firstCert(bundlePath)
	if err != nil {
		return err
	}
	if err := writeFile(OldPath(bundlePath), certPEM(cur.Raw), 0644); err != nil {
		return err
	}
	// The engine user must read the new bundle, as it read the old one.
	if err := sameOwner(next, bundlePath); err != nil {
		return err
	}
	return os.Rename(next, bundlePath)
}

func sameOwner(dst, ref string) error {
	fi, err := os.Stat(ref)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(dst, int(st.Uid), int(st.Gid))
}

// Retire removes the root that the engine does not use from the trust set:
// the old root after Promote, or the next root before Promote. The second
// case stops a rotation.
func Retire(bundlePath string) error {
	var drop string
	switch {
	case exists(OldPath(bundlePath)):
		drop = OldPath(bundlePath)
	case exists(NextPath(bundlePath)):
		drop = NextPath(bundlePath)
	default:
		return errors.New("ca: no old or next root to retire")
	}
	if err := os.Remove(drop); err != nil {
		return err
	}
	if err := os.Remove(LinkPath(bundlePath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Publish writes the trust set: the current root, then the next root, the
// old root and the link, each one time. Without a rotation, the set is the
// same bytes as the cert that Init writes. Thus a pin of that cert stays
// correct.
func Publish(bundlePath, trustPath string) error {
	var out []byte
	seen := map[string]bool{}
	for i, p := range []string{bundlePath, NextPath(bundlePath), OldPath(bundlePath), LinkPath(bundlePath)} {
		c, err := firstCert(p)
		if i > 0 && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if seen[string(c.Raw)] {
			continue
		}
		seen[string(c.Raw)] = true
		out = append(out, certPEM(c.Raw)...)
	}
	return writeFile(trustPath, out, 0644)
}

// Root is one root of the engine and its role: current, next or old.
type Root struct {
	Role string
	Cert *x509.Certificate
}

// Status returns the current root, then the next and the old root when
// they exist.
func Status(bundlePath string) ([]Root, error) {
	cur, err := firstCert(bundlePath)
	if err != nil {
		return nil, err
	}
	roots := []Root{{"current", cur}}
	for _, r := range []struct{ role, path string }{{"next", NextPath(bundlePath)}, {"old", OldPath(bundlePath)}} {
		c, err := firstCert(r.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return roots, err
		}
		roots = append(roots, Root{r.role, c})
	}
	return roots, nil
}
