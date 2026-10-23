// Package ca owns the certificate authority of the engine: the root bundle on
// disk and the cached leaf minted for each SNI. internal/engine,
// pf engine -init-ca and pf engine ca call it.
package ca

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const lruCap = 256

// renewBefore mints a cached leaf again this long before NotAfter.
const renewBefore = 24 * time.Hour

func fresh(c *tls.Certificate) bool {
	return c.Leaf != nil && time.Until(c.Leaf.NotAfter) > renewBefore
}

type Store struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	mu     sync.Mutex
	ll     *list.List
	idx    map[string]*list.Element
}

type cacheEnt struct {
	key  string
	cert *tls.Certificate
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPEM(b)
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// stage writes data to a new file beside its final destination and returns
// the name of that file. os.CreateTemp creates with O_EXCL under a name that
// no other process can predict. Thus a racing initialiser and an agent that
// plants a symlink cannot get to the staging step. A fixed staging path would
// not give this. If the code unlinks such a path first, it only adds a second
// race in which two writers delete the file of the other. The Sync is
// important because one of the two artefacts is the CA private key. The bytes
// are on disk before the file gets a name that a reader looks for. Thus an
// interrupted run leaves a full bundle or no bundle, never a half bundle.
func stage(dir string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".pf-ca-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	err = func() error {
		if err := f.Chmod(mode); err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := stage(dir, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) CertPEM() []byte {
	if s == nil || s.caCert == nil {
		return nil
	}
	return certPEM(s.caCert.Raw)
}

// adopt publishes again the public cert from the bundle already on disk. Two
// files cannot appear in one step. Thus the bundle is the one source of
// truth, and the cert is only a copy of what is in it. The worst result of an
// interrupted or losing run is a full bundle with a stale or missing cert.
// The next Init reads the bundle and corrects that. The Load occurs also
// when there is no cert to write. Thus the code reports a bundle that cannot
// be parsed here, not at the next startup.
func adopt(bundlePath, certPath string) error {
	s, err := Load(bundlePath)
	if err != nil {
		return err
	}
	if certPath == "" {
		return nil
	}
	return writeFile(certPath, s.CertPEM(), 0644)
}

// rootTemplate is the template of each root: Init makes the first, Rotate
// makes the next ones.
func rootTemplate(cn string, now time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}, nil
}

// newRoot makes a self-signed root and returns its cert+key bundle.
func newRoot(cn string, now time.Time) (der, bundle []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl, err := rootTemplate(cn, now)
	if err != nil {
		return nil, nil, nil, err
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	bundle = append(certPEM(der), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return der, bundle, key, nil
}

func Init(bundlePath, certPath string) error {
	if _, err := os.Stat(bundlePath); err == nil {
		return adopt(bundlePath, certPath)
	}
	der, bundle, _, err := newRoot("pi-fortress", time.Now())
	if err != nil {
		return err
	}
	bundleDir := filepath.Dir(bundlePath)
	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		return err
	}
	// The code stages the two full artefacts before it publishes one. Thus the
	// only remaining gap is the two metadata operations below. No reader sees a
	// cert that is ahead of its bundle by more than that.
	bundleTmp, err := stage(bundleDir, bundle, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(bundleTmp)
	certTmp := ""
	if certPath != "" {
		certDir := filepath.Dir(certPath)
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return err
		}
		if certTmp, err = stage(certDir, certPEM(der), 0644); err != nil {
			return err
		}
		defer os.Remove(certTmp)
	}
	// os.Link refuses to replace a name that already exists. Thus the first
	// initialiser that gets here owns the root. Each later initialiser loses and
	// adopts it. A rename would let the root of the loser quietly replace the
	// root of the winner. This is the CA key of a TLS-terminating gateway. A
	// root replaced under a running engine is an identity change that nobody
	// requested and nothing reports. Link refuses a planted symlink for the
	// same reason that it refuses a real file. Thus the key also cannot go to
	// a path that the agent selects.
	if err := os.Link(bundleTmp, bundlePath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return adopt(bundlePath, certPath)
		}
		return err
	}
	if certTmp == "" {
		return nil
	}
	return os.Rename(certTmp, certPath)
}

// ErrUnusableRoot starts each refusal of a bundle that loads but cannot be a
// certificate authority. Init also reports it, because Init adopts the
// bundle that it finds on disk.
var ErrUnusableRoot = errors.New("ca: bundle is not a usable certificate authority")

// checkRoot refuses a bundle that is not a CA from which the engine can really
// issue. A matching key pair shows only that the two PEM blocks are a pair. It
// does not show that the cert can sign. These all load correctly and then mint
// leaves that no client accepts:
//   - A leaf put into the bundle path.
//   - A root without certSign.
//   - A root outside its validity window.
//
// Without this check, the failure would show as a TLS error on each
// connection, with nothing that names the cause.
//
// checkRoot refuses an expired root. It does not use it. If it accepted it,
// the box would still not work: the TLS stacks of the agents reject a chain to
// an expired root in the same way. Thus the choice is not "soft failure vs
// hard outage". It is "one loud failure at startup vs the same outage on all
// connections with no explanation". A clock with enough drift to make a
// ten-year root invalid breaks the handshake by itself. Thus the two messages
// name the window, the clock that this machine reads, and the two actions
// that an operator can do.
func checkRoot(c *x509.Certificate, now time.Time) error {
	const stamp = time.RFC3339
	name := c.Subject.CommonName
	if name == "" {
		name = c.Subject.String()
	}
	if !c.IsCA || !c.BasicConstraintsValid {
		return fmt.Errorf("%w: %q is not a CA certificate (no CA basic constraint); the bundle holds a leaf, not a root: point -ca at the real bundle or create one with pf engine -init-ca", ErrUnusableRoot, name)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: %q may not sign certificates (its key usage has no certSign); nothing it issues would be trusted: create a new root with pf engine -init-ca", ErrUnusableRoot, name)
	}
	if now.Before(c.NotBefore) {
		return fmt.Errorf("%w: %q is not valid until %s and this machine's clock reads %s; certificates it issues would be rejected: fix the clock (check NTP), then start the engine again", ErrUnusableRoot, name, c.NotBefore.UTC().Format(stamp), now.UTC().Format(stamp))
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("%w: %q expired at %s and this machine's clock reads %s; every certificate it issues would be rejected: fix the clock if it is wrong, otherwise move the old bundle aside, run pf engine -init-ca and re-install the new root on the agents", ErrUnusableRoot, name, c.NotAfter.UTC().Format(stamp), now.UTC().Format(stamp))
	}
	return nil
}

func LoadPEM(pemBytes []byte) (*Store, error) {
	tc, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return nil, err
	}
	if len(tc.Certificate) == 0 {
		return nil, errors.New("ca: empty cert")
	}
	parsed, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := tc.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca: key is not a signer")
	}
	if err := checkRoot(parsed, time.Now()); err != nil {
		return nil, err
	}
	return &Store{
		caCert: parsed,
		caKey:  signer,
		ll:     list.New(),
		idx:    make(map[string]*list.Element),
	}, nil
}

func (s *Store) Root() *x509.Certificate {
	return s.caCert
}

func (s *Store) LeafFor(sni string, orig netip.Addr) (*tls.Certificate, error) {
	key := strings.ToLower(strings.TrimSuffix(sni, "."))
	if key == "" {
		if !orig.IsValid() {
			return nil, errors.New("ca: no sni or ip")
		}
		key = "ip:" + orig.String()
	}
	s.mu.Lock()
	if el, ok := s.idx[key]; ok {
		cert := el.Value.(*cacheEnt).cert
		if fresh(cert) {
			s.ll.MoveToFront(el)
			s.mu.Unlock()
			return cert, nil
		}
		// A hot host never leaves the LRU. Thus the code must evict an
		// expiring leaf here. If not, the agent sees an expired certificate forever.
		s.ll.Remove(el)
		delete(s.idx, key)
	}
	s.mu.Unlock()
	cert, err := s.mint(key, sni, orig)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.idx[key]; ok && fresh(el.Value.(*cacheEnt).cert) {
		s.ll.MoveToFront(el)
		return el.Value.(*cacheEnt).cert, nil
	}
	el := s.ll.PushFront(&cacheEnt{key: key, cert: cert})
	s.idx[key] = el
	for s.ll.Len() > lruCap {
		back := s.ll.Back()
		s.ll.Remove(back)
		delete(s.idx, back.Value.(*cacheEnt).key)
	}
	return cert, nil
}

func (s *Store) mint(key, sni string, orig netip.Addr) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	name := sni
	if name == "" {
		name = orig.String()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if strings.HasPrefix(key, "ip:") {
		ip := orig
		if !ip.IsValid() {
			ip, _ = netip.ParseAddr(strings.TrimPrefix(key, "ip:"))
		}
		if ip.IsValid() {
			tmpl.IPAddresses = []net.IP{net.IP(ip.AsSlice())}
		}
	} else {
		tmpl.DNSNames = []string{strings.ToLower(strings.TrimSuffix(sni, "."))}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &priv.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}
