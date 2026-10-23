package doctor

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/ca"
)

func root(role string, notAfter time.Time) ca.Root {
	return ca.Root{Role: role, Cert: &x509.Certificate{Subject: pkix.Name{CommonName: "pi-fortress"}, NotAfter: notAfter}}
}

func TestCARootRung(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	far, soon := now.AddDate(9, 0, 0), now.AddDate(0, 0, 30)
	for _, tc := range []struct {
		name  string
		roots []ca.Root
		err   error
		st    Status
		want  string
	}{
		{"ok", []ca.Root{root("current", far)}, nil, OK, "sudo pf engine ca rotate"},
		{"expires soon", []ca.Root{root("current", soon)}, nil, Warn, "expires in 30 days"},
		{"expired", []ca.Root{root("current", now.Add(-time.Hour))}, nil, Fail, "enrol each agent again"},
		{"rotating", []ca.Root{root("current", soon), root("next", far)}, nil, Warn, "then sudo pf engine ca promote"},
		{"promoted", []ca.Root{root("current", far), root("old", soon)}, nil, OK, "sudo pf engine ca retire"},
		{"not root", nil, fmt.Errorf("open: %w", fs.ErrPermission), Warn, "sudo pf doctor"},
	} {
		r, ok := CARootRung(tc.roots, tc.err, now)
		if !ok || r.Status != tc.st || !strings.Contains(r.Detail, tc.want) {
			t.Errorf("%s: %v %v %q, want %v with %q", tc.name, ok, r.Status, r.Detail, tc.st, tc.want)
		}
	}
	if _, ok := CARootRung(nil, fmt.Errorf("open: %w", fs.ErrNotExist), now); ok {
		t.Error("a box with no engine bundle got a ca root rung")
	}
}

// The rung reads what pf engine ca writes.
func TestCARootRungReadsTheBundle(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := ca.Init(bundle, ""); err != nil {
		t.Fatal(err)
	}
	if err := ca.Rotate(bundle, time.Now()); err != nil {
		t.Fatal(err)
	}
	roots, err := ca.Status(bundle)
	r, ok := CARootRung(roots, err, time.Now())
	if !ok || r.Status != OK || !strings.Contains(r.Detail, "current pi-fortress sha256:") || !strings.Contains(r.Detail, "; next pi-fortress ") {
		t.Fatalf("%v %v %q", ok, r.Status, r.Detail)
	}
	roots, err = ca.Status(filepath.Join(t.TempDir(), "none.pem"))
	if _, ok := CARootRung(roots, err, time.Now()); ok {
		t.Fatal("a missing bundle got a rung")
	}
}
