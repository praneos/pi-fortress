package alert

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestWebhookNeverCarriesTheBodyFingerprint guards the one path that
// actually leaves the gateway. A body hash taken after substitution comes
// from a credential, so it must never be posted. The alerter tails
// strip.jsonl, whose rows carry no hash. It posts a fixed summary, not the
// row. This test keeps both of those true: a row widened with a hash, or a
// payload changed to echo the event verbatim, fails here.
func TestWebhookNeverCarriesTheBodyFingerprint(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv, got := hookServer(t, &status)
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	const bodySHA = "5f2b9c1d0e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	const fuzzy = "T1F3A1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E5F60718293A4B5C6D7E8F9A0B1C2"
	row := `{"ev":"substitution_refused","host":"login.example.com","where":"body",` +
		`"rule":"refused:kind_not_allowed","cause":"kind_not_allowed","slot":"OAUTH",` +
		`"kind":"CANARY","alert":true,"body_sha256":"` + bodySHA + `","tlsh":"` + fuzzy + `"}` + "\n"
	if err := os.WriteFile(strip, []byte(row), 0644); err != nil {
		t.Fatal(err)
	}
	a := &Alerter{
		StripLog:   strip,
		OffsetPath: filepath.Join(dir, "off"),
		LastPath:   filepath.Join(dir, "last"),
		PolicyDirs: []string{policyDir(t, srv.URL)},
		Client:     srv.Client(),
		Stdout:     &syncBuf{},
		Stderr:     &syncBuf{},
	}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(*got) == 0 {
		t.Fatal("nothing posted")
	}
	for _, body := range *got {
		for _, blob := range []string{bodySHA, fuzzy} {
			if strings.Contains(body, blob) {
				t.Fatalf("webhook payload carries the body fingerprint %q: %s", blob, body)
			}
		}
		for _, key := range []string{"body_sha256", "tlsh"} {
			if strings.Contains(body, key) {
				t.Fatalf("webhook payload names the confined field %q: %s", key, body)
			}
		}
	}
}
