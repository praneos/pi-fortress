package feedstage

import (
	"os/exec"
	"strings"
	"testing"
)

// The import runs as root. It reads lines and the eyeball table, and
// nothing else. Thus its import graph has no HTTP or TLS client, no
// decompressor, no CSV reader and no feed parser of internal/fetch.
func TestImportGraphHasNoNetworkClientOrFeedParser(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list -deps gave %d packages", len(deps))
	}
	for _, p := range deps {
		switch {
		case p == "net/http", strings.HasPrefix(p, "net/http/"),
			p == "crypto/tls", p == "crypto/x509",
			strings.HasPrefix(p, "compress/"),
			p == "encoding/csv",
			p == "os/exec",
			p == "pi-fortress/internal/fetch":
			t.Errorf("internal/feedstage depends on %s", p)
		}
	}
}
