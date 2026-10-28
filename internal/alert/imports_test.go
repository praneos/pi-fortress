package alert

import (
	"testing"

	"pi-fortress/internal/testsupport"
)

// pf alert sends text about the logs. It must not link the HTTP scanner,
// the list compiler or the credential store.
func TestAlertDaemonImports(t *testing.T) {
	testsupport.NoImports(t, "internal/alert",
		"pi-fortress/internal/fence",
		"pi-fortress/internal/httpwire",
		"pi-fortress/internal/policycompile",
		"pi-fortress/internal/secrets",
		"golang.org/x/crypto/scrypt",
	)
}
