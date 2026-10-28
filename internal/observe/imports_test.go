package observe

import (
	"testing"

	"pi-fortress/internal/testsupport"
)

// pf observe reads the logs of the gateway. It needs the key rules and the
// map format, not the HTTP scanner, the list compiler or the credential
// store.
func TestObserveDaemonImports(t *testing.T) {
	testsupport.NoImports(t, "internal/observe",
		"pi-fortress/internal/fence",
		"pi-fortress/internal/httpwire",
		"pi-fortress/internal/policycompile",
		"pi-fortress/internal/secrets",
		"golang.org/x/crypto/scrypt",
	)
}
