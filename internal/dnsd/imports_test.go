package dnsd

import (
	"testing"

	"pi-fortress/internal/testsupport"
)

// The resolver parses the packets of the agent network. A reviewer reads
// this package and what it imports, so the list is short on purpose: no
// HTTP scanner, list compiler or credential store with its key derivation.
// A helper that the resolver needs from one of these packages belongs in a
// small package that both import.
func TestDNSDaemonImports(t *testing.T) {
	testsupport.NoImports(t, "internal/dnsd",
		"pi-fortress/internal/fence",
		"pi-fortress/internal/httpwire",
		"pi-fortress/internal/pctdecode",
		"pi-fortress/internal/policycompile",
		"pi-fortress/internal/secrets",
		"pi-fortress/internal/secretscan",
		"golang.org/x/crypto/pbkdf2",
		"golang.org/x/crypto/scrypt",
	)
}
