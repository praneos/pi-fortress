package www

import (
	"testing"

	"pi-fortress/internal/testsupport"
)

// pf www takes input from a browser. It needs the slot and kind rules of
// the credential store. It does not need the enroll command, the fence or
// the list compiler.
func TestWWWDaemonImports(t *testing.T) {
	testsupport.NoImports(t, "internal/www",
		"pi-fortress/internal/enroll",
		"pi-fortress/internal/fence",
		"pi-fortress/internal/httpwire",
		"pi-fortress/internal/policycompile",
	)
}
