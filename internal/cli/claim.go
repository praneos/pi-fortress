package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/audit"
	"pi-fortress/internal/secrets"
)

// runClaim issues a one-time claim code for a slot. It does the same as
// 'c' on the Secrets screen of the TUI, without a terminal. It is for an
// unattended enrolment, for example the first boot of the appliance. It
// uses the same verb, the same audit line, and the same claims dir.
func runClaim(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("claim", stderr)
	slot := fs.String("slot", "", "slot to issue a claim code for (pf enroll list)")
	secretsPath := fs.String("secrets", "", "secrets.env (default: the broker's store)")
	wwwDir := fs.String("www", "", "www directory holding claims/ (default /var/lib/pi-fortress/www)")
	auditPath := fs.String("audit", audit.DefaultPath, "audit log")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if strings.TrimSpace(*slot) == "" {
		fmt.Fprintln(stderr, "usage: pf claim -slot SLOT")
		return 2
	}
	c := admin.Defaults()
	if *secretsPath != "" {
		c.SecretsPath = *secretsPath
		c.Store = secrets.Open(*secretsPath)
	}
	if *wwwDir != "" {
		c.WWWDir = *wwwDir
	}
	c.Audit = audit.New(*auditPath)
	v, err := c.Call(admin.RoleAdmin, "claim.issue", admin.Args{Name: *slot})
	if err != nil {
		return fail(stderr, err)
	}
	cl, ok := v.(admin.Claim)
	if !ok {
		return fail(stderr, fmt.Errorf("claim.issue returned %T", v))
	}
	fmt.Fprintf(stdout, "code=%s\nslot=%s\nexpires=%s\ncommand=%s\n",
		cl.Code, cl.Slot, cl.Expires.UTC().Format(time.RFC3339), cl.Command)
	return 0
}
