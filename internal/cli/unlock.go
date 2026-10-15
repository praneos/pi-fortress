package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/audit"
	"pi-fortress/internal/secrets"
)

// pf unlock is the human in the reboot path. All other parts of the box
// come back automatically: the house and agent segments, DNS, DHCP,
// routing, the ruleset, the fence itself. Only credential substitution
// waits for this. That is the cost of sealing, and it cannot be hidden.
// After a power cut at 03:00, the agents run. Each request that needs a
// credential gets the same refusal as each other cause, until someone
// types this.
func runUnlock(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("unlock", stderr)
	sock := fs.String("sock", secrets.AdminSock, "broker admin socket")
	lock := fs.Bool("lock", false, "drop the key instead of entering one")
	state := fs.Bool("state", false, "print whether the store is sealed and open")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	c := &admin.Config{BrokerAdmin: *sock}
	ctx := context.Background()

	switch {
	case *state:
		st, err := c.SecretsState(ctx)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, st)
		return 0
	case *lock:
		err := c.LockSecrets(ctx)
		logUnlock("secrets.lock", err)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "locked")
		return 0
	}

	pass, err := secrets.ReadPassphrase("Passphrase: ", stdout)
	if err != nil {
		return fail(stderr, err)
	}
	err = c.UnlockSecrets(ctx, string(pass))
	logUnlock("secrets.unlock", err)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "unlocked")
	return 0
}

// logUnlock records an unlock attempt: who did it, and if it worked.
// This is probably the line with the highest value in the audit log. It
// has no Args: the only argument was the passphrase, and that never
// goes to disk.
func logUnlock(verb string, err error) {
	e := audit.Entry{
		Verb:  verb,
		Role:  "admin",
		Actor: audit.Actor(os.Getenv, os.Getuid()),
		OK:    err == nil,
	}
	if err != nil {
		e.Err = err.Error()
	}
	_ = audit.New(audit.DefaultPath).Append(e)
}
