package cli

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/ship"
)

// rollbackToUsage answers the -to that rollback no longer has. Rollback
// goes back to .prev and to no other location. pf upgrade moves forward.
const rollbackToUsage = "pf rollback goes back one version only (to the release before this one); to install a newer release use pf upgrade -version"

// runRollback is pf rollback (docs/signed_ship.md, "Rollback and kept
// releases"): it swaps .prev back in and re-applies.
func runRollback(args []string, _, stderr io.Writer) int {
	for _, a := range args {
		if a == "--" {
			break
		}
		if name, _, _ := strings.Cut(a, "="); name == "-to" || name == "--to" {
			fmt.Fprintln(stderr, rollbackToUsage)
			return 2
		}
	}
	fs := newFlags("rollback", stderr)
	withState := fs.Bool("with-state", false, "also restore the kept state.tar over /etc/pi-fortress and /var/lib/pi-fortress before the re-apply: the one taken just before the current release replaced .prev")
	force := fs.Bool("force", false, "roll back even though the target build's state_max is below this box's state.version")
	in := shipInstallerFlags(fs, stderr)
	fs.StringVar(&in.EtcDir, "etc-dir", "/etc/pi-fortress", "restored by -with-state")
	fs.StringVar(&in.LibDir, "lib-dir", "/var/lib/pi-fortress", "restored by -with-state")
	fs.StringVar(&in.StateVersionPath, "state-version-file", ship.DefaultStateVersionPath, "on-disk state schema version")
	pf := fs.String("pf", "/usr/local/sbin/pf", "pf binary that runs apply")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	release, err := shipExclusive(in)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf rollback: %w", err))
	}
	defer release()
	in.Lock = func() (func(), error) {
		l, err := admin.TryLock(admin.ApplyLockPath)
		if err != nil {
			return nil, err
		}
		return l.Release, nil
	}
	in.Apply = func() error {
		cmd := exec.Command(applyPF(in.Dir, *pf), "apply")
		cmd.Stdout, cmd.Stderr = stderr, stderr
		return cmd.Run()
	}
	row, err := in.Rollback(ship.RollbackOptions{WithState: *withState, Force: *force})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stderr, "pf rollback: now at version %d (%s)\n", row.Version, time.Now().Format(time.RFC3339))
	return 0
}
