package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/ca"
)

const engineCAUsage = "usage: pf engine ca status|rotate|promote|retire [-ca FILE] [-apply=false]"

// runEngineCA changes the roots of the engine in two steps, with an
// overlap (docs/fence.md, "Egress CA rotation"):
//
//	rotate   add a next root to the trust set; the engine signs with the current root
//	promote  the engine signs with the next root; the old root stays in the set
//	retire   remove the root that the engine does not use from the set
//
// Each verb that changes a root holds the apply lock, writes the cert and
// the trust set again, and then runs pf apply. apply copies the trust set
// to www and restarts the engine. Thus the verb and apply never write the
// same files at the same time.
func runEngineCA(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("engine ca", stderr)
	caPath := fs.String("ca", "/var/lib/pi-fortress/engine/ca.pem", "CA cert+key PEM of the engine")
	runApply := fs.Bool("apply", true, "run pf apply after the change, to serve the trust set and restart the engine")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, engineCAUsage)
	if !ok {
		return code
	}
	var step func() error
	switch verb {
	case "status":
		return printCAStatus(stdout, stderr, *caPath)
	case "rotate":
		step = func() error { return ca.Rotate(*caPath, time.Now()) }
	case "promote":
		step = func() error { return ca.Promote(*caPath) }
	case "retire":
		step = func() error { return ca.Retire(*caPath) }
	default:
		fmt.Fprintln(stderr, engineCAUsage)
		return 2
	}
	lock, err := admin.TryLock(applyLockPath)
	if err != nil {
		fail(stderr, fmt.Errorf("pf engine ca %s: %w", verb, err))
		if errors.Is(err, admin.ErrLocked) {
			return 75
		}
		return 1
	}
	defer lock.Release()
	start := time.Now()
	err = step()
	if err == nil {
		err = ca.Init(*caPath, ca.CertPath(*caPath))
	}
	if err == nil {
		err = ca.Publish(*caPath, ca.TrustPath(*caPath))
	}
	logTool("engine ca "+verb, map[string]string{"ca": *caPath}, time.Since(start), err)
	if err != nil {
		return fail(stderr, err)
	}
	if code := printCAStatus(stdout, stderr, *caPath); code != 0 {
		return code
	}
	if !*runApply {
		fmt.Fprintln(stdout, "run sudo pf apply to serve the trust set and restart the engine")
		return 0
	}
	// The lock descriptor stays open through the exec, as in runApply.
	return runScript("apply", nil, stderr)
}

// printCAStatus prints each root with its fingerprint and end date, the
// sha256 of the trust set, and the next step of a rotation.
func printCAStatus(stdout, stderr io.Writer, caPath string) int {
	roots, err := ca.Status(caPath)
	if err != nil {
		return fail(stderr, err)
	}
	roles := map[string]bool{}
	for _, r := range roots {
		roles[r.Role] = true
		sum := sha256.Sum256(r.Cert.Raw)
		fmt.Fprintf(stdout, "%-8s %s  sha256:%s  not after %s\n", r.Role, r.Cert.Subject.CommonName,
			hex.EncodeToString(sum[:8]), r.Cert.NotAfter.UTC().Format("2006-01-02"))
	}
	if raw, err := os.ReadFile(ca.TrustPath(caPath)); err == nil {
		sum := sha256.Sum256(raw)
		fmt.Fprintf(stdout, "trust set sha256 %s (the hash that setup.sh takes)\n", hex.EncodeToString(sum[:]))
	}
	switch {
	case roles["next"]:
		fmt.Fprintln(stdout, "next step: restart each agent so that it trusts the next root, then sudo pf engine ca promote")
	case roles["old"]:
		fmt.Fprintln(stdout, "next step: when no agent needs the old root, sudo pf engine ca retire")
	}
	return 0
}
