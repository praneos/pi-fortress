//go:build vagrant

package itest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/testsupport"
)

// lifecycleOptIn runs the lifecycle group only with PF_E2E_LIFECYCLE=1.
// Unlike all other groups, it ships bundles, upgrades, and does a rollback
// of the gateway. Thus it is a release gate
// (docs/signed_ship.md), not part of the
// default run: `lab.sh test -run 'TestLab/lifecycle'`
// PF_E2E_LIFECYCLE=1, or the same against a real Pi with PF_TARGET=pi.
func lifecycleOptIn(fn func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		if os.Getenv("PF_E2E_LIFECYCLE") != "1" {
			t.Skip("ships and rolls back the gateway: PF_E2E_LIFECYCLE=1 to run it")
		}
		fn(t)
	}
}

// shipArch is the GOARCH of the bundle: amd64 in the lab, arm64 on a real
// Pi. The lab proves the ship/rollback logic. The Pi is the one place that
// tests the arch-specific renameat2 syscall number.
func shipArch() string {
	if target() == "pi" {
		return "arm64"
	}
	return "amd64"
}

// labRelease is a throwaway ed25519 release key, made one time for each
// run, under t.TempDir(). This group must never sign with
// ~/.ssh/pi_fortress_release: the purpose of that key is that only a human ships with it
// (docs/signed_ship.md).
func labRelease(t *testing.T) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "pf-lifecycle-release")
	if _, err := run(t, 30*time.Second, "ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-C", "pf-lifecycle-test", "-q"); err != nil {
		t.Fatalf("ssh-keygen %s: %v", key, err)
	}
	return key
}

// trustLabRelease installs the public key of release as the
// pi-fortress-release allowed signer of the gw/Pi (docs/signed_ship.md,
// Setup). Then `pf ship install` accepts bundles that this run signs. The
// line is appended next to the signer of the operator, never in place of
// it. The exact prior bytes of the file come back when the group ends: on
// a real Pi, that file is what lets the next `make pi-ship` in.
//
// The backup belongs to this run. It is made new, and removed after the
// restore. A backup left from an earlier run is refused, not reused or
// overwritten. A restore of it could undo all signer changes made since.
// An overwrite could lose the only copy of the original, if that run died
// with its lab line still in place. On a box that had no allowed_signers,
// the lab line is removed again, not left behind.
func trustLabRelease(t *testing.T, release string) {
	t.Helper()
	pub, err := os.ReadFile(release + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(pub))
	if len(f) < 2 {
		t.Fatalf("unreadable release pubkey: %s", pub)
	}
	const signers = "/etc/pi-fortress/allowed_signers"
	const saved = signers + ".pf-lifecycle"
	const absent = signers + ".pf-lifecycle-absent"
	line := "release namespaces=\"pi-fortress-release\" " + f[0] + " " + f[1]
	out, err := ssh(t, 15*time.Second, "pi", "sudo install -d -m 0755 /etc/pi-fortress && if sudo test -e "+saved+" -o -e "+absent+"; then echo pf-lifecycle-stale; exit 3; fi; "+
		"if sudo test -e "+signers+"; then sudo cp -p "+signers+" "+saved+"; else sudo touch "+absent+"; fi")
	if strings.Contains(out, "pf-lifecycle-stale") {
		t.Fatalf("%s or %s is left from an earlier lifecycle run; compare it with %s, put back what is right and remove it, then run again", saved, absent, signers)
	}
	if err != nil {
		t.Fatalf("could not back up %s: %v\n%s", signers, err, out)
	}
	t.Cleanup(func() {
		restore := "if sudo test -e " + saved + "; then sudo cp -p " + saved + " " + signers + " && sudo rm -f " + saved + "; " +
			"elif sudo test -e " + absent + "; then sudo sh -c " + shellQuote(`grep -vxF "$1" "$2" > "$2.tmp"; if [ -s "$2.tmp" ]; then cat "$2.tmp" > "$2"; else rm -f "$2"; fi; rm -f "$2.tmp"`) +
			" sh " + shellQuote(line) + " " + signers + " && sudo rm -f " + absent + "; fi"
		if out, err := ssh(t, 15*time.Second, "pi", restore); err != nil {
			t.Errorf("RESTORE FAILED: %s may still trust the lab release key; the backup is %s (or %s if there was no file): %v\n%s", signers, saved, absent, err, out)
		}
	})
	pi(t, "echo '"+line+"' | sudo tee -a "+signers+" >/dev/null && sudo chmod 0644 "+signers+" && sudo chown root:root "+signers)
}

// buildBundle builds and tars a bundle for arch under t.TempDir(), the
// same `pf ship bundle` a real ship runs (Makefile pi-bundle, with its GOARCH
// parameter).
func buildBundle(t *testing.T, arch string) string {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "pf-bundle.tar")
	if _, err := run(t, 3*time.Minute, "make", "-s", "-C", testsupport.RepoRoot(t), "pi-bundle",
		"GOARCH="+arch, "PI_BUNDLE="+bundle); err != nil {
		t.Fatalf("make pi-bundle GOARCH=%s: %v", arch, err)
	}
	return bundle
}

// buildBrokenBundle is a bundle whose apply succeeds and whose required
// unit never runs: the apply.sh of the copy names one more unit in
// units.required, a unit that does not exist. The post-upgrade doctor
// exists to catch this build: a clean apply with a dead service. Nothing
// in the shipped code knows that it is under test. A stop of a real unit
// from apply.sh does not work as a rig: pf apply restarts the fence
// after apply.sh returns (seen on the Pi).
func buildBrokenBundle(t *testing.T, arch string) string {
	t.Helper()
	root := testsupport.RepoRoot(t)
	tree := filepath.Join(t.TempDir(), "tree")
	if _, err := run(t, 3*time.Minute, "rsync", "-a", "--exclude", ".git", "--exclude", ".vagrant", "--exclude", "dist", "--exclude", "bin", root+"/", tree+"/"); err != nil {
		t.Fatalf("copy the tree: %v", err)
	}
	apply := filepath.Join(tree, "vm", "pi", "apply.sh")
	raw, err := os.ReadFile(apply)
	if err != nil {
		t.Fatal(err)
	}
	const anchor = "  >/var/lib/pi-fortress/units.required"
	if strings.Count(string(raw), anchor) != 1 {
		t.Fatalf("apply.sh no longer writes units.required once through %q; update the rig", anchor)
	}
	rigged := strings.Replace(string(raw), anchor, "  pi-fortress-lifecycle-rigged.service \\\n"+anchor, 1)
	if err := os.WriteFile(apply, []byte(rigged), 0755); err != nil {
		t.Fatal(err)
	}
	// pi-bundle stages only what git tracks or would track. Thus the copy
	// becomes a checkout of its own. The copied .gitignore keeps ignored
	// files out, as it does in the real tree.
	if _, err := run(t, time.Minute, "sh", "-c", "cd "+shellQuote(tree)+" && git init -q && git add -A && git -c user.name=rig -c user.email=rig@pi-fortress.invalid commit -qm rig"); err != nil {
		t.Fatalf("make the rigged tree a checkout: %v", err)
	}
	bundle := filepath.Join(t.TempDir(), "pf-bundle.tar")
	if _, err := run(t, 3*time.Minute, "make", "-s", "-C", tree, "pi-bundle", "GOARCH="+arch, "PI_BUNDLE="+bundle); err != nil {
		t.Fatalf("make pi-bundle on the rigged tree: %v", err)
	}
	return bundle
}

// signBundle signs bundle with release, in namespace pi-fortress-release,
// exactly as `pi-sign` does (Makefile).
func signBundle(t *testing.T, release, bundle string) {
	t.Helper()
	_ = os.Remove(bundle + ".sig")
	if _, err := run(t, 30*time.Second, "ssh-keygen", "-Y", "sign", "-f", release, "-n", "pi-fortress-release", bundle); err != nil {
		t.Fatalf("sign %s: %v", bundle, err)
	}
}

// piApply is pi for a command that runs pf apply, sometimes two times. An
// install whose doctor fails waits for the 90 s settle window, then does a
// rollback and applies again, much longer than the 45 s of pi.
func piApply(t *testing.T, cmd string) string {
	t.Helper()
	out, err := ssh(t, 8*time.Minute, "pi", cmd)
	if err != nil {
		t.Fatalf("pi %s: %v\n%s", cmd, err, out)
	}
	return out
}

// shipInstall copies bundle and its .sig into a scratch incoming
// directory on the gw/Pi. Then it runs `pf ship install -incoming DIR`
// directly, as root, with the extra flags. The dead-man subtest gives
// -confirm-deadline. It is a flag, not an env variable, because sudo can
// drop env. `pf ship install` does not take a bundle path. It reads the
// fixed pair name (internal/ship.BundleName/SigName,
// "pf-bundle.tar"/".sig") from -incoming. That is why buildBundle gives
// its file that name. `vm/cloudlab/lab.sh ship` and `make pi-ship` test
// the pfship/rrsync upload transport. This group points -incoming at its
// own directory. Thus it has deterministic control of the confirm and
// dead-man timing. It does not race the production incoming-directory
// watcher.
func shipInstall(t *testing.T, bundle, flags string) string {
	t.Helper()
	dir := fmt.Sprintf("/tmp/pf-lifecycle-%d", time.Now().UnixNano())
	pi(t, "mkdir -p "+dir)
	t.Cleanup(func() { _, _ = ssh(t, 10*time.Second, "pi", "rm -rf "+dir) })
	rsh := "ssh -F " + sshCfg + " -o BatchMode=yes -o ConnectTimeout=15"
	for _, ext := range []string{"", ".sig"} {
		if _, err := run(t, 2*time.Minute, "rsync", "-t", "-e", rsh, bundle+ext, "pi:"+dir+"/"); err != nil {
			t.Fatalf("rsync %s%s to the gw: %v", bundle, ext, err)
		}
	}
	cmd := "sudo pf ship install -incoming " + dir
	if flags != "" {
		cmd += " " + flags
	}
	// A refused or rolled-back install exits non-zero, and some subtests
	// want that outcome. Thus the error is not fatal here. The subtests
	// use the version file to decide.
	out, err := ssh(t, 8*time.Minute, "pi", cmd)
	if err != nil {
		t.Logf("%s: %v\n%s", cmd, err, out)
	}
	return out
}

// shipVersion is the floor pf ship install and pf rollback move
// (docs/signed_ship.md, "State version"; "Rollback and kept releases").
func shipVersion(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(pi(t, "sudo cat /var/lib/pi-fortress/ship.version 2>/dev/null || echo 0"))
}

func hasPending(t *testing.T) bool {
	t.Helper()
	out := pi(t, "test -f /var/lib/pi-fortress/ship.pending && echo yes || echo no")
	return strings.TrimSpace(out) == "yes"
}

func dnsWorks(t *testing.T) bool {
	t.Helper()
	out, err := ssh(t, 10*time.Second, "pi", "dig +short +time=3 +tries=1 example.com")
	return err == nil && firstIPv4(out) != ""
}

// treeBlacklist is a list in the tree that pf ship install publishes: the
// copy that pf rollback mirrors into .prev before it swaps it back.
const treeBlacklist = "/opt/pi-fortress/vm/policy/blacklist.domains"

// editTreeList appends a comment line unique to this run to the
// blacklist.domains of the tree. The line is safe to apply, and it is the
// kind of post-upgrade list edit that a rollback must keep. It removes the
// line again when t ends, and keeps the inode, mode and owner of the file.
func editTreeList(t *testing.T) string {
	t.Helper()
	line := fmt.Sprintf("# pf-lifecycle: a rollback keeps this edit %d", time.Now().UnixNano())
	pi(t, "sudo test -f "+treeBlacklist+" && echo "+shellQuote(line)+" | sudo tee -a "+treeBlacklist+" >/dev/null")
	t.Cleanup(func() {
		strip := "sudo sh -c " + shellQuote(`grep -vxF "$1" "$2" > "$2.pf-lifecycle"; cat "$2.pf-lifecycle" > "$2"; rm -f "$2.pf-lifecycle"`) + " sh " + shellQuote(line) + " " + treeBlacklist
		if out, err := ssh(t, 15*time.Second, "pi", strip); err != nil {
			t.Errorf("could not take the lifecycle line out of %s: %v\n%s", treeBlacklist, err, out)
		}
	})
	return line
}

func treeListHas(t *testing.T, line string) bool {
	t.Helper()
	out := pi(t, "sudo grep -qxF "+shellQuote(line)+" "+treeBlacklist+" && echo yes || echo no")
	return strings.TrimSpace(out) == "yes"
}

// lifecycleTests walks install, doctor, rollback, an auto-reverting bad
// build, the dead-man deadline and confirm, in that order, against
// vm/cloudlab (amd64) or a real Pi (PF_TARGET=pi, arm64): the arch
// follows the target at all steps (shipArch).
//
// Commands under test: pf ship install, pf ship confirm, pf ship deadman,
// pf doctor --post-upgrade, pf rollback. Files asserted on: ship.version
// (read by this file, until a public accessor exists),
// /var/lib/pi-fortress/ship.pending, /var/lib/pi-fortress/releases/<ver>/.
func lifecycleTests(t *testing.T) {
	arch := shipArch()
	release := labRelease(t)
	trustLabRelease(t, release)

	base := shipVersion(t)

	t.Run("ship N-1 then N, post-upgrade doctor passes", func(t *testing.T) {
		bN1 := buildBundle(t, arch)
		signBundle(t, release, bN1)
		shipInstall(t, bN1, "")
		vN1 := shipVersion(t)
		if vN1 == base {
			t.Fatalf("shipping N-1 did not raise the version: still %s", vN1)
		}
		// The manifest version is the unix-second clock of the build
		// (docs/signed_ship.md flow 1). N must be strictly above N-1.
		time.Sleep(1100 * time.Millisecond)
		bN := buildBundle(t, arch)
		signBundle(t, release, bN)
		shipInstall(t, bN, "")
		vN := shipVersion(t)
		if vN == vN1 {
			t.Fatalf("shipping N did not raise the version: still %s", vN)
		}
		out := pi(t, "sudo pf doctor --post-upgrade")
		if strings.Contains(strings.ToLower(out), "fail") {
			t.Fatalf("post-upgrade doctor did not pass:\n%s", out)
		}
		pi(t, "sudo pf ship confirm")
	})

	t.Run("pf rollback returns to N-1 with state intact", func(t *testing.T) {
		before := shipVersion(t)
		marker := pi(t, "sudo cat /etc/pi-fortress/allowed_signers")
		edit := editTreeList(t)
		if !treeListHas(t, edit) {
			t.Fatalf("the list edit did not land in %s", treeBlacklist)
		}
		piApply(t, "sudo pf rollback")
		after := shipVersion(t)
		if after == before {
			t.Fatalf("pf rollback did not lower the version: still %s", before)
		}
		state := pi(t, "sudo cat /etc/pi-fortress/allowed_signers")
		if state != marker {
			t.Fatalf("/etc/pi-fortress state did not survive the rollback")
		}
		if !treeListHas(t, edit) {
			t.Fatalf("a %s edit made after shipping N was undone by the rollback (the operator's lists must ride across it)", treeBlacklist)
		}
		if !dnsWorks(t) {
			t.Fatalf("gw's resolver is not answering after the rollback")
		}
	})

	t.Run("a bundle whose required unit never runs reverts on its own", func(t *testing.T) {
		before := shipVersion(t)
		b := buildBrokenBundle(t, arch)
		signBundle(t, release, b)
		out := shipInstall(t, b, "")
		after := shipVersion(t)
		if after != before {
			t.Fatalf("a build that breaks DNS raised the version instead of reverting:\n%s", out)
		}
		if !dnsWorks(t) {
			t.Fatalf("gw's own resolver is not answering after the auto-revert")
		}
	})

	t.Run("an unconfirmed upgrade reverts after the dead-man deadline", func(t *testing.T) {
		before := shipVersion(t)
		b := buildBundle(t, arch)
		signBundle(t, release, b)
		shipInstall(t, b, "-confirm-deadline 60s")
		after := shipVersion(t)
		if after == before {
			t.Fatalf("ship did not raise the version")
		}
		if !hasPending(t) {
			t.Fatalf("no ship.pending after an unconfirmed install")
		}
		// The ship-deadman.timer of the box can revert first. The lock lets
		// exactly one of them act. The other finds the lock held, and leaves
		// ship.pending to the run that holds the lock. That run clears it
		// only after its re-apply is done. Thus the test waits for the end state.
		time.Sleep(70 * time.Second)
		piApply(t, "sudo pf ship deadman")
		eventually(t, 3*time.Minute, func() string {
			if got := shipVersion(t); got != before {
				return "the dead-man deadline did not revert: version is " + got + ", want " + before
			}
			if hasPending(t) {
				return "ship.pending is still there after the dead-man revert"
			}
			return ""
		})
	})

	t.Run("pf ship confirm clears the pending state", func(t *testing.T) {
		b := buildBundle(t, arch)
		signBundle(t, release, b)
		shipInstall(t, b, "")
		if !hasPending(t) {
			t.Fatalf("no ship.pending after an install")
		}
		pi(t, "sudo pf ship confirm")
		if hasPending(t) {
			t.Fatalf("ship.pending is still there after pf ship confirm")
		}
	})
}
