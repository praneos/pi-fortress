package ship

import (
	"fmt"
	"os"
	"path/filepath"

	"pi-fortress/internal/jsonl"
)

// RollbackOptions configures pf rollback (docs/signed_ship.md,
// "State version"). The zero value swaps .prev back in, applies again
// and lowers the floor. There is no target other than .prev.
type RollbackOptions struct {
	// WithState also puts a kept state.tar back over EtcDir and LibDir,
	// after the swap and before the apply. That is the snapshot that the
	// current release took immediately before it replaced .prev: the
	// state that .prev ran with (docs/signed_ship.md).
	WithState bool
	// Force bypasses the state-version guard. Without it, a build whose
	// StateMax is below the state already on disk is refused.
	Force bool
}

// releasesRoot is in.ReleasesDir, or DefaultReleasesDir.
func (in *Installer) releasesRoot() string {
	if in.ReleasesDir != "" {
		return in.ReleasesDir
	}
	return DefaultReleasesDir
}

// Rollback is pf rollback: it swaps Dir.prev back in. It needs no
// signature: the floor stops a *remote* replay through pfship, and root
// on the box can already do anything. An error means that the operator
// did not get what they asked for. Either nothing changed (the row is
// rollback_failed, and any pending confirm stays armed), or the tree is
// back but its apply or -with-state failed. The error says which.
func (in *Installer) Rollback(opt RollbackOptions) (jsonl.Ship, error) {
	prev := in.Dir + ".prev"
	target, err := readStamp(prev)
	if err != nil {
		return jsonl.Ship{}, fmt.Errorf("pf rollback: %s: %w", prev, err)
	}
	if target == 0 {
		if _, err := os.Lstat(prev); err != nil {
			return jsonl.Ship{}, fmt.Errorf("pf rollback: no previous tree at %s to restore", prev)
		}
	}
	if err := in.checkStateGuard(target, opt.Force); err != nil {
		return jsonl.Ship{}, err
	}
	cur, err := readVersion(in.VersionPath, in.Dir)
	if err != nil {
		return jsonl.Ship{}, fmt.Errorf("pf rollback: %w", err)
	}
	var before func() error
	if opt.WithState {
		raw, err := in.snapshotTakenOver(cur, target)
		if err != nil {
			return jsonl.Ship{}, fmt.Errorf("pf rollback: -with-state: %w; nothing was changed", err)
		}
		before = func() error { return RestoreState(in.etcDir(), in.libDir(), raw) }
	}
	res := in.rollbackThen(target, fmt.Errorf("operator ran pf rollback, from %d", cur), before)
	if !res.restored {
		row := jsonl.Ship{Result: "rollback_failed", Version: cur, Reason: res.err.Error()}
		in.record(row)
		return row, fmt.Errorf("pf rollback: still at version %d, nothing was rolled back: %v", cur, res.err)
	}
	if in.PendingPath != "" {
		RemovePending(in.PendingPath)
	}
	row := jsonl.Ship{Result: "rollback", Version: target, Reason: res.err.Error()}
	in.record(row)
	if res.stateErr != nil {
		return row, fmt.Errorf("pf rollback: tree restored to %d, but -with-state failed: %w", target, res.stateErr)
	}
	if !res.applied {
		return row, fmt.Errorf("pf rollback: tree restored to %d, but it is not applied: %v", target, res.err)
	}
	return row, nil
}

// snapshotTakenOver reads the state.tar that the install of cur took
// immediately before it replaced target: releases/<cur>/state.tar. That
// is the state that target ran with. A kept release that records which
// version was live at its snapshot must name target. A release kept
// before that record existed is taken at its word.
func (in *Installer) snapshotTakenOver(cur, target int64) ([]byte, error) {
	meta, ok, err := readReleaseMeta(in.releasesRoot(), cur)
	if err != nil {
		return nil, err
	}
	if ok && meta.StateOf != target {
		return nil, fmt.Errorf("the state kept with %d was taken over %d, not %d", cur, meta.StateOf, target)
	}
	return os.ReadFile(filepath.Join(releaseDir(in.releasesRoot(), cur), "state.tar"))
}

// checkStateGuard refuses a rollback to target when the release that it
// would install declares a StateMax below the state version already on
// disk, unless force is set. The manifest of target is read from
// releases/<target>/bundle.tar when one is kept. When none is kept
// (pruned, or the release is older than kept releases), the guard
// cannot be evaluated. It is skipped with a warning on stderr. It does
// not block the one command that an operator has left for recovery.
func (in *Installer) checkStateGuard(target int64, force bool) error {
	cur, err := ReadStateVersion(in.stateVersionPath())
	if err != nil {
		return fmt.Errorf("pf rollback: state version: %w", err)
	}
	bundle := filepath.Join(releaseDir(in.releasesRoot(), target), "bundle.tar")
	mp, err := PeekManifest(bundle, in.Limits)
	if err != nil {
		fmt.Fprintf(in.stderr(), "pf rollback: state version of %d is unknown (%v); proceeding without the state-version guard\n", target, err)
		return nil
	}
	declaredMax := mp.EffectiveStateMax()
	if declaredMax >= cur || force {
		return nil
	}
	return fmt.Errorf("pf rollback: version %d reads state up to %d, but this box is on state %d; "+
		"a sidecar newer than that build ignores would come back into effect (secrets.expires among them below state 2); "+
		"pass -force to roll back anyway", target, declaredMax, cur)
}
