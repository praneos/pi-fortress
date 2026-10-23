package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"pi-fortress/internal/ca"
)

// EngineCA is the bundle that the engine signs with.
const EngineCA = "/var/lib/pi-fortress/engine/ca.pem"

// caExpiryWarn is the time that an operator needs for a rotation with an
// overlap: rotate, a restart of each agent, promote.
const caExpiryWarn = 90 * 24 * time.Hour

// CARootRung shows the roots of the engine (pf engine ca status) and the
// next step of a rotation. It warns when the current root expires within
// 90 days. No bundle, no rung: the box has no engine yet.
func CARootRung(roots []ca.Root, err error, now time.Time) (Result, bool) {
	at := func(detail string, st Status) (Result, bool) {
		return Result{Rung: "ca root", Where: "engine", Detail: detail, Status: st}, true
	}
	switch {
	case errors.Is(err, fs.ErrNotExist) && len(roots) == 0:
		return Result{}, false
	case errors.Is(err, fs.ErrPermission):
		return at("the engine CA is root-only; run sudo pf doctor to read its dates", Warn)
	case err != nil:
		return at(err.Error(), Warn)
	case len(roots) == 0:
		return Result{}, false
	}
	var parts []string
	var next, old bool
	for _, r := range roots {
		sum := sha256.Sum256(r.Cert.Raw)
		parts = append(parts, fmt.Sprintf("%s %s sha256:%s until %s", r.Role, r.Cert.Subject.CommonName,
			hex.EncodeToString(sum[:8]), r.Cert.NotAfter.UTC().Format("2006-01-02")))
		next = next || r.Role == "next"
		old = old || r.Role == "old"
	}
	detail := strings.Join(parts, "; ")
	switch {
	case next:
		detail += "; restart each agent so that it trusts the next root, then sudo pf engine ca promote"
	case old:
		detail += "; when no agent needs the old root: sudo pf engine ca retire"
	default:
		detail += "; to change it: sudo pf engine ca rotate (docs/fence.md)"
	}
	// Status puts the current root first.
	switch left := roots[0].Cert.NotAfter.Sub(now); {
	case left <= 0:
		return at("the current root has expired, and the engine cannot start with it. A rotation needs a valid root: "+
			"move the bundle aside, run sudo pf apply (it makes a new root) and enrol each agent again; "+strings.Join(parts, "; "), Fail)
	case left < caExpiryWarn:
		return at(fmt.Sprintf("the current root expires in %d days; %s", int(left.Hours()/24), detail), Warn)
	}
	return at(detail, OK)
}
