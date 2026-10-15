package admin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/www"

	"pi-fortress/internal/base"
)

// EnrollStats is the enrollment data that the box records: slots in
// secrets.env, the engine CA, the files that www serves, and the claim
// ledger (issued and redeemed codes, setup.sh fetches).
type EnrollStats struct {
	Slots        int
	Kinds        int
	Disabled     int
	CAFP         string
	CANotAfter   time.Time
	CASubject    string
	SetupSH      time.Time
	CAPEM        time.Time
	WWWDir       string
	CACertPath   string
	Issued       int
	Redeemed     int
	LastRedeem   time.Time
	LastRedeemIP string
	LastSetup    time.Time
	LastSetupIP  string
	// LedgerPartial says that the counts came from a window over the ledger,
	// not from the full ledger. Either a rotated generation exists, or the
	// current one is longer than the read window. The counts are then a tail,
	// and they decrease after a rotation. A screen that shows them as totals
	// tells the operator that enrolments were undone.
	LedgerPartial bool
}

// Claim is what claim.issue gives the screen: the code, the time when it
// expires, and the exact line to paste on the agent.
type Claim struct {
	Code    string
	Slot    string
	Expires time.Time
	Command string
	// CommandLines is Command, broken at points where a pasted copy still runs.
	// It is for a screen that is too narrow for the one line (the TUI clips, it
	// does not wrap).
	CommandLines []string
}

func (c *Config) claimsDir() string { return www.ClaimsDir(c.WWWDir) }

// IssueClaim writes the one-time claim file and the ledger line. apply.sh
// creates the claims directory as root:pf-fortress 0770.
func (c *Config) IssueClaim(slot string) (Claim, error) {
	slot = strings.ToLower(strings.TrimSpace(slot))
	rows, err := c.store().ListSlots()
	if err != nil {
		return Claim{}, err
	}
	var kinds []string
	for _, r := range rows {
		if r.Slot == slot {
			for _, k := range r.Keys {
				kinds = append(kinds, k.Kind)
			}
		}
	}
	if len(kinds) == 0 {
		return Claim{}, errors.New("unknown slot " + slot)
	}
	if off, _ := c.store().Disabled(); off[slot] != 0 {
		return Claim{}, errors.New("slot is disabled")
	}
	var gitHosts []string
	if slices.Contains(kinds, "GITHUB_TOKEN") {
		if pol, err := corepolicy.LoadFiles(filepath.Join(c.PolicyDir, "core.hosts"), filepath.Join(c.PolicyDir, "core.hosts.local")); err == nil {
			gitHosts = pol.HostsWithKind("GITHUB_TOKEN")
		}
	}
	cl, err := www.IssueClaim(c.claimsDir(), slot, kinds, gitHosts...)
	if err != nil {
		return Claim{}, err
	}
	_ = www.AppendEvent(c.claimsDir(), www.Event{Ev: "issued", Code: cl.Code, Slot: slot, UID: os.Getuid()})
	pi := c.netVal("PI_IP", "10.77.0.1")
	// curl -f: without it, a mistyped or expired code saves the 404 body. The
	// operator then reads a checksum failure, not the one important fact: the
	// code was not redeemed. The checksum is that of the script
	// (www.ClaimCommand).
	cmd, lines := www.ClaimCommand(pi, cl)
	return Claim{Code: cl.Code, Slot: slot, Expires: cl.Expires, Command: cmd, CommandLines: lines}, nil
}

func (c *Config) EnrollStats() (EnrollStats, error) {
	st := EnrollStats{WWWDir: c.WWWDir, CACertPath: c.CACertPath}
	events, partial := www.ReadLedgerCovering(c.claimsDir())
	st.LedgerPartial = partial
	for _, ev := range events {
		at, _ := base.ParseISO(ev.T)
		switch ev.Ev {
		case "issued":
			st.Issued++
		case "redeemed":
			st.Redeemed++
			st.LastRedeem, st.LastRedeemIP = at, Printable(ev.IP)
		case "setup":
			st.LastSetup, st.LastSetupIP = at, Printable(ev.IP)
		}
	}
	rows, err := c.Slots()
	st.Slots = len(rows)
	for _, r := range rows {
		st.Kinds += len(r.Keys)
		if !r.DisabledAt.IsZero() {
			st.Disabled++
		}
	}
	if cert := loadCert(c.CACertPath); cert != nil {
		sum := sha256.Sum256(cert.Raw)
		st.CAFP, st.CANotAfter, st.CASubject = hex.EncodeToString(sum[:8]), cert.NotAfter, cert.Subject.CommonName
	}
	st.SetupSH = mtime(filepath.Join(c.WWWDir, "setup.sh"))
	st.CAPEM = mtime(filepath.Join(c.WWWDir, "ca.pem"))
	return st, err
}

func loadCert(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

func mtime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
