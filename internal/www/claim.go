package www

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pi-fortress/internal/enroll"
	"pi-fortress/internal/secrets"
)

const (
	ClaimTTL      = 5 * time.Minute
	claimAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	claimLen      = 6
	sweepAfter    = time.Hour
	limitPerMin   = 10
	setupWindow   = time.Minute
	seenMax       = 4096
	// hitsMax bounds the table of the claim limiter, as seenMax bounds the
	// table for setup. The number and the reason are the same. The endpoint is
	// different.
	hitsMax = 4096
)

var ErrNoClaim = errors.New("claim: no such code")

type Claim struct {
	Code    string    `json:"code"`
	Slot    string    `json:"slot"`
	Kinds   []string  `json:"kinds"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	// GitHosts are the core.hosts names that carry GITHUB_TOKEN. The side that
	// issues the claim reads them, because it can read policy. www cannot.
	GitHosts []string `json:"git_hosts,omitempty"`
	// SetupSHA256 is the hex sha256 of the setup.sh that www served at claim
	// issue. The claim script refuses a download that does not match it
	// (ClaimScript). It is empty when there was no setup.sh. Then the claim
	// script refuses to run at all.
	SetupSHA256 string `json:"setup_sha256,omitempty"`
	// CASHA256 is the same for ca.pem. setup.sh also fetches ca.pem over plain
	// HTTP, and then trusts it for each TLS connection that the agent makes.
	// The claim script gives it to setup.sh to check.
	CASHA256 string `json:"ca_sha256,omitempty"`
}

// setupPath is the setup.sh that www serves from dir. The copy in the lab
// shared folder comes first, so a lab run serves the tree it started from.
func setupPath(dir string) string {
	return firstFile("/vagrant/vm/agent/setup.sh", filepath.Join(dir, "setup.sh"))
}

// caPath is the ca.pem www serves from dir.
func caPath(dir string) string {
	return firstFile(filepath.Join(dir, "ca.pem"), "/etc/pi-fortress/egress-ca.pem", "/etc/pi-fortress/mitm-ca.pem")
}

// fileSHA256 is path's hex sha256, or "" when it cannot be read.
func fileSHA256(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ClaimsDir(wwwDir string) string { return filepath.Join(wwwDir, "claims") }

func NewCode() (string, error) {
	b := make([]byte, claimLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = claimAlphabet[int(b[i])%len(claimAlphabet)]
	}
	return string(b), nil
}

func validCode(code string) bool {
	if len(code) != claimLen {
		return false
	}
	for _, r := range code {
		if !strings.ContainsRune(claimAlphabet, r) {
			return false
		}
	}
	return true
}

// IssueClaim writes claims/<CODE>.json. This file is the only record that
// the redeem side needs. The TUI runs as root, and www runs as a DynamicUser
// in the group of the claims directory. So the file goes in that group with
// mode 0640. www reads it and renames it (rename needs the directory, not
// the file), but www can never rewrite the slot that it names. apply.sh
// also sets the directory setgid. With the chown here, a directory that a
// user made again by hand cannot silently break enrolment.
func IssueClaim(dir, slot string, kinds []string, gitHosts ...string) (Claim, error) {
	code, err := NewCode()
	if err != nil {
		return Claim{}, err
	}
	now := time.Now().UTC()
	c := Claim{Code: code, Slot: strings.ToLower(slot), Kinds: kinds, Issued: now, Expires: now.Add(ClaimTTL), GitHosts: gitHosts,
		// dir is ClaimsDir(wwwDir), so its parent is what www serves.
		SetupSHA256: fileSHA256(setupPath(filepath.Dir(dir))), CASHA256: fileSHA256(caPath(filepath.Dir(dir)))}
	if !scriptFields(c) {
		return Claim{}, errors.New("claim: invalid slot or kind")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return Claim{}, err
	}
	path := filepath.Join(dir, code+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return Claim{}, err
	}
	_, werr := f.Write(raw)
	if werr == nil {
		werr = groupOfDir(dir, f)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return Claim{}, werr
	}
	return c, nil
}

// groupOfDir puts f in the group of dir, so the redeem side can read it.
// The redeem side shares that group and nothing else. It works by
// descriptor: www can write dir, so at the time of a chown by name, the
// name could be a link that www left there.
func groupOfDir(dir string, f *os.File) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := f.Chown(-1, int(st.Gid)); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return nil
}

// RedeemClaim consumes a code. The rename is the single-use guarantee: a
// second caller finds no <CODE>.json. RedeemClaim also consumes expired
// files, and refuses them. It also refuses a file with a field that
// scriptFields does not accept. That answer is the same as for an unknown
// code.
func RedeemClaim(dir, code string) (Claim, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !validCode(code) {
		return Claim{}, ErrNoClaim
	}
	src := filepath.Join(dir, code+".json")
	dst := filepath.Join(dir, code+".redeemed")
	if err := os.Rename(src, dst); err != nil {
		return Claim{}, ErrNoClaim
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		return Claim{}, ErrNoClaim
	}
	var c Claim
	if json.Unmarshal(raw, &c) != nil || c.Code != code || time.Now().After(c.Expires) || !scriptFields(c) {
		return Claim{}, ErrNoClaim
	}
	return c, nil
}

// Sweep removes redeemed files and expired claims older than an hour.
func Sweep(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cut := time.Now().Add(-sweepAfter)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".redeemed") && !strings.HasSuffix(name, ".json") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(cut) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// ClaimScript is what the agent pipes into sh: setup.sh for the CA and
// network, then the placeholder files for the slot. ClaimScript writes the
// fields of c and pi into shell. So it writes no value that does not match
// its grammar (scriptFields, scriptHost). For such a value, the script only
// stops.
func ClaimScript(pi string, c Claim) string {
	if !scriptHost(pi) || !scriptFields(c) {
		return "#!/bin/sh\necho 'pi-fortress: this claim is not valid; issue another on the gateway' >&2\nexit 1\n"
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -e\nPI='" + pi + "'\n")
	// Without both hashes, nothing below can be checked. A claim issued before
	// apply put setup.sh and ca.pem in place enrols nothing.
	if c.SetupSHA256 == "" || c.CASHA256 == "" {
		b.WriteString("echo 'pi-fortress: the gateway had no setup.sh or ca.pem when this code was issued; run pf apply there and issue another' >&2\nexit 1\n")
		return b.String()
	}
	// The script downloads to a file and checks it. It does not pipe the
	// download into a shell. /bin/sh has no pipefail, so a pipeline reports the
	// status of the shell, and a shell that gets no input exits 0. A setup.sh
	// that got a 404 or stopped half way did not trigger set -e. The script
	// then wrote the placeholder files and printed "enrolled" for a box that
	// never got the CA or the routes. The claim is one-time and is already
	// spent at that point. So the next step for the operator is to enrol a box
	// that is not enrolled. A failure here costs them one re-issue instead.
	b.WriteString(`S=$(mktemp)
trap 'rm -f "$S"' EXIT
curl -fsS "http://$PI/setup.sh" -o "$S"
[ -s "$S" ]
`)
	// The download is plain HTTP on the agent segment. So a second agent that
	// claims the address of the Pi by ARP could supply its own setup.sh for the
	// script to run as root. This script is itself checked against a hash that
	// the operator copied from the Pi (ClaimCommand). It also carries the hash
	// of the setup.sh that the Pi had at issue.
	b.WriteString(`echo "` + c.SetupSHA256 + `  $S" | sha256sum -c
sudo bash "$S" "$PI" '` + c.CASHA256 + `'
`)
	if hasKind(c.Kinds, "CLAUDE_OAT") {
		raw, _ := json.MarshalIndent(enroll.AgentCredentialsDoc(c.Slot), "", "  ")
		b.WriteString("mkdir -p \"$HOME/.claude\"\ncat >\"$HOME/.claude/.credentials.json\" <<'PFEOF'\n" + string(raw) + "\nPFEOF\n")
	}
	b.WriteString("mkdir -p \"$HOME/.pi-fortress\"\ncat >\"$HOME/.pi-fortress/env.sh\" <<'PFEOF'\n")
	for _, k := range c.Kinds {
		b.WriteString("export " + k + "='" + enroll.Placeholder(c.Slot, k) + "'\n")
	}
	b.WriteString("PFEOF\necho 'pi-fortress: enrolled slot " + c.Slot + "; source ~/.pi-fortress/env.sh'\n")
	if hasKind(c.Kinds, "GITHUB_TOKEN") {
		b.WriteString(gitCredentials(c.Slot, c.GitHosts))
	}
	return b.String()
}

// ClaimCommand is what the operator pastes on the agent for claim c. It
// gives one line, and also the lines that a screen shows. The claim script
// goes over plain HTTP. So before any part of the script runs, the command
// checks it against the hash of the script that this gateway will serve.
// The operator copies the command from the TUI or the console of the Pi. An
// agent on the segment cannot rewrite that channel. The script is fixed at
// issue: it depends only on pi and the claim file, and www renders it from
// the same two. In the pasted lines, the first line sets h. The second line
// ends in && so that the shell continues to read. The one line has the same
// words.
//
// The hash has its own variable, so no shown line is much past 70 columns.
// A mismatch stops at sha256sum -c. The code is spent at that point, and
// the operator issues a different code from the Pi.
func ClaimCommand(pi string, c Claim) (string, []string) {
	sum := sha256.Sum256([]byte(ClaimScript(pi, c)))
	lines := []string{
		"h=" + hex.EncodeToString(sum[:]),
		`f=$(mktemp) && curl -fsSo "$f" http://` + pi + "/claim/" + c.Code + " &&",
		`echo "$h  $f" | sha256sum -c && sh "$f"`,
	}
	return lines[0] + "; " + lines[1] + " " + lines[2], lines
}

// gitCredentials is the git half of the script. For each host, it writes
// one store-helper line, and replaces only the lines of that host in
// ~/.git-credentials. It sets the store helper when git has none. It does
// not change a helper that is already set, and it gives the command to
// change it. Placeholders only.
func gitCredentials(slot string, hosts []string) string {
	var lines, pats, names []string
	for _, h := range hosts {
		if !safeHost(h) {
			continue
		}
		names = append(names, h)
		lines = append(lines, "https://x-access-token:"+enroll.Placeholder(slot, "GITHUB_TOKEN")+"@"+h)
		pats = append(pats, strings.ReplaceAll(h, ".", `\.`))
	}
	if len(lines) == 0 {
		return ""
	}
	re := "^https://([^@/]*@)?(" + strings.Join(pats, "|") + ")([:/]|$)"
	return `if command -v git >/dev/null 2>&1; then
(
umask 077
C="$HOME/.git-credentials"
touch "$C"
chmod 600 "$C"
rc=0
grep -Ev '` + re + `' "$C" >"$C.pf-new" || rc=$?
[ "$rc" -le 1 ]
cat >>"$C.pf-new" <<'PFEOF'
` + strings.Join(lines, "\n") + `
PFEOF
mv "$C.pf-new" "$C"
)
H=$(cd / && git config --get-all credential.helper || true)
if [ -z "$H" ]; then
git config --global credential.helper store
elif ! printf '%s\n' "$H" | grep -qx store; then
echo "pi-fortress: git credential.helper is already '$(printf '%s' "$H" | tr '\n' ' ')', left as is; to use ~/.git-credentials run: git config --global --replace-all credential.helper store"
fi
echo 'pi-fortress: git credentials for ` + strings.Join(names, " ") + ` in ~/.git-credentials'
else
echo 'pi-fortress: git not found, git credentials skipped'
fi
`
}

// scriptFields reports whether each field of c that ClaimScript writes
// matches its grammar. The slot must be in its stored form: 16 lower-case
// hex digits. Each kind must be a stored kind. Each hash must be empty or
// 64 lower-case hex digits. GitHosts is not in this check. gitCredentials
// drops each name that safeHost refuses, because core.hosts can give a
// "*." name that has no place in ~/.git-credentials.
func scriptFields(c Claim) bool {
	if c.Slot != strings.ToLower(strings.TrimSpace(c.Slot)) || secrets.ValidSlotID(c.Slot) != nil {
		return false
	}
	for _, k := range c.Kinds {
		if !secrets.ValidKind(k) {
			return false
		}
	}
	return validSum(c.SetupSHA256) && validSum(c.CASHA256)
}

// validSum accepts "" or the hex sha256 that fileSHA256 gives.
func validSum(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 2*sha256.Size || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// scriptHost accepts an IP address or a name that safeHost accepts.
func scriptHost(h string) bool { return net.ParseIP(h) != nil || safeHost(h) }

func safeHost(h string) bool {
	if h == "" {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func hasKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

// recent collapses repeat fetches of the same public file by the same
// address into one ledger line a minute. /setup.sh and /ca.pem are the
// unauthenticated half of the surface. They have none of the throttles of
// the claim endpoint. So a client in a loop used to buy one line of disk
// for each request, on a partition that the broker store and the audit log
// share. The operator reads from the ledger that an address fetched
// setup.sh, and when. That fact survives the collapse. The retry count does
// not survive, and it was never worth a partition. The table itself is
// state that an unauthenticated caller can grow, so it is bounded. Stale
// entries go first. If the table is still full after that, recent drops
// the full table. It does not let the table climb.
type recent struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (s *recent) first(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.at == nil {
		s.at = map[string]time.Time{}
	}
	if t, ok := s.at[key]; ok && now.Sub(t) < setupWindow {
		return false
	}
	if len(s.at) >= seenMax {
		for k, t := range s.at {
			if now.Sub(t) >= setupWindow {
				delete(s.at, k)
			}
		}
		if len(s.at) >= seenMax {
			s.at = map[string]time.Time{}
		}
	}
	s.at[key] = now
	return true
}

// limiter throttles the claim endpoint per source address. Its table is
// state that an unauthenticated caller can grow: one key for each address
// that ever asked, kept for the life of the process. So it is bounded in
// the same way as recent. The limiter drops an address when its window has
// passed. If the table is still full after that, it drops the full table.
// The thing that bounds the ledger should not itself be unbounded.
//
// A drop of the full table gives each address a new minute. recent makes
// the same trade, and it is a small one here. This limiter is per-address.
// So it never throttled a flood from enough different addresses to fill
// the table. It protects against one address in a loop. The sweep never
// forgets that address, because its window has not passed.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	now := time.Now()
	old, seen := l.hits[ip]
	keep := old[:0]
	for _, t := range old {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= limitPerMin {
		l.hits[ip] = keep
		return false
	}
	// Only a new address can grow the table, so only a new address has
	// to pay for the sweep.
	if !seen && len(l.hits) >= hitsMax {
		l.sweep(now)
	}
	l.hits[ip] = append(keep, now)
	return true
}

// sweep drops each address whose last request is outside the window. If
// the table is still full after that, sweep drops the table.
func (l *limiter) sweep(now time.Time) {
	for k, ts := range l.hits {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= time.Minute {
			delete(l.hits, k)
		}
	}
	if len(l.hits) >= hitsMax {
		l.hits = map[string][]time.Time{}
	}
}
