package www

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pi-fortress/internal/agentcreds"
	"pi-fortress/internal/secrets"
)

const (
	ClaimTTL      = 5 * time.Minute
	claimAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// claimLen is 8 symbols of 32, thus 40 bits. The operator reads the code
	// from a screen and types it on a different box, so the code stays short.
	claimLen    = 8
	sweepAfter  = time.Hour
	limitPerMin = 10
	setupWindow = time.Minute
	seenMax     = 4096
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
	// (ClaimScript). IssueClaim refuses to issue a claim when there is no
	// setup.sh. If a claim file has no hash, the claim script refuses to run
	// at all.
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

// caFallbacks are the CA files that www serves when dir has no ca.pem.
// A test points them at its own files.
var caFallbacks = []string{"/etc/pi-fortress/egress-ca.pem", "/etc/pi-fortress/mitm-ca.pem"}

// caPaths are the files that caPath picks from, in order.
func caPaths(dir string) []string {
	return append([]string{filepath.Join(dir, "ca.pem")}, caFallbacks...)
}

// caPath is the ca.pem www serves from dir.
func caPath(dir string) string {
	return firstFile(caPaths(dir)...)
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

// ClaimsDir holds the claim files. Only root writes it. www is in its group
// and reads it (vm/pi/apply.sh installs it 2750 root:pf-fortress).
func ClaimsDir(wwwDir string) string { return filepath.Join(wwwDir, "claims") }

// RedeemedDir is the directory that www writes: one marker for each spent
// code, and the ledger. It is next to claimsDir (2770 root:pf-fortress).
// www can redeem a claim, but it can never create, change or remove one.
func RedeemedDir(claimsDir string) string { return filepath.Clean(claimsDir) + "-redeemed" }

func markerPath(claimsDir, code string) string {
	return filepath.Join(RedeemedDir(claimsDir), code+".redeemed")
}

// makeRedeemedDir makes RedeemedDir when it is missing, in the group of
// claimsDir, mode 2770. Root calls it. The parent is not writable by www,
// so a chown and chmod by name are safe here.
func makeRedeemedDir(claimsDir string) error {
	rd := RedeemedDir(claimsDir)
	if err := os.Mkdir(rd, 0770); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	fi, err := os.Stat(claimsDir)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(rd, -1, int(st.Gid)); err != nil && !errors.Is(err, os.ErrPermission) {
			return err
		}
	}
	return os.Chmod(rd, 0770|os.ModeSetgid)
}

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
// mode 0640. www can read the file, but it cannot write the file or the
// directory. Thus www can never create a claim, or rewrite the slot that a
// claim names. To spend a code, www makes a marker in RedeemedDir. apply.sh
// also sets the directory setgid. With the chown here, a directory that a
// user made again by hand cannot silently break enrolment. IssueClaim first
// sweeps old claims and markers, because www cannot remove them.
func IssueClaim(dir, slot string, kinds []string, gitHosts ...string) (Claim, error) {
	Sweep(dir)
	if err := makeRedeemedDir(dir); err != nil {
		return Claim{}, err
	}
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
	// Without setup.sh and ca.pem, the claim script can enrol nothing. The
	// operator gets this error now, not a code that a redeem spends for no
	// result.
	if c.SetupSHA256 == "" || c.CASHA256 == "" {
		return Claim{}, errors.New("claim: no setup.sh or ca.pem to serve; run pf apply first")
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
// descriptor, so the chown applies only to the file that this call made.
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

// RedeemClaim consumes a code. www reads claims from dir and writes only in
// RedeemedDir(dir). First it reads the claim. It refuses an expired claim,
// a claim file that the owner of dir did not make, a field that
// scriptFields does not accept, and a claim whose setup.sh or ca.pem hash
// is not the hash of the file that www serves now. That answer is the same
// as for an unknown code, and it does not spend the code. Only after all
// checks pass does it make the marker <CODE>.redeemed with O_EXCL. The
// O_EXCL create is the lock and the single-use guarantee: of two callers
// that pass the checks at the same time, only one makes the marker. The
// marker is on disk, so a code stays spent after a restart. A guess leaves
// no file.
func RedeemClaim(dir, code string) (Claim, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !validCode(code) {
		return Claim{}, ErrNoClaim
	}
	src := filepath.Join(dir, code+".json")
	if _, err := os.Lstat(src); err != nil {
		return Claim{}, ErrNoClaim
	}
	raw, err := readClaim(dir, src)
	if err != nil {
		return Claim{}, ErrNoClaim
	}
	var c Claim
	if json.Unmarshal(raw, &c) != nil || c.Code != code || time.Now().After(c.Expires) || !scriptFields(c) || !servesSame(dir, c) {
		return Claim{}, ErrNoClaim
	}
	m, err := os.OpenFile(markerPath(dir, code), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0640)
	if err != nil {
		return Claim{}, ErrNoClaim
	}
	if err := m.Close(); err != nil {
		return Claim{}, ErrNoClaim
	}
	return c, nil
}

// servesSame reports whether www serves now the setup.sh and ca.pem that c
// has the hashes of. After a pf apply that replaced one of them, the claim
// script fails its hash check on the agent. So such a claim is refused
// before the marker. A claim with an empty hash passes here. ClaimScript
// then gives the operator the message for that case.
func servesSame(dir string, c Claim) bool {
	www := filepath.Dir(dir)
	if c.SetupSHA256 != "" && fileSHA256(setupPath(www)) != c.SetupSHA256 {
		return false
	}
	return c.CASHA256 == "" || fileSHA256(caPath(www)) == c.CASHA256
}

// claimMax bounds the read of one claim file. A real claim is far smaller.
const claimMax = 64 << 10

// readClaim reads the claim file at path. The file must be a regular file
// with the owner of dir. Root owns dir and makes each claim. So a file with
// a different owner is not a claim.
func readClaim(dir, path string) ([]byte, error) {
	di, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !sameOwner(di, fi) {
		return nil, ErrNoClaim
	}
	return io.ReadAll(io.LimitReader(f, claimMax))
}

// sameOwner reports whether a and b have the same owner.
func sameOwner(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && sa.Uid == sb.Uid
}

// Sweep removes old claims, and then the marker of each claim that is gone.
// Root runs it (IssueClaim, pf www -init-ledger), because www can remove
// nothing in dir. A claim goes after an hour. A file in dir that the owner
// of dir did not make goes at once: no redeem accepts it. A marker goes
// only after its claim, so a code stays spent while its claim file exists.
// A <CODE>.redeemed in dir is a spent claim of the layout before
// RedeemedDir. It goes after an hour.
func Sweep(dir string) {
	cut := time.Now().Add(-sweepAfter)
	if di, err := os.Stat(dir); err == nil {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".redeemed") && !strings.HasSuffix(name, ".json") {
				continue
			}
			if fi, err := e.Info(); err == nil && (fi.ModTime().Before(cut) || !sameOwner(di, fi)) {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}
	entries, _ := os.ReadDir(RedeemedDir(dir))
	for _, e := range entries {
		code, ok := strings.CutSuffix(e.Name(), ".redeemed")
		if !ok {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, code+".json")); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(cut) {
			_ = os.Remove(filepath.Join(RedeemedDir(dir), e.Name()))
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
		raw, _ := json.MarshalIndent(agentcreds.Doc(c.Slot), "", "  ")
		b.WriteString("mkdir -p \"$HOME/.claude\"\ncat >\"$HOME/.claude/.credentials.json\" <<'PFEOF'\n" + string(raw) + "\nPFEOF\n")
	}
	b.WriteString("mkdir -p \"$HOME/.pi-fortress\"\ncat >\"$HOME/.pi-fortress/env.sh\" <<'PFEOF'\n")
	for _, k := range c.Kinds {
		b.WriteString("export " + k + "='" + secrets.Placeholder(c.Slot, k) + "'\n")
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
		lines = append(lines, "https://x-access-token:"+secrets.Placeholder(slot, "GITHUB_TOKEN")+"@"+h)
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
