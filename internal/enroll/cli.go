package enroll

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/base"
	"pi-fortress/internal/secrets"
)

func secretsPath(override string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	if v := strings.TrimSpace(os.Getenv("PI_FORTRESS_SECRETS")); v != "" {
		return v
	}
	return "/etc/pi-fortress/broker/secrets.env"
}

// The location of the paste file of the agent when nobody names a place:
// the shared policy directory of the lab, else the directory of the
// gateway. These are variables, so the tests do not depend on the machine
// that runs them. A desktop that has run vm/desk/setup.sh lock has its
// own /etc/pi-fortress, owned by root, and three mint tests failed there
// on 2026-09-22.
var (
	labPolicyDir = "/vagrant/vm/policy"
	gatewayDir   = "/etc/pi-fortress"
)

func PasteOutPath(slot string, kinds []string, explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	name := "agent-env-" + slot + ".sh"
	if hasClaudeOAT(kinds) {
		name = "agent-credentials-" + slot + ".json"
	}
	if st, err := os.Stat(labPolicyDir); err == nil && st.IsDir() {
		_ = os.MkdirAll(filepath.Join(labPolicyDir, "generated"), 0755)
		return filepath.Join(labPolicyDir, "generated", name)
	}
	if st, err := os.Stat(gatewayDir); err == nil && st.IsDir() {
		return filepath.Join(gatewayDir, name)
	}
	return ""
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: pf enroll [--secrets PATH] mint|list|peek|migrate|delete|purge|renew|seal|unseal|state ...")
}

func Main(args []string, stdout, stderr io.Writer) int {
	return MainIO(args, os.Stdin, stdout, stderr)
}

func MainIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	secretsOverride := ""
	rest := args
	if len(rest) >= 2 && rest[0] == "--secrets" {
		secretsOverride = rest[1]
		rest = rest[2:]
	}
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	cmd := rest[0]
	path := secretsPath(secretsOverride)
	st := secrets.Open(path)
	start := time.Now()
	rc, changed := dispatch(cmd, rest[1:], st, stdin, stdout, stderr)
	logEnroll(cmd, changed, rc, time.Since(start))
	return rc
}

// dispatch runs one subcommand and gives back what the audit log should
// say that it did. The three commands that take an identifier report it
// themselves, and the code does not scrape it back from the flag set.
// That keeps the audit payload an allow-list, as admin.Args.fields() is.
// So --oat, --ort and --value cannot reach the log through a parse of the
// argv that also carried them. seal and unseal have nothing to report, for
// the same reason as pf unlock: their only argument is the passphrase,
// which is read from the terminal and never written.
func dispatch(cmd string, args []string, st *secrets.Store, stdin io.Reader, stdout, stderr io.Writer) (int, map[string]string) {
	switch cmd {
	case "mint":
		return cmdMint(args, st, stdin, stdout, stderr)
	case "list":
		return cmdList(st, stdout, stderr), nil
	case "peek":
		return cmdPeek(args, st, stdout, stderr), nil
	case "migrate":
		return cmdMigrate(st, stdout, stderr)
	case "delete":
		return cmdDelete(args, st, stdout, stderr)
	case "purge":
		return cmdPurge(args, st, stdout, stderr)
	case "renew":
		return cmdRenew(args, st, stdout, stderr)
	case "seal":
		return cmdSeal(st, stdout, stderr), nil
	case "unseal":
		return cmdUnseal(st, stdout, stderr), nil
	case "state":
		return cmdState(st, stdout, stderr), nil
	default:
		usage(stderr)
		return 2, nil
	}
}

// enrollMutates names the subcommands that change the store. list, peek
// and state read it. A record of each read would bury the writes, which
// are the point. Verb.Mutates makes the same judgement for the verb table.
// An unknown subcommand is absent from this map, so it is not recorded:
// nothing changed.
var enrollMutates = map[string]bool{
	"mint": true, "migrate": true, "delete": true,
	"purge": true, "renew": true, "seal": true, "unseal": true,
}

// logEnroll records what pf enroll did. This is the only account of the
// history of the credential store. The mint, the delete and the retention
// purge that vm/pi/apply.sh runs unattended on each apply all occur here.
// None of them goes through admin.CallCtx.
//
// The outcome is an exit code, not an error, because that is all that
// this layer has. The subcommands print their own diagnosis to stderr
// and return a number. To name the code is more honest than to invent a
// message for it.
func logEnroll(cmd string, args map[string]string, rc int, took time.Duration) {
	if !enrollMutates[cmd] {
		return
	}
	e := audit.Entry{
		Verb:  "enroll." + cmd,
		Role:  "admin",
		Actor: audit.Actor(os.Getenv, os.Getuid()),
		Args:  args,
		OK:    rc == 0,
		MS:    took.Milliseconds(),
	}
	if rc != 0 {
		e.Err = "exit " + strconv.Itoa(rc)
	}
	_ = audit.Default().Append(e)
}

// readStdinPair takes the oat on the first line and the ort on the
// second. So a clipboard can go through a pipe over ssh, and the tokens
// are never shell arguments.
func readStdinPair(r io.Reader) (string, string) {
	sc := bufio.NewScanner(r)
	var lines []string
	for sc.Scan() && len(lines) < 2 {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	for len(lines) < 2 {
		lines = append(lines, "")
	}
	return lines[0], lines[1]
}

// cmdMint returns the slot and kind that it minted for the audit log, and
// nothing else. --oat, --ort and --value are the credential itself. The
// slot id is the placeholder that goes in config files in its place.
func cmdMint(args []string, st *secrets.Store, stdin io.Reader, stdout, stderr io.Writer) (int, map[string]string) {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "", "")
	oat := fs.String("oat", "", "")
	ort := fs.String("ort", "", "")
	value := fs.String("value", "", "")
	out := fs.String("out", "", "")
	fromStdin := fs.Bool("stdin", false, "")
	expiresFlag := fs.String("expires", DefaultExpiry, "")
	headerFlag := fs.String("header", "", "")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	// Read before --stdin writes into the same variables.
	argvTokens := argvTokenFlags(fs)
	if strings.TrimSpace(*kind) == "" {
		fmt.Fprintln(stderr, "usage: pf enroll mint --kind KIND [--oat ...] [--ort ...] [--value ...] [--stdin] [--out PATH] [--expires 90d|RFC3339|none] [--header H[,H...]]")
		return 2, nil
	}
	// This is parsed before anything is minted. A bad --expires must not leave
	// a minted slot with no way to set the deadline that was asked for.
	// Each new slot expires unless the operator says none. Slots minted
	// before the default existed keep no deadline until renewed.
	expiresAt, err := parseMintExpiry(*expiresFlag)
	if err != nil {
		fmt.Fprintf(stderr, "bad --expires: %s\n", err)
		return 2, nil
	}
	// --header is checked, and core.hosts.local planned, before anything
	// is minted. A name that apply would refuse, or a kind that no host binds,
	// must not leave a slot behind that no header can carry.
	var hp *headerPlan
	if headerFlagSet(fs) {
		plan, code := planMintHeaders(*kind, *headerFlag, stderr)
		if plan == nil {
			return code, nil
		}
		hp = plan
	}
	// Before the tokens come from stdin, and before any write. A mint
	// seals the row that it writes, and this process holds no key, so
	// the answer is already fixed. A read of the paste first would cost
	// the operator their clipboard for nothing. cmdMigrate short-circuits
	// on a sealed store for the same reason.
	if err := st.MintAllowed(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1, nil
	}
	if *fromStdin {
		a, b := readStdinPair(stdin)
		*oat, *ort, *value = a, b, a
	}
	kinds, err := secrets.KindsFor(*kind)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2, nil
	}
	values, bad := mintValues(kinds, *oat, *ort, *value)
	if len(bad) > 0 {
		fmt.Fprintln(stderr, strings.Join(bad, "\n"))
		return 2, nil
	}
	if len(argvTokens) > 0 {
		fmt.Fprintf(stderr, "warning: %s: a token in the command line shows in ps and in the shell history; use --stdin\n", strings.Join(argvTokens, ", "))
	}
	if hp != nil && hp.changed {
		if err := hp.write(); err != nil {
			fmt.Fprintf(stderr, "--header: %s\n", err)
			return 1, map[string]string{"kind": *kind}
		}
	}
	slot, err := st.MintKinds(kinds, values)
	minted := map[string]string{"kind": *kind}
	if hp != nil {
		minted["header"] = *headerFlag
	}
	if slot != "" {
		minted["slot"] = slot
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1, minted
	}
	if !expiresAt.IsZero() {
		if err := st.SetExpiry(slot, expiresAt); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1, minted
		}
		minted["expires"] = expiresAt.UTC().Format(time.RFC3339)
	}
	return reportMint(slot, kinds, expiresAt, *out, hp, stdout, stderr), minted
}

// parseMintExpiry gives the zero time for an empty flag, "none" or
// "never". The slot then has no deadline.
func parseMintExpiry(flagValue string) (time.Time, error) {
	raw := strings.TrimSpace(flagValue)
	if raw == "" || strings.EqualFold(raw, "none") || strings.EqualFold(raw, "never") {
		return time.Time{}, nil
	}
	return parseExpiry(time.Now(), flagValue)
}

// planMintHeaders checks --header and plans core.hosts.local. On a
// refusal it writes the reason to stderr and gives a nil plan and the
// exit code.
func planMintHeaders(kind, headerFlag string, stderr io.Writer) (*headerPlan, int) {
	hdrs, err := parseHeaderFlag(headerFlag)
	if err != nil {
		fmt.Fprintf(stderr, "bad --header: %s\n", err)
		return nil, 2
	}
	hk, err := secrets.KindsFor(kind)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return nil, 2
	}
	plan, err := planHeaders(base.PolicyDir(), hk[0], hdrs)
	if err != nil {
		fmt.Fprintf(stderr, "--header: %s\n", err)
		return nil, 1
	}
	return &plan, 0
}

// mintValues gives the value of each kind. For the Claude pair, it gives
// the reasons that the pair is refused, if there are any.
func mintValues(kinds []string, oat, ort, value string) (map[string]string, []string) {
	if !hasClaudeOAT(kinds) {
		return map[string]string{kinds[0]: value}, nil
	}
	if bad := ClaudeMintErrors(oat, ort); len(bad) > 0 {
		return nil, bad
	}
	return map[string]string{"CLAUDE_OAT": oat, "CLAUDE_ORT": ort}, nil
}

// reportMint prints the minted slot and the agent paste, and writes the
// paste file. It gives the exit code.
func reportMint(slot string, kinds []string, expiresAt time.Time, out string, hp *headerPlan, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "slot=%s\n", slot)
	for _, k := range kinds {
		fmt.Fprintf(stdout, "%s=%s\n", k, secrets.Placeholder(slot, k))
	}
	if !expiresAt.IsZero() {
		fmt.Fprintf(stdout, "expires=%s\n", expiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, AgentPaste(slot, kinds))
	if dest := PasteOutPath(slot, kinds, out); dest != "" {
		if err := WriteAgentPaste(slot, kinds, dest); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "wrote "+dest)
		fmt.Fprintln(stdout, "host: xclip -selection clipboard < vm/policy/generated/"+filepath.Base(dest))
	}
	if hp != nil {
		fmt.Fprintln(stdout)
		verb := "wrote"
		if !hp.changed {
			verb = "already in"
		}
		for _, l := range hp.lines {
			fmt.Fprintf(stdout, "%s %s: %s\n", verb, hp.path, l)
		}
		fmt.Fprintln(stdout, "sudo pf apply makes it live")
	}
	return 0
}

// argvTokenFlags names each of --oat, --ort and --value that carries a
// token on the command line. A command-line argument shows in ps, in the
// shell history and in the journal, so cmdMint writes one warning for
// them. The mint continues, so scripts do not break. The warning names
// the flags only, never their values.
func argvTokenFlags(fs *flag.FlagSet) []string {
	var names []string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "oat", "ort", "value":
			if strings.TrimSpace(f.Value.String()) != "" {
				names = append(names, "--"+f.Name)
			}
		}
	})
	return names
}

func headerFlagSet(fs *flag.FlagSet) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == "header" })
	return set
}

func cmdList(st *secrets.Store, stdout, stderr io.Writer) int {
	rows, err := st.ListSlots()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	for _, row := range rows {
		expires := row.Expires
		if expires == "" {
			expires = "-"
		}
		for _, key := range row.Keys {
			fmt.Fprintf(stdout, "%s  %s  %s  %s  %s\n", row.Slot, key.Kind, key.Dummy, key.State, expires)
		}
	}
	return 0
}

func cmdPeek(args []string, st *secrets.Store, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("peek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	slotFlag := fs.String("slot", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := openIfSealed(st, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	snap, err := st.Snapshot()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	want := strings.ToLower(strings.TrimSpace(*slotFlag))
	type row struct{ slot, kind, live string }
	var rows []row
	for _, sl := range snap {
		if want != "" && sl.ID != want {
			continue
		}
		rows = append(rows, row{sl.ID, sl.Kind, sl.Live})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].slot != rows[j].slot {
			return rows[i].slot < rows[j].slot
		}
		return rows[i].kind < rows[j].kind
	})
	if want != "" && len(rows) == 0 {
		fmt.Fprintln(stderr, "slot not found")
		return 1
	}
	for _, r := range rows {
		fmt.Fprintf(stdout, "%s  %s  %s\n", r.slot, r.kind, RedactLive(r.live, 8, 4))
		if r.kind == "CLAUDE_ORT" && strings.HasPrefix(r.live, OATPrefix) {
			fmt.Fprintln(stdout, "  WARN: refresh is oat01; remint with --ort sk-ant-ort01-…")
		}
		if r.kind == "CLAUDE_OAT" && strings.HasPrefix(r.live, ORTPrefix) {
			fmt.Fprintln(stdout, "  WARN: access is ort01; remint with --oat sk-ant-oat01-…")
		}
	}
	return 0
}

// cmdMigrate reports how many unslotted values it moved. Nothing else
// about a migration is recordable. The values that it moves are the
// credentials themselves, and the slot ids that it mints for them are
// already in the store that it just rewrote.
func cmdMigrate(st *secrets.Store, stdout, stderr io.Writer) (int, map[string]string) {
	state, err := st.State()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1, nil
	}
	// This runs on each pf apply, so it must never stop to prompt. It
	// also has nothing to do here. An unslotted value in a sealed store
	// would be plaintext under a sealed header. That is the fault that
	// fails the full store shut, not something to migrate.
	if state.Sealed && !state.Unlocked {
		fmt.Fprintln(stdout, "sealed store: nothing to migrate")
		return 0, map[string]string{"moved": "0"}
	}
	moved, err := st.MigrateUnslotted()
	detail := map[string]string{"moved": strconv.Itoa(len(moved))}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1, detail
	}
	for _, m := range moved {
		fmt.Fprintf(stdout, "migrated %s -> %s\n", m.Old, secrets.Placeholder(m.Slot, m.Kind))
	}
	return 0, detail
}

// cmdDelete reports the slots that it actually removed, not the slots
// that it was asked for. A list that names four slots, of which one was
// already gone, is a different event. Readers use the audit log to learn
// what is no longer on the box.
func cmdDelete(args []string, st *secrets.Store, stdout, stderr io.Writer) (int, map[string]string) {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	slotFlag := fs.String("slot", "", "")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	var slots []string
	for _, slot := range strings.Split(*slotFlag, ",") {
		slot = strings.ToLower(strings.TrimSpace(slot))
		if slot == "" {
			continue
		}
		// Refuse the full list on one bad id, before anything is deleted.
		if _, err := hex.DecodeString(slot); err != nil || len(slot) != secrets.SlotLen {
			fmt.Fprintf(stderr, "invalid slot %q\n", slot)
			return 2, nil
		}
		slots = append(slots, slot)
	}
	if len(slots) == 0 {
		fmt.Fprintln(stderr, "usage: pf enroll delete --slot SLOT[,SLOT...]")
		return 2, nil
	}
	rc := 0
	var gone []string
	for _, slot := range slots {
		removed, err := st.DeleteSlot(slot)
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2, deleted(gone)
		}
		if len(removed) == 0 {
			fmt.Fprintf(stderr, "slot not found: %s\n", slot)
			rc = 1
			continue
		}
		gone = append(gone, slot)
		fmt.Fprintf(stdout, "deleted slot=%s kinds=%s\n", slot, strings.Join(removed, ","))
	}
	return rc, deleted(gone)
}

// deleted names the slots that went, or nothing at all when none went.
// An empty "slots" field would read as a delete that named no slot, not
// as a delete that found none.
func deleted(slots []string) map[string]string {
	if len(slots) == 0 {
		return nil
	}
	return map[string]string{"slots": strings.Join(slots, ",")}
}

// cmdRenew sets or clears the expiry deadline of a slot. The new deadline
// can be earlier or later than the old one. It never touches secrets.env. The deadline is in its own sidecar
// (secrets.expires), the same file that harvest never writes. So a renew
// is the one and only way that the expiry of a slot moves: a refresh that
// captures a new oat/ort cannot move it by accident.
func cmdRenew(args []string, st *secrets.Store, stdout, stderr io.Writer) (int, map[string]string) {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	fs.SetOutput(stderr)
	slotFlag := fs.String("slot", "", "")
	expiresFlag := fs.String("expires", "", "")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	slot := strings.ToLower(strings.TrimSpace(*slotFlag))
	usageErr := func() (int, map[string]string) {
		fmt.Fprintln(stderr, "usage: pf enroll renew --slot SLOT --expires 30d|RFC3339|none")
		return 2, nil
	}
	if slot == "" {
		return usageErr()
	}
	if _, err := hex.DecodeString(slot); err != nil || len(slot) != secrets.SlotLen {
		fmt.Fprintf(stderr, "invalid slot %q\n", slot)
		return 2, nil
	}
	raw := strings.TrimSpace(*expiresFlag)
	if raw == "" {
		return usageErr()
	}
	var at time.Time
	if strings.EqualFold(raw, "none") || strings.EqualFold(raw, "never") {
		at = time.Time{}
	} else {
		var err error
		at, err = parseExpiry(time.Now(), raw)
		if err != nil {
			fmt.Fprintf(stderr, "bad --expires: %s\n", err)
			return 2, nil
		}
	}
	if err := st.SetExpiry(slot, at); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1, map[string]string{"slot": slot}
	}
	detail := map[string]string{"slot": slot}
	if at.IsZero() {
		detail["expires"] = "none"
		fmt.Fprintf(stdout, "slot=%s expires=none\n", slot)
	} else {
		detail["expires"] = at.UTC().Format(time.RFC3339)
		fmt.Fprintf(stdout, "slot=%s expires=%s\n", slot, detail["expires"])
	}
	return 0, detail
}

// cmdPurge is the one mutation on this box that nobody asks for.
// vm/pi/apply.sh runs it unattended on each apply, so a credential can
// disappear with no operator present. So its audit line is the line that
// answers "the agent stopped working and nobody touched it". It names the
// retention window that decided, and each slot that the window took.
func cmdPurge(args []string, st *secrets.Store, stdout, stderr io.Writer) (int, map[string]string) {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	older := fs.String("older-than", "7d", "")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	d, err := parseDays(*older)
	if err != nil {
		fmt.Fprintln(stderr, "usage: pf enroll purge --older-than 7d")
		return 2, map[string]string{"older-than": *older}
	}
	purged, err := st.PurgeOlderThan(d)
	detail := map[string]string{"older-than": *older, "purged": strconv.Itoa(len(purged))}
	if len(purged) > 0 {
		detail["slots"] = strings.Join(purged, ",")
	}
	for _, id := range purged {
		fmt.Fprintf(stdout, "purged slot=%s\n", id)
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1, detail
	}
	return 0, detail
}

// parseDays reads the retention argument. It decides which quarantined
// slots are deleted permanently. So when it cannot read the argument
// exactly, it refuses, and does not make a best guess.
//
// Sscanf was the wrong reader: it stops at the first character that it
// cannot use, and calls that a success. So "0x10d" was zero days, and
// purged the full quarantine. The day arithmetic was also unchecked: a
// count that is large enough overflows into a negative duration, which
// puts the cutoff in the future, with the same effect. And the non-day
// path never examined the sign, so "-1h" did it intentionally.
func parseDays(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > maxRetentionDays {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("bad duration %q: retention cannot be negative", s)
	}
	return d, nil
}

// maxRetentionDays is a century. Past it, the day-to-nanosecond
// multiplication overflows. A number that large is a typo in any
// case: nothing is retained for longer than the box exists.
const maxRetentionDays = 36500

// DefaultExpiry is how long a slot lives when it is minted without
// --expires. The broker warns daily over the last seven days (internal/broker expiry.go).
const DefaultExpiry = "90d"

// parseExpiry reads --expires for mint and renew: an absolute RFC3339
// instant, or a duration from now in the syntax of parseDays ("30d", "12h").
// It does not accept an empty string. The caller decides what no flag
// means: mint leaves the deadline unset, and renew refuses. A renew with
// nothing to change is a no-op that is better to catch than to ignore
// silently.
func parseExpiry(now time.Time, s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	d, err := parseDays(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither RFC3339 nor a duration like 30d: %w", s, err)
	}
	return now.Add(d), nil
}

// openIfSealed prompts for the passphrase when the next verb needs
// plaintext values and the store is sealed. peek is the only caller: it is
// the one verb that must print values, so it is the one verb worth a stop
// of the operator. migrate also needs values, but it runs on each pf apply
// and must never block. So it short-circuits on a sealed store, and does
// not come here. mint is refused outright: pf enroll holds no key to seal
// with, whatever is typed at a prompt. All other verbs work on the
// inventory alone. That is why a sealed box is still diagnosable.
func openIfSealed(st *secrets.Store, out io.Writer) error {
	state, err := st.State()
	if err != nil {
		return err
	}
	if !state.Sealed || state.Unlocked {
		return nil
	}
	if state.Fault != "" {
		return errors.New(state.Fault)
	}
	pass, err := secrets.ReadPassphrase("Passphrase: ", out)
	if err != nil {
		return err
	}
	return st.Unlock(pass)
}

// cmdSeal encrypts each value in the store at once. The full file or
// nothing: a plaintext value that stays valid beside a sealed value would
// be a downgrade that anything with write access could take, under a
// header that still said sealed.
func cmdSeal(st *secrets.Store, stdout, stderr io.Writer) int {
	pass, err := secrets.ConfirmNewPassphrase(stdout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := st.Seal(pass); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "sealed. every reboot now needs pf unlock before any credential is substituted.")
	return 0
}

func cmdUnseal(st *secrets.Store, stdout, stderr io.Writer) int {
	pass, err := secrets.ReadPassphrase("Passphrase: ", stdout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := st.Unseal(pass); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "unsealed. values are at rest in the clear again.")
	return 0
}

// cmdState answers "why is nothing being substituted" without an open of
// anything. It names the state of the store, and never a value.
func cmdState(st *secrets.Store, stdout, stderr io.Writer) int {
	state, err := st.State()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch {
	case state.Fault != "":
		fmt.Fprintln(stdout, "fault: "+state.Fault)
		fmt.Fprintln(stdout, "the store is failed shut; every substitution is refused.")
		return 1
	case !state.Sealed:
		fmt.Fprintln(stdout, "plaintext")
	case state.Unlocked:
		fmt.Fprintln(stdout, "sealed, unlocked")
	default:
		// The key is in the memory of the broker and in no other place.
		// So this process, which opened the file for itself, holds no key.
		// It would say "locked" about a store that the broker serves from
		// (seen on the Pi 2026-09-22, directly after a good unlock). Only
		// the broker can say whether the store is open.
		switch brokerState() {
		case "sealed unlocked":
			fmt.Fprintln(stdout, "sealed, unlocked")
		case "sealed locked":
			fmt.Fprintln(stdout, "sealed, locked: pf unlock")
		default:
			fmt.Fprintln(stdout, "sealed; the broker did not say whether it holds the key: pf unlock -state")
		}
	}
	return 0
}

// brokerState asks the running broker what it holds. Empty when there is
// no broker to ask: each test, and each box with the fence down.
var brokerState = func() string {
	conn, err := net.DialTimeout("unix", secrets.AdminSock, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(secrets.AdminState + "\n")); err != nil {
		return ""
	}
	reply, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(reply)
}
