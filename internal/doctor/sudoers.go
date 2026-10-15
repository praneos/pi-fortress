package doctor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
)

var sudoTags = map[string]bool{
	"NOPASSWD": true, "PASSWD": true, "NOEXEC": true, "EXEC": true,
	"SETENV": true, "NOSETENV": true, "LOG_INPUT": true, "NOLOG_INPUT": true,
	"LOG_OUTPUT": true, "NOLOG_OUTPUT": true, "MAIL": true, "NOMAIL": true,
	"FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

// NopasswdAll reports whether sudoers text grants ALL commands without a
// password, or disables authentication in Defaults. It also reports
// whether it understood the full file while it decided.
//
// complete is false when the text held something that this parser skips:
// an alias definition, whose expansion could change an innocent-looking
// rule into a grant of ALL, or an include directive, whose target is a
// file that this parser never opened. A false here does not mean that a
// grant was found. It means that this parser is not entitled to state
// "no grant" as a fact, and the report must say inconclusive instead. An
// includedir that names one of covered is the exception: covered is a
// directory where the caller reads each file (SudoersFiles), so its
// contents are checked, not skipped. Stock Debian and Pi OS end sudoers
// with exactly that line.
func NopasswdAll(text string, covered ...string) (nopasswd, complete bool) {
	complete = true
	text = strings.ReplaceAll(text, "\\\n", " ")
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@include") || strings.HasPrefix(line, "#include") {
			if dir, ok := includeDir(line); !ok || !slices.Contains(covered, dir) {
				complete = false
			}
			continue
		}
		if line[0] == '#' {
			continue
		}
		if f := strings.Fields(line)[0]; strings.HasPrefix(f, "Defaults") {
			if strings.Contains(strings.ReplaceAll(line, " ", ""), "!authenticate") {
				return true, complete
			}
			continue
		} else if strings.HasSuffix(f, "_Alias") {
			complete = false
			continue
		}
		_, spec, ok := strings.Cut(line, "=")
		if ok && specNopasswdAll(spec) {
			return true, complete
		}
	}
	return false, complete
}

// specNopasswdAll reports whether the command list of one rule (the text
// after "=") holds ALL under NOPASSWD. A tag stays in effect for the
// commands that follow it, until a later tag changes it.
func specNopasswdAll(spec string) bool {
	nopw := false
	for item := range strings.SplitSeq(spec, ",") {
		s := strings.TrimSpace(item)
		if strings.HasPrefix(s, "(") {
			if _, after, ok := strings.Cut(s, ")"); ok {
				s = strings.TrimSpace(after)
			}
		}
		for {
			tag, rest, ok := strings.Cut(s, ":")
			if !ok || !sudoTags[strings.TrimSpace(tag)] {
				break
			}
			switch strings.TrimSpace(tag) {
			case "NOPASSWD":
				nopw = true
			case "PASSWD":
				nopw = false
			}
			s = strings.TrimSpace(rest)
		}
		if f := strings.Fields(s); nopw && len(f) > 0 && f[0] == "ALL" {
			return true
		}
	}
	return false
}

// includeDir is the directory that an @includedir or #includedir line
// names, when it names one by an absolute path. sudo resolves a relative
// path against the including file. This code does not know that file, so
// it does not claim the directory.
func includeDir(line string) (string, bool) {
	verb := strings.Fields(line)[0]
	if verb != "@includedir" && verb != "#includedir" {
		return "", false
	}
	arg := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, verb)), `"`)
	if !filepath.IsAbs(arg) {
		return "", false
	}
	return filepath.Clean(arg), true
}

// SudoersFiles lists the files that sudo reads by default. It skips the
// sudoers.d names that sudo itself skips (a dot or a trailing ~). A
// sudoers.d that is there and cannot be listed is returned as an error,
// and is not dropped. It is a directory full of rules that nobody checked.
// The caller must not report a clean box on the strength of the one file
// that it did read.
func SudoersFiles(etc string) ([]string, error) {
	files := []string{filepath.Join(etc, "sudoers")}
	ents, err := os.ReadDir(filepath.Join(etc, "sudoers.d"))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	for _, e := range ents {
		if n := e.Name(); !e.IsDir() && !strings.Contains(n, ".") && !strings.HasSuffix(n, "~") {
			files = append(files, filepath.Join(etc, "sudoers.d", n))
		}
	}
	return files, err
}

// SudoRung is a best-effort parse, so its negative answer is reported as
// one. A grant that was found is a fact, and stays a Warn. "nothing
// found" is stated flatly only when each file was read and each line was
// understood. If not, the rung says so. "no passwordless sudo for ALL"
// over a skipped alias or an unread directory is a report that tells an
// operator something that it does not know.
func SudoRung(files []string, dirErr error) (Result, bool) {
	at := func(detail string, st Status) (Result, bool) {
		return Result{Rung: "sudo", Where: "pi", Detail: detail, Status: st}, true
	}
	var hits, unreadable []string
	found, complete := false, true
	// SudoersFiles puts sudoers first, and lists each file of the sudoers.d
	// beside it. So an includedir of that directory is read here.
	var covered []string
	if len(files) > 0 && dirErr == nil {
		covered = []string{filepath.Join(filepath.Dir(files[0]), "sudoers.d")}
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		found = true
		if err != nil {
			unreadable = append(unreadable, f)
			continue
		}
		hit, whole := NopasswdAll(string(raw), covered...)
		if !whole {
			complete = false
		}
		if hit {
			hits = append(hits, f)
		}
	}
	switch {
	case len(hits) > 0:
		return at("passwordless sudo for ALL in "+strings.Join(hits, ", ")+": a stolen login key is root (docs/signed_ship.md)", Warn)
	case len(unreadable) > 0 || dirErr != nil:
		what := append([]string{}, unreadable...)
		if dirErr != nil {
			what = append(what, dirErr.Error())
		}
		return at("cannot read "+strings.Join(what, ", ")+", so whether sudo asks for a password is inconclusive; run sudo pf doctor", Warn)
	case found && !complete:
		return at("nothing granting passwordless ALL in what could be parsed, but aliases and include directives are not expanded, so this is inconclusive; check with sudo -l", Warn)
	case found:
		return at("no passwordless sudo for ALL", OK)
	}
	return Result{}, false
}

// ShipRung is the last signed ship attempt, if any.
func ShipRung(row jsonl.Ship, ok bool) (Result, bool) {
	if !ok {
		return Result{}, false
	}
	when := row.T
	if t, err := time.Parse(time.RFC3339Nano, row.T); err == nil {
		when = t.Local().Format("2006-01-02 15:04")
	}
	detail := fmt.Sprintf("last ship %s at %s, version %d %s", row.Result, when, row.Version, row.SHA)
	// confirm is not a problem to report: it is the operator (or, in time,
	// the post-upgrade doctor) who says that the last upgrade is good.
	// deadman stays a Warn. It means that an upgrade reverted itself
	// unattended. That is worth a look from an operator, although nothing
	// here is broken now.
	if row.Result == "ok" || row.Result == "confirm" {
		return Result{Rung: "ship", Where: "pi", Detail: strings.TrimSpace(detail), Status: OK}, true
	}
	return Result{Rung: "ship", Where: "pi", Detail: detail + ": " + row.Reason, Status: Warn}, true
}
