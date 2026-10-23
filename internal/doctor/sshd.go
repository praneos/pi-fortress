package doctor

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sshdKeys are the sshd_config keywords that decide whether sshd asks
// for a password. ChallengeResponseAuthentication is the old name of
// KbdInteractiveAuthentication.
var sshdKeys = map[string]string{
	"passwordauthentication":          "passwordauthentication",
	"kbdinteractiveauthentication":    "kbdinteractiveauthentication",
	"challengeresponseauthentication": "kbdinteractiveauthentication",
	"usepam":                          "usepam",
}

// sshdSetting is the first value of a keyword, and the file that set it.
type sshdSetting struct{ value, file string }

// sshdScan reads an sshd_config as sshd does for these keywords: the
// first value wins, and an Include reads its files (sorted, relative to
// the directory of the main file) at that point. A value inside a Match
// block applies only to some logins. It is not a first value, but it sets
// conditional. unreadable lists the files that it could not read.
type sshdScan struct {
	base        string
	set         map[string]sshdSetting
	conditional bool
	unreadable  []string
}

func (s *sshdScan) file(path string, depth int) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		s.unreadable = append(s.unreadable, path)
		return
	}
	inMatch := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		f := strings.Fields(strings.ReplaceAll(line, "=", " "))
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		key := strings.ToLower(f[0])
		switch {
		case key == "match":
			inMatch = true
		case key == "include" && depth < 8:
			for _, pat := range f[1:] {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join(s.base, pat)
				}
				names, _ := filepath.Glob(pat)
				sort.Strings(names)
				for _, n := range names {
					s.file(n, depth+1)
				}
			}
		case sshdKeys[key] != "" && len(f) > 1:
			k := sshdKeys[key]
			if inMatch {
				if strings.EqualFold(f[1], "yes") {
					s.conditional = true
				}
				continue
			}
			if _, ok := s.set[k]; !ok {
				s.set[k] = sshdSetting{strings.ToLower(f[1]), path}
			}
		}
	}
}

// SSHPasswordRung tells whether sshd takes passwords, from its config
// files. sshd -T would be exact, but it needs root. This is a
// best-effort parse, as SudoRung is: "keys only" is stated flatly only
// when each file was read and no Match block turns passwords on again.
// No sshd_config means no sshd, and no rung.
func SSHPasswordRung(sshdConfig string) (Result, bool) {
	at := func(detail string, st Status) (Result, bool) {
		return Result{Rung: "ssh", Where: "pi", Detail: detail, Status: st}, true
	}
	if _, err := os.Stat(sshdConfig); errors.Is(err, fs.ErrNotExist) {
		return Result{}, false
	}
	s := &sshdScan{base: filepath.Dir(sshdConfig), set: map[string]sshdSetting{}}
	s.file(sshdConfig, 0)
	// The defaults of sshd: passwords yes, keyboard-interactive yes, PAM no.
	// Keyboard-interactive asks for the password only through PAM.
	get := func(k, def string) sshdSetting {
		if v, ok := s.set[k]; ok {
			return v
		}
		return sshdSetting{def, "the sshd default"}
	}
	pw := get("passwordauthentication", "yes")
	kbd := get("kbdinteractiveauthentication", "yes")
	pam := get("usepam", "no")
	const fix = "add a login key to authorized_keys and run sudo pf apply, which turns passwords off"
	switch {
	case pw.value == "yes":
		return at("sshd takes passwords (PasswordAuthentication yes, from "+pw.file+"); "+fix, Warn)
	case kbd.value == "yes" && pam.value == "yes":
		return at("sshd takes passwords through PAM (KbdInteractiveAuthentication yes, from "+kbd.file+"); "+fix, Warn)
	case len(s.unreadable) > 0:
		return at("cannot read "+strings.Join(s.unreadable, ", ")+", so whether sshd takes passwords is inconclusive; run sudo pf doctor or sudo sshd -T", Warn)
	case s.conditional:
		return at("passwords are off, but a Match block turns password or keyboard-interactive login on for some logins; check with sudo sshd -T -C user=<name>", Warn)
	}
	return at("sshd takes keys only", OK)
}
