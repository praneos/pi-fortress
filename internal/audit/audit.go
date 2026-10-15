// Package audit is the record of administrative changes: which verb ran,
// with which arguments, when, and if it succeeded.
//
// It can honestly claim less than "who did what". This limit is the
// design. It is not a gap to fix later. This product has no identity
// other than "root ran pf tui": the TUI hardcodes RoleAdmin
// (internal/tui/app.go), no code constructs RoleOperator, and no code
// reads unix peer credentials. Thus an entry records the actor that it
// can really observe: SUDO_USER when a sudoer started the root process,
// and the uid if not. The entry tells which of the two it is. It does not
// show a guess as a fact. A root shell can set SUDO_USER to any value.
// This record helps the honest operator find what occurred. It is not
// evidence against a hostile operator who already owns the box.
//
// One verb in the table of internal/admin has a credential:
// secrets.unlock gets the store passphrase in Args.Secret. Args.fields()
// keeps it out of the record. Its absence does not. Args.fields() is an
// allow-list: it names the fields to copy. Thus it drops each field that
// is not on the list. Keep it that way. If fields() becomes a denylist,
// or the code records Args with no change because "no verb has a
// secret", the passphrase goes into the audit log.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"pi-fortress/internal/base"
)

const DefaultPath = "/var/log/pi-fortress/audit.jsonl"

// PathEnv redirects the log for the entry points that are not the verb
// table. internal/admin has a path in its Config. Thus a test builds one
// and points it at a temp dir. pf enroll, pf fetch, pf compile, the www
// claim handoff and vm/pi/apply.sh have no such Config. Without this, the
// only way to test their audit lines would be to run the tests as root
// against the real /var/log. apply.sh reads the same variable. Thus the
// shell line and the Go lines go into one file.
const PathEnv = "PF_AUDIT_LOG"

// Default is the log for an entry point that has no configuration of its
// own with a path.
func Default() *Log {
	if v := strings.TrimSpace(os.Getenv(PathEnv)); v != "" {
		return New(v)
	}
	return New(DefaultPath)
}

// Entry is one line. The field names are the same as in
// internal/www/ledger.go, the other actor-and-action record of the repo.
type Entry struct {
	Ev    string            `json:"ev"`
	T     string            `json:"t"`
	Verb  string            `json:"verb"`
	Role  string            `json:"role,omitempty"`
	Actor string            `json:"actor,omitempty"`
	Args  map[string]string `json:"args,omitempty"`
	OK    bool              `json:"ok"`
	Err   string            `json:"err,omitempty"`
	MS    int64             `json:"ms,omitempty"`
}

// Log appends entries. It opens the file for each write, like
// internal/jsonl. An admin action is rare, so a held handle gives no
// benefit. A file that is open only during a write continues correctly
// after a rotation, and no code must tell it about the rotation.
type Log struct {
	Path string
	Now  func() string

	mu sync.Mutex
}

func New(path string) *Log { return &Log{Path: path} }

func (l *Log) stamp() string {
	if l.Now != nil {
		return l.Now()
	}
	return base.NowISO(nil)
}

// Append writes one entry. It returns a write failure, but callers on the
// action path ignore it. If a Pi did not reboot because its audit log is
// full, that would be a worse failure than the gap in the record.
func (l *Log) Append(e Entry) error {
	if l == nil || l.Path == "" {
		return nil
	}
	if e.T == "" {
		e.T = l.stamp()
	}
	if e.Ev == "" {
		e.Ev = "verb"
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0755); err != nil {
		return err
	}
	// 0600: the log names what an operator changed. The TUI reads it,
	// and the TUI is root. Nothing in pf-fortress needs it.
	f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(raw, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Actor names the actor, as far as the process can tell. Under sudo, the
// shell exports SUDO_USER and the uid is 0. Thus the two together tell
// more than one alone. The string tells which one it is, so a reader
// never thinks that an inference is an identity.
func Actor(env func(string) string, uid int) string {
	if env == nil {
		env = os.Getenv
	}
	who := strings.TrimSpace(env("SUDO_USER"))
	if plainName(who) {
		return "sudo:" + who
	}
	return "uid:" + strconv.Itoa(uid)
}

// plainName keeps a control byte or a space out of the record. The person
// who ran sudo sets SUDO_USER. Thus it is input, not a fact.
func plainName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}
