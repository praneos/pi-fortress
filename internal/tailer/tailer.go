// Package tailer follows a JSONL log from a saved offset and runs the drain,
// show, once and watch loops over it. internal/alert uses it.
package tailer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const defaultSleep = 200 * time.Millisecond

// maxLine limits one record. The agent writes most of the data in these
// logs. Thus a sequence of bytes with no newline was an allocation with a
// size that the agent selected. ReadString of bufio would grow to hold all
// of it. No code here parses a JSONL record that long. Thus the code
// counts it and drops it. It does not keep it.
const maxLine = 1 << 20

// tailWindow is how far back Show looks for the last record. The log is
// append-only and unbounded. When the code read the full log to find the
// last line, pf alert show cost the size of the log.
const tailWindow = 64 << 10

// offsetWidth is the fixed width of the offset record. The sidecar owns
// its offset file, but not the root-owned directory of the file (apply.sh
// creates the file first). Thus it cannot write a temp file and rename it.
// It writes the record in place, at one length, and never truncates first.
// A crash during a write leaves the old record or the new one. It never
// leaves the empty file that made Run skip to the end of the log. The width
// holds the offset, the dev:ino and the head sum with space to spare.
const offsetWidth = 128

// headSpan is how many bytes at the start of the log the head sum covers.
// The sum covers min(offset, headSpan) bytes. Thus the code can compute it
// again at a restart from the saved offset alone.
const headSpan = 4096

// headSumLen is the length of the head sum in hex digits.
const headSumLen = 32

// fileID names an inode. A byte offset is correct only for the file in
// which the code counted it. logrotate renames the log and the writer opens
// a new one. The new file gets past the old offset in minutes. Thus a size
// comparison never sees the rotation. Then the code skips permanently all
// data written to the new file before it grew past the old offset.
type fileID struct{ dev, ino uint64 }

func idOf(fi os.FileInfo) fileID {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{uint64(sys.Dev), uint64(sys.Ino)}
}

func (id fileID) String() string {
	return strconv.FormatUint(id.dev, 10) + ":" + strconv.FormatUint(id.ino, 10)
}

func parseID(s string) fileID {
	dev, ino, ok := strings.Cut(s, ":")
	if !ok {
		return fileID{}
	}
	d, err := strconv.ParseUint(dev, 10, 64)
	if err != nil {
		return fileID{}
	}
	i, err := strconv.ParseUint(ino, 10, 64)
	if err != nil {
		return fileID{}
	}
	return fileID{d, i}
}

// headSum is the hex of the first 16 bytes of the SHA-256 of the first n
// bytes of f. The dev:ino pair does not identify a file for all time. When
// the log rotates two or more times while the sidecar is stopped, the
// file system can give the old inode number to a new log. The head of that
// new log has other records. Thus the sum of the head tells the two files
// apart, and the inode number does not.
func headSum(f *os.File, n int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, n)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:headSumLen], nil
}

// headIs reports if the first min(off, headSpan) bytes of f have the head
// sum want. A file that is shorter than that has another head.
func headIs(f *os.File, off int64, want string) bool {
	n := min(off, headSpan)
	if n <= 0 {
		return true
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() < n {
		return false
	}
	got, err := headSum(f, n)
	return err == nil && got == want
}

// parseSum returns s when it is a head sum, and "" when it is not.
func parseSum(s string) string {
	if len(s) != headSumLen {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

type Tail struct {
	Path       string
	OffsetPath string
	// ShowPath is the log that Show and Watch read. It can be different from Path.
	ShowPath string
	LastPath string
	Empty    string
	Poll     time.Duration
	Stdout   io.Writer
	// Stderr gets the cause of a failed drain. Before, Run discarded that
	// error. Thus a sidecar that could not read its log, or could not
	// deliver what it read, looked the same as one with nothing to tell.
	Stderr io.Writer
	// The code calls Handler one time for each drain pass. It returns the
	// sink for that pass. Thus the setup for each pass stays out of the line loop.
	Handler func() func(line string)
	// Deliver is Handler for a sink that can fail. A line that it rejects
	// went nowhere. Thus the pass stops on it, and the checkpoint keeps the
	// offset of that line. The next pass tries it again. It does not skip
	// an alert that the operator never received. Set one of Handler and
	// Deliver, not both.
	Deliver func() func(line string) error
	Line    func(line string) string

	// The code holds the descriptor between passes. If it follows only the
	// name, it cannot recover the bytes appended to the old inode between
	// the last pass and the rename. If it reads the held descriptor to EOF
	// before it looks at the name, it can.
	f       *os.File
	r       *bufio.Reader
	off     int64
	id      fileID
	lastErr string
	// saved is the last record written. Thus a pass that moved nothing
	// writes nothing.
	saved string
	// sum is the head sum of f over its first sumN bytes. The code
	// computes it again only when sumN changes.
	sum  string
	sumN int64
	// After runs at the end of each Drain pass, after the code saves the
	// checkpoint. internal/alert posts from it. Thus the code waits for a
	// slow or failed webhook only after it records the lines of the pass.
	After func() error
	// idle is a test hook. Watch calls it each time it catches up with
	// the log and before it sleeps.
	idle func()
}

func Out(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}

// Err is Out for the error side. Before, report was silent when Stderr was
// nil, and all daemon callers left it nil. Thus the drain error that tells
// that a line was never delivered was written nowhere. The operator must
// know about a tail that cannot read its log or deliver its records, also
// when the caller did not set Stderr.
func Err(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stderr
}

// Printable is s with each rune that is not printable changed to '?':
//   - Newlines, so a field cannot forge a second log line.
//   - ESC and the C1 controls, so a field cannot control a terminal.
//   - Bidi and other format runes, so a field cannot reorder what the
//     operator reads.
//
// All text from a log row that an agent caused goes through here before it
// gets to a console, the journal or a webhook.
func Printable(s string) string {
	clean := true
	for _, r := range s {
		if !unicode.IsPrint(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func Field(event map[string]any, key, empty string) string {
	if v := strings.TrimSpace(fmt.Sprint(event[key])); v != "" && v != "<nil>" {
		return v
	}
	return empty
}

func (t *Tail) out() io.Writer {
	return Out(t.Stdout)
}

func (t *Tail) sleep() time.Duration {
	if t.Poll > 0 {
		return t.Poll
	}
	return defaultSleep
}

// sink builds the line handler of this pass. A Handler cannot fail. Thus
// the code always counts its lines as delivered.
func (t *Tail) sink() func(string) error {
	if t.Deliver != nil {
		return t.Deliver()
	}
	if t.Handler == nil {
		return func(string) error { return nil }
	}
	h := t.Handler()
	return func(line string) error {
		h(line)
		return nil
	}
}

// loadOffset reads "<bytes>[ <dev>:<ino>[ <head sum>]]". apply creates the
// file empty first, so the sidecar can own it. An empty or unreadable
// offset counts as no offset. If not, the code would ignore fromEnd and the
// first run would replay the full log.
//
// A record from an older pf has no head sum. sum is then "", and attach
// trusts the dev:ino pair as before. The other choice, to start again from
// zero, would send each old alert in the log again after an upgrade. The
// next save writes the head sum. A pf that does not know the head sum reads
// only the first two fields, so it can also read the new record.
func (t *Tail) loadOffset() (off int64, id fileID, sum string, ok bool) {
	raw, err := os.ReadFile(t.OffsetPath)
	if err != nil {
		return 0, fileID{}, "", false
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0, fileID{}, "", false
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, fileID{}, "", false
	}
	if len(f) > 1 {
		id = parseID(f[1])
	}
	if len(f) > 2 {
		sum = parseSum(f[2])
	}
	return n, id, sum, true
}

func (t *Tail) saveOffset() error {
	if t.OffsetPath == "" {
		return nil
	}
	mark := strconv.FormatInt(t.off, 10)
	if t.id != (fileID{}) {
		mark += " " + t.id.String()
		// An offset of zero is correct for each file. Thus it needs no sum.
		if n := min(t.off, headSpan); n > 0 && t.f != nil {
			if n != t.sumN {
				sum, err := headSum(t.f, n)
				if err != nil {
					return err
				}
				t.sum, t.sumN = sum, n
			}
			mark += " " + t.sum
		}
	}
	if mark == t.saved {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(t.OffsetPath), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(t.OffsetPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	rec := fmt.Sprintf("%-*s\n", offsetWidth, mark)
	_, err = f.WriteAt([]byte(rec), 0)
	if err == nil {
		err = f.Truncate(int64(len(rec)))
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	t.saved = mark
	return nil
}

func (t *Tail) shut() {
	if t.f != nil {
		_ = t.f.Close()
	}
	t.f, t.r, t.off, t.id = nil, nil, 0, fileID{}
	t.sum, t.sumN = "", 0
}

// attach opens Path. The rotation path sets restart. The saved offset of
// that path is for the inode that just finished. The code must not apply
// it to the new inode.
func (t *Tail) attach(fromEnd, restart bool) error {
	f, err := os.OpenFile(t.Path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	id := idOf(fi)
	off := int64(0)
	if !restart {
		saved, savedID, savedSum, ok := t.loadOffset()
		switch {
		case !ok && fromEnd:
			off = fi.Size()
		case !ok:
			off = 0
		// A rotation between two runs of the sidecar leaves no descriptor
		// to use. Thus the offset file tells the inode in which it counted
		// bytes. An offset from a different inode starts again from zero.
		case savedID != (fileID{}) && savedID != id:
			off = 0
		// The inode number can be the same and the file another. The head
		// sum tells. A file that has the same head and grew keeps its
		// offset.
		case savedSum != "" && !headIs(f, saved, savedSum):
			off = 0
		default:
			off = saved
		}
	}
	if off > fi.Size() {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	t.f, t.r, t.off, t.id = f, bufio.NewReaderSize(f, maxLine), off, id
	return nil
}

// readLine returns the next complete line with its newline, the bytes it
// consumed, and if the line went past maxLine and was dropped. io.EOF means
// that the file ended. Data that the writer left without a newline is not
// a record yet. readLine reports it as consumed, so the caller can rewind to it.
func readLine(r *bufio.Reader) (line string, n int64, dropped bool, err error) {
	var chunk []byte
	for {
		c, e := r.ReadSlice('\n')
		n += int64(len(c))
		if e == bufio.ErrBufferFull {
			dropped = true
			continue
		}
		if e != nil {
			return "", n, dropped, e
		}
		if !dropped {
			chunk = c
		}
		return string(chunk), n, dropped, nil
	}
}

// read drains the held descriptor. A line that the sink rejects stops the
// pass, and the offset still points at that line.
func (t *Tail) read(sink func(string) error) error {
	for {
		line, n, dropped, err := readLine(t.r)
		if err == nil {
			if !dropped {
				if e := sink(line); e != nil {
					// readLine already consumed this line from t.r. t.r
					// (unlike t.off) stays into the next poll: Run keeps
					// the same descriptor across ticks. Without a rewind
					// here, the next call would give the sink the line
					// *after* this one, while the saved offset still
					// pointed before it. That would silently skip the
					// rejected line permanently and then checkpoint the
					// wrong byte count. A seek back to t.off makes the next
					// read see this line again, later in this process or
					// after a restart.
					if _, se := t.f.Seek(t.off, io.SeekStart); se != nil {
						return se
					}
					t.r.Reset(t.f)
					return e
				}
			}
			t.off += n
			continue
		}
		if err != io.EOF {
			return err
		}
		if n > 0 {
			// The writer is in the middle of a record. Rewind to the last
			// complete line. Thus the next pass reads the full record. It
			// does not parse its prefix and checkpoint past the rest.
			if _, e := t.f.Seek(t.off, io.SeekStart); e != nil {
				return e
			}
			t.r.Reset(t.f)
		}
		return nil
	}
}

func (t *Tail) Drain(fromEnd bool) error {
	if err := os.MkdirAll(filepath.Dir(t.Path), 0755); err != nil {
		return err
	}
	sink := t.sink()
	if t.f == nil {
		if err := t.attach(fromEnd, false); err != nil {
			return err
		}
	}
	err := t.read(sink)
	if err == nil {
		if fi, e := os.Stat(t.Path); e == nil && idOf(fi) != t.id {
			t.shut()
			if e := t.attach(false, true); e != nil {
				err = e
			} else {
				err = t.read(sink)
			}
		}
	}
	if saveErr := t.saveOffset(); err == nil {
		err = saveErr
	}
	if t.After != nil {
		if afterErr := t.After(); err == nil {
			err = afterErr
		}
	}
	return err
}

// lastJSONL returns the last record of ShowPath. It reads from the tail
// of the file, not the full file.
func (t *Tail) lastJSONL() string {
	f, err := os.Open(t.ShowPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	at := int64(0)
	if fi.Size() > tailWindow {
		at = fi.Size() - tailWindow
	}
	if _, err := f.Seek(at, io.SeekStart); err != nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(f, tailWindow))
	if err != nil {
		return ""
	}
	text := string(raw)
	// A window that does not start at byte zero starts in the middle of
	// the record that holds its first byte. Half a record printed as a
	// full record is worse than nothing.
	if at > 0 {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			return ""
		}
		text = text[i+1:]
	}
	last := ""
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			last = line
		}
	}
	return last
}

func (t *Tail) Show() int {
	if line := t.lastJSONL(); line != "" {
		fmt.Fprintln(t.out(), Printable(line))
		return 0
	}
	if raw, err := os.ReadFile(t.LastPath); err == nil {
		text := strings.TrimSpace(string(raw))
		if text != "" {
			fmt.Fprintln(t.out(), Printable(text))
			return 0
		}
	}
	fmt.Fprintln(t.out(), t.Empty)
	return 0
}

func (t *Tail) Once() int {
	t.report(t.Drain(false))
	return t.Show()
}

// report tells one time why a drain failed. The same reason on each poll
// would fill the journal. A changed reason, or a first one, is new data.
func (t *Tail) report(err error) {
	if err == nil {
		t.lastErr = ""
		return
	}
	if err.Error() == t.lastErr {
		return
	}
	t.lastErr = err.Error()
	fmt.Fprintf(Err(t.Stderr), "tail %s: %v\n", t.Path, err)
}

func (t *Tail) Run(ctx context.Context) error {
	defer t.shut()
	t.report(t.Drain(true))
	tk := time.NewTicker(t.sleep())
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
			t.report(t.Drain(false))
		}
	}
}

func (t *Tail) Watch(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(t.ShowPath), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(t.ShowPath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	id := fileID{}
	if fi, err := f.Stat(); err == nil {
		id = idOf(fi)
	}
	r := bufio.NewReaderSize(f, maxLine)
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, n, dropped, err := readLine(r)
		if err == nil {
			off += n
			if !dropped {
				if t.Line != nil {
					line = t.Line(line)
				}
				fmt.Fprintln(t.out(), Printable(strings.TrimRight(line, "\n")))
			}
			continue
		}
		if err != io.EOF {
			return err
		}
		if n > 0 {
			// Half a record that the writer did not finish: rewind and
			// wait for the rest. Do not print the prefix and then the
			// remainder as two lines.
			if _, e := f.Seek(off, io.SeekStart); e != nil {
				return e
			}
			r.Reset(f)
		}
		// After a rotation, this descriptor points at a file that no
		// process writes to now. That is how pf alert watch became quiet
		// for the rest of the boot.
		if fi, e := os.Stat(t.ShowPath); e == nil && idOf(fi) != id {
			if next, e := os.OpenFile(t.ShowPath, os.O_RDONLY, 0644); e == nil {
				_ = f.Close()
				f, id, off, r = next, idOf(fi), 0, bufio.NewReaderSize(next, maxLine)
				continue
			}
		}
		if t.idle != nil {
			t.idle()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(t.sleep()):
		}
	}
}
