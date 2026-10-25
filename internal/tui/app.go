package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"pi-fortress/internal/admin"
)

const (
	// menuWidth is where the content column starts: the menu labels,
	// then a rule and a space between them and the content.
	menuWidth = 18
	tailN     = 50
)

type row struct {
	text string
	sel  bool
}

// promptCap is the length in bytes after which a prompt refuses all
// input. The prompt line shows [full] at that length.
const promptCap = 253

type prompt struct {
	label string
	buf   string
	yn    bool
	// mask hides what the operator types. A passphrase is the only input here
	// that must not be readable over the shoulder of the operator. It must not
	// reach the screen for the same reason that it does not reach the audit
	// log.
	mask bool
	// typed is set on a confirm. Its answer must come from the keyboard. A
	// pasted key does nothing on it, so a string that the operator is told
	// to paste cannot answer it.
	typed bool
	done  func(string)
}

type event struct {
	key  Key
	line string
	done error
	err  error
	tick bool
	// stats is the 5 s refresh of the live views: Overview, Devices and the
	// Blocked table of Activity.
	stats bool
}

// claimView is the overlay after claim.issue: code, countdown and the
// one-liner, until any key.
type claimView struct {
	admin.Claim
	stop chan struct{}
}

// place is where the operator left one view: the cursor, the viewport
// of a view with nothing to select, and the tab.
type place struct{ pos, scroll, tab int }

type App struct {
	cfg  *admin.Config
	role admin.Role
	t    Terminal
	w, h int
	// nets is the menu. The code builds it again on each reload, because a
	// plain segment appears when an operator applies one. menu indexes it.
	nets  []netEntry
	menu  int
	cur   view
	focus bool
	help  bool
	quit  bool
	msg   string
	// warn is the standing condition that an operator must see from all
	// screens. msg is different: it is the result of the last operator action,
	// and the next reload clears it.
	warn   string
	places map[view]*place
	// lastSec is the last section of each network. Thus when the operator
	// opens a network again from the menu, it returns to that section.
	lastSec map[string]section
	rows    []row
	// setRows is what each selectable row of a Settings view edits, in row
	// order. A zero key is a row that only reads.
	setRows []setTarget
	// pending is an edit that is saved but not applied: "local" when apply
	// --local covers it, "full" when it needs the full apply. A is the key
	// that runs it, and the footer says so until it has run.
	pending string
	// edits are the saved edits that wait for an apply, oldest first, each
	// named as its save message names it, one for each key. The A confirm
	// shows them. applying is the A apply that streams now, with the edits
	// that it took from edits and pending. When that apply fails, the code
	// gives them back.
	edits    []string
	applying *applyRun
	pr       *prompt

	pane     []string
	paneBusy bool
	// paneFollow pins the Actions pane to its newest line until a key
	// moves the selection again.
	paneFollow bool
	events     chan event
	// Idle ends Run after that long without a keypress. Thus a seat on a blank
	// HDMI does not stay on an open management screen. Zero disables it. An
	// action in progress can finish first.
	// It is not a logout: Run returns to the shell that started it, and that
	// session stays open. Thus the seat is still the user who logged in. The
	// login manager must lock the console, not this code.
	Idle    time.Duration
	idleHit bool
	// idleOut is true when the idle timer ended Run. Run then writes
	// idleNote to the restored terminal.
	idleOut bool
	ctx     context.Context
	cancel  context.CancelFunc

	hosts []admin.Host
	// logs is logs.list, read one time: the fixed logs, then one resolver log
	// for each plain segment.
	logs  []string
	items []string
	feeds []feedRow
	slots []string
	claim *claimView

	stats   admin.Stats
	clients []admin.ClientStat
	// detail is the segment/ip of the client that is open on a Devices view,
	// or "" for the table. back is the table row to return to.
	detail string
	back   int
	// utf8 says that the locale can show the block glyphs. If not, ASCII bars.
	utf8 bool
}

// New builds the app. The TUI runs with RoleAdmin today (sudo is the full
// privilege model). A narrower seat account will use the role check.
func New(cfg *admin.Config, t Terminal) *App {
	return &App{cfg: cfg, role: admin.RoleAdmin, t: t, events: make(chan event, 256),
		cur:  view{netOverview, secOverview},
		utf8: strings.Contains(strings.ToUpper(os.Getenv("LANG")+os.Getenv("LC_ALL")), "UTF")}
}

// call routes each screen action through the verb table.
// call answers ErrNoVerb, and does not panic, when no Config is behind the
// screen. The scroll tests build an App with rows and no socket, because
// they test the viewport. Without this, a draw that asks the admin side
// which tabs to show would crash on the nil. A path that draws a screen
// must not depend on a box.
func (a *App) call(name string, args admin.Args) (any, error) {
	if a.cfg == nil {
		return nil, admin.ErrNoVerb
	}
	return a.cfg.Call(a.role, name, args)
}

// Run drives the loop until q, Ctrl-C, idle timeout or end of input. When
// it stops, it cancels each action that still streams.
func (a *App) Run() error {
	if err := a.t.EnterRaw(); err != nil {
		return err
	}
	// Joined last. Run returns from approximately six places: q, Ctrl-C, idle,
	// EOF, a read error. Before, it returned from all of them while the key
	// goroutine was still in ReadKey. Nothing woke the goroutine. A cancel of
	// the context releases a send but not a terminal read. Thus the goroutine
	// and its tty lived longer than the TUI, and the next shell command shared
	// stdin with a reader that nobody could stop. Restore ends the read, so
	// the order below is important. Defers run in reverse, so this wait occurs
	// after the cancel and after the restore.
	var workers sync.WaitGroup
	defer workers.Wait()
	// After the restore, so that the line stays on the shell screen. An
	// operator who comes back to a shell prompt must not read it as a
	// logout. The idle exit does not ask about saved edits, as q does. Thus
	// the second line names them.
	defer func() {
		if a.idleOut {
			note := idleNote + "\n"
			if n := len(a.edits); n > 0 {
				note += unapplied(n) + "\n"
			}
			_ = a.t.Write([]byte(note))
		}
	}()
	defer a.t.Restore()
	a.ctx, a.cancel = context.WithCancel(context.Background())
	defer a.cancel()
	workers.Add(1)
	go func() {
		defer workers.Done()
		a.readKeys()
	}()
	idle := time.NewTimer(a.idleWait())
	defer idle.Stop()
	// The stats screens refresh on a ticker. The ticker exists only while one
	// of them shows. Thus all other screens keep their key-driven loop.
	var tick *time.Ticker
	defer func() {
		if tick != nil {
			tick.Stop()
		}
	}()
	a.reload()
	a.draw()
	for !a.quit {
		var ev event
		var tickC <-chan time.Time
		tick, tickC = a.syncTicker(tick)
		select {
		case ev = <-a.events:
		case <-tickC:
			ev = event{stats: true}
		case <-idle.C:
			if a.paneBusy {
				a.idleHit = true
				continue
			}
			a.idleOut = true
			return nil
		}
		if stop, err := a.dispatch(ev, idle); stop {
			return err
		}
		a.draw()
	}
	return nil
}

// readKeys sends each key to the loop until a read fails or the app stops.
func (a *App) readKeys() {
	for {
		k, err := a.t.ReadKey()
		// A read that ended because the app stops is not an event for the app.
		// The loop already stopped its reads. The EOF that Restore gives back
		// would only stay in the buffer for the next reader that drains it. The
		// check is before the send, because when both are ready, the select can
		// pick either.
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		select {
		case a.events <- event{key: k, err: err}:
		case <-a.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// syncTicker starts the stats ticker when the screen needs it, and stops
// it when the screen does not. The channel is nil when no ticker runs.
func (a *App) syncTicker(tick *time.Ticker) (*time.Ticker, <-chan time.Time) {
	if !a.ticks() {
		if tick != nil {
			tick.Stop()
		}
		return nil, nil
	}
	if tick == nil {
		tick = time.NewTicker(statsTick)
	}
	return tick, tick.C
}

// dispatch applies one event. stop tells Run to return err.
func (a *App) dispatch(ev event, idle *time.Timer) (stop bool, err error) {
	switch {
	case ev.err != nil:
		if errors.Is(ev.err, io.EOF) {
			return true, nil
		}
		return true, ev.err
	case ev.line != "":
		a.pane = append(a.pane, ev.line)
		if len(a.pane) > 500 {
			a.pane = a.pane[len(a.pane)-500:]
		}
	case ev.tick:
		if a.claim == nil || time.Now().After(a.claim.Expires) {
			a.closeClaim()
		}
	case ev.stats:
		a.rebuild()
	case ev.done != nil:
		return a.finishApply(ev.done), nil
	default:
		a.idleHit = false
		if a.Idle > 0 {
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(a.Idle)
		}
		a.handle(ev.key)
	}
	return false, nil
}

// finishApply records the result of the action that streamed to the pane.
// It is true when the idle timer fired during the action, and Run must stop.
func (a *App) finishApply(done error) bool {
	a.paneBusy = false
	run := a.applying
	a.applying = nil
	if _, ok := done.(doneMarker); ok {
		a.pane = append(a.pane, "done")
	} else {
		a.pane = append(a.pane, "error: "+done.Error())
		if run != nil {
			a.untake(run)
		}
	}
	if a.idleHit {
		// Painted first: an apply that ran longer than the idle timer
		// ends on its result, not on the line before it.
		a.draw()
		a.idleOut = true
		return true
	}
	return false
}

// nonEmpty keeps the standing warnings in one line, most urgent first. A
// sealed store means that no credentialed workflow runs at all. That is
// more important than a blocklist that is a day old.
func nonEmpty(s ...string) []string {
	out := s[:0]
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// idleNote is the line that the idle exit leaves on the tty. The idle exit
// is not a logout. The shell that started the TUI is still open.
const idleNote = "session still open; the TUI did not lock the console"

func (a *App) idleWait() time.Duration {
	if a.Idle > 0 {
		return a.Idle
	}
	return time.Duration(1<<63 - 1)
}

func (a *App) reload() {
	a.msg = ""
	a.warn = strings.Join(nonEmpty(
		a.cfg.SecretsWarning(context.Background()),
		a.cfg.FetchStatus().Warning(),
	), "  |  ")
	a.nets = buildNets(a.plainSegments())
	// When a segment goes away under a running seat, its views go too.
	if a.entry() == nil {
		a.cur, a.focus = view{netOverview, secOverview}, false
	}
	a.menu = min(a.menu, len(a.nets)-1)
	a.rebuild()
}

// netList is the menu, or its fixed part before the first reload. The
// scroll tests draw an App that never asked the admin side anything.
func (a *App) netList() []netEntry {
	if a.nets == nil {
		a.nets = buildNets(nil)
	}
	return a.nets
}

// entry is the menu entry of the network on screen.
func (a *App) entry() *netEntry {
	for i, e := range a.netList() {
		if e.id == a.cur.net {
			return &a.netList()[i]
		}
	}
	return nil
}

// here is the place of the current view, made on the first visit. It is a
// lazy map, not one made in New, so that an App built bare in a test works.
func (a *App) here() *place {
	if a.places == nil {
		a.places = map[view]*place{}
	}
	p := a.places[a.cur]
	if p == nil {
		p = &place{}
		a.places[a.cur] = p
	}
	return p
}

// rebuild refreshes the rows and keeps the cursor on the screen.
func (a *App) rebuild() {
	a.setRows = nil
	a.rows = a.build()
	n := a.selectable()
	if p := a.here(); p.pos >= n {
		p.pos = max(n-1, 0)
	}
	if n == 0 {
		a.scrollBy(0)
	}
}

func (a *App) selectable() int {
	n := 0
	for _, r := range a.rows {
		if r.sel {
			n++
		}
	}
	return n
}

func (a *App) handle(k Key) {
	if k.Kind == KeyResize {
		return
	}
	if a.pr != nil {
		a.promptKey(k)
		return
	}
	// Outside a prompt, a key is a command. A paste is text, not commands:
	// a pasted "q" must not quit, and a pasted "dyes" must not delete.
	if k.Paste {
		a.msg = "paste ignored outside a prompt"
		return
	}
	a.paneFollow = false
	if a.claim != nil {
		a.closeClaim()
		return
	}
	if a.help {
		a.help = false
		return
	}
	switch k.Kind {
	case KeyCtrlC:
		a.askQuit()
	case KeyEsc:
		if !a.closeDetail() {
			a.focus = false
		}
	case KeyCtrlR, KeyF5:
		a.reload()
	case KeyTab:
		if a.focus {
			a.nextTab(1)
		}
	case KeyRune:
		switch {
		case k.Rune == 'q':
			switch {
			case a.closeDetail():
			case a.focus:
				a.focus = false
			default:
				a.askQuit()
			}
		case k.Rune == '?':
			a.help = true
		case k.Rune == 'A':
			a.applyPending()
		case k.Rune >= '1' && k.Rune <= '9' && int(k.Rune-'1') < len(a.netList()):
			a.open(int(k.Rune - '1'))
		case !a.focus:
			a.menuKey(k)
		default:
			a.screenKey(k)
		}
	default:
		if a.focus {
			a.screenKey(k)
		} else {
			a.menuKey(k)
		}
	}
}

// askQuit is q on the menu and Ctrl-C. With saved edits that no apply
// took, it asks first and names the count. A silent quit leaves the
// operator sure of a change that never took effect. While an action
// streams, it also asks: the quit stops that action, and Ctrl-C is the
// reflex of an operator who only wants the screen to stop. When both are
// true, one prompt names both.
func (a *App) askQuit() {
	n := len(a.edits)
	if n == 0 && !a.paneBusy {
		a.quit = true
		return
	}
	what := unapplied(n)
	switch {
	case a.paneBusy && n > 0:
		what = "an action still runs; " + what
	case a.paneBusy:
		what = "an action still runs and quit stops it"
	}
	a.confirm(what+"; quit anyway", func() { a.quit = true })
}

// unapplied names n saved edits that no apply took.
func unapplied(n int) string {
	if n == 1 {
		return "1 saved edit was never applied"
	}
	return fmt.Sprintf("%d saved edits were never applied", n)
}

// open shows menu entry i at the section where the operator last left it.
func (a *App) open(i int) {
	e := a.netList()[i]
	sec, ok := a.lastSec[e.id]
	if !ok {
		sec = e.secs[0]
	}
	a.menu, a.focus = i, true
	a.detail = ""
	a.cur = view{e.id, sec}
	a.reload()
}

// goTo opens one section of a network, for a key that jumps across the
// menu. A goes to the Actions of System to show the running apply.
func (a *App) goTo(net string, sec section) {
	for i, e := range a.netList() {
		if e.id == net {
			a.menu = i
		}
	}
	a.detail = ""
	a.cur, a.focus = view{net, sec}, true
	a.remember()
	a.rebuild()
}

func (a *App) remember() {
	if a.lastSec == nil {
		a.lastSec = map[string]section{}
	}
	a.lastSec[a.cur.net] = a.cur.sec
}

// nextSection is Left and Right inside a network. Right from the last
// section goes to the first. Left from the first goes back to the menu,
// the same way that Right from the menu came in.
func (a *App) nextSection(d int) {
	e := a.entry()
	if e == nil {
		return
	}
	i := slices.Index(e.secs, a.cur.sec) + d
	switch {
	case i < 0:
		a.focus = false
		return
	case i >= len(e.secs):
		i = 0
	}
	a.detail = ""
	a.cur.sec = e.secs[i]
	a.remember()
	a.reload()
}

func (a *App) menuKey(k Key) {
	n := len(a.netList())
	switch {
	case k.Kind == KeyDown || k.Rune == 'j':
		a.menu = (a.menu + 1) % n
	case k.Kind == KeyUp || k.Rune == 'k':
		a.menu = (a.menu + n - 1) % n
	case k.Kind == KeyEnter || k.Kind == KeyRight || k.Rune == 'l':
		a.open(a.menu)
	}
}

func (a *App) move(d int) {
	n := a.selectable()
	if n == 0 {
		a.scrollBy(d)
		return
	}
	p := a.here()
	p.pos = min(max(p.pos+d, 0), n-1)
}

func (a *App) nextTab(d int) {
	n := len(a.tabNames())
	if n == 0 {
		return
	}
	p := a.here()
	p.tab = (p.tab + d + n) % n
	p.pos = 0
	a.detail = ""
	a.reload()
}

// tabIndex is the current tab, kept inside a strip that can be shorter
// now than when the operator chose the tab.
func (a *App) tabIndex() int {
	i := a.here().tab
	if i < 0 || i >= len(a.tabNames()) {
		return 0
	}
	return i
}

// selected returns the index among selectable rows, or -1.
func (a *App) selected() int {
	if a.selectable() == 0 {
		return -1
	}
	return a.here().pos
}

func (a *App) ask(label string, done func(string)) {
	a.pr = &prompt{label: label, done: done}
}

// askValue is ask for a key that already has a value. The prompt opens on
// that value, so Enter keeps it. Enter on an emptied prompt cancels.
// Before, an empty submit cleared WG_IF, SSH_TO or HOUSE_ADMIN_IP, so one
// stray key could undo a setting. To clear, the operator types "-"
// explicitly, and done receives it as "".
func (a *App) askValue(label, cur string, done func(string)) {
	a.pr = &prompt{label: label + " (- clears)", buf: cur, done: func(v string) {
		switch v {
		case "":
			a.msg = "cancelled"
		case cur:
			a.msg = "unchanged"
		case "-":
			done("")
		default:
			done(v)
		}
	}}
}

func (a *App) askSecret(label string, done func(string)) {
	a.pr = &prompt{label: label, mask: true, done: done}
}

func (a *App) confirm(label string, done func()) {
	a.pr = &prompt{label: label + " [y/N]", yn: true, typed: true, done: func(s string) {
		if s == "y" {
			done()
		} else {
			a.msg = "cancelled"
		}
	}}
}

func (a *App) confirmTyped(label string, done func()) {
	a.ask(label+" (type yes)", func(s string) {
		if s == "yes" {
			done()
		} else {
			a.msg = "cancelled"
		}
	})
	a.pr.typed = true
}

func (a *App) promptKey(k Key) {
	p := a.pr
	if k.Paste && p.typed {
		return
	}
	switch k.Kind {
	case KeyEsc, KeyCtrlC:
		a.pr = nil
		a.msg = "cancelled"
	case KeyBackspace:
		// One character, not one byte. When the code cut a byte off a
		// multibyte character, the buffer kept half of the character. That
		// buffer can be a passphrase on its way to the sealed store.
		if len(p.buf) > 0 {
			_, n := utf8.DecodeLastRuneInString(p.buf)
			p.buf = p.buf[:len(p.buf)-n]
		}
	case KeyEnter:
		// The line end of a paste is not an Enter of the operator. Before, it
		// saved the pasted value before the operator saw it. The operator
		// reads the value on the prompt line and then presses Enter.
		if k.Paste {
			return
		}
		a.pr = nil
		p.done(strings.TrimSpace(p.buf))
	case KeyRune:
		if p.yn {
			a.pr = nil
			p.done(strings.ToLower(string(k.Rune)))
			return
		}
		if k.Rune >= 0x20 && len(p.buf) < promptCap {
			p.buf += string(k.Rune)
		}
	}
}

func (a *App) showClaim(cl admin.Claim) {
	a.claim = &claimView{Claim: cl, stop: make(chan struct{})}
	var done <-chan struct{}
	if a.ctx != nil {
		done = a.ctx.Done()
	}
	go func(stop chan struct{}) {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-done:
				return
			case <-t.C:
				select {
				case a.events <- event{tick: true}:
				case <-stop:
					return
				case <-done:
					return
				}
			}
		}
	}(a.claim.stop)
}

func (a *App) closeClaim() {
	if a.claim != nil {
		close(a.claim.stop)
		a.claim = nil
		a.reload()
	}
}

func (a *App) fail(err error) bool {
	if err != nil {
		a.msg = "error: " + err.Error()
		return true
	}
	return false
}

// stream runs fn on its own goroutine, and posts each output line to the
// Actions pane. One action at a time.
func (a *App) stream(title, verb string, args admin.Args) {
	if a.paneBusy {
		a.msg = "an action is already running"
		return
	}
	a.paneBusy, a.paneFollow = true, true
	a.pane = []string{"$ " + title}
	// The message of the last action is old now. If it stays, it takes the
	// footer from "running...", and a save message still says "A applies"
	// while A runs.
	a.msg = ""
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		w := &lineWriter{ch: a.events, done: ctx.Done()}
		args.Out = w
		_, err := a.cfg.CallCtx(ctx, a.role, verb, args)
		w.flush()
		// The result is important even to a loop that was just told to quit.
		// It stops the pane from showing "running...", and a caller that
		// waits on the child reads it. The cancelled seat wins only when the
		// buffer is also full. Then nobody is left to drain it, and the send
		// would never return.
		select {
		case a.events <- event{done: errOrDone(err)}:
		default:
			select {
			case a.events <- event{done: errOrDone(err)}:
			case <-ctx.Done():
			}
		}
	}()
}

type doneMarker struct{}

func (doneMarker) Error() string { return "done" }

func errOrDone(err error) error {
	if err == nil {
		return doneMarker{}
	}
	return err
}

// maxPaneLine is the limit for one line of action output. The subprocess
// decides how much it prints before a newline. Thus a different process
// sized the partial line buffer here. After the cap, the code emits the
// line as it is, and the rest of that line becomes a new line.
const maxPaneLine = 4 << 10

type lineWriter struct {
	ch   chan event
	done <-chan struct{}
	buf  string
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			if len(w.buf) < maxPaneLine {
				break
			}
			i = maxPaneLine
		}
		if l := strings.TrimRight(w.buf[:i], "\r"); l != "" {
			if !w.send(l) {
				return len(p), nil
			}
		}
		w.buf = w.buf[min(i+1, len(w.buf)):]
	}
	return len(p), nil
}

// flush emits all text that the command left without a trailing newline.
// Before, an error message without a newline was the line that the
// operator most needed, and the pane never showed it.
func (w *lineWriter) flush() {
	if l := strings.TrimRight(w.buf, "\r\n"); l != "" {
		w.send(l)
	}
	w.buf = ""
}

// send stops when the seat is gone. The pane channel holds 256 events, and
// Run stops its reads of the channel when it returns. Thus an
// unconditional send blocked this goroutine for the life of the process.
func (w *lineWriter) send(line string) bool {
	select {
	case w.ch <- event{line: line}:
		return true
	case <-w.done:
		return false
	}
}

func (a *App) draw() {
	a.w, a.h = a.t.Size()
	b := newBuffer(a.w, a.h)
	title := " Pi Fortress  " + a.viewTitle()
	b.line(0, 0, b.w, title, reverse)
	// A stale blocklist is a standing fault with no other symptom. All
	// screens continue to say ok while the lists decay. The warning goes on
	// the title bar, so the operator sees it from all locations. The title
	// bar holds only the warning. msg goes in the footer (drawFooter). When
	// the two used one slot, one Esc on a prompt removed the warning.
	if a.warn != "" {
		b.put(min(len(title)+2, b.w), 0, clip("! "+a.warn, b.w-len(title)-2), reverse)
	}
	x := 0
	// The claim overlay uses the full width. Its command carries a
	// 64-digit hash and must reach the operator unclipped at 80 columns.
	// The menu column would not leave space for this.
	if b.w >= 40 && a.claim == nil {
		for i, e := range a.netList() {
			at := plain
			if i == a.menu && !a.focus {
				at = reverse
			} else if e.id == a.cur.net {
				at = bold
			}
			b.line(0, 1+i, menuWidth-2, clip(menuLabel(i, e), menuWidth-3), at)
		}
		rule := "|"
		if a.utf8 {
			rule = "│"
		}
		for y := 1; y < b.h-1; y++ {
			b.put(menuWidth-2, y, rule, plain)
		}
		x = menuWidth
	}
	switch {
	case a.claim != nil:
		a.drawClaim(b, x)
	case a.help:
		a.drawHelp(b, x)
	default:
		a.drawContent(b, x)
	}
	a.drawFooter(b)
	_ = a.t.Write(b.frame())
}

func (a *App) drawContent(b *buffer, x int) {
	width := b.w - x
	top, bottom := 1, b.h-2
	if bottom < top {
		return
	}
	if secs := a.sectionLine(); secs.text != "" {
		secs.draw(b, x, top, width, bold)
		top++
	}
	if tabs := a.tabLine(); tabs.text != "" {
		tabs.draw(b, x, top, width, plain)
		top++
	}
	// The explanation of a Settings row uses the last content line. Thus
	// the row itself can stay a short label.
	if help := a.settingHelp(); len(help) > 0 && bottom-len(help) >= top {
		for i, l := range help {
			b.line(x, bottom-len(help)+1+i, width, l, bold)
		}
		bottom -= len(help)
	}
	avail := bottom - top + 1
	if avail <= 0 {
		return
	}
	rows := a.rows
	if a.cur.sec == secActions {
		rows = append(rows, a.paneRows()...)
	}
	selIdx := a.selected()
	curLine := 0
	n := 0
	for i, r := range rows {
		if r.sel {
			if n == selIdx {
				curLine = i
			}
			n++
		}
	}
	start := 0
	switch {
	case selIdx < 0:
		// Nothing selectable: the viewport is what j/k moves.
		start = a.viewStart(len(rows), avail)
	case curLine >= avail:
		start = curLine - avail + 1
	}
	if a.cur.sec == secActions && a.paneFollow {
		start = max(len(rows)-avail, 0)
	}
	// n counts selectable rows from the top of the list, because selIdx
	// does. Before, the count started again at the scrolled start. That
	// compared a count relative to the pane with an index relative to the
	// list. Thus when the list was longer than the pane, the highlight was
	// on a different row from the row that an action would use, or on no row.
	n = 0
	for _, r := range rows[:min(start, len(rows))] {
		if r.sel {
			n++
		}
	}
	for i := start; i < len(rows) && i-start < avail; i++ {
		r := rows[i]
		at := plain
		if r.sel {
			if n == selIdx && a.focus {
				at = reverse
			}
			n++
		}
		b.line(x, top+i-start, width, clip(r.text, width), at)
	}
}

// bottomAnchored says the view opens on its newest row. A log does; a
// status page does not.
func (a *App) bottomAnchored() bool {
	switch a.cur.sec {
	case secAdminLog:
		return true
	case secActivity:
		return !a.activityTab().blocked
	}
	return false
}

// viewStart changes the scroll position into a first row. scroll counts
// rows from the position where the screen opens. Thus zero is always "as
// it opened". The clamp below stops a rebuild that shortened the list from
// leaving the pane past the end of the list.
func (a *App) viewStart(rows, avail int) int {
	maxStart := max(rows-avail, 0)
	start := a.here().scroll
	if a.bottomAnchored() {
		start = maxStart - start
	}
	return min(max(start, 0), maxStart)
}

// pageRows is the number of content lines that the pane shows. move needs
// it to clamp a scroll. It reads the geometry that the last draw measured.
func (a *App) pageRows() int {
	top, bottom := 1, a.h-2
	if a.sectionLine().text != "" {
		top++
	}
	if a.tabLine().text != "" {
		top++
	}
	bottom -= len(a.settingHelp())
	return max(bottom-top+1, 1)
}

// scrollBy moves the viewport on a screen that has no cursor. Logs and
// Status build nothing selectable. Before, j/k, PgUp/PgDn, Home and End
// did nothing on them, but the footer showed the keys. All text above the
// last screenful was unreachable.
func (a *App) scrollBy(d int) {
	rows := len(a.rows)
	if a.cur.sec == secActions {
		rows += len(a.pane) + 1
	}
	maxScroll := max(rows-a.pageRows(), 0)
	if a.bottomAnchored() {
		d = -d
	}
	p := a.here()
	p.scroll = min(max(p.scroll+d, 0), maxScroll)
}

func (a *App) paneRows() []row {
	out := []row{{text: ""}}
	for _, l := range a.pane {
		out = append(out, row{text: l})
	}
	return out
}

// viewTitle is the title bar's "where am I".
func (a *App) viewTitle() string {
	e := a.entry()
	if e == nil {
		return ""
	}
	if len(e.secs) == 1 {
		return e.label
	}
	return e.label + " > " + sectionNames[a.cur.sec]
}

// menuLabel numbers the first nine entries after their jump key.
func menuLabel(i int, e netEntry) string {
	if i < 9 {
		return fmt.Sprintf("%d %s", i+1, e.label)
	}
	return "  " + e.label
}

// strip is a row of names with the current one highlighted: the
// sections, or the tabs under them.
type strip struct {
	text     string
	from, to int // the current name, in runes of text
}

// joined lays parts out after prefix and marks parts[sel].
func joined(prefix string, parts []string, sel int) strip {
	before := prefix + strings.Join(parts[:sel], " ")
	if sel > 0 {
		before += " "
	}
	from := utf8.RuneCountInString(before)
	return strip{
		text: prefix + strings.Join(parts, " "),
		from: from,
		to:   from + utf8.RuneCountInString(parts[sel]),
	}
}

// draw paints the strip on row y, clipped to width, the current name
// in picked.
func (s strip) draw(b *buffer, x, y, width int, at attr) {
	b.line(x, y, width, s.text, at)
	if to := min(s.to, width); s.from < to {
		b.put(x+s.from, y, string([]rune(s.text)[s.from:to]), picked)
	}
}

// sectionLine is the sections of the network, with the current one
// highlighted. All networks have the same sections, so it reads the same
// at all locations. Overview has one section and no strip.
func (a *App) sectionLine() strip {
	e := a.entry()
	if e == nil || len(e.secs) < 2 {
		return strip{}
	}
	var parts []string
	for _, sec := range e.secs {
		parts = append(parts, " "+sectionNames[sec]+" ")
	}
	line := joined("", parts, max(slices.Index(e.secs, a.cur.sec), 0))
	if hint := "  (Left/Right)"; len(line.text)+len(hint) <= a.contentWidth() {
		line.text += hint
	}
	return line
}

// tabNames is the strip under the sections: the lists under Filtering,
// the views under Activity.
func (a *App) tabNames() []string {
	var names []string
	switch a.cur.sec {
	case secFiltering:
		for _, l := range filterLists(a.cur) {
			names = append(names, listLabel(l))
		}
		names = append(names, "Feeds")
	case secActivity:
		for _, t := range a.activityTabs(a.cur) {
			names = append(names, t.name)
		}
		if len(names) < 2 {
			return nil
		}
	}
	return names
}

func (a *App) tabLine() strip {
	names := a.tabNames()
	if len(names) == 0 {
		return strip{}
	}
	var parts []string
	for _, n := range names {
		parts = append(parts, " "+n+" ")
	}
	return fitTabs(parts, a.tabIndex(), a.w-menuWidth)
}

// fitTabs keeps the selected tab on the strip. Logs has one tab for each
// fixed log plus one for each plain segment. That is eight on a box with a
// desk, and does not fit 80 columns. When the code clipped from the right,
// the strip showed all tabs except the selected tab, and cut the last
// visible name in half. It shows only whole tabs. It drops tabs from the
// right down to the selection, then from the left. "<" and ">" show that
// some tabs are off that side, and "(Tab)" appears when there is space.
func fitTabs(parts []string, sel, w int) strip {
	const tail = "  (Tab)"
	lay := func(lo, hi int) (strip, bool) {
		pre := ""
		if lo > 0 {
			pre = "< "
		}
		s := joined(pre, parts[lo:hi], sel-lo)
		if hi < len(parts) {
			s.text += " >"
		}
		return s, utf8.RuneCountInString(s.text) <= w
	}
	lo, hi := 0, len(parts)
	s, ok := lay(lo, hi)
	for ; !ok && hi > sel+1; s, ok = lay(lo, hi) {
		hi--
	}
	for ; !ok && lo < sel; s, ok = lay(lo, hi) {
		lo++
	}
	// A drop from the left can make space on the right again.
	for ok && hi < len(parts) {
		t, more := lay(lo, hi+1)
		if !more {
			break
		}
		s, hi = t, hi+1
	}
	if utf8.RuneCountInString(s.text)+len(tail) <= w {
		s.text += tail
	}
	return s
}

func (a *App) drawFooter(b *buffer) {
	y := b.h - 1
	if a.pr != nil {
		shown := a.pr.buf
		if a.pr.mask {
			shown = strings.Repeat("*", len(shown))
		}
		// A full prompt refuses each next key. Before, it did this silently.
		// Thus a pasted value that was too long was saved in cut form, and the
		// operator did not know. The mark stays after the clip.
		end := "_"
		if len(a.pr.buf) >= promptCap {
			end = "_ [full]"
		}
		b.line(0, y, b.w, clip(a.pr.label+": "+shown, b.w-len(end))+end, reverse)
		return
	}
	hint := "j/k move  Enter open  1-9 jump  ? help  q quit"
	prefix := ""
	if a.paneBusy {
		prefix = "running...  "
	}
	if a.pending != "" && !a.paneBusy {
		prefix = "A applies saved changes  "
	}
	if a.msg != "" {
		a.drawMessage(b, y, prefix, hint)
		return
	}
	if a.focus {
		hint = footerHint(a.viewHint(), commonKeys, b.w-len(prefix))
	}
	b.line(0, y, b.w, clip(prefix+hint, b.w), reverse)
}

// drawMessage puts msg at the start of the footer, then the state and the
// keys in the space that stays. When the space is short, the keys of the
// screen go first, then the state. "? help" stays. The code cuts msg only
// when "? help" alone does not leave space for it.
func (a *App) drawMessage(b *buffer, y int, prefix, hint string) {
	const help = "  ? help"
	n := utf8.RuneCountInString(a.msg)
	if a.focus {
		hint = footerHint(a.viewHint(), commonKeys, b.w-n-2-len(prefix))
	}
	tail := help
	for _, t := range []string{"  " + prefix + hint, "  " + prefix + strings.TrimPrefix(help, "  "), help} {
		if n+len(t) <= b.w {
			tail = t
			break
		}
	}
	msg := clip(a.msg, b.w-len(tail))
	at := reverse
	if _, w, ok := strings.Cut(a.msg, warnSep); strings.HasPrefix(a.msg, "error: ") || ok && strings.Contains(w, renderFails) {
		at = alarm
	}
	b.line(0, y, b.w, "", reverse)
	b.put(0, y, msg, at)
	b.put(utf8.RuneCountInString(msg), y, tail, reverse)
}

// commonKeys are the three keys that all screens share. An operator cannot
// find them again by other means. ? explains the rest. A terminal that
// clipped ? off the line also removed the way to find out what it
// clipped.
const commonKeys = "Esc back  ^R refresh  ? help"

// footerHint fits the keys of a screen and the common keys into w. When
// both do not fit, it removes the keys of the screen from the right.
//
// Secrets is the screen that made this necessary: seven keys, 66
// characters before the common keys start. Thus an 80-column terminal cut
// the line to "Esc back  ^~", and an operator on a stock terminal could
// not see that help existed. To clip is correct at a narrow width (nothing
// here wraps). But the clip from the right removed the wrong end. The keys
// that exit a screen and reload it stay. The keys of the screen go, and
// ".." says that some went.
func footerHint(screen, common string, w int) string {
	if screen == "" {
		return common
	}
	if len(screen)+2+len(common) <= w {
		return screen + "  " + common
	}
	const more = "  ..  "
	keys := strings.Split(screen, "  ")
	for len(keys) > 1 {
		keys = keys[:len(keys)-1]
		s := strings.Join(keys, "  ")
		if len(s)+len(more)+len(common) <= w {
			return s + more + common
		}
	}
	return common
}

// viewHint is the keys of the current view, most used first. On a narrow
// terminal, footerHint removes them from the right.
func (a *App) viewHint() string {
	switch a.cur.sec {
	case secDevices:
		switch {
		case a.detail != "":
			return "j/k scroll  Esc table"
		case a.cur.net == netHouse:
			return "Enter details  r reserve  d delete"
		}
		return "Enter details"
	case secFiltering:
		switch {
		case a.onFeedsTab():
			return "e enable/disable  Tab next"
		case a.cur.readOnlyLists():
			return "Tab next list"
		case a.cur.net == netHouse:
			return "a add  d delete  t test  Tab next"
		}
		return "a add  d delete  Tab next"
	case secActivity:
		if len(a.tabNames()) > 1 {
			return "Tab next view  j/k scroll"
		}
		return "j/k scroll"
	case secSettings:
		if len(a.setRows) > 0 {
			return "Enter edit  A apply"
		}
		return "j/k scroll"
	case secKeys:
		return "u unlock  L lock  c claim  x disable  R restore  p purge  d delete"
	case secFeeds:
		return "e enable/disable"
	case secActions:
		return "Enter run"
	}
	return "j/k scroll"
}

// helpText fits the 64 columns an 80-column terminal leaves beside the
// menu, and the 22 rows a 24-row terminal leaves between the bars. A line
// past those rows is not shown, and the last line says how to close.
var helpText = []string{
	"pf tui: keyboard only; nothing listens on the network.",
	"1-9, j/k+Enter  open a network   Esc, q    back to the menu",
	"Left/Right      section          Tab       next list or view",
	"j/k, PgUp/PgDn  move             ^R, F5    refresh",
	"A               apply edits      q (menu)  quit",
	"",
	"Every network has Devices, Filtering, Activity and Settings;",
	"the agent network also has Keys. System is the Pi itself.",
	"An edit is saved at once and takes effect at the next apply.",
	"A runs pf apply --local after a list or segment edit, else the",
	"full apply, on System > Actions, one at a time under",
	admin.ApplyLockPath + "; quitting kills it: wait for done.",
	"A fence change drops the open agent connections.",
	"^ marks a threat seen and not stopped; ! a standing fault.",
	"Keys never shows a value. A sealed store refuses substitution",
	"until u takes the passphrase (masked, never logged).",
	"A prompt takes 253 bytes, then shows [full]. Enter saves; the",
	"line end of a paste does not; a paste is never a command.",
	"No key for some time stops the TUI; its shell stays open. Only",
	"the login manager can lock this seat.",
	"",
	"Any key closes this help.",
}

func (a *App) drawClaim(b *buffer, x int) {
	c := a.claim
	left := max(int(time.Until(c.Expires).Seconds()), 0)
	lines := []string{
		"claim code for slot " + c.Slot,
		"",
		"    " + c.Code,
		"",
		fmt.Sprintf("expires in %ds, single use", left),
		// The code redeems the slot for each person who reads it. The
		// passphrase is masked for that reason, and this code is not. Thus
		// the screen says why it is a secret too.
		"secret until redeemed; do not share this screen",
		"",
		"on the agent, all of it (the hash checks the script):",
	}
	// The command carries a 64-digit hash. Thus the screen shows it on the
	// lines that the code built, each short enough to stay unclipped.
	cmd := c.CommandLines
	if len(cmd) == 0 {
		cmd = []string{c.Command}
	}
	for _, l := range cmd {
		lines = append(lines, "  "+l)
	}
	lines = append(lines, "", "any key closes")
	for i, l := range lines {
		if 1+i >= b.h-1 {
			break
		}
		at := plain
		if i == 2 {
			at = bold
		}
		b.line(x, 1+i, b.w-x, clip(l, b.w-x), at)
	}
}

func (a *App) drawHelp(b *buffer, x int) {
	for i, l := range helpText {
		if 1+i >= b.h-1 {
			break
		}
		b.line(x, 1+i, b.w-x, clip(l, b.w-x), plain)
	}
}
