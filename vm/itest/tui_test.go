//go:build vagrant

package itest

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// tuiTests are the "TUI, in one sitting" operator checks. The screen logic already has unit tests against a Fake
// terminal. Nothing there proves that the shipped binary paints anything
// on a real box. Thus each check here runs `sudo pf tui` on the Pi over a
// real pty, and reads back the frames that it painted.
//
// A check that a quiet lab cannot show is marked skipped by name, not
// asserted loosely: a screen with no rows would make all substring checks
// pass, and that is worse than no check at all.
func tuiTests(t *testing.T) {
	t.Run("the menu lists every network with its jump key", tuiMenuTests)
	t.Run("the keys each view accepts", tuiKeyTests)
	t.Run("the footer names the view's own keys", tuiFooterTests)
	t.Run("help opens anywhere and comes back to the same row", tuiHelpTests)
	t.Run("tabs cycle on Activity and on Filtering", tuiTabTests)
	t.Run("Health names the units systemd names", tuiStatusTests)
	t.Run("an agent list takes an add and gives it back on delete", tuiAgentListTests)
	t.Run("a feed toggles off and back on", tuiFeedTests)
	t.Run("A runs the apply a saved edit needs", tuiApplyTests)
	t.Run("Keys names its columns", tuiSecretsTests)
	t.Run("Settings lists the house settings and Esc writes nothing", tuiSettingsTests)
	t.Run("Actions runs reload house dns and audits it", tuiActionTests)
	t.Run("a device detail opens and Esc returns to its row", tuiClientDetailTests)
	t.Run("the Activity chart draws a week or says it has no data", tuiChartTests)
	t.Run("bars follow the locale", tuiBarTests)
	t.Run("a small terminal wraps no line", tuiSmallTests)
	t.Run("a resize repaints at the new size", tuiResizeTests)
	t.Run("quit puts the terminal back", tuiQuitTests)
	t.Run("idle exit ends the session on its own", tuiIdleTests)
}

// The bytes that a terminal sends for the keys that the checklist names.
// escWait in internal/tui/term.go is 40ms. Thus a lone Esc is read as Esc
// only when nothing follows it inside that window. tuiKeyGap stops the Esc
// in "Esc goes back" from being read as the head of an arrow key.
const (
	kEsc   = "\x1b"
	kEnter = "\r"
	kTab   = "\t"
	kCtrlC = "\x03"
	kCtrlR = "\x12"
	kUp    = "\x1b[A"
	kDown  = "\x1b[B"
	kRight = "\x1b[C"
	kLeft  = "\x1b[D"
	kHome  = "\x1b[H"
	kEnd   = "\x1b[F"
	kPgUp  = "\x1b[5~"
	kPgDn  = "\x1b[6~"
	kF5    = "\x1b[15~"
)

const (
	// tuiKeyGap is the pause between keystrokes; see the escape note above.
	tuiKeyGap = 200 * time.Millisecond
	// tuiStart is the head start that `sudo pf tui` gets before the first
	// key. Keys that arrive earlier are not lost (the line discipline holds
	// them). But the frames of a run that has not reached EnterRaw yet
	// cannot be counted against the keys.
	tuiStart = 2 * time.Second
	// tuiCooked is the same for a run left in the normal mode of the tty,
	// where an early Ctrl-C would be a signal, not a keystroke.
	tuiCooked = 4 * time.Second
	// tuiIdle bounds a run from the far end: with no key for this long, the
	// TUI exits by itself. Thus a key script that does not reach a quit
	// cannot leave the suite waiting on a live pty.
	tuiIdle = 20 * time.Second
	// tuiSlack is what the local deadline adds on top of the key script
	// and tuiIdle. It is the backstop for an ssh that never returns.
	tuiSlack = 60 * time.Second

	tuiMark      = "PFTUIEND"
	tuiAltEnter  = "\x1b[?1049h"
	tuiAltLeave  = "\x1b[?1049l"
	tuiCursorOn  = "\x1b[?25h"
	tuiFrameHome = "\x1b[H"
	tuiReverse   = "\x1b[0;7m"
	tuiPicked    = "\x1b[0;1;7m"

	tuiHouseEnv = "/etc/pi-fortress/house.env"
	// The overlay a ship keeps, which is the file the seat writes.
	tuiNetEnvLocal = "/etc/pi-fortress/net.env.local"
	tuiAuditLog    = "/var/log/pi-fortress/audit.jsonl"
	// tuiAgentList is the first tab of the agent network's Filtering.
	tuiAgentList  = "blacklist.domains"
	tuiListToken  = "zz-tui-itest.example"
	tuiMenuHint   = "j/k move  Enter open  1-9 jump  ? help  q quit"
	tuiFocusHint  = "  Esc back  ^R refresh  ? help"
	tuiNoStats    = "no data yet; observe flushes every PF_OBSERVE_FLUSH_INTERVAL"
	tuiBarGlyphs  = "▁▂▃▄▅▆▇█"
	tuiBarASCII   = "_.:-=+*#"
	tuiHelpAnchor = "pf tui: keyboard only"
	tuiTitle      = " Pi Fortress  "
	tuiSecStrip   = "(Left/Right)"
)

// tuiHouseSettings is the Settings of the home network, first row to last,
// as the checklist writes it. It is here, not read from internal/tui, so
// that a rename that the operator would see fails this test.
var tuiHouseSettings = []struct{ key, label string }{
	{"HOUSE_BLOCK_DIRECT_IP", "Block direct-IP connections"},
	{"HOUSE_BLOCK_HTTP", "Block plain HTTP"},
	{"HOUSE_BLOCK_VPN", "Block devices' own VPNs"},
	{"HOUSE_EGRESS", "Outbound ports"},
	{"HOUSE_ALLOW_WIFI_CALLING", "Wi-Fi calling"},
	{"HOUSE_ALLOW_CALL_UDP", "Call apps' UDP"},
	{"HOUSE_ALLOW_WHATSAPP", "WhatsApp messages"},
	{"HOUSE_ALLOW_PORTS", "Extra ports"},
	{"HOUSE_DNS_UPSTREAM", "Upstream DNS"},
	{"HOUSE_DOT_AUTH_NAME", "DoT provider name"},
	{"HOUSE_DOT_IPS", "DoT provider addresses"},
	{"HOUSE_PRIVATE_DNS", "Allow Private DNS"},
	{"WG_IF", "VPN tunnel"},
	{"WG_BYPASS_MARK", "Tunnel bypass mark"},
	{"HOUSE_IF", "Interface"},
	{"HOUSE_NET", "Subnet"},
	{"HOUSE_IP", "Pi's address"},
	{"HOUSE_DHCP_START", "DHCP range start"},
	{"HOUSE_DHCP_END", "DHCP range end"},
	{"HOUSE_ADMIN_IP", "Admin machine"},
}

// tuiHouseGroups head the house rows, in order.
var tuiHouseGroups = []string{"Filtering", "Apps & ports", "DNS & VPN", "Network"}

// tuiNetSettings are System's Settings, which edit net.env.local, the
// file a ship keeps.
var tuiNetSettings = []string{"Upstream DNS", "DoT provider name", "DoT provider addresses", "Untrusted uplink"}

// tuiAgentActivity is the Activity tab order of the agent network. The
// home network has Blocked, DNS log and Firewall log. A plain segment has
// Blocked and its own DNS log.
var tuiAgentActivity = []string{"Blocked", "DNS log", "New destinations", "Keys stripped", "Alerts"}

// tuiHouseFiltering is the Filtering tab order of the home network: its lists
// by their friendly names, then the feeds that reach it.
var tuiHouseFiltering = []string{"Blocked sites", "Never block", "Private DNS name", "Private DNS addresses", "Direct-IP exceptions", "Feeds"}

// tuiBox is the menu on the box under test: Overview, the agent and home
// networks, one entry per segments.d segment, then System. The lab has a
// desk. A Pi before the VLAN cutover does not, and the jump key of System
// changes with that. Thus each key script is built from this, not from
// fixed digits.
type tuiBox struct {
	plain []string
}

func tuiBoxOf(t *testing.T) tuiBox {
	t.Helper()
	// The same rule that the seat uses: a *.env file in name order that
	// names both NET and IP. A file without one of them was never applied.
	out, err := ssh(t, 15*time.Second, "pi", `cd /etc/pi-fortress/segments.d 2>/dev/null || exit 0; for f in *.env; do [ -f "$f" ] && sudo -n grep -q '^NET=' "$f" && sudo -n grep -q '^IP=' "$f" && echo "${f%.env}"; done; true`)
	if err != nil {
		t.Fatalf("listing segments.d: %v\n%s", err, out)
	}
	return tuiBox{plain: strings.Fields(out)}
}

func (b tuiBox) nets() []string {
	return append(append([]string{"overview", "agent", "house"}, b.plain...), "system")
}

// label is the menu entry of a network and the first half of its title.
func (b tuiBox) label(net string) string {
	switch net {
	case "overview":
		return "Overview"
	case "agent":
		return "Agent network"
	case "house":
		return "Home network"
	case "system":
		return "System"
	}
	return strings.ToUpper(net[:1]) + net[1:]
}

func tuiSections(net string) []string {
	switch net {
	case "overview":
		return []string{"Overview"}
	case "agent":
		return []string{"Devices", "Filtering", "Activity", "Settings", "Keys"}
	case "system":
		return []string{"Health", "Settings", "Feeds", "Admin log", "Actions"}
	}
	return []string{"Devices", "Filtering", "Activity", "Settings"}
}

// digit is the jump key of a network.
func (b tuiBox) digit(t *testing.T, net string) string {
	t.Helper()
	i := slices.Index(b.nets(), net)
	if i < 0 || i > 8 {
		t.Fatalf("%s has no jump key on this box (menu %v)", net, b.nets())
	}
	return strconv.Itoa(i + 1)
}

// open is the keys that reach one view from the menu: the digit of the
// network, which opens its first section, then l for each section after
// it. It assumes that the network was not left on a different section
// earlier in the same session, because a network opens again where it was left.
func (b tuiBox) open(t *testing.T, net, sec string) []string {
	t.Helper()
	i := slices.Index(tuiSections(net), sec)
	if i < 0 {
		t.Fatalf("%s has no %s section", net, sec)
	}
	return tuiKeys(b.digit(t, net), tuiRepeat(i, "l"))
}

// title is what the title bar starts with on a view.
func (b tuiBox) title(net, sec string) string {
	if net == "overview" {
		return tuiTitle + "Overview"
	}
	return tuiTitle + b.label(net) + " > " + sec
}

// tuiRun is one `pf tui` session on the Pi.
type tuiRun struct {
	keys       []string      // one keystroke per entry, tuiKeyGap apart
	flags      string        // pf tui flags; "" means -idle tuiIdle
	env        string        // env pf runs under, e.g. "LANG=C LC_ALL=C"
	rows, cols int           // pty size; 0 means 24x80
	pre        string        // shell run on the Pi first; must end in ";"
	cooked     bool          // leave the tty echoing, as a login seat has it
	wait       time.Duration // extra time to allow after the last key
}

// tuiFrame is one painted screen: the app writes the full buffer in one
// write, so a frame is exactly h lines of exactly w cells.
type tuiFrame struct {
	w, h  int
	lines []string // w runes each, escapes removed
	rev   []bool   // per line: painted in reverse video
	bad   string   // set when the chunk was not a rectangle
}

type tuiSession struct {
	out    string // everything the pty sent back
	frames []tuiFrame
	rc     int
	before string // stty -g before pf tui
	after  string // stty -g after it
	stty   string // stty -a after it
	took   time.Duration
}

var tuiANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

func tuiStrip(s string) string { return tuiANSI.ReplaceAllString(s, "") }

// tuiBracketPicked turns the highlighted section or tab, painted as
// " Feeds " in bold reverse, into "[Feeds]": the same width, and text a
// frame check can match without reading attributes.
func tuiBracketPicked(l string) string {
	parts := strings.Split(l, tuiPicked)
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		end := strings.Index(p, "\x1b[")
		if end < 0 {
			end = len(p)
		}
		if span := p[:end]; len(span) >= 2 && span[0] == ' ' && span[len(span)-1] == ' ' {
			parts[i] = "[" + span[1:len(span)-1] + "]" + p[end:]
		}
	}
	return strings.Join(parts, tuiPicked)
}

// tuiTyped turns a string into one entry per keystroke.
func tuiTyped(s string) []string {
	var out []string
	for _, r := range s {
		out = append(out, string(r))
	}
	return out
}

// tuiRepeat is n presses of the same key.
func tuiRepeat(n int, k string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = k
	}
	return out
}

func tuiKeys(parts ...any) []string {
	var out []string
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			out = append(out, v)
		case []string:
			out = append(out, v...)
		default:
			panic("tuiKeys: not a key")
		}
	}
	return out
}

// remote is the shell line that the Pi runs. It records the mode of the
// tty before and after the TUI, because "q restores the terminal" is a
// claim about the termios that pf tui gives back, not about what was printed.
func (r tuiRun) remote() string {
	// sane first, and only for a cooked run: ssh -tt with a pipe for stdin
	// has no local terminal to copy modes from. Thus the pty that it opens
	// starts without echo, icanon or isig. If it stayed that way, "the tty
	// still has echo after the quit" would be a statement about this
	// harness, not about pf tui, which restores the mode that it got. sane
	// makes the baseline the same as the one that an operator logs in with.
	mode := " -echo -icanon -isig"
	if r.cooked {
		mode = " sane"
	}
	flags := r.flags
	if flags == "" {
		flags = "-idle " + tuiIdle.String()
	}
	// sudo -n: with a live pty on stdin, a password prompt would consume
	// the key script and not fail. The run would then end only at the
	// local deadline.
	run := "sudo -n"
	if r.env != "" {
		run += " env " + r.env
	}
	return fmt.Sprintf("stty rows %d cols %d%s; B=$(stty -g); %s%s pf tui %s; rc=$?; A=$(stty -g); S=$(stty -a | tr '\\n' ' '); printf '\\n%s rc=%%s before=%%s after=%%s stty=%%s\\n' \"$rc\" \"$B\" \"$A\" \"$S\"",
		r.rows, r.cols, mode, r.pre, run, flags, tuiMark)
}

// tuiDrive runs one session and returns what the Pi painted. Three
// separate bounds stop a TUI that stops reading from stalling the suite:
// the remote -idle ends the app, the local context kills ssh, and a run
// that ends without the trailing marker fails here. It does not return an
// empty frame list, against which a caller would assert nothing.
func tuiDrive(t *testing.T, r tuiRun) *tuiSession {
	t.Helper()
	if sshCfg == "" {
		t.Fatal("ssh config not loaded")
	}
	if r.rows == 0 {
		r.rows = 24
	}
	if r.cols == 0 {
		r.cols = 80
	}
	head := tuiStart
	if r.cooked {
		head = tuiCooked
	}
	budget := head + time.Duration(len(r.keys))*tuiKeyGap + r.wait + tuiIdle + tuiSlack
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-tt", "-F", sshCfg, "-o", "BatchMode=yes", "pi", r.remote())
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(head)
		for _, k := range r.keys {
			// A write that fails means that the session is already gone. The
			// wait below reports that with the full transcript.
			if _, err := in.Write([]byte(k)); err != nil {
				return
			}
			time.Sleep(tuiKeyGap)
		}
	}()
	waitErr := cmd.Wait()
	s := &tuiSession{out: strings.ReplaceAll(out.String(), "\x00", ""), took: time.Since(start)}
	tail := s.out
	if len(tail) > 4000 {
		tail = tail[len(tail)-4000:]
	}
	if waitErr != nil {
		if sudoRefused(s.out + errb.String()) {
			skipNoSudo(t, "pi", "sudo pf tui")
		}
		t.Fatalf("pf tui: %v (after %s)\nstderr: %s\ntail:\n%s", waitErr, s.took.Round(time.Millisecond), errb.String(), tuiStrip(tail))
	}
	s.parse(t)
	return s
}

// parse splits the transcript into frames. Each paint starts with a
// cursor-home, so the chunks between them are the frames. The first chunk
// is what the login wrote before the alternate screen. It is discarded,
// not parsed.
func (s *tuiSession) parse(t *testing.T) {
	t.Helper()
	i := strings.Index(s.out, tuiMark+" rc=")
	if i < 0 {
		t.Fatalf("pf tui never reached its end marker; the session did not run to completion:\n%s", tuiStrip(s.out))
	}
	for _, f := range strings.Fields(s.out[i:]) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "rc":
			s.rc, _ = strconv.Atoi(v)
		case "before":
			s.before = v
		case "after":
			s.after = v
		}
	}
	if j := strings.Index(s.out[i:], "stty="); j >= 0 {
		s.stty = " " + strings.TrimSpace(s.out[i+j+len("stty="):]) + " "
	}
	if s.rc != 0 {
		// The wrapper still exits 0 when pf tui does not. Thus a sudo
		// refusal comes here, not as a failed ssh.
		if sudoRefused(s.out) {
			skipNoSudo(t, "pi", "sudo pf tui")
		}
		t.Fatalf("pf tui exited %d:\n%s", s.rc, tuiStrip(s.out))
	}
	a := strings.Index(s.out, tuiAltEnter)
	if a < 0 {
		t.Fatalf("pf tui never switched to the alternate screen; it painted nothing:\n%s", tuiStrip(s.out))
	}
	chunks := strings.Split(s.out[a:], tuiFrameHome)
	for _, c := range chunks[1:] {
		// The last paint has the restore escapes and the marker line attached
		// to its final row. Remove them: they are not cells.
		if j := strings.Index(c, tuiCursorOn); j >= 0 {
			c = c[:j]
		}
		lines := strings.Split(c, "\r\n")
		if len(lines) < 3 {
			continue // the clear-screen that follows EnterRaw, not a paint
		}
		f := tuiFrame{h: len(lines), lines: make([]string, len(lines)), rev: make([]bool, len(lines))}
		for i, l := range lines {
			f.lines[i] = tuiStrip(tuiBracketPicked(l))
			f.rev[i] = strings.Contains(l, tuiReverse)
			n := utf8.RuneCountInString(f.lines[i])
			if i == 0 {
				f.w = n
			}
			if n != f.w && f.bad == "" {
				// A row that is not exactly as wide as the screen means that
				// the paint wrapped. That moves all rows below it.
				f.bad = fmt.Sprintf("line %d is %d cells wide, the first line is %d: %q", i, n, f.w, f.lines[i])
			}
		}
		s.frames = append(s.frames, f)
	}
	if len(s.frames) == 0 {
		t.Fatalf("pf tui painted no frame at all:\n%s", tuiStrip(s.out))
	}
}

// frame is the i'th paint, including the paint that the app makes before
// it reads a key. A negative i counts back from the last.
func (s *tuiSession) frame(t *testing.T, i int) tuiFrame {
	t.Helper()
	if i < 0 {
		i += len(s.frames)
	}
	if i < 0 || i >= len(s.frames) {
		t.Fatalf("wanted frame %d of %d", i, len(s.frames))
	}
	f := s.frames[i]
	if f.bad != "" {
		t.Fatalf("frame %d did not fit the screen: %s\n%s", i, f.bad, f.text())
	}
	return f
}

// steady checks the one-paint-per-key rule. Only the live views (Overview,
// Devices and the Blocked table of Activity) repaint by themselves, every
// 5 s. A key script goes through them in much less time. Thus in all
// other views, a surplus frame is a view that refreshes when it should
// not. A missing frame is a key that the pty lost.
func (s *tuiSession) steady(t *testing.T, keys []string) {
	t.Helper()
	if len(s.frames) != len(keys)+1 {
		t.Fatalf("%d keys drew %d frames, wanted %d (one before the first key, one per key)", len(keys), len(s.frames), len(keys)+1)
	}
}

func (f tuiFrame) text() string { return strings.Join(f.lines, "\n") }

func (f tuiFrame) footer() string { return strings.TrimRight(f.lines[f.h-1], " ") }

func (f tuiFrame) title() string { return strings.TrimRight(f.lines[0], " ") }

// selected is the content of the one row painted in reverse between the
// title and the footer: the cursor. The menu column shares those rows.
// Thus the return value is the part to the right of it.
func (f tuiFrame) selected() string {
	for i := 1; i < f.h-1; i++ {
		if f.rev[i] {
			return f.content(i)
		}
	}
	return ""
}

func (f tuiFrame) has(subs ...string) bool {
	txt := f.text()
	for _, s := range subs {
		if !strings.Contains(txt, s) {
			return false
		}
	}
	return true
}

func (f tuiFrame) must(t *testing.T, what string, subs ...string) {
	t.Helper()
	txt := f.text()
	for _, s := range subs {
		if !strings.Contains(txt, s) {
			t.Fatalf("%s: no %q on the screen:\n%s", what, s, txt)
		}
	}
}

// same is frame equality including the cursor, which is how "Esc returns
// to the same screen and row" is checked.
func (f tuiFrame) same(g tuiFrame) bool {
	if f.text() != g.text() || f.h != g.h {
		return false
	}
	for i := range f.rev {
		if f.rev[i] != g.rev[i] {
			return false
		}
	}
	return true
}

// tuiContentX is where the content column starts: the menu uses the first
// menuWidth cells of each row. Thus a content line must be cut from the
// row, not read whole.
const tuiContentX = 18

// content is the part of a row right of the menu column.
func (f tuiFrame) content(i int) string {
	r := []rune(f.lines[i])
	if len(r) <= tuiContentX {
		return ""
	}
	return strings.TrimRight(string(r[tuiContentX:]), " ")
}

// first is the earliest frame that has all substrings. The live views
// repaint on a ticker. Thus their frames cannot be counted against the
// key script, and must be found by their content.
func (s *tuiSession) first(t *testing.T, subs ...string) tuiFrame {
	t.Helper()
	for i := range s.frames {
		if s.frames[i].bad == "" && s.frames[i].has(subs...) {
			return s.frames[i]
		}
	}
	t.Fatalf("no frame carried %q; the last one was:\n%s", subs, s.frame(t, -1).text())
	return tuiFrame{}
}

// --- checklist :239 Menu ---

func tuiMenuTests(t *testing.T) {
	box := tuiBoxOf(t)
	keys := []string{"q"}
	s := tuiDrive(t, tuiRun{keys: keys})
	s.steady(t, keys)
	f := s.frame(t, 0)
	for i, net := range box.nets() {
		f.must(t, "menu", fmt.Sprintf("%d %s", i+1, box.label(net)))
	}
	if got := f.footer(); got != tuiMenuHint {
		t.Fatalf("menu hint is %q, wanted %q", got, tuiMenuHint)
	}
	if got := f.title(); !strings.HasPrefix(got, box.title("overview", "")) {
		t.Fatalf("title is %q", got)
	}
	// The seat opens on Overview: a verdict before any detail, then a
	// line per network.
	if !f.has("All good") && !f.has("Needs attention") {
		t.Fatalf("Overview gives no verdict:\n%s", f.text())
	}
	f.must(t, "Overview", "network", "devices", "blocked today", "Agent network", "Home network")
}

// --- checklist :240 Keys ---

func tuiKeyTests(t *testing.T) {
	box := tuiBoxOf(t)
	t.Run("1-9 jump straight to a network and Esc goes back", func(t *testing.T) {
		keys := []string{"3", kEsc, box.digit(t, "system"), kEsc, "q"}
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		s.frame(t, 1).must(t, "3 opens the home network", box.title("house", "Devices"))
		s.frame(t, 2).must(t, "Esc goes back to the menu", tuiMenuHint)
		s.frame(t, 3).must(t, "the last entry opens System", box.title("system", "Health"))
		if got := s.frame(t, 4).footer(); got != tuiMenuHint {
			t.Fatalf("Esc left the footer at %q", got)
		}
	})

	t.Run("Enter l and Right all open the highlighted row and q walks back", func(t *testing.T) {
		keys := []string{kDown, kDown, kEnter, "q", kRight, "q", "l", "q", "q"}
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		// Two downs from Overview is the home network. Frames 3, 5 and 7
		// are the three ways in; 4, 6 and 8 are q walking back out.
		for _, i := range []int{3, 5, 7} {
			s.frame(t, i).must(t, "open", box.title("house", "Devices"), "r reserve  d delete"+tuiFocusHint)
		}
		for _, i := range []int{4, 6, 8} {
			if got := s.frame(t, i).footer(); got != tuiMenuHint {
				t.Fatalf("frame %d: q left the footer at %q, wanted the menu hint", i, got)
			}
		}
	})

	t.Run("Left and Right move sections and Left from the first is the menu", func(t *testing.T) {
		keys := []string{"3", kRight, "l", kLeft, "h", kLeft, "q"}
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		for i, sec := range []string{"Devices", "Filtering", "Activity", "Filtering", "Devices"} {
			f := s.frame(t, i+1)
			f.must(t, sec, box.title("house", sec), "["+sec+"]", tuiSecStrip)
		}
		if got := s.frame(t, 6).footer(); got != tuiMenuHint {
			t.Fatalf("Left from Devices left the footer at %q, wanted the menu hint", got)
		}
	})

	t.Run("PgDn End Home and PgUp move the cursor", func(t *testing.T) {
		// The Settings of the home network is the view whose rows are fixed
		// and known. Thus the cursor can be named, not counted.
		open := box.open(t, "house", "Settings")
		keys := tuiKeys(open, kEnd, kHome, kPgDn, kPgUp, "q", "q")
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		n := len(open)
		first, last := tuiHouseSettings[0].label, tuiHouseSettings[len(tuiHouseSettings)-1].label
		for _, c := range []struct {
			frame int
			key   string
			want  string
		}{
			{n, "open", first},
			{n + 1, "End", last},
			{n + 2, "Home", first},
			{n + 4, "PgUp", first},
		} {
			if got := strings.TrimSpace(s.frame(t, c.frame).selected()); !strings.HasPrefix(got, c.want) {
				t.Fatalf("after %s the cursor is on %q, wanted %s", c.key, got, c.want)
			}
		}
		// PgDn moves half a screen, not to the end. It must move, and PgUp
		// above must bring it back.
		if got := strings.TrimSpace(s.frame(t, n+3).selected()); strings.HasPrefix(got, first) {
			t.Fatalf("PgDn did not move the cursor off %s: %q", first, got)
		}
	})

	t.Run("Ctrl-C quits from the menu", func(t *testing.T) {
		keys := []string{kCtrlC}
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		if !strings.Contains(s.out, tuiAltLeave) {
			t.Fatal("Ctrl-C ended the app without leaving the alternate screen")
		}
	})
}

// --- checklist :241 Footer ---

func tuiFooterTests(t *testing.T) {
	box := tuiBoxOf(t)
	// All sections of all networks: its digit, l across the rest, Esc.
	// 120 columns, because Keys has seven keys of its own before the three
	// that all views share. At 80, footerHint omits the own keys of the
	// view (asserted in internal/tui). This checks the content at a width
	// that holds it.
	type seen struct {
		net, sec string
		frame    int
	}
	var keys []string
	var views []seen
	for _, net := range box.nets() {
		for i, sec := range tuiSections(net) {
			if i == 0 {
				keys = append(keys, box.digit(t, net))
			} else {
				keys = append(keys, "l")
			}
			views = append(views, seen{net, sec, len(keys)})
		}
		keys = append(keys, kEsc)
	}
	keys = append(keys, "q")
	s := tuiDrive(t, tuiRun{keys: keys, cols: 120})
	s.steady(t, keys)
	at := map[string]tuiFrame{}
	for _, v := range views {
		f := s.frame(t, v.frame)
		f.must(t, v.net+" "+v.sec, box.title(v.net, v.sec))
		got := f.footer()
		if !strings.HasSuffix(got, tuiFocusHint) {
			t.Fatalf("%s %s footer %q does not end in %q", v.net, v.sec, got, tuiFocusHint)
		}
		if strings.TrimSpace(strings.TrimSuffix(got, tuiFocusHint)) == "" {
			t.Fatalf("%s %s has the shared footer and no hint of its own: %q", v.net, v.sec, got)
		}
		at[v.net+"/"+v.sec] = f
	}
	// The hints that the checklist names. Thus the test catches a hint
	// table that goes blank or moves by one, not only "something is there".
	at["house/Devices"].must(t, "house Devices hint", "Enter details  r reserve  d delete"+tuiFocusHint)
	at["house/Filtering"].must(t, "house Filtering hint", "a add  d delete  t test  Tab next"+tuiFocusHint)
	at["house/Settings"].must(t, "house Settings hint", "Enter edit  A apply"+tuiFocusHint)
	at["agent/Activity"].must(t, "agent Activity hint", "Tab next view  j/k scroll"+tuiFocusHint)
	at["agent/Keys"].must(t, "Keys hint", "u unlock  L lock  c claim"+"  x disable  R restore  p purge  d delete"+tuiFocusHint)
	at["agent/Settings"].must(t, "the agent network's Settings are read-only", "Fixed by the fence", "j/k scroll"+tuiFocusHint)
	at["system/Actions"].must(t, "Actions hint", "Enter run"+tuiFocusHint)
	at["system/Feeds"].must(t, "Feeds hint", "e enable/disable"+tuiFocusHint)
	for _, p := range box.plain {
		at[p+"/Filtering"].must(t, p+" Filtering is the agent lists, read-only", "shared with the agent network", "Tab next list"+tuiFocusHint)
	}

	t.Run("^R and F5 both redraw the view", func(t *testing.T) {
		open := box.open(t, "house", "Settings")
		keys := tuiKeys(open, kCtrlR, kF5, "q", "q")
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		n := len(open)
		first, ctrlR, f5 := s.frame(t, n), s.frame(t, n+1), s.frame(t, n+2)
		// Settings reads a file that does not change under it. Thus a reload
		// must come back to the same view. This proves that both keys reach
		// the app at all, and that neither key leaves the view.
		if !first.same(ctrlR) || !first.same(f5) {
			t.Fatalf("a refresh changed the Settings view:\nopen:\n%s\n^R:\n%s\nF5:\n%s", first.text(), ctrlR.text(), f5.text())
		}
	})
}

// --- checklist :242 Help ---

func tuiHelpTests(t *testing.T) {
	box := tuiBoxOf(t)
	open := box.open(t, "house", "Settings")
	keys := tuiKeys(open, kDown, kDown, "?", kEsc, "?", "q", "q", "q")
	// 80 columns: the help is written to fit the 64 cells beside the menu.
	s := tuiDrive(t, tuiRun{keys: keys})
	s.steady(t, keys)
	n := len(open)
	before := s.frame(t, n+2)
	for _, i := range []int{n + 3, n + 5} {
		s.frame(t, i).must(t, "help", tuiHelpAnchor, "/run/pi-fortress/apply.lock", "quitting kills it")
	}
	// The row is important: help that came back to the top of the view
	// would lose the place of an operator in a twenty-row list.
	for _, i := range []int{n + 4, n + 6} {
		if got := s.frame(t, i); !got.same(before) {
			t.Fatalf("frame %d: leaving help did not come back to the same view and row\nbefore:\n%s\nafter:\n%s", i, before.text(), got.text())
		}
	}

	t.Run("? opens help on the menu too", func(t *testing.T) {
		keys := []string{"?", kEsc, "q"}
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		s.frame(t, 1).must(t, "help on the menu", tuiHelpAnchor)
		if !s.frame(t, 2).same(s.frame(t, 0)) {
			t.Fatal("Esc from help did not put the menu back")
		}
	})
}

// --- checklist :243 Tabs ---

func tuiTabTests(t *testing.T) {
	box := tuiBoxOf(t)
	t.Run("Tab cycles the agent network's Activity views", func(t *testing.T) {
		// 160 columns: five tab names and the (Tab) marker do not fit a
		// narrower strip. This subtest is about the order and the key, not
		// the scrolling. internal/tui asserts the scrolling separately.
		open := box.open(t, "agent", "Activity")
		keys := tuiKeys(open, tuiRepeat(len(tuiAgentActivity), kTab), "q", "q")
		s := tuiDrive(t, tuiRun{keys: keys, cols: 160})
		s.steady(t, keys)
		n := len(open)
		s.frame(t, n).must(t, "Activity tabs", append([]string{"[" + tuiAgentActivity[0] + "]", "(Tab)"}, tuiAgentActivity[1:]...)...)
		for i := 1; i <= len(tuiAgentActivity); i++ {
			want := tuiAgentActivity[i%len(tuiAgentActivity)]
			s.frame(t, n+i).must(t, fmt.Sprintf("Tab %d", i), "["+want+"]")
		}
	})

	t.Run("Tab walks the home network's lists and ends on its feeds", func(t *testing.T) {
		open := box.open(t, "house", "Filtering")
		keys := tuiKeys(open, tuiRepeat(len(tuiHouseFiltering)-1, kTab), "q", "q")
		s := tuiDrive(t, tuiRun{keys: keys, cols: 160})
		s.steady(t, keys)
		n := len(open)
		s.frame(t, n).must(t, "Filtering tabs", append([]string{"[" + tuiHouseFiltering[0] + "]", "Blocked sites: house.domains"}, tuiHouseFiltering[1:]...)...)
		last := s.frame(t, n+len(tuiHouseFiltering)-1)
		last.must(t, "the last tab", "[Feeds]", "id ", "enabled")
	})

	t.Run("a plain segment's Activity has its own DNS log", func(t *testing.T) {
		if len(box.plain) == 0 {
			t.Skip("no segments.d segment on this box, so no plain segment's Activity to open")
		}
		seg := box.plain[0]
		open := box.open(t, seg, "Activity")
		keys := tuiKeys(open, kTab, "q", "q")
		s := tuiDrive(t, tuiRun{keys: keys})
		s.steady(t, keys)
		n := len(open)
		s.frame(t, n).must(t, seg+" Activity", box.title(seg, "Activity"), "[Blocked]", "DNS log")
		s.frame(t, n+1).must(t, seg+" DNS log", "[DNS log]")
	})
}

// --- checklist :246 Status ---

func tuiStatusTests(t *testing.T) {
	box := tuiBoxOf(t)
	open := box.open(t, "system", "Health")
	keys := tuiKeys(open, "q", "q")
	// 40 rows: the units, stubs and interfaces of a real Pi push "uplink"
	// past a 24-row screen, and the view scrolls. It does not compress them.
	s := tuiDrive(t, tuiRun{keys: keys, rows: 40})
	s.steady(t, keys)
	f := s.frame(t, len(open))
	f.must(t, "Health", box.title("system", "Health"), "units", "interfaces", "uplink")
	// The unit block goes from the "units" line to the blank line. Each row
	// is checked against what systemd says now, which `pf doctor` also
	// reads. This catches a view that paints a stale or hard-coded state.
	var units []string
	in := false
	for i := 1; i < f.h-1; i++ {
		body := f.content(i)
		switch {
		case body == "units":
			in = true
		case in && strings.TrimSpace(body) == "":
			in = false
		case in:
			units = append(units, strings.TrimSpace(body))
		}
	}
	if len(units) < 3 {
		t.Fatalf("Health listed %d units:\n%s", len(units), f.text())
	}
	overview := s.frame(t, 0)
	for _, u := range units {
		fields := strings.Fields(u)
		if len(fields) != 2 {
			t.Fatalf("unit row %q is not `name state`", u)
		}
		name, shown := fields[0], fields[1]
		live := strings.TrimSpace(pi(t, "systemctl is-active "+name+" || true"))
		if live != shown {
			t.Errorf("%s: the view says %q, systemd says %q", name, shown, live)
		}
		// A unit that is not running is a problem that Overview must name.
		// If not, its verdict is a claim that nobody checked.
		if shown != "active" && shown != "unknown" && !overview.has(name+" is "+shown) {
			t.Errorf("%s is %s and Overview does not say so:\n%s", name, shown, overview.text())
		}
	}
	// The other half of this item (the feed age in the title bar) shows
	// only after the blocklist is stale. Thus a new lab cannot show it.
	if note := strings.TrimSpace(strings.TrimPrefix(f.title(), box.title("system", "Health"))); note != "" {
		t.Logf("title note: %q", note)
		// A standing warning is a problem, so the verdict of Overview names it.
		if strings.Contains(note, "feeds:") && !overview.has("Needs attention", "feeds:") {
			t.Errorf("the title warns about feeds and Overview does not:\n%s", overview.text())
		}
	} else {
		t.Log("no feed-age note in the title: this lab's lists are current, so that half of the item is not covered here")
	}
}

// --- checklist :249 Agent lists ---

// tuiPolicyDir mirrors admin.Defaults: the synced tree of the lab when it
// is there, or else the installed tree. On a Vagrant lab, edits below go
// into a file that is checked into this repo. Thus they are backed up first.
func tuiPolicyDir(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(pi(t, "d=/vagrant/vm/policy; [ -d \"$d\" ] || d=/etc/pi-fortress; echo \"$d\""))
}

// tuiKeepFile copies a file aside and returns the restore to defer. Thus
// a run that dies between an add and its delete does not leave the policy
// tree of the lab edited. On a Vagrant lab, that tree is the vm/policy of
// this repo. strict also fails the test when the round trip did not
// restore the file byte for byte.
//
// Deferred, not registered with t.Cleanup: the test context is cancelled
// before cleanups run, so the ssh for the restore would never leave the
// machine. t.Fatal unwinds defers, and that is the important case.
func tuiKeepFile(t *testing.T, path string, strict bool) func() {
	t.Helper()
	bak := path + ".pf-tui-itest.bak"
	if out, err := ssh(t, 30*time.Second, "pi", "sudo -n cp -a "+path+" "+bak); err != nil {
		t.Fatalf("backing up %s: %v\n%s", path, err, out)
	}
	return func() {
		out, err := ssh(t, 30*time.Second, "pi", "sudo -n cmp -s "+path+" "+bak+" && echo same || echo differs; sudo -n mv -f "+bak+" "+path)
		if err != nil {
			t.Errorf("restoring %s from %s: %v\n%s", path, bak, err, out)
			return
		}
		if !strings.Contains(out, "differs") {
			return
		}
		if strict {
			t.Errorf("%s was left changed and has been restored from the backup", path)
			return
		}
		t.Logf("%s did not come back byte for byte and has been restored from the backup", path)
	}
}

// tuiKeepMaybe is tuiKeepFile for a file that does not have to exist,
// such as net.env.local on a box that nobody tuned. If the file is absent,
// the restore removes what the run created in its place.
func tuiKeepMaybe(t *testing.T, path string, strict bool) func() {
	t.Helper()
	out, err := ssh(t, 30*time.Second, "pi", "if sudo -n test -e "+path+"; then echo present; else echo absent; fi")
	if err != nil {
		t.Fatalf("checking %s: %v\n%s", path, err, out)
	}
	if strings.Contains(out, "present") {
		return tuiKeepFile(t, path, strict)
	}
	return func() {
		out, err := ssh(t, 30*time.Second, "pi", "if sudo -n test -e "+path+"; then echo differs; sudo -n rm -f "+path+"; else echo same; fi")
		if err != nil {
			t.Errorf("removing %s, which the run created: %v\n%s", path, err, out)
			return
		}
		if !strings.Contains(out, "differs") {
			return
		}
		if strict {
			t.Errorf("%s was created by the run and has been removed", path)
			return
		}
		t.Logf("%s was created by the run and has been removed", path)
	}
}

func tuiAgentListTests(t *testing.T) {
	box := tuiBoxOf(t)
	path := tuiPolicyDir(t) + "/" + tuiAgentList
	defer tuiKeepFile(t, path, true)()
	count := func() int { return grepCount(t, path, tuiListToken) }
	if n := count(); n != 0 {
		t.Fatalf("%s already has %d %s lines; an earlier run left them", path, n, tuiListToken)
	}
	// a, the name, Enter; then End onto the new last row, d, y.
	open := box.open(t, "agent", "Filtering")
	keys := tuiKeys(open, "a", tuiTyped(tuiListToken), kEnter, kEnd, "d", "y", "q", "q")
	s := tuiDrive(t, tuiRun{keys: keys})
	s.steady(t, keys)
	n := len(open) + len(tuiListToken)
	s.frame(t, len(open)).must(t, "the first list", "[Blocked sites]", "Blocked sites: "+tuiAgentList)
	added := s.frame(t, n+2)
	added.must(t, "after a", "added "+tuiListToken+"; A applies")
	// A message with no row behind it would mean that the edit went
	// nowhere. The row that proves it is the row that End goes to, below.
	// It is not a second copy of the name in this frame: the new entry
	// goes to the end of a list longer than the viewport. Thus it is not
	// painted until the cursor scrolls there. The file also cannot answer
	// it: the full key script, delete included, already ran before these
	// assertions read it.
	onRow := s.frame(t, n+3)
	if got := onRow.selected(); !strings.HasPrefix(got, tuiListToken) {
		t.Fatalf("End did not land on the added row; the cursor is on %q:\n%s", got, onRow.text())
	}
	s.frame(t, n+4).must(t, "d asks first", "delete "+tuiListToken+" [y/N]")
	gone := s.frame(t, n+5)
	gone.must(t, "after y", "deleted "+tuiListToken)
	if strings.Count(gone.text(), tuiListToken) != 1 {
		t.Fatalf("the deleted name is still on the screen (only the message should name it):\n%s", gone.text())
	}
	if n := count(); n != 0 {
		t.Fatalf("%s still has %d %s lines after the delete", path, n, tuiListToken)
	}
}

// --- checklist: A applies ---

// tuiApplyToken is a house blocklist line only this test writes.
const tuiApplyToken = "zz-tui-apply.example"

// tuiApplyTests is the full loop that an operator runs: an edit saved,
// the footer that says it waits for an apply, A and y that run apply
// --local on System > Actions, and the note gone after the apply. Then the
// same to remove the line again. No q while the apply streams: q would
// cancel it. Thus each session ends on the idle exit, which waits for the action.
func tuiApplyTests(t *testing.T) {
	box := tuiBoxOf(t)
	path := tuiPolicyDir(t) + "/house.domains"
	defer tuiKeepFile(t, path, true)()
	if n := grepCount(t, path, tuiApplyToken); n != 0 {
		t.Fatalf("%s already has %s; an earlier run left it", path, tuiApplyToken)
	}
	const pending = "A applies saved changes"
	session := func(what string, edit ...any) *tuiSession {
		open := box.open(t, "house", "Filtering")
		keys := tuiKeys(append([]any{open}, append(edit, "A", "y")...)...)
		s := tuiDrive(t, tuiRun{keys: keys, wait: 3 * time.Minute})
		s.first(t, pending)
		s.first(t, "run pf apply --local now [y/N]")
		s.first(t, box.title("system", "Actions"), "$ pf apply --local")
		last := s.frame(t, -1)
		last.must(t, what+": the apply finished", box.title("system", "Actions"), "local policy reloaded", "done")
		if last.has("error:") || strings.Contains(last.footer(), pending) {
			t.Fatalf("%s: the apply failed or the note stayed:\n%s", what, last.text())
		}
		return s
	}
	session("add", "a", tuiTyped(tuiApplyToken), kEnter)
	if n := grepCount(t, path, tuiApplyToken); n != 1 {
		t.Fatalf("%s has %d %s lines after the add", path, n, tuiApplyToken)
	}
	session("delete", kEnd, "d", "y")
	if n := grepCount(t, path, tuiApplyToken); n != 0 {
		t.Fatalf("%s still has %s after the delete", path, tuiApplyToken)
	}
}

// --- checklist :250 Feeds ---

func tuiFeedTests(t *testing.T) {
	box := tuiBoxOf(t)
	// Strict: the shipped file and the file of the Pi (after MergeSeed) are
	// in the form that SetFeedEnabled writes. Thus off and on again is byte identical.
	path := tuiPolicyDir(t) + "/sources.json"
	defer tuiKeepFile(t, path, true)()
	open := box.open(t, "system", "Feeds")
	keys := tuiKeys(open, "e", kCtrlR, "e", kCtrlR, "q", "q")
	s := tuiDrive(t, tuiRun{keys: keys})
	s.steady(t, keys)
	// The cursor is on the first feed row, and the enabled column is its
	// last field. A view with no feed at all shows a broken lab, not a
	// quiet lab: sources.json ships with feeds in it.
	on := func(i int) string {
		f := s.frame(t, i)
		row := f.selected()
		if row == "" || !strings.Contains(f.text(), "id ") {
			t.Fatalf("frame %d has no feed row:\n%s", i, f.text())
		}
		fields := strings.Fields(row)
		return fields[len(fields)-1]
	}
	n := len(open)
	first, off, offAfterR, back, backAfterR := on(n), on(n+1), on(n+2), on(n+3), on(n+4)
	if off == first {
		t.Fatalf("e left the first feed at %q", first)
	}
	if offAfterR != off {
		t.Fatalf("^R lost the toggle: %q became %q", off, offAfterR)
	}
	if back != first || backAfterR != first {
		t.Fatalf("toggling back did not restore %q: %q then %q", first, back, backAfterR)
	}
}

// --- checklist :251 Secrets ---

func tuiSecretsTests(t *testing.T) {
	box := tuiBoxOf(t)
	// Wide enough for the full column line: the five headings are 80
	// cells, and an 80-column screen without the menu cuts the last heading.
	open := box.open(t, "agent", "Keys")
	keys := tuiKeys(open, "q", "q")
	s := tuiDrive(t, tuiRun{keys: keys, cols: 120})
	s.steady(t, keys)
	f := s.frame(t, len(open))
	f.must(t, "Keys", box.title("agent", "Keys"), "store: ", "slot", "kinds (state)", "last used", "last hour", "state")
	// c, x, R, d, u and L all act on a slot. A claim or a quarantine here
	// would fight the secrets group for the same store. Thus this run only
	// proves the view and its columns. The key half of the item is for the
	// operator.
	if f.has("no slots") {
		t.Log("no slots on this box, so only the column line is checked here")
	}
}

// --- checklist :253 Settings ---

func tuiSettingsTests(t *testing.T) {
	box := tuiBoxOf(t)
	// The run only opens and cancels. But a TUI that wrote nevertheless
	// would leave the box edited. These put both files back in all cases.
	defer tuiKeepMaybe(t, tuiHouseEnv, true)()
	defer tuiKeepMaybe(t, tuiNetEnvLocal, true)()
	sum := func(path string) string {
		out, err := ssh(t, 30*time.Second, "pi", "sudo -n md5sum "+path+" 2>/dev/null || echo absent")
		if err != nil {
			t.Fatalf("md5sum %s: %v\n%s", path, err, out)
		}
		return strings.Fields(strings.TrimSpace(out))[0]
	}
	house, net := sum(tuiHouseEnv), sum(tuiNetEnvLocal)
	// Extra ports is a row for which Enter shows a prompt. The rows above
	// it change on Enter, and would write the file.
	ports := slices.IndexFunc(tuiHouseSettings, func(s struct{ key, label string }) bool { return s.key == "HOUSE_ALLOW_PORTS" })
	open := box.open(t, "house", "Settings")
	keys := tuiKeys(open, tuiRepeat(ports, kDown), kEnter, kEsc, "q")
	sysAt := len(keys) + 2
	keys = tuiKeys(keys, box.open(t, "system", "Settings"), "q", "q")
	// 52 rows: four groups, twenty rows and the help lines under them.
	// 120 columns, so the whole explanation shows; the [KEY] leads it and
	// survives any width.
	s := tuiDrive(t, tuiRun{keys: keys, rows: 52, cols: 120})
	s.steady(t, keys)
	n := len(open)
	f := s.frame(t, n)
	f.must(t, "house Settings", box.title("house", "Settings"), tuiHouseEnv)
	f.must(t, "house groups", tuiHouseGroups...)
	for _, r := range tuiHouseSettings {
		f.must(t, "house rows", r.label)
	}
	// The line under the list explains the selected row and names its key.
	f.must(t, "help line", "["+tuiHouseSettings[0].key+"]")
	s.frame(t, n+ports).must(t, "help follows the cursor", "[HOUSE_ALLOW_PORTS]")
	s.frame(t, n+ports+1).must(t, "Enter opens the editor", "HOUSE_ALLOW_PORTS (- clears): ")
	s.frame(t, n+ports+2).must(t, "Esc cancels it", "cancelled")
	sys := s.frame(t, sysAt)
	sys.must(t, "System Settings", append([]string{box.title("system", "Settings"), tuiNetEnvLocal}, tuiNetSettings...)...)
	if after := sum(tuiHouseEnv); after != house {
		t.Fatalf("%s changed under a cancelled edit: %s -> %s", tuiHouseEnv, house, after)
	}
	if after := sum(tuiNetEnvLocal); after != net {
		t.Fatalf("%s changed with nothing edited: %s -> %s", tuiNetEnvLocal, net, after)
	}
}

// --- checklist :254 Actions ---

func tuiActionTests(t *testing.T) {
	// The action under test acts on the house segment. Without one, the
	// TUI labels it "house segment not configured" and runs nothing.
	houseIF := strings.TrimSpace(pi(t, "grep -hE '^HOUSE_IF=' /etc/pi-fortress/house.env 2>/dev/null | cut -d= -f2- | tr -d \"\\\"' \" || true"))
	if houseIF == "" {
		t.Skip("no HOUSE_IF on this box: reload house dns needs a house segment; the cloud lab has one, a real Pi needs the house adapter in")
	}
	box := tuiBoxOf(t)
	audited := func() int { return grepCount(t, tuiAuditLog, "dns.reload") }
	before := audited()
	// Only `reload house dns`, action five. apply and apply --local take
	// the apply lock for up to five minutes, and restart the fence under
	// any other work of the suite. Thus they stay a job for the operator.
	open := box.open(t, "system", "Actions")
	keys := tuiKeys(open, tuiRepeat(4, kDown), kEnter, "q", "q")
	s := tuiDrive(t, tuiRun{keys: keys, wait: 20 * time.Second})
	s.steady(t, keys)
	n := len(open)
	s.frame(t, n).must(t, "Actions", "apply --local", "fetch feeds", "restart house dns", "reload house dns", "reboot", "shutdown")
	if got := s.frame(t, n+4).selected(); !strings.HasPrefix(got, "reload house dns") {
		t.Fatalf("the cursor is on %q, not on reload house dns", got)
	}
	s.frame(t, n+5).must(t, "Enter runs it", "reloaded ")
	if after := audited(); after <= before {
		t.Fatalf("%s gained no dns.reload row: %d before, %d after", tuiAuditLog, before, after)
	}
}

// --- checklist :256 Client detail ---

func tuiClientDetailTests(t *testing.T) {
	box := tuiBoxOf(t)
	keys := tuiKeys(box.open(t, "house", "Devices"), kEnter, kEsc, kEsc, "q")
	// Tall on purpose: a real device fills top names to its cap of 20.
	// That puts the events heading below a 24-row screen. A quiet lab
	// never gets there. A phone on the house network does in minutes.
	// 120 columns: the device table is wider than 80 cells minus the
	// menu. "lease" tells the table apart from the detail below.
	s := tuiDrive(t, tuiRun{keys: keys, rows: 60, cols: 120})
	opened := s.first(t, box.title("house", "Devices"))
	if opened.has("no leases or reservations") {
		// An assertion about a detail that was never opened would pass on
		// an empty screen. Thus the item has no coverage, and the skip
		// says so.
		t.Skip("no house device on this box, so no detail can be opened")
	}
	for _, f := range s.frames {
		if f.has("nothing recorded for") {
			t.Skip("the first house device has no observe counts yet, so its detail cannot be opened")
		}
	}
	// The detail and the table have the same title. Thus the headings of
	// the detail tell them apart, not a frame number: Devices repaints on
	// its own ticker.
	var detail, back tuiFrame
	for _, f := range s.frames {
		switch {
		case f.has("top names", "top dests"):
			detail = f
		case detail.h != 0 && f.has("pin", "queries", "lease"):
			back = f
		}
		if back.h != 0 {
			break
		}
	}
	if detail.h == 0 {
		t.Fatalf("Enter on a device row opened no detail:\n%s", s.frame(t, -1).text())
	}
	detail.must(t, "device detail", "top names", "top dests", "events")
	if back.h == 0 {
		t.Fatalf("Esc did not come back to the device table:\n%s", s.frame(t, -1).text())
	}
	if got := back.selected(); got == "" {
		t.Fatalf("Esc came back with no row under the cursor:\n%s", back.text())
	}
}

// --- checklist :258 Events chart ---

// tuiBarRows are the chart rows of an Activity frame, in order.
func tuiBarRows(f tuiFrame) []string {
	var out []string
	for _, l := range f.lines {
		if strings.Contains(l, "blocked 7d") || strings.Contains(l, "  queries  ") || strings.Contains(l, "  flows  ") {
			out = append(out, strings.TrimRight(l, " "))
		}
	}
	return out
}

func tuiChartTests(t *testing.T) {
	box := tuiBoxOf(t)
	keys := tuiKeys(box.open(t, "house", "Activity"), kEsc, "q")
	// 100 columns: at 80 the table header is three cells wider than the
	// content column and "destination" loses its tail.
	s := tuiDrive(t, tuiRun{keys: keys, cols: 100})
	f := s.first(t, box.title("house", "Activity"))
	f.must(t, "Activity header", "[Blocked]", "time", "threat", "source", "destination")
	bars := tuiBarRows(f)
	switch {
	case len(bars) == 0:
		// The checklist gives this view two shapes. The empty shape is a
		// claim of its own, so it is checked, not skipped.
		f.must(t, "empty Activity", tuiNoStats)
		t.Log("no series on this box, so the bar rows are not covered here; the no-data line is")
	case len(bars) != 3:
		// The week of one network: its own three rows, not those of all segments.
		t.Fatalf("%d chart rows, wanted the home network's three:\n%s", len(bars), strings.Join(bars, "\n"))
	default:
		if !strings.Contains(bars[0], "house") || !strings.Contains(bars[0], "blocked 7d") || !strings.Contains(bars[0], "max ") {
			t.Errorf("chart row has no `house  blocked 7d ... max N`: %q", bars[0])
		}
		if !strings.Contains(bars[1], "queries") || !strings.Contains(bars[2], "flows") {
			t.Errorf("the chart is missing its queries or flows row: %q / %q", bars[1], bars[2])
		}
	}
}

// --- checklist :262 UTF-8 bars and :263 plain bars ---

func tuiBarTests(t *testing.T) {
	box := tuiBoxOf(t)
	check := func(t *testing.T, env, want, notWant string) {
		keys := tuiKeys(box.open(t, "house", "Activity"), kEsc, "q")
		s := tuiDrive(t, tuiRun{keys: keys, env: env})
		bars := tuiBarRows(s.first(t, box.title("house", "Activity")))
		if len(bars) == 0 {
			t.Skip("no series on this box: with no bars drawn there is nothing to tell the two glyph sets apart")
		}
		for i := 0; i < len(bars); i += 3 {
			// Only the cells to the right of the label: the menu column and
			// the words of the row have characters from both sets. The bars
			// must follow the locale.
			_, cells, ok := strings.Cut(bars[i], "blocked 7d")
			if !ok {
				t.Fatalf("%q is not a blocked 7d row", bars[i])
			}
			if !strings.ContainsAny(cells, want) {
				t.Errorf("%s: no %s glyph in the bars of %q", env, want, bars[i])
			}
			if strings.ContainsAny(cells, notWant) {
				t.Errorf("%s: a %s glyph in the bars of %q", env, notWant, bars[i])
			}
		}
	}
	t.Run("a UTF-8 locale draws block glyphs", func(t *testing.T) {
		check(t, "LANG=C.UTF-8", tuiBarGlyphs, tuiBarASCII)
	})
	t.Run("the C locale draws ASCII bars", func(t *testing.T) {
		check(t, "LANG=C LC_ALL=C", tuiBarASCII, tuiBarGlyphs)
	})
}

// --- checklist :264 Small terminal ---

func tuiSmallTests(t *testing.T) {
	box := tuiBoxOf(t)
	// The densest views: the chart of the home network, a device table,
	// Overview, and the house Settings with its help lines under the list.
	// The house opens again on Activity, so one l from there is Settings.
	keys := tuiKeys(box.open(t, "house", "Activity"), kEsc, "2", kEsc, "1", kEsc, "3", "l", kEsc, "q")
	s := tuiDrive(t, tuiRun{keys: keys, rows: 24, cols: 80})
	// Each paint is read as a rectangle. Thus a row that went past 80
	// cells and wrapped shows here as the wrong width, not as a missing
	// chart row that nobody sees.
	for i, f := range s.frames {
		if f.bad != "" {
			t.Fatalf("frame %d wrapped on a 24x80 terminal: %s", i, f.bad)
		}
		if f.w != 80 || f.h != 24 {
			t.Fatalf("frame %d is %dx%d, the terminal is 80x24:\n%s", i, f.w, f.h, f.text())
		}
	}
	s.first(t, box.title("house", "Settings"), "Filtering", "Apps & ports")
	if bars := tuiBarRows(s.first(t, box.title("house", "Activity"))); len(bars) == 0 {
		t.Log("no series on this box, so `Activity keeps every chart row` is not covered here; the no-wrap half is")
	} else if len(bars) != 3 {
		t.Fatalf("a 24-row terminal dropped a chart row: %d of them\n%s", len(bars), strings.Join(bars, "\n"))
	}
}

// --- checklist :265 Resize ---

func tuiResizeTests(t *testing.T) {
	box := tuiBoxOf(t)
	// Nothing local can resize this pty: ssh forwards a window change only
	// from its own terminal, and the test has none. Thus the Pi resizes it
	// from the inside. That is the same SIGWINCH that the app would get
	// from a dragged window.
	pre := "T=$(tty); (sleep 6; stty -F \"$T\" rows 40 cols 120) & "
	keys := box.open(t, "house", "Activity")
	s := tuiDrive(t, tuiRun{keys: keys, pre: pre, flags: "-idle 12s", wait: 20 * time.Second})
	var small, big *tuiFrame
	for i := range s.frames {
		f := s.frames[i]
		if f.bad != "" {
			t.Fatalf("frame %d did not repaint cleanly: %s", i, f.bad)
		}
		if f.w == 80 && f.h == 24 && small == nil {
			small = &s.frames[i]
		}
		if f.w == 120 && f.h == 40 {
			big = &s.frames[i]
		}
	}
	if small == nil {
		t.Fatalf("nothing was painted at the starting 80x24 size (%d frames)", len(s.frames))
	}
	if big == nil {
		t.Fatalf("the resize to 120x40 was never painted; the last frame is %dx%d:\n%s",
			s.frame(t, -1).w, s.frame(t, -1).h, s.frame(t, -1).text())
	}
	big.must(t, "after the resize", box.title("house", "Activity"))
	if got := strings.TrimRight(big.footer(), " "); got == "" {
		t.Fatal("the repainted screen has no footer")
	}
}

// --- checklist :266 Quit ---

func tuiQuitTests(t *testing.T) {
	// Cooked mode on purpose: the purpose of the item is that the tty that
	// an operator logged in with comes back as it was, with echo and all.
	// Thus the run must start from that mode, not from a mode that this
	// test changed first.
	check := func(t *testing.T, key string) {
		s := tuiDrive(t, tuiRun{keys: []string{key}, cooked: true})
		if s.before == "" || s.after == "" {
			t.Fatalf("no termios readings around the run:\n%s", tuiStrip(s.out))
		}
		if s.before != s.after {
			t.Fatalf("the tty was not put back:\nbefore %s\nafter  %s", s.before, s.after)
		}
		for _, flag := range []string{" echo ", " icanon ", " isig "} {
			if !strings.Contains(s.stty, flag) {
				t.Fatalf("the tty is missing%safter the quit: %s", flag, s.stty)
			}
		}
		// The alternate screen must be left. After the escape that leaves
		// it, nothing may be written except the marker that this harness
		// itself prints.
		i := strings.LastIndex(s.out, tuiAltLeave)
		if i < 0 {
			t.Fatalf("the app never left the alternate screen:\n%s", tuiStrip(s.out))
		}
		rest := strings.TrimSpace(strings.ReplaceAll(s.out[i+len(tuiAltLeave):], "\r", ""))
		if !strings.HasPrefix(rest, tuiMark+" ") {
			t.Fatalf("stray output after the terminal was restored: %q", rest)
		}
	}
	t.Run("q from the menu", func(t *testing.T) { check(t, "q") })
	t.Run("Ctrl-C", func(t *testing.T) { check(t, kCtrlC) })
}

// --- checklist :267 Idle exit ---

func tuiIdleTests(t *testing.T) {
	// Five seconds, not the minute that the checklist types manually: it
	// is the same timer. A suite that waits a minute for each item stops
	// being run.
	const idle = 5 * time.Second
	s := tuiDrive(t, tuiRun{flags: "-idle " + idle.String(), wait: 30 * time.Second})
	if s.took < idle {
		t.Fatalf("pf tui -idle %s exited after %s, before the timer could fire", idle, s.took)
	}
	if s.took > idle+45*time.Second {
		t.Fatalf("pf tui -idle %s took %s to exit", idle, s.took)
	}
	if s.before != s.after {
		t.Fatalf("the idle exit left the tty changed:\nbefore %s\nafter  %s", s.before, s.after)
	}
	if !strings.Contains(s.out, tuiAltLeave) {
		t.Fatal("the idle exit did not leave the alternate screen")
	}
}
