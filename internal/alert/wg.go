package alert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultWGLast = "/var/lib/pi-fortress/wg.last"

type WGStatus struct {
	Handshake time.Time
	Endpoint  string
	Never     bool
}

func ClassifyWG(st WGStatus, now time.Time, max time.Duration) string {
	if max <= 0 {
		max = 3 * time.Minute
	}
	if st.Never || st.Handshake.IsZero() || now.Sub(st.Handshake) > max {
		return "down"
	}
	return "up"
}

func ParseWGLast(raw string) (state string, since time.Time) {
	f := strings.Fields(strings.TrimSpace(raw))
	if len(f) == 0 {
		return "", time.Time{}
	}
	state = f[0]
	if len(f) > 1 {
		if sec, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			since = time.Unix(sec, 0)
		}
	}
	return state, since
}

func FormatWGLast(state string, at time.Time) string {
	if state == "down" && !at.IsZero() {
		return fmt.Sprintf("down %d\n", at.Unix())
	}
	return state + "\n"
}

func WGMessage(ifname, next, endpoint string, age time.Duration, never bool, downFor time.Duration) string {
	if next == "down" {
		if never || age <= 0 {
			return fmt.Sprintf("WG %s no handshake ever (endpoint %s)", ifname, endpoint)
		}
		return fmt.Sprintf("WG %s no handshake for %s (endpoint %s)", ifname, age.Truncate(time.Second), endpoint)
	}
	if downFor > 0 {
		return fmt.Sprintf("WG %s handshake back after %s", ifname, downFor.Truncate(time.Second))
	}
	return fmt.Sprintf("WG %s handshake back", ifname)
}

// WGTransition compares the last recorded state with the live handshake.
// With no last file: the first down fires, the first up is silent (healthy boot).
func WGTransition(ifname, lastRaw string, st WGStatus, now time.Time, max time.Duration) (next, msg string, write string) {
	if ifname == "" {
		ifname = "wg0"
	}
	prev, since := ParseWGLast(lastRaw)
	next = ClassifyWG(st, now, max)
	if prev == next {
		return next, "", ""
	}
	if prev == "" && next == "up" {
		return next, "", FormatWGLast(next, time.Time{})
	}
	age := time.Duration(0)
	if !st.Handshake.IsZero() {
		age = now.Sub(st.Handshake)
	}
	downFor := time.Duration(0)
	if next == "up" && !since.IsZero() {
		downFor = now.Sub(since)
	}
	at := now
	if next == "up" {
		at = time.Time{}
	}
	return next, WGMessage(ifname, next, st.Endpoint, age, st.Never || st.Handshake.IsZero(), downFor), FormatWGLast(next, at)
}

// ParseWGShow reads `wg show <if> latest-handshakes` and `... endpoints`
// per peer, by public key. The tunnel is up if the handshake of any peer is
// recent. So the newest handshake across peers is the one that counts, and
// the endpoint named is the endpoint of that peer. With no handshake
// anywhere, it is the endpoint of the first peer that has one.
func ParseWGShow(latest, endpoints string) WGStatus {
	eps := map[string]string{}
	var firstEP string
	for line := range strings.SplitSeq(endpoints, "\n") {
		f := strings.Fields(line)
		key, ep := "", ""
		switch {
		case len(f) >= 2 && strings.Contains(f[len(f)-1], ":"):
			key, ep = f[0], f[len(f)-1]
		case len(f) == 1 && strings.Contains(f[0], ":") && !strings.Contains(f[0], "/"):
			ep = f[0]
		default:
			continue
		}
		if _, seen := eps[key]; !seen {
			eps[key] = ep
		}
		if firstEP == "" {
			firstEP = ep
		}
	}
	st := WGStatus{Never: true, Endpoint: firstEP}
	var best int64
	for line := range strings.SplitSeq(latest, "\n") {
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		sec, err := strconv.ParseInt(f[len(f)-1], 10, 64)
		if err != nil || sec <= best {
			continue
		}
		key := ""
		if len(f) >= 2 {
			key = f[0]
		}
		best = sec
		st.Never = false
		st.Handshake = time.Unix(sec, 0)
		if ep, ok := eps[key]; ok {
			st.Endpoint = ep
		}
	}
	return st
}

func readWG(ifname string) (WGStatus, error) {
	latest, err := exec.Command("wg", "show", ifname, "latest-handshakes").Output()
	if err != nil {
		return WGStatus{Never: true}, err
	}
	ep, _ := exec.Command("wg", "show", ifname, "endpoints").Output()
	return ParseWGShow(string(latest), string(ep)), nil
}

func (a *Alerter) WGOnce(ifname string, max time.Duration) int {
	if ifname == "" {
		ifname = "wg0"
	}
	if max <= 0 {
		max = 3 * time.Minute
	}
	path := DefaultWGLast
	if a != nil && a.LastPath != "" && strings.HasSuffix(a.LastPath, "wg.last") {
		path = a.LastPath
	} else if a != nil && a.LastPath != "" {
		path = filepath.Join(filepath.Dir(a.LastPath), "wg.last")
	}
	st, err := readWG(ifname)
	if err != nil {
		st = WGStatus{Never: true}
	}
	raw, _ := os.ReadFile(path)
	now := time.Now()
	if a != nil && a.Now != nil {
		now = a.Now()
	}
	_, msg, write := WGTransition(ifname, string(raw), st, now, max)
	// The state file is the only record that the transition was
	// announced, so the code writes it after the announcement, not before.
	// When the code recorded the new state first, a webhook that was down for
	// the one run that saw the change made "the tunnel went down" into a thing
	// that no later run would ever report.
	if msg != "" {
		fmt.Fprintln(a.out(), msg)
		if err := a.PostMessage(LoadURL(a.PolicyDirs), msg); err != nil {
			fmt.Fprintf(a.errw(), "alert wg: %s not announced; leaving the state to be retried\n", ifname)
			return 1
		}
	}
	if write != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err == nil {
			_ = os.WriteFile(path, []byte(write), 0644)
		}
	}
	return 0
}
