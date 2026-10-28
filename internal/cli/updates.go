package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/alert"
	"pi-fortress/internal/doctor"
)

// DefaultUpdatesLast is the state of pf alert updates. update-check.service
// can write it and no other path.
const DefaultUpdatesLast = "/var/lib/pi-fortress/updates.last"

// updatesRemind is the time after which the same pending things are told
// again.
const updatesRemind = 7 * 24 * time.Hour

// updState is the content of updates.last: the time at which each pending
// thing was first seen, and the keys and time of the last post.
type updState struct {
	first  map[string]int64
	posted []string
	at     int64
}

// The file has one "posted <unix> <key>..." line and one
// "seen <key> <unix>" line for each pending thing. Keys have no spaces.
func parseUpdState(raw string) updState {
	st := updState{first: map[string]int64{}}
	for l := range strings.SplitSeq(raw, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && f[0] == "posted":
			if at, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				st.at, st.posted = at, f[2:]
			}
		case len(f) == 3 && f[0] == "seen":
			if at, err := strconv.ParseInt(f[2], 10, 64); err == nil {
				st.first[f[1]] = at
			}
		}
	}
	return st
}

func (st updState) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "posted %d", st.at)
	for _, k := range st.posted {
		b.WriteString(" " + k)
	}
	b.WriteString("\n")
	keys := make([]string, 0, len(st.first))
	for k := range st.first {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "seen %s %d\n", k, st.first[k])
	}
	return b.String()
}

// decideUpdates gives the message to post, if any, and the state to keep.
// A thing is due when it stayed for its Wait. The check posts when the
// set of due things changes (also when it becomes empty, so that the
// operator sees that a reboot cleared it), and again after updatesRemind
// while the set stays. posted is the state after a good post; kept is the
// state after no post or a failed post. kept still records the first-seen
// times, so that the Wait of a pending package goes on.
func decideUpdates(items []doctor.Update, prev updState, now time.Time) (msg string, posted, kept updState) {
	first := map[string]int64{}
	var due []doctor.Update
	for _, it := range items {
		t, ok := prev.first[it.Key]
		if !ok {
			t = now.Unix()
		}
		first[it.Key] = t
		if now.Sub(time.Unix(t, 0)) >= it.Wait {
			due = append(due, it)
		}
	}
	keys := make([]string, len(due))
	for i, it := range due {
		keys[i] = it.Key
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	kept = updState{first: first, posted: prev.posted, at: prev.at}
	posted = updState{first: first, posted: keys, at: now.Unix()}
	switch {
	case !slices.Equal(keys, prev.posted):
		if len(keys) == 0 {
			return "UPDATES: nothing waits now; the installed updates are active", posted, kept
		}
		return "UPDATES: " + updatesText(due), posted, kept
	case len(keys) > 0 && now.Sub(time.Unix(prev.at, 0)) >= updatesRemind:
		return "UPDATES (still waiting): " + updatesText(due), posted, kept
	}
	return "", kept, kept
}

// updatesText puts the due things on one line. The packages go into one
// part, with the first five names.
func updatesText(due []doctor.Update) string {
	var parts, pkgs []string
	for _, it := range due {
		if strings.HasPrefix(it.Key, "pkg:") {
			pkgs = append(pkgs, it.Text)
			continue
		}
		parts = append(parts, it.Text)
	}
	if len(pkgs) > 0 {
		slices.Sort(pkgs)
		s := fmt.Sprintf("%d automatic updates are not installed after %dh", len(pkgs), int(doctor.PackageWait.Hours()))
		if len(pkgs) > 5 {
			s += ": " + strings.Join(pkgs[:5], ", ") + fmt.Sprintf(" and %d more", len(pkgs)-5)
		} else {
			s += ": " + strings.Join(pkgs, ", ")
		}
		parts = append(parts, s+" (see /var/log/unattended-upgrades)")
	}
	return strings.Join(parts, "; ")
}

// aptSimulate runs apt-get in simulate mode, with no lock. It changes
// nothing. An error gives no package check for this run.
func aptSimulate() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "dist-upgrade")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.Output()
	return string(out), err
}

// alertUpdates is "pf alert updates": it posts the updates that wait for
// the operator (a reboot, a bootloader image, a package that
// unattended-upgrades did not install, a new major release).
func alertUpdates(a *alert.Alerter, path string, stdout, stderr io.Writer) int {
	p := doctor.DefaultUpdatePaths()
	items := doctor.RebootUpdates(p.Reboot)
	items = append(items, doctor.BootloaderUpdates(p)...)
	items = append(items, doctor.ReleaseUpdates(p)...)
	if sim, err := aptSimulate(); err != nil {
		fmt.Fprintf(stderr, "alert updates: apt-get -s: %v; no package check in this run\n", err)
	} else {
		items = append(items, doctor.PackageUpdates(sim)...)
	}
	raw, _ := os.ReadFile(path)
	msg, posted, kept := decideUpdates(items, parseUpdState(string(raw)), time.Now())
	next := kept
	if msg != "" {
		fmt.Fprintln(stdout, msg)
		// As in pf alert wg: the state records a post only after the post.
		if err := a.PostMessage(alert.LoadURL(a.PolicyDirs), msg); err != nil {
			fmt.Fprintln(stderr, "alert updates: not posted; the next run tries again")
		} else {
			next = posted
		}
	}
	if err := os.WriteFile(path, []byte(next.String()), 0644); err != nil {
		fmt.Fprintf(stderr, "alert updates: %v\n", err)
		return 1
	}
	return 0
}
