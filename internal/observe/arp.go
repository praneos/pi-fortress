package observe

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// The threats that an address claim is reported under. arpSelf is a
// neighbour that answers for the address that the Pi believes is its own
// on that segment. arpLease is a leased or reserved address answered by a
// MAC that the lease was never given to -- this includes the static
// management address of the AP. arpFlip is one address answered by two
// different MACs over time.
const (
	arpSelf  = "arp_self"
	arpLease = "arp_lease"
	arpFlip  = "arp_flip"
)

const (
	// arpQuiet limits a changing address to one alert per window. A device
	// that flaps between two MACs every few seconds -- a badly bridged VM,
	// or an attacker who wants the evidence buried -- would otherwise fill
	// the 1000-row ring by itself within the hour, and push all other
	// alerts out of it. The window counts what it swallows, and does not
	// lose it: the next alert says how many claims it stands for.
	arpQuiet = 15 * time.Minute
	// arpRepeat states again a claim that stays in place without a change. A
	// hostile binding does not have to change to keep working. With one alert
	// per binding, a claim that held for a fortnight would age out of the
	// ring, and the ledger would say that nothing was wrong.
	arpRepeat = 6 * time.Hour
	// maxARP limits the binding table, as maxClients limits clients. Its
	// keys are addresses that a neighbour chooses with one packet. Thus
	// without a limit, a neighbour decides how big the state file gets.
	maxARP = 1024
)

// ARPRec is the MAC that last answered for one address. The state file
// keeps it, so a claim across a restart is still recognised as a change,
// not as a first sighting -- a reboot is exactly when an attacker wants
// the ledger to forget.
type ARPRec struct {
	MAC       string    `json:"mac"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Alerted stamps the last alert raised for this address. Claims counts
	// what arpQuiet swallowed since then.
	Alerted time.Time `json:"alerted,omitzero"`
	Claims  uint32    `json:"claims,omitempty"`
}

// arpTable is the kernel cache of who answered for which address,
// ip → mac. An unreadable file is an empty table: a box with no
// /proc/net/arp has nothing to say here, and that is no reason to stop
// the remainder of the pass.
//
// The proc file is the fast path, and the command is the path that
// actually runs on the Pi. observe.service sets ProcSubset=pid. This hides
// all of /proc that is not a pid directory, also /proc/net. Thus the
// daemon gets ENOENT when it reads its own ARP cache, while a shell on the
// same box reads six entries. This is the same shape as the conntrack
// fallback above it: the file is absent for a reason that is not related
// to an absence of data.
func (o *Observer) arpTable() map[string]string {
	raw, err := os.ReadFile(o.ARPPath)
	if err == nil {
		return parseARP(string(raw))
	}
	if !os.IsNotExist(err) || len(o.ARPCmd) == 0 {
		return map[string]string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.ARPCmd[0], o.ARPCmd[1:]...)
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return map[string]string{}
	}
	return parseNeigh(string(out))
}

// parseNeigh reads `ip -4 neigh show` into ip → mac. A neighbour with no
// lladdr is one that the kernel asked about and got no answer from --
// FAILED or INCOMPLETE. This is the netlink form of the flags 0x0 rows
// that parseARP drops.
func parseNeigh(text string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		for i := 1; i < len(f)-1; i++ {
			if f[i] == "lladdr" {
				if mac := strings.ToLower(f[i+1]); mac != "00:00:00:00:00:00" {
					out[f[0]] = mac
				}
				break
			}
		}
	}
	return out
}

// watchARP compares the ARP cache of the kernel with what answered for
// each address in the last pass. It raises an alert when the answer
// changed, when a neighbour answers for the address of the Pi itself, or
// when the MAC that holds a leased address is not the MAC that the lease
// was given to. ARP and DHCP are cooperative: the last writer on the wire
// wins, and nothing on the Pi refuses it. Thus this makes the betrayal
// visible, and does not pretend to prevent it.
//
// Scope: the table is a cache of what the Pi itself resolved. Thus a claim
// aimed at a different client never gets to this table, and a claim that
// lands and is withdrawn between two passes leaves nothing in it. Seeing
// those needs a listener on the wire. This is a tripwire on the view of
// the Pi itself, not coverage of the segment.
//
// arpSelf is the narrowest of the three, for the same reason: the kernel
// caches no entry for an address that the box holds itself. Thus on a
// healthy Pi, its own address never shows here, and this check never
// fires. It fires when the Pi does not actually hold the address that it
// was configured with -- an interface that never came up, or an address
// removed from it -- and a neighbour answers in its place. That is a
// different failure from the one that the name suggests, and it is worth
// a report in both cases.
func (o *Observer) watchARP(st *State) {
	arp := o.arpTable()
	if len(arp) == 0 {
		return
	}
	if st.ARP == nil {
		st.ARP = map[string]*ARPRec{}
	}
	segs := o.segments()
	_, leased := o.leaseNames()
	now := o.now().UTC()
	// Sorted, so a pass that raises several alerts puts them in the ring
	// in the same order each time, whatever order the map gives.
	ips := make([]string, 0, len(arp))
	for ip := range arp {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		mac := arp[ip]
		s, ok := segmentOf(segs, ip)
		if !ok {
			// An address on none of the segments of this box: the upstream
			// gateway, a WAN neighbour. Nobody here owns it, so nothing
			// here can say who must answer for it.
			continue
		}
		key := s.Name + "/" + ip
		rec, known := st.ARP[key]
		if !known {
			rec = &ARPRec{MAC: mac, FirstSeen: now}
			st.ARP[key] = rec
		}
		was, since := rec.MAC, rec.LastSeen
		changed := !known || was != mac
		rec.LastSeen = now
		if changed {
			rec.MAC, rec.FirstSeen = mac, now
		}
		threat, detail := verdict(s, ip, mac, was, leased[ip], since, now)
		if threat == "" {
			continue
		}
		// A binding that just changed gets a strong hold-down, because an
		// attacker can make that one repeat at will. A claim that only
		// stays in place states itself again much more slowly.
		window := arpRepeat
		if changed {
			window = arpQuiet
		}
		if !rec.Alerted.IsZero() && now.Sub(rec.Alerted) < window {
			if changed {
				rec.Claims++
			}
			continue
		}
		if rec.Claims > 0 {
			detail = fmt.Sprintf("%s (+%d more)", detail, rec.Claims)
		}
		rec.Alerted, rec.Claims = now, 0
		o.alert(st, Event{T: now, Segment: s.Name, Src: ip, Dst: mac, Threat: threat, Detail: detail})
	}
	pruneARP(st)
}

// verdict names the loudest true fact about ip answered by mac, or ""
// when there is nothing to report. The order is important: an address
// that is both the address of the Pi and leased to somebody is reported
// as the address of the Pi, because the operator must act on that claim
// first. was is the MAC that answered before, empty on a first sighting.
// Thus an address that nobody has a prior claim on raises nothing.
func verdict(s Seg, ip, mac, was, lease string, since, now time.Time) (threat, detail string) {
	switch {
	case ip == s.IP:
		return arpSelf, "answers for the Pi's own address on " + s.Name
	case lease != "" && lease != mac:
		return arpLease, "address is leased to " + lease
	case was != "" && was != mac:
		return arpFlip, "was " + was + " " + ago(since, now) + " earlier"
	}
	return "", ""
}

// ago gives how long before now the displaced MAC last answered, rounded
// to what an operator reads at a glance, not to the nanosecond at which
// the cache sample occurred.
func ago(since, now time.Time) string {
	if since.IsZero() || since.After(now) {
		return "some time"
	}
	return now.Sub(since).Round(time.Second).String()
}

// pruneARP keeps the binding table at maxARP by least recently answered.
func pruneARP(st *State) {
	prune(st.ARP, maxARP, func(r *ARPRec) string { return r.LastSeen.UTC().Format(time.RFC3339) })
}
