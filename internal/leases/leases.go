// Package leases is the address book of the house segment: the lease file
// of dnsmasq and the house.hosts reservations of the operator.
// internal/admin shows them. internal/observe uses them to name clients.
// admin already imports observe. Thus the parsers are below both.
package leases

import (
	"strconv"
	"strings"
	"time"
)

type Lease struct {
	Expiry   time.Time
	MAC      string
	IP       string
	Hostname string
	ClientID string
}

// Expired tells if the lease expired. dnsmasq writes 0 in the expiry
// column for a lease that it holds with no time limit. That is not an
// expiry at the start of 1970. If the code read it as one, it would drop
// exactly the entries that name the permanent devices of the house.
func (l Lease) Expired(now time.Time) bool {
	return l.Expiry.Unix() > 0 && l.Expiry.Before(now)
}

type Reservation struct{ MAC, IP, Name string }

// ParseLeases reads the lease file of dnsmasq: "expiry mac ip hostname client-id".
func ParseLeases(text string) []Lease {
	var out []Lease
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		secs, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		l := Lease{Expiry: time.Unix(secs, 0), MAC: strings.ToLower(f[1]), IP: f[2], Hostname: f[3]}
		if len(f) > 4 {
			l.ClientID = f[4]
		}
		if l.Hostname == "*" {
			l.Hostname = ""
		}
		out = append(out, l)
	}
	return out
}

// ParseReservations reads house.hosts lines "mac,ip,name". It skips
// comments and malformed lines. They are not errors, because dnsmasq also
// skips them.
func ParseReservations(lines []string) []Reservation {
	var out []Reservation
	for _, line := range lines {
		if r, ok := ParseReservation(line); ok {
			out = append(out, r)
		}
	}
	return out
}

func ParseReservation(line string) (Reservation, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Reservation{}, false
	}
	f := strings.Split(line, ",")
	if len(f) < 2 {
		return Reservation{}, false
	}
	r := Reservation{MAC: strings.ToLower(strings.TrimSpace(f[0])), IP: strings.TrimSpace(f[1])}
	if len(f) > 2 {
		r.Name = strings.TrimSpace(f[2])
	}
	return r, true
}
