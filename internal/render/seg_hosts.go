package render

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SegHost is one fixed lease on a DHCP=on segment: a line of its
// dhcp.<name>.hosts. apply writes it into the dnsmasq conf of that
// segment as dhcp-host=MAC,IP[,name].
type SegHost struct {
	MAC, IP, Name string
	line          int
}

func (h SegHost) String() string {
	if h.Name == "" {
		return h.MAC + "," + h.IP
	}
	return h.MAC + "," + h.IP + "," + h.Name
}

// SegmentHostsPath is the reservations file of a plain segment, the
// house.hosts of the house for each segment: dhcp.<name>.hosts next to
// segments.d, so /etc/pi-fortress/dhcp.iot.hosts on the box. It is next to
// segments.d for the same reason as SegmentAllowPath. It has a prefix, and
// is not <name>.hosts, because a segment can have the name core or
// dns-agent-go, and apply already writes .hosts files for those names.
func SegmentHostsPath(segmentsDir, name string) string {
	return filepath.Join(SegmentsParent(segmentsDir), "dhcp."+name+".hosts")
}

// reHostName is the hostnameRE of internal/admin, which the reservations
// of the house must match.
var reHostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// loadSegHosts reads the reservations of a segment, in the house.hosts
// form. The code reads the file of the house leniently, because dnsmasq
// skips a bad line there. These lines become dhcp-host options in a conf.
// A bad line there fails dnsmasq --test after the ruleset is loaded. Thus
// loadSegHosts refuses each bad line here. An absent file means no
// reservations. A file that is there but not readable does not mean that.
// If it did, the render would remove all fixed leases on the segment.
func loadSegHosts(s *Segment, dir string) error {
	path := SegmentHostsPath(dir, s.Name)
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("segment %s: %s cannot be read (%v). Nothing was changed.", s.Name, path, err)
	}
	s.HostsPath = path
	byMAC, byIP := map[string]SegHost{}, map[string]SegHost{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 2 || len(f) > 3 {
			return fmt.Errorf("%s:%d: '%s' is not MAC,IP or MAC,IP,name. Nothing was changed.", path, n, line)
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		hw, err := net.ParseMAC(f[0])
		if err != nil || len(hw) != 6 {
			return fmt.Errorf("%s:%d: '%s' is not a MAC address such as 02:00:00:00:00:01. Nothing was changed.", path, n, f[0])
		}
		if !reIPv4.MatchString(f[1]) {
			return fmt.Errorf("%s:%d: '%s' is not an IPv4 address. Nothing was changed.", path, n, f[1])
		}
		h := SegHost{MAC: hw.String(), IP: f[1], line: n}
		if len(f) == 3 {
			if !reHostName.MatchString(f[2]) {
				return fmt.Errorf("%s:%d: '%s' is not a host name (letters, digits and inner dashes, at most 63). Nothing was changed.", path, n, f[2])
			}
			h.Name = f[2]
		}
		if o, ok := byMAC[h.MAC]; ok {
			return fmt.Errorf("%s:%d: %s is already reserved on line %d; one address per device. Nothing was changed.", path, n, h.MAC, o.line)
		}
		if o, ok := byIP[h.IP]; ok {
			return fmt.Errorf("%s:%d: %s is already reserved for %s on line %d. Nothing was changed.", path, n, h.IP, o.MAC, o.line)
		}
		byMAC[h.MAC], byIP[h.IP] = h, h
		s.Hosts = append(s.Hosts, h)
	}
	return nil
}

// checkSegHosts is the rule of the house for a reservation (internal/admin
// reservable) on a segment: a host address of NET that is not the address
// of the Pi. Inside or outside the dynamic range are both allowed, as on
// the house. Reservations with DHCP off are refused. Nothing would give
// them out, and the house has no DHCP-off case to copy. Thus, in case of
// doubt, the result is a refusal.
func checkSegHosts(s Segment) error {
	if len(s.Hosts) == 0 {
		return nil
	}
	if s.DHCP != "on" {
		what := "1 address"
		if len(s.Hosts) > 1 {
			what = fmt.Sprintf("%d addresses", len(s.Hosts))
		}
		return fmt.Errorf("segment %s: %s reserves %s, but DHCP is off, so nothing would hand them out. Set DHCP=on with a DHCP_START and DHCP_END, or empty the file. Nothing was changed.", s.Name, s.HostsPath, what)
	}
	p := netip.MustParsePrefix(s.Net).Masked()
	for _, h := range s.Hosts {
		a := netip.MustParseAddr(h.IP)
		at := fmt.Sprintf("segment %s: %s:%d: %s", s.Name, s.HostsPath, h.line, h.IP)
		switch {
		case !p.Contains(a):
			return fmt.Errorf("%s is not inside NET=%s. Nothing was changed.", at, s.Net)
		case h.IP == s.IP:
			return fmt.Errorf("%s is IP, the address the Pi answers on. Nothing was changed.", at)
		case a == p.Addr():
			return fmt.Errorf("%s is the network address of NET=%s, which no device can hold. Nothing was changed.", at, s.Net)
		case a == lastAddr(p):
			return fmt.Errorf("%s is the broadcast address of NET=%s, which no device can hold. Nothing was changed.", at, s.Net)
		}
	}
	return nil
}
