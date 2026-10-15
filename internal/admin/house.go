package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/leases"
	"pi-fortress/internal/render"
)

// Lease and Reservation are internal/leases types. The parsers moved there,
// so observe can name house clients without an import of admin.
type (
	Lease       = leases.Lease
	Reservation = leases.Reservation
)

// Host is one row of the Devices screen: a lease, a reservation, or both.
type Host struct {
	MAC, IP, Name string
	Reserved      bool
	Lease         *Lease
}

var (
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	ifaceRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,14}$`)
)

func ParseLeases(text string) []Lease { return leases.ParseLeases(text) }

func ParseReservations(lines []string) []Reservation { return leases.ParseReservations(lines) }

func parseReservation(line string) (Reservation, bool) { return leases.ParseReservation(line) }

// Leases and Reservations are display paths. Nothing goes back to the file
// from them. Thus a file that cannot be read shows as nothing, and the
// screen does not fail. The edit paths below do not get that luxury.
func (c *Config) Leases() []Lease {
	lines, _ := readLines(c.HouseLeases)
	return ParseLeases(strings.Join(lines, "\n"))
}

func (c *Config) Reservations() []Reservation {
	lines, _ := readLines(c.HouseHosts)
	return ParseReservations(lines)
}

func (c *Config) Hosts() []Host {
	var out []Host
	byMAC := map[string]int{}
	for _, r := range c.Reservations() {
		byMAC[r.MAC] = len(out)
		out = append(out, Host{MAC: r.MAC, IP: r.IP, Name: r.Name, Reserved: true})
	}
	for _, l := range c.Leases() {
		l := l
		if i, ok := byMAC[l.MAC]; ok {
			out[i].Lease = &l
			continue
		}
		out = append(out, Host{MAC: l.MAC, IP: l.IP, Name: Printable(l.Hostname), Lease: &l})
	}
	slices.SortStableFunc(out, func(a, b Host) int { return cmpIP(a.IP, b.IP) })
	return out
}

func cmpIP(a, b string) int {
	pa, ea := netip.ParseAddr(a)
	pb, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil {
		return strings.Compare(a, b)
	}
	return pa.Compare(pb)
}

func houseDefaults(env map[string]string) map[string]string {
	def := map[string]string{"HOUSE_NET": "10.78.0.0/24", "HOUSE_IP": "10.78.0.1", "HOUSE_DHCP_START": "10.78.0.100", "HOUSE_DHCP_END": "10.78.0.199"}
	for k, v := range def {
		if env[k] == "" {
			env[k] = v
		}
	}
	return env
}

// houseEnv is House() with the read failure kept. A house.env that is
// absent is a configuration, and the defaults below describe the house that
// the box would build. A house.env that exists but cannot be read is a
// fault. If the code fills in the same defaults, it invents a network that
// the box is not on. All code that makes a decision goes through here: what
// is in the house network, which address is free, and whether a new tuple
// of the operator is consistent. Validation against an invented house is a
// gate that passes all input.
func (c *Config) houseEnv() (map[string]string, error) {
	env, err := base.LoadEnvFile(c.HouseEnv)
	if err != nil {
		return nil, fmt.Errorf("the house configuration cannot be read, so nothing can be checked against it: %w", err)
	}
	return houseDefaults(env), nil
}

// House is the lenient reader, for the screens that only show what they
// found. All code that makes a decision uses houseEnv.
func (c *Config) House() map[string]string {
	env, err := c.houseEnv()
	if err != nil {
		return houseDefaults(map[string]string{})
	}
	return env
}

// Reserve pins mac to ip in house.hosts. It replaces an existing line for
// the same MAC. An empty ip takes the next free address.
func (c *Config) Reserve(mac, ip, name string) (Reservation, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return Reservation{}, errors.New("invalid MAC")
	}
	if name != "" && !hostnameRE.MatchString(name) {
		return Reservation{}, errors.New("invalid name")
	}
	if ip == "" {
		if ip, err = c.NextFreeIP(); err != nil {
			return Reservation{}, err
		}
	}
	if err := c.reservable(ip); err != nil {
		return Reservation{}, err
	}
	r := Reservation{MAC: hw.String(), IP: ip, Name: name}
	err = c.withEditLock(func() error {
		lines, err := readLines(c.HouseHosts)
		if err != nil {
			return err
		}
		for _, o := range ParseReservations(lines) {
			if o.MAC != r.MAC && o.IP == ip {
				return fmt.Errorf("%s already reserved for %s", ip, o.MAC)
			}
		}
		kept := slices.DeleteFunc(lines, func(l string) bool {
			o, ok := parseReservation(l)
			return ok && o.MAC == r.MAC
		})
		line := r.MAC + "," + r.IP
		if r.Name != "" {
			line += "," + r.Name
		}
		return writeLines(c.HouseHosts, append(kept, line))
	})
	if err != nil {
		return Reservation{}, err
	}
	return r, nil
}

func (c *Config) Unreserve(mac string) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	return c.withEditLock(func() error {
		lines, err := readLines(c.HouseHosts)
		if err != nil {
			return err
		}
		kept := slices.DeleteFunc(slices.Clone(lines), func(l string) bool {
			o, ok := parseReservation(l)
			return ok && o.MAC == mac
		})
		if len(kept) == len(lines) {
			return errors.New("no reservation for " + mac)
		}
		return writeLines(c.HouseHosts, kept)
	})
}

// hostAddr parses ip as a host address of pfx: in pfx, and not the network
// address or the broadcast address.
func hostAddr(pfx netip.Prefix, ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() || !pfx.Contains(a) {
		return netip.Addr{}, fmt.Errorf("%s is not inside %s", ip, pfx)
	}
	if a == pfx.Masked().Addr() || a == lastAddr(pfx) {
		return netip.Addr{}, fmt.Errorf("%s is the network or broadcast address of %s", ip, pfx)
	}
	return a, nil
}

// reservable refuses the gateway and the admin address. An operator can
// reserve, but only an admin sets HOUSE_ADMIN_IP. Thus a reservation must
// not give a MAC the ssh privileges of the admin. Reserve first, then set
// the admin address to that reservation.
func (c *Config) reservable(ip string) error {
	env, err := c.houseEnv()
	if err != nil {
		return err
	}
	pfx, err := netip.ParsePrefix(env["HOUSE_NET"])
	if err != nil {
		return err
	}
	if _, err := hostAddr(pfx, ip); err != nil {
		return err
	}
	switch ip {
	case env["HOUSE_IP"]:
		return fmt.Errorf("%s is the gateway", ip)
	case env["HOUSE_ADMIN_IP"]:
		return fmt.Errorf("%s is HOUSE_ADMIN_IP", ip)
	}
	return nil
}

// checkHouseTuple validates net, gateway, DHCP range and admin address
// together. Thus a change to one of them cannot leave the others pointing
// outside the network.
func checkHouseTuple(env map[string]string) error {
	pfx, err := netip.ParsePrefix(env["HOUSE_NET"])
	if err != nil || !pfx.Addr().Is4() {
		return errors.New("HOUSE_NET: want an IPv4 CIDR")
	}
	if pfx.Bits() > 30 {
		return errors.New("HOUSE_NET: no room for hosts")
	}
	addrs := map[string]netip.Addr{}
	for _, k := range []string{"HOUSE_IP", "HOUSE_DHCP_START", "HOUSE_DHCP_END", "HOUSE_ADMIN_IP"} {
		if k == "HOUSE_ADMIN_IP" && env[k] == "" {
			continue
		}
		a, err := hostAddr(pfx, env[k])
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		addrs[k] = a
	}
	lo, hi, gw := addrs["HOUSE_DHCP_START"], addrs["HOUSE_DHCP_END"], addrs["HOUSE_IP"]
	if hi.Less(lo) {
		return errors.New("HOUSE_DHCP_END is below HOUSE_DHCP_START")
	}
	if lo.Compare(gw) <= 0 && gw.Compare(hi) <= 0 {
		return errors.New("HOUSE_IP is inside the DHCP range")
	}
	if admin, ok := addrs["HOUSE_ADMIN_IP"]; ok && admin == gw {
		return errors.New("HOUSE_ADMIN_IP is the gateway")
	}
	return nil
}

// NextFreeIP picks the lowest address in HOUSE_NET that is not the gateway,
// not in the DHCP pool, and not held by a reservation or a live lease.
// Reservations are outside the pool, so a pool change never collides with
// them.
func (c *Config) NextFreeIP() (string, error) {
	env, err := c.houseEnv()
	if err != nil {
		return "", err
	}
	pfx, err := netip.ParsePrefix(env["HOUSE_NET"])
	if err != nil {
		return "", err
	}
	pfx = pfx.Masked()
	used := map[string]bool{env["HOUSE_IP"]: true}
	for _, r := range c.Reservations() {
		used[r.IP] = true
	}
	for _, l := range c.Leases() {
		used[l.IP] = true
	}
	lo, _ := netip.ParseAddr(env["HOUSE_DHCP_START"])
	hi, _ := netip.ParseAddr(env["HOUSE_DHCP_END"])
	last := lastAddr(pfx)
	for a := pfx.Addr().Next(); a.Less(last); a = a.Next() {
		if used[a.String()] || (lo.IsValid() && hi.IsValid() && a.Compare(lo) >= 0 && a.Compare(hi) <= 0) {
			continue
		}
		return a.String(), nil
	}
	return "", errors.New("no free address in " + pfx.String())
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(b)
}

var houseKeys = map[string]func(string) error{
	"HOUSE_IF":                 checkIface,
	"HOUSE_NET":                checkPrefix,
	"HOUSE_IP":                 checkAddr,
	"HOUSE_DHCP_START":         checkAddr,
	"HOUSE_DHCP_END":           checkAddr,
	"HOUSE_ADMIN_IP":           checkAddrOrEmpty,
	"HOUSE_DNS_UPSTREAM":       checkAddrOrEmpty,
	"HOUSE_DOT_AUTH_NAME":      checkDNSNameOrEmpty,
	"HOUSE_DOT_IPS":            checkAddrsOrEmpty,
	"HOUSE_BLOCK_DIRECT_IP":    checkOnOff,
	"HOUSE_BLOCK_HTTP":         checkOnOff,
	"HOUSE_BLOCK_VPN":          checkOnOff,
	"HOUSE_PRIVATE_DNS":        checkOnOff,
	"HOUSE_EGRESS":             checkEgress,
	"HOUSE_ALLOW_WIFI_CALLING": checkOnOff,
	"HOUSE_ALLOW_CALL_UDP":     checkOnOff,
	"HOUSE_ALLOW_WHATSAPP":     checkOnOff,
	"HOUSE_ALLOW_PORTS":        checkPorts,
	"WG_IF":                    checkIfaceOrEmpty,
	"WG_BYPASS_MARK":           checkMark,
}

var HouseKeys = []string{"HOUSE_IF", "HOUSE_NET", "HOUSE_IP", "HOUSE_DHCP_START", "HOUSE_DHCP_END", "HOUSE_ADMIN_IP", "HOUSE_DNS_UPSTREAM", "HOUSE_DOT_AUTH_NAME", "HOUSE_DOT_IPS", "HOUSE_BLOCK_DIRECT_IP", "HOUSE_BLOCK_HTTP", "HOUSE_BLOCK_VPN", "HOUSE_PRIVATE_DNS", "HOUSE_EGRESS", "HOUSE_ALLOW_WIFI_CALLING", "HOUSE_ALLOW_CALL_UDP", "HOUSE_ALLOW_WHATSAPP", "HOUSE_ALLOW_PORTS", "WG_IF", "WG_BYPASS_MARK"}

// HouseDoT is the provider of the house itself: a name and the addresses of
// that name. pf render refuses each half without the other. Thus the code
// sets the two together or not at all. The box pair is edited as one change
// for the same reason. Refer to SetNetEnv.
var HouseDoT = []string{"HOUSE_DOT_AUTH_NAME", "HOUSE_DOT_IPS"}

// HouseOnOff are the keys that the TUI changes with one key press. Each has
// the value that an empty or absent line means (render.Config reads it the
// same way).
var HouseOnOff = map[string]string{"HOUSE_BLOCK_DIRECT_IP": "on", "HOUSE_BLOCK_HTTP": "off", "HOUSE_BLOCK_VPN": "on", "HOUSE_PRIVATE_DNS": "off", "HOUSE_ALLOW_WIFI_CALLING": "off", "HOUSE_ALLOW_CALL_UDP": "off", "HOUSE_ALLOW_WHATSAPP": "on"}

// checkEgress is HOUSE_EGRESS; empty is strict.
func checkEgress(v string) error {
	switch v {
	case "", "strict", "audit", "open":
		return nil
	}
	return errors.New("want strict, audit or open")
}

// checkPorts is HOUSE_ALLOW_PORTS, read the way pf render reads it.
func checkPorts(v string) error {
	_, _, err := render.ParsePorts(strings.Trim(v, `"`))
	return err
}

func checkOnOff(v string) error {
	if v != "" && v != "on" && v != "off" {
		return errors.New("want on or off")
	}
	return nil
}

func checkIface(v string) error {
	if !ifaceRE.MatchString(v) {
		return errors.New("invalid interface name")
	}
	return nil
}

func checkIfaceOrEmpty(v string) error {
	if v == "" {
		return nil
	}
	return checkIface(v)
}

func checkMark(v string) error {
	if v == "" {
		return nil
	}
	if len(v) < 3 || v[:2] != "0x" {
		return errors.New("want a hex fwmark")
	}
	for _, c := range v[2:] {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return errors.New("want a hex fwmark")
	}
	return nil
}

func checkPrefix(v string) error {
	p, err := netip.ParsePrefix(v)
	if err != nil || !p.Addr().Is4() {
		return errors.New("want an IPv4 CIDR")
	}
	return nil
}

func checkAddr(v string) error {
	a, err := netip.ParseAddr(v)
	if err != nil || !a.Is4() {
		return errors.New("want an IPv4 address")
	}
	return nil
}

func checkAddrOrEmpty(v string) error {
	if v == "" {
		return nil
	}
	return checkAddr(v)
}

// checkedKeys trims each value of kv in place and checks it with its
// function from allowed. It gives the keys of kv in sorted order.
func checkedKeys(kv map[string]string, allowed map[string]func(string) error) ([]string, error) {
	if len(kv) == 0 {
		return nil, errors.New("nothing to set")
	}
	keys := make([]string, 0, len(kv))
	for key := range kv {
		check, ok := allowed[key]
		if !ok {
			return nil, errors.New("unknown key " + key)
		}
		kv[key] = strings.TrimSpace(kv[key])
		if err := check(kv[key]); err != nil {
			return nil, errors.New(key + ": " + err.Error())
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// SetHouseEnv edits one allowlisted key in place. It keeps comments and
// order. It appends a key that is absent or only commented out. It
// validates the full address tuple again with the new value in place.
func (c *Config) SetHouseEnv(key, value string) error {
	_, err := c.SetHouseEnvKeys(map[string]string{key: value})
	return err
}

// SetHouseEnvKeys is the same edit for more than one key at a time. The
// warning that it returns is what is still wrong with a box that did not
// render before this edit. SetNetEnv gives the reason for both. The house
// DoT provider is the caller that needs the map. Render refuses the name
// without its addresses, so the code can only set the two together.
func (c *Config) SetHouseEnvKeys(kv map[string]string) (string, error) {
	keys, err := checkedKeys(kv, houseKeys)
	if err != nil {
		return "", err
	}
	env, err := c.houseEnv()
	if err != nil {
		return "", err
	}
	for _, key := range keys {
		env[key] = kv[key]
	}
	if err := checkHouseTuple(env); err != nil {
		return "", err
	}
	// pf render reads house.env from a path. Thus the code renders the
	// candidate from a copy. It does not write the file and roll it back. An
	// operator cannot act on a refusal that already changed the file.
	before := c.renderErr(c.NetEnv(), c.HouseEnv)
	cand, err := c.candidateHouse(kv, keys)
	if err != nil {
		return "", err
	}
	defer os.Remove(cand)
	if err := c.renderErr(c.NetEnv(), cand); err != nil && before == nil {
		return "", err
	}
	// The quote rule is per key: refer to setEnvLines. The code writes all keys
	// except the DoT pair bare, because pf render parses this file and a
	// quote would become part of the value.
	if err := c.withEditLock(func() error {
		return setEnvLines(c.HouseEnv, kv, keys, quoteHouse)
	}); err != nil {
		return "", err
	}
	if err := c.renderErr(c.NetEnv(), c.HouseEnv); err != nil {
		return "the configuration still does not render: " + err.Error(), nil
	}
	return "", nil
}

// candidateHouse is house.env with the edit applied, in a temp file. Thus
// the render check can run on what the file would become.
func (c *Config) candidateHouse(kv map[string]string, keys []string) (string, error) {
	lines, err := readLines(c.HouseEnv)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(c.HouseEnv), "house.env.check")
	if err != nil {
		return "", err
	}
	path := f.Name()
	_ = f.Close()
	if err := writeLines(path, lines); err != nil {
		os.Remove(path)
		return "", err
	}
	if err := setEnvLines(path, kv, keys, quoteHouse); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// Resolve asks the house resolver directly. Thus the operator sees the
// sinkhole answer (0.0.0.0), not the answer from the resolver of the Pi.
func Resolve(server, name string) ([]string, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	ctx, cancel := timeout(4 * time.Second)
	defer cancel()
	return r.LookupHost(ctx, name)
}
