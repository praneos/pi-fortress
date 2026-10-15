// Package doctor walks each segment from the cable up, and stops at the
// first rung that fails. status prints the box. doctor says which part of
// it is wrong.
package doctor

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/render"
)

// Probes the live box. Swapped in tests.
var (
	ifaceByName = net.InterfaceByName
	ifaceAddrs  = func(i *net.Interface) ([]net.Addr, error) { return i.Addrs() }
	readFile    = os.ReadFile
	unitActive  = func(unit string) bool {
		return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
	}
	usbList = func() string {
		out, _ := exec.Command("lsusb").Output()
		return string(out)
	}
	resolveVia = func(server, name string, d time.Duration) ([]string, error) {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: d}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		return r.LookupHost(ctx, name)
	}
)

// Adapters that enumerate as their own driver CD, and become a NIC only
// after a mode switch. The house adapter is the RTL8153. Without this,
// the box reports only an absent interface.
// A bare eject was the old hint. On 2026-09-22, the adapter answered each
// eject with "status 0" and did not switch. The unit escalates past the
// eject, and its log says which rung held.
const driverCDFix = "sudo systemctl start pi-fortress-usb-nic-switch.service, then journalctl -u pi-fortress-usb-nic-switch; if it still says driver-CD, unplug the adapter and plug it back in"

var driverCD = map[string]string{
	"0bda:8151": "RTL8153 sitting in driver-CD mode; " + driverCDFix,
	"0bda:1a2b": "RTL8152 sitting in driver-CD mode; " + driverCDFix,
	"2357:0601": "adapter sitting in driver-CD mode; " + driverCDFix,
}

type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	}
	return "FAIL"
}

// Segment is one cable: the interface, the address that the Pi holds on
// it, and the resolver that serves it.
type Segment struct {
	Name, IF, IP, Unit, Leases string
	DHCP                       bool
	// DHCPUnit is the unit that serves DHCP when that is a different daemon
	// from the DNS daemon. Empty means that Unit does both. That is dnsmasq
	// on the house before pf dns took its DNS role. After that, pf dns
	// answers and dnsmasq keeps DHCP. Then one "resolver: active" rung would
	// tell an operator that the house has DNS, from a unit that runs with
	// port=0.
	DHCPUnit string
	// probe is the name that resolve asks the resolver of the segment for.
	probe string
}

type Result struct {
	Rung, Where, Detail string
	Status              Status
}

// Load reads the two env files that apply reads. A missing house.env means
// no house segment. That is a configuration, not a fault.
func Load(netEnv, houseEnv, probe string) ([]Segment, error) {
	var piIP, intIF, allow string
	read := func(_ int, key, val string) error {
		switch key {
		case "PI_IP":
			piIP = val
		case "INT_IF":
			intIF = val
		case "ALLOW_DOMAIN":
			allow = val
		}
		return nil
	}
	if err := render.EnvLines(netEnv, read); err != nil {
		return nil, err
	}
	// apply sources the operator overlay after net.env. So a value set
	// there is the value that the running box was built from.
	if err := render.EnvLines(netEnv+".local", read); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if piIP == "" {
		return nil, fmt.Errorf("%s: no PI_IP", netEnv)
	}
	if intIF == "" {
		intIF = ifaceWithAddr(piIP)
	}
	if intIF == "" {
		return nil, fmt.Errorf("no interface holds PI_IP=%s and INT_IF is not set in %s", piIP, netEnv)
	}
	// pf dns serves each segment, and the resolver unit of dnsmasq is gone.
	// So a name of that unit here would report a dead unit as the fault when
	// the resolver is fine.
	const agentUnit = "pi-fortress-dns-agent-go.service"
	segs := []Segment{{Name: "agent", IF: intIF, IP: piIP, Unit: agentUnit}}

	var houseIF, houseIP string
	err := render.EnvLines(houseEnv, func(_ int, key, val string) error {
		switch key {
		case "HOUSE_IF":
			houseIF = val
		case "HOUSE_IP":
			houseIP = val
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if houseIF != "" {
		if houseIP == "" {
			houseIP = render.DefaultHouseIP
		}
		// The house is a segment of pf dns, and dnsmasq continues to do
		// DHCP. So the two roles are two units, and the rungs name them
		// separately.
		segs = append(segs, Segment{
			Name: "house", IF: houseIF, IP: houseIP,
			Unit:     agentUnit,
			DHCPUnit: "pi-fortress-dns-house.service",
			Leases:   filepath.Join("/var/lib/pi-fortress", "house.leases"),
			DHCP:     true,
		})
	}
	if probe == "" {
		probe = allow
	}
	if probe == "" {
		probe = "example.com"
	}
	for i := range segs {
		segs[i].probe = probe
	}
	return segs, nil
}

// Check walks one segment and stops at the first rung that fails: a
// missing interface makes each rung above it noise.
func Check(s Segment) []Result {
	at := func(rung, detail string, st Status) Result {
		return Result{Rung: rung, Where: s.Name, Detail: detail, Status: st}
	}
	ifc, err := ifaceByName(s.IF)
	if err != nil {
		return []Result{at("link", fmt.Sprintf("%s: no such interface (check ip -br link)%s", s.IF, hardwareHint()), Fail)}
	}
	detail, st := linkRung(s.IF, ifc)
	rs := []Result{at("link", s.IF+": "+detail, st)}
	if st == Fail {
		return rs
	}

	addrs, _ := ifaceAddrs(ifc)
	if !holds(addrs, s.IP) {
		rs = append(rs, at("address", fmt.Sprintf("%s is not on %s; run sudo pf apply", s.IP, s.IF), Fail))
		return rs
	}
	rs = append(rs, at("address", s.IP+" on "+s.IF, OK))

	// DHCP first where it is its own daemon. It is the rung that says
	// whether a client can get an address at all, and a resolver fault
	// below it is a different repair.
	if s.DHCPUnit != "" {
		if unitActive(s.DHCPUnit) {
			rs = append(rs, at("dhcp", s.DHCPUnit+" active", OK))
		} else {
			rs = append(rs, at("dhcp", s.DHCPUnit+" is not active; journalctl -u "+s.DHCPUnit, Fail))
		}
	}

	if !unitActive(s.Unit) {
		rs = append(rs, at("resolver", s.Unit+" is not active; journalctl -u "+s.Unit, Fail))
		return rs
	}
	rs = append(rs, at("resolver", s.Unit+" active", OK))

	if s.DHCP {
		rs = append(rs, s.leaseRung(at))
	}

	got, err := resolveVia(s.IP, s.probe, 3*time.Second)
	if err != nil {
		rs = append(rs, at("resolve", fmt.Sprintf("%s via %s: %v", s.probe, s.IP, err), Fail))
		return rs
	}
	rs = append(rs, at("resolve", fmt.Sprintf("%s -> %s", s.probe, strings.Join(got, " ")), OK))
	return rs
}

// A segment whose own end is healthy, but that has never given a lease,
// usually has its fault at the far side: an access point on the wrong
// subnet, or one that still runs its own DHCP server.
func (s Segment) leaseRung(at func(string, string, Status) Result) Result {
	data, err := readFile(s.Leases)
	if os.IsPermission(err) {
		return at("leases", s.Leases+" is root-only; run doctor with sudo to count them", Warn)
	}
	if err != nil {
		return at("leases", err.Error(), Warn)
	}
	n, newest := 0, int64(0)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		n++
		if v, err := strconv.ParseInt(f[0], 10, 64); err == nil && v > newest {
			newest = v
		}
	}
	if n == 0 {
		return at("leases", "none handed out: the AP may be on another subnet or running its own DHCP", Warn)
	}
	return at("leases", fmt.Sprintf("%d, newest expires %s", n, time.Unix(newest, 0).Format(time.RFC3339)), OK)
}

// Report prints the ladder and returns the process status: any failed
// rung is a non-zero exit, and a warning is not.
func Report(w io.Writer, rs []Result) int {
	code := 0
	for _, r := range rs {
		if r.Status == Fail {
			code = 1
		}
		fmt.Fprintf(w, "%-4s %-8s %-6s %s\n", r.Status, r.Rung, r.Where, r.Detail)
	}
	return code
}

// The address survives a pulled cable on purpose, so carrier is the
// only rung that notices one. Green here means a dead segment reads as
// healthy all the way up the ladder.
func linkRung(name string, i *net.Interface) (string, Status) {
	if i.Flags&net.FlagUp == 0 {
		return "down", Fail
	}
	d := "up"
	if speed := strings.TrimSpace(sysfs(name, "speed")); speed != "" && speed != "-1" {
		d += ", " + speed + "Mb/s"
	}
	if strings.TrimSpace(sysfs(name, "carrier")) == "0" {
		return "disconnected (no carrier: nothing on the other end of the cable)", Warn
	}
	return d, OK
}

func sysfs(name, file string) string {
	b, err := readFile(filepath.Join("/sys/class/net", name, file))
	if err != nil {
		return ""
	}
	return string(b)
}

// hardwareHint changes "there is no such interface" into a reason,
// whenever a known driver-CD adapter is on the bus.
func hardwareHint() string {
	list := usbList()
	var hits []string
	for id, why := range driverCD {
		if strings.Contains(list, id) {
			hits = append(hits, why)
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return ". " + strings.Join(hits, "; ")
}

func holds(addrs []net.Addr, ip string) bool {
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok && p.IP.String() == ip {
			return true
		}
	}
	return false
}

func ifaceWithAddr(ip string) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		addrs, err := ifaceAddrs(&i)
		if err != nil {
			continue
		}
		if holds(addrs, ip) {
			return i.Name
		}
	}
	return ""
}

// FenceUnits is the fence itself: the broker holds the credentials and
// the policy, and the engine is the proxy in front of them. Neither owns
// an address or a resolver. So nothing in the per-segment ladder notices
// when one is stopped.
var FenceUnits = []string{"pi-fortress-broker.service", "pi-fortress-engine.service"}

// UnitsRung reports units that are not running as one rung. It has the
// same shape as the per-segment resolver rung: the unit is named, the
// remedy is the journalctl line for it, and a stopped unit is a Fail. So
// a box with a dead fence exits non-zero, and does not print green.
func UnitsRung(units ...string) (Result, bool) {
	if len(units) == 0 {
		return Result{}, false
	}
	at := func(detail string, st Status) (Result, bool) {
		return Result{Rung: "units", Where: "fence", Detail: detail, Status: st}, true
	}
	var dead []string
	for _, u := range units {
		if !unitActive(u) {
			dead = append(dead, u)
		}
	}
	if len(dead) > 0 {
		return at(strings.Join(dead, ", ")+" not active; journalctl -u "+strings.Join(dead, " -u "), Fail)
	}
	return at(strings.Join(units, ", ")+" active", OK)
}

// SecretsRung answers the question that a sealed box makes an operator ask
// at the worst moment: all is green, so why does nothing work? A sealed
// store is silent until something needs a credential. That can be hours
// after the reboot that caused it, and the failure that shows is a 503
// that intentionally says nothing.
//
// state is the STATE line from the admin socket of the broker, and err is
// the return of the request for it. Before, a socket that did not answer
// caused this rung to be absent from the report. That is the one case
// where the operator most needs a line. A broker that is down answers
// nothing. So a doctor that speaks only when the broker answers prints
// an all-green ladder over a fence that passes nothing.
func SecretsRung(state string, err error) (Result, bool) {
	at := func(detail string, st Status) (Result, bool) {
		return Result{Rung: "secrets", Where: "fence", Detail: detail, Status: st}, true
	}
	if err != nil {
		return at("the broker admin socket did not answer, so the credential store could not be checked: "+
			err.Error()+"; journalctl -u pi-fortress-broker.service", Fail)
	}
	switch {
	case state == "":
		return Result{}, false
	case strings.HasPrefix(state, "fault "):
		return at(strings.TrimPrefix(state, "fault ")+"; the store is failed shut and every substitution is refused", Fail)
	case state == "sealed locked":
		return at("the credential store is sealed and no passphrase has been entered since boot; run sudo pf unlock", Warn)
	case state == "sealed unlocked":
		return at("credential store sealed and open", OK)
	case state == "plaintext":
		return at("credential store is not sealed; values are at rest in the clear", OK)
	}
	return at("unrecognised store state "+state, Warn)
}
