package doctor

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// PostUpgradeConfig is what pf doctor --post-upgrade checks directly after
// pf ship install applies a new tree, before the box is trusted enough
// to arm the confirm-or-revert timer
// (docs/signed_ship.md, "Confirm or revert"). Each probe
// is a hook, so a test drives it without a real socket, network or unit
// table. DefaultPostUpgradeConfig connects the real ones.
type PostUpgradeConfig struct {
	// Units is what apply.sh actually enabled and expects active
	// (loaded from UnitsSource, for example /var/lib/pi-fortress/units.required,
	// so this package never hardcodes which ones are optional). Empty
	// means that the list could not be read. The rung then warns, and does
	// not silently pass.
	Units       []string
	UnitsSource string

	Segments     []Segment
	BlockDomain  string
	PublicDomain string

	BrokerSocket string
	EngineAddr   string

	UplinkServer string
	UplinkName   string

	Timeout time.Duration

	UnitActive func(string) bool
	Resolve    func(server, name string, timeout time.Duration) ([]string, error)
	DialUnix   func(path string, timeout time.Duration) error
	DialTCP    func(addr string, timeout time.Duration) error
}

// DefaultPostUpgradeConfig sets the real hooks and the fixed
// canaries: pi-fortress-block.test (RFC 2606), example.com, and Quad9
// as the upstream DNS_UPSTREAM default. The caller must still set
// Units, Segments, BrokerSocket, EngineAddr and, if net.env overrides
// it, UplinkServer.
func DefaultPostUpgradeConfig() PostUpgradeConfig {
	return PostUpgradeConfig{
		BlockDomain:  "pi-fortress-block.test",
		PublicDomain: "example.com",
		UplinkServer: "9.9.9.9",
		UplinkName:   "example.com",
		Timeout:      3 * time.Second,
		UnitActive:   unitActive,
		Resolve:      resolveVia,
		DialUnix: func(path string, timeout time.Duration) error {
			c, err := net.DialTimeout("unix", path, timeout)
			if err != nil {
				return err
			}
			return c.Close()
		},
		DialTCP: func(addr string, timeout time.Duration) error {
			c, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return err
			}
			return c.Close()
		},
	}
}

// PostUpgrade runs each configured rung and returns the ladder that the
// same Report renders: units, then a sinkhole and a public resolve per
// segment, then the broker and engine sockets, then the uplink. A
// zero-value hook (nil) skips that rung, and does not panic. So a test
// can configure only what it intends to exercise.
func PostUpgrade(cfg PostUpgradeConfig) []Result {
	at := func(rung, where, detail string, st Status) Result {
		return Result{Rung: rung, Where: where, Detail: detail, Status: st}
	}
	var rs []Result

	switch {
	case cfg.UnitActive == nil:
	case len(cfg.Units) == 0:
		rs = append(rs, at("units", "post-upgrade", "no required-unit list"+suffix(cfg.UnitsSource)+"; run pf apply once more, or check manually", Warn))
	default:
		var dead []string
		for _, u := range cfg.Units {
			if !cfg.UnitActive(u) {
				dead = append(dead, u)
			}
		}
		if len(dead) > 0 {
			rs = append(rs, at("units", "post-upgrade", strings.Join(dead, ", ")+" not active; journalctl -u "+strings.Join(dead, " -u "), Fail))
		} else {
			rs = append(rs, at("units", "post-upgrade", strings.Join(cfg.Units, ", ")+" active", OK))
		}
	}

	if cfg.Resolve != nil {
		for _, s := range cfg.Segments {
			rs = append(rs, sinkholeRung(cfg, s, at))
			rs = append(rs, publicResolveRung(cfg, s, at))
		}
	}

	dialRung := func(rung, addr string, err error) Result {
		if err != nil {
			return at(rung, "fence", addr+": "+err.Error(), Fail)
		}
		return at(rung, "fence", addr+" accepts connections", OK)
	}
	if cfg.DialUnix != nil && cfg.BrokerSocket != "" {
		rs = append(rs, dialRung("broker", cfg.BrokerSocket, cfg.DialUnix(cfg.BrokerSocket, cfg.Timeout)))
	}
	if cfg.DialTCP != nil && cfg.EngineAddr != "" {
		rs = append(rs, dialRung("engine", cfg.EngineAddr, cfg.DialTCP(cfg.EngineAddr, cfg.Timeout)))
	}

	if cfg.Resolve != nil && cfg.UplinkServer != "" {
		got, err := cfg.Resolve(cfg.UplinkServer, cfg.UplinkName, cfg.Timeout)
		if err != nil || len(got) == 0 {
			rs = append(rs, at("uplink", "pi", uplinkDetail(cfg, got, err), Fail))
		} else {
			rs = append(rs, at("uplink", "pi", fmt.Sprintf("default route + uplink ok: %s -> %s via %s", cfg.UplinkName, strings.Join(got, " "), cfg.UplinkServer), OK))
		}
	}

	return rs
}

func sinkholeRung(cfg PostUpgradeConfig, s Segment, at func(string, string, string, Status) Result) Result {
	got, err := cfg.Resolve(s.IP, cfg.BlockDomain, cfg.Timeout)
	switch {
	case err != nil:
		return at("sinkhole", s.Name, fmt.Sprintf("%s via %s: %v", cfg.BlockDomain, s.IP, err), Fail)
	case !onlyAnswer(got, "0.0.0.0"):
		return at("sinkhole", s.Name, fmt.Sprintf("%s via %s -> %s, want 0.0.0.0", cfg.BlockDomain, s.IP, strings.Join(got, " ")), Fail)
	}
	return at("sinkhole", s.Name, cfg.BlockDomain+" sinkholed at "+s.IP, OK)
}

func publicResolveRung(cfg PostUpgradeConfig, s Segment, at func(string, string, string, Status) Result) Result {
	got, err := cfg.Resolve(s.IP, cfg.PublicDomain, cfg.Timeout)
	if err != nil || len(got) == 0 {
		msg := fmt.Sprintf("%s via %s: ", cfg.PublicDomain, s.IP)
		if err != nil {
			msg += err.Error()
		} else {
			msg += "no answer"
		}
		return at("resolve", s.Name, msg, Fail)
	}
	return at("resolve", s.Name, fmt.Sprintf("%s -> %s", cfg.PublicDomain, strings.Join(got, " ")), OK)
}

func uplinkDetail(cfg PostUpgradeConfig, got []string, err error) string {
	msg := fmt.Sprintf("%s via upstream %s: ", cfg.UplinkName, cfg.UplinkServer)
	if err != nil {
		return msg + err.Error()
	}
	_ = got
	return msg + "no answer"
}

func onlyAnswer(got []string, want string) bool {
	if len(got) == 0 {
		return false
	}
	for _, g := range got {
		if g != want {
			return false
		}
	}
	return true
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}
