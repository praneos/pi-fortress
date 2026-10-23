package cli

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/doctor"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/render"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/ship"
)

// doctor is the ladder, and status is the dump. The first FAIL line is the
// diagnosis. The lines above it are rungs below it on the ladder, and they
// held.
func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("doctor", stderr)
	netEnv := fs.String("net-env", "/etc/pi-fortress/net.env", "net.env path")
	houseEnv := fs.String("house-env", "/etc/pi-fortress/house.env", "house.env path")
	segDir := fs.String("segments-dir", "/etc/pi-fortress/segments.d", "plain segment files, for the paranoid and DHCP rungs")
	probe := fs.String("probe", "", "name to resolve through each segment (default: ALLOW_DOMAIN)")
	sock := fs.String("broker-admin", secrets.AdminSock, "broker admin socket, for the credential store rung")
	etc := fs.String("etc", "/etc", "directory holding sudoers and sudoers.d, for the sudo rung")
	shipLog := fs.String("ship-log", ship.Defaults().Log, "signed ship log, for the ship rung")
	postUpgrade := fs.Bool("post-upgrade", false, "after a ship install: required units, sinkhole + public resolve per segment, broker + engine sockets, uplink; exit 0/1, none of the other rungs")
	unitsFile := fs.String("units-file", "/var/lib/pi-fortress/units.required", "unit list apply.sh wrote, for -post-upgrade")
	brokerSock := fs.String("broker-sock", "/run/pi-fortress/broker/broker.sock", "broker credential socket, for -post-upgrade")
	settleFor := fs.Duration("settle", 90*time.Second, "for -post-upgrade: keep re-checking a failing ladder this long before failing it")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	segs, err := doctor.Load(*netEnv, *houseEnv, *probe)
	if err != nil {
		return fail(stderr, err)
	}
	if *postUpgrade {
		cfg := doctor.DefaultPostUpgradeConfig()
		cfg.Segments = segs
		cfg.Units, cfg.UnitsSource = loadUnitsRequired(*unitsFile)
		cfg.BrokerSocket = *brokerSock
		if len(segs) > 0 {
			cfg.EngineAddr = net.JoinHostPort(segs[0].IP, "8080")
		}
		if up := upstreamResolver(*netEnv); up != "" {
			cfg.UplinkServer = up
		}
		return doctor.Report(stdout, settle(cfg, *settleFor, time.Sleep))
	}
	var rs []doctor.Result
	for _, s := range segs {
		rs = append(rs, doctor.Check(s)...)
	}
	rs = append(rs, doctor.SegmentParanoid(*segDir)...)
	rs = append(rs, doctor.SegmentDHCP(*segDir)...)
	// The fence units come before the store. A broker that is stopped
	// also cannot answer a question about the store. The operator must
	// read the cause before the consequence.
	if r, ok := doctor.UnitsRung(doctor.FenceUnits...); ok {
		rs = append(rs, r)
	}
	state, err := (&admin.Config{BrokerAdmin: *sock}).SecretsState(context.Background())
	if r, ok := doctor.SecretsRung(state, err); ok {
		rs = append(rs, r)
	}
	if r, ok := doctor.CARestartRung(doctor.CARestartPending); ok {
		rs = append(rs, r)
	}
	if r, ok := doctor.SudoRung(doctor.SudoersFiles(*etc)); ok {
		rs = append(rs, r)
	}
	if r, ok := doctor.ShipRung(jsonl.LastShip(*shipLog)); ok {
		rs = append(rs, r)
	}
	rs = append(rs, doctor.RebootRung(doctor.DefaultRebootPaths(), time.Now()))
	return doctor.Report(stdout, rs)
}

// settle runs the post-upgrade ladder until it has no Fail or the
// window closes. apply.sh restarts units and pf dns at its end. Thus
// the first look can find a resolver that still binds or a unit that
// still starts. A failure on that look would roll back a good build. A
// real fault is still there when the window closes.
func settle(cfg doctor.PostUpgradeConfig, window time.Duration, sleep func(time.Duration)) []doctor.Result {
	const step = 5 * time.Second
	for waited := time.Duration(0); ; waited += step {
		rs := doctor.PostUpgrade(cfg)
		failed := false
		for _, r := range rs {
			if r.Status == doctor.Fail {
				failed = true
				break
			}
		}
		if !failed || waited >= window {
			return rs
		}
		sleep(step)
	}
}

// loadUnitsRequired reads the record that apply.sh keeps of the units
// that it just enabled unconditionally. (Derive the list from what
// apply.sh enables. Do not hardcode units that are optional.) It reports
// a missing or empty file through source, and does not guess. Then
// -post-upgrade warns. It does not print nothing or make its own list.
func loadUnitsRequired(path string) ([]string, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, path + ": " + err.Error()
	}
	var units []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			units = append(units, line)
		}
	}
	if len(units) == 0 {
		return nil, path + ": empty"
	}
	return units, ""
}

// upstreamResolver is DNS_UPSTREAM from net.env (net.env.local wins if
// it also sets one): the resolver that the Pi itself forwards to. The
// doctor asks it directly. Thus a DNS answer from it proves the default
// route and the uplink, and the post-upgrade doctor connects to nothing else.
//
// With DoT on (DOT_IPS set), the output chain refuses plain DNS to
// DNS_UPSTREAM. Thus the question goes to the local stub on 127.0.0.1.
// This is the same switch that apply.sh makes for DNS_FORWARD. An answer
// from the stub still proves the uplink, because the stub asks over DoT.
func upstreamResolver(netEnv string) string {
	var up, dot string
	set := func(_ int, key, val string) error {
		switch {
		case key == "DNS_UPSTREAM" && val != "":
			up = val
		case key == "DOT_IPS":
			dot = strings.Trim(val, `"' `)
		}
		return nil
	}
	render.EnvLines(netEnv, set)
	render.EnvLines(netEnv+".local", set)
	if dot != "" {
		return "127.0.0.1"
	}
	return up
}
