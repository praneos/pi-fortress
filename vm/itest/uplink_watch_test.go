//go:build vagrant

package itest

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	uplinkWatchUnit  = "pi-fortress-uplink-watch.service"
	uplinkWatchTimer = "pi-fortress-uplink-watch.timer"
	uplinkRecord     = "/var/lib/pi-fortress/uplink.json"
	uplinkStateDir   = "/var/lib/pi-fortress/uplink"
)

// uplinkWatchTests check the uplink watchdog (internal/uplink) on the live
// box. The first four are read-only, except one check run, and run on a
// real Pi too. The last one activates a stand-in connection, so it is lab
// only.
//
// No subtest takes the real uplink down. In both labs the uplink of the
// gateway is the path of this ssh session (cloud lab: the mgmt NIC, which
// ifupdown keeps; VirtualBox: the NAT adapter of vagrant), and
// NetworkManager does not manage it. Thus the functional check uses a
// NetworkManager dummy connection with no address and no route as the
// stand-in uplink. It proves the path that the real uplink takes: the
// sandboxed root unit, nmcli over D-Bus, the activation, the event row and
// the alert sidecar.
func uplinkWatchTests(t *testing.T) {
	t.Run("the timer is enabled and active", uplinkWatchTimerTests)
	t.Run("the unit has its sandbox", uplinkWatchUnitTests)
	t.Run("apply recorded the uplink connection, or none when NetworkManager does not manage it", uplinkWatchRecordTests)
	t.Run("a check runs clean in the sandbox", uplinkWatchCheckTests)
	t.Run("a stand-in connection that is down comes back, and the alert sidecar reads the row", labOnly(uplinkWatchStandInTests))
}

func uplinkWatchTimerTests(t *testing.T) {
	if strings.TrimSpace(pi(t, "grep -s '^UPLINK_WATCH=' /etc/pi-fortress/net.env.local | tail -1")) == "UPLINK_WATCH=0" {
		t.Skip("UPLINK_WATCH=0 in net.env.local: the operator turned the watchdog off")
	}
	if out := strings.TrimSpace(pi(t, "systemctl is-enabled "+uplinkWatchTimer+" 2>&1 || true")); out != "enabled" {
		t.Errorf("%s is %q, want enabled", uplinkWatchTimer, out)
	}
	if out := strings.TrimSpace(pi(t, "systemctl is-active "+uplinkWatchTimer+" 2>&1 || true")); out != "active" {
		t.Errorf("%s is %q, want active", uplinkWatchTimer, out)
	}
}

// What systemd merged from the unit file.
func uplinkWatchUnitTests(t *testing.T) {
	want := map[string]string{
		"LoadState":               "loaded",
		"Type":                    "oneshot",
		"User":                    "",
		"CapabilityBoundingSet":   "",
		"AmbientCapabilities":     "",
		"NoNewPrivileges":         "yes",
		"RestrictAddressFamilies": "AF_UNIX",
		"ProtectSystem":           "strict",
		"ProtectHome":             "yes",
		"PrivateTmp":              "yes",
		"PrivateDevices":          "yes",
		"ProtectKernelTunables":   "yes",
		"ProtectProc":             "invisible",
		"StateDirectory":          "pi-fortress/uplink",
		"MemoryMax":               "67108864",
		"TasksMax":                "32",
	}
	props := make([]string, 0, len(want))
	for k := range want {
		props = append(props, k)
	}
	p := showProps(t, uplinkWatchUnit, props...)
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s %s=%q, want %q", uplinkWatchUnit, k, p[k], v)
		}
	}
}

// apply records the NetworkManager connection on WAN_IF. With no
// NetworkManager on WAN_IF, it records none.
func uplinkWatchRecordTests(t *testing.T) {
	wan := uplinkIF(pi(t, "sudo nft list chain inet fortress input"))
	if wan == "" {
		t.Fatal("no uplink DHCP rule in the input chain")
	}
	state := ""
	for line := range strings.SplitSeq(pi(t, "nmcli -t -f DEVICE,STATE device status 2>/dev/null || true"), "\n") {
		if d, s, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && d == wan {
			state = s
		}
	}
	show := pi(t, "/usr/local/sbin/pf uplink show")
	switch {
	case state == "" || state == "unmanaged" || strings.Contains(state, "externally"):
		if !contains(show, "record: none") {
			t.Errorf("NetworkManager does not manage %s (%q), but pf uplink show says:\n%s", wan, state, show)
		}
	case strings.HasPrefix(state, "connected"):
		if !lineWith(show, "record: ", " on "+wan) {
			t.Errorf("%s is %q, but the record is not for it:\n%s", wan, state, show)
		}
	default:
		t.Skipf("%s is %q now: the record of the last apply cannot be checked against it", wan, state)
	}
}

// One check, started by hand: it ends with success, and the journal shows
// no refusal of the sandbox or of NetworkManager.
func uplinkWatchCheckTests(t *testing.T) {
	if out, err := ssh(t, 2*time.Minute, "pi", "sudo systemctl start "+uplinkWatchUnit); err != nil {
		t.Fatalf("start %s: %v\n%s", uplinkWatchUnit, err, out)
	}
	if out := strings.TrimSpace(pi(t, "systemctl show -p Result --value "+uplinkWatchUnit)); out != "success" {
		t.Errorf("%s result %q", uplinkWatchUnit, out)
	}
	log := pi(t, "sudo journalctl -u "+uplinkWatchUnit+" -n 40 --no-pager -o cat")
	for _, bad := range []string{"operation not permitted", "read-only file system", "permission denied", "not authorized"} {
		if strings.Contains(strings.ToLower(log), bad) {
			t.Errorf("the journal of %s has %q:\n%s", uplinkWatchUnit, bad, log)
		}
	}
}

var uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// A dummy connection, down, is the recorded uplink for the length of the
// test. The first check waits, the second runs nmcli connection up, the
// third sees it active and writes the row, and the alert sidecar logs its
// line. The box gets its record, its state and its timer back.
func uplinkWatchStandInTests(t *testing.T) {
	if out, _ := ssh(t, 15*time.Second, "pi", "nmcli -t -f RUNNING general 2>/dev/null"); strings.TrimSpace(out) != "running" {
		t.Skip("NetworkManager does not run on this gateway")
	}
	if out, _ := ssh(t, 15*time.Second, "pi", "sudo modprobe -n -q dummy && echo ok"); strings.TrimSpace(out) != "ok" {
		t.Skip("no dummy module in this kernel")
	}
	const (
		con      = "itest-uplink-standin"
		ifn      = "pfitest0"
		bak      = uplinkRecord + ".itest-bak"
		stateBak = uplinkStateDir + "/watch.json.itest-bak"
		delAll   = "for u in $(nmcli -t -f UUID,NAME con show | awk -F: '$2 == \"" + con + "\" {print $1}'); do sudo nmcli con delete uuid \"$u\" >/dev/null; done"
	)
	// A run that was killed can leave its stand-in behind.
	pi(t, delAll)
	since := strings.TrimSpace(pi(t, "date '+%Y-%m-%d %H:%M:%S'"))
	timerWas := strings.TrimSpace(pi(t, "systemctl is-active "+uplinkWatchTimer+" 2>&1 || true"))
	t.Cleanup(func() {
		if out, err := ssh(t, 30*time.Second, "pi", delAll); err != nil {
			t.Errorf("RESTORE: could not delete the stand-in connection %s: %v\n%s", con, err, out)
		}
		restore := "sudo sh -c 'if [ -e " + bak + " ]; then mv -f " + bak + " " + uplinkRecord + "; else rm -f " + uplinkRecord + "; fi; " +
			"rm -f " + uplinkStateDir + "/watch.json; if [ -e " + stateBak + " ]; then mv -f " + stateBak + " " + uplinkStateDir + "/watch.json; fi'"
		if out, err := ssh(t, 30*time.Second, "pi", restore); err != nil {
			t.Errorf("RESTORE: the uplink record and state did not come back: %v\n%s", err, out)
		}
		if timerWas == "active" {
			if out, err := ssh(t, 30*time.Second, "pi", "sudo systemctl start "+uplinkWatchTimer); err != nil {
				t.Errorf("RESTORE: %s did not start again: %v\n%s", uplinkWatchTimer, err, out)
			}
		}
	})
	// The timer must not run a check between the steps below.
	pi(t, "sudo systemctl stop "+uplinkWatchTimer)
	pi(t, "sudo sh -c 'rm -f "+bak+" "+stateBak+"; if [ -e "+uplinkRecord+" ]; then cp -p "+uplinkRecord+" "+bak+"; fi; "+
		"if [ -e "+uplinkStateDir+"/watch.json ]; then mv "+uplinkStateDir+"/watch.json "+stateBak+"; fi'")

	pi(t, "sudo nmcli con add type dummy ifname "+ifn+" con-name "+con+" ipv4.method disabled ipv6.method disabled connection.autoconnect no >/dev/null")
	uuid := strings.TrimSpace(pi(t, "nmcli -g connection.uuid con show id "+con))
	if !uuidShape.MatchString(uuid) {
		t.Fatalf("the stand-in has no usable UUID: %q", uuid)
	}
	rec := `{"uuid":"` + uuid + `","name":"` + con + `","device":"` + ifn + `"}`
	pi(t, "printf '%s\\n' '"+rec+"' | sudo tee "+uplinkRecord+" >/dev/null")

	activeState := func() string {
		t.Helper()
		for line := range strings.SplitSeq(pi(t, "nmcli -t -f UUID,STATE con show --active"), "\n") {
			if u, s, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && u == uuid {
				return s
			}
		}
		return ""
	}
	check := func(n int) {
		t.Helper()
		if out, err := ssh(t, 2*time.Minute, "pi", "sudo systemctl start "+uplinkWatchUnit); err != nil {
			t.Fatalf("check %d: %v\n%s", n, err, out)
		}
	}
	journal := func() string {
		return pi(t, "sudo journalctl -u "+uplinkWatchUnit+" --since '"+since+"' --no-pager -o cat")
	}
	if s := activeState(); s != "" {
		t.Fatalf("the stand-in is %q before the first check; it must be down", s)
	}
	check(1)
	if s := activeState(); s != "" {
		t.Fatalf("one check activated the stand-in (%q); the watchdog must wait for a second check:\n%s", s, journal())
	}
	check(2)
	if s := activeState(); s != "activated" {
		t.Fatalf("after the second check the stand-in is %q, want activated:\n%s", s, journal())
	}
	if j := journal(); !contains(j, "nmcli connection up "+uuid+": done") {
		t.Errorf("the journal does not show the try:\n%s", j)
	}
	check(3)
	row := pi(t, "tail -n 1 "+uplinkStateDir+"/events.jsonl")
	if !contains(row, `"uuid":"`+uuid+`"`) || !contains(row, `"rule":"uplink_back"`) || !contains(row, `"tries":1`) {
		t.Fatalf("the last event row is not the return of the stand-in:\n%s", row)
	}
	want := "UPLINK BACK " + ifn + " (" + con + ")"
	deadline := time.Now().Add(20 * time.Second)
	for {
		out := pi(t, "sudo journalctl -u pi-fortress-alert --since '"+since+"' --no-pager -o cat")
		if contains(out, want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the alert sidecar did not read the row in 20 s (no %q in its journal):\n%s", want, out)
		}
		time.Sleep(2 * time.Second)
	}
}
