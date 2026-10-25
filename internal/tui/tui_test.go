package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/www"
)

func testConfig(t *testing.T) (*admin.Config, *[][]string) {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policy, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"policy/house.domains":            "ads.example\n",
		"policy/house_direct_ip.allow":    "76.76.2.0/24\n",
		"policy/house_default.domains":    "youtube.com\n",
		"policy/blacklist.domains":        "pi-fortress-block.test\n",
		"policy/sources.json":             `{"feeds":[{"id":"f1","kind":"domains","format":"plain","url":"http://x"}]}`,
		"house.env":                       "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=\n",
		"house.hosts":                     "aa:bb:cc:dd:ee:01,10.78.0.20,mac\n",
		"house.leases":                    "1893456000 aa:bb:cc:dd:ee:02 10.78.0.101 phone *\n",
		"secrets.env":                     "",
		"net.env":                         "AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nAGENT_IP=10.77.0.10\nDNS_UPSTREAM=9.9.9.9\n",
		"observe.json":                    `{"dns":{},"flows":{},"started":"2026-01-01T00:00:00Z"}`,
		"strip.jsonl":                     `{"host":"api.example"}` + "\n",
		"monitor/system-2026-01-01.jsonl": `{"ts":"2026-01-01T00:00:00Z","cpu_pct":3.2,"load1":0.5,"mem_used_mb":281,"mem_used_pct":3.5,"wifi":{"wlan0":{"quality":60,"level_dbm":-55}},"net":{"wlan0":{"rx_kbps":1.5,"tx_kbps":0.5}}}` + "\n",
		"policy/generated/x.report":       "",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	calls := &[][]string{}
	c := &admin.Config{
		PolicyDir:   policy,
		HouseEnv:    filepath.Join(dir, "house.env"),
		NetEnvPath:  filepath.Join(dir, "net.env"),
		NetEnvLocal: filepath.Join(dir, "net.env.local"),
		HouseHosts:  filepath.Join(dir, "house.hosts"),
		HouseLeases: filepath.Join(dir, "house.leases"),
		SecretsPath: filepath.Join(dir, "secrets.env"),
		ObservePath: filepath.Join(dir, "observe.json"),
		OffsetPath:  filepath.Join(dir, "dns.offset"),
		DNSLogPath:  filepath.Join(dir, "dns.jsonl"),
		HouseDNSLog: filepath.Join(dir, "dns-house.jsonl"),
		StripLog:    filepath.Join(dir, "strip.jsonl"),
		AlertLast:   filepath.Join(dir, "alert.last"),
		MonitorDir:  filepath.Join(dir, "monitor"),
		LockPath:    filepath.Join(dir, "apply.lock"),
		PfCmd:       []string{"/bin/echo", "pf"},
		Net:         map[string]string{"AGENT_IP": "10.77.0.10"},
		Ifaces: func() []admin.Iface {
			return []admin.Iface{{Name: "eth0", Up: true, Addrs: []string{"10.77.0.1/24"}}, {Name: "wlan0", Up: true, Addrs: []string{"192.0.2.10/24"}}}
		},
		Exec: func(_ context.Context, argv []string) ([]byte, error) {
			*calls = append(*calls, argv)
			if argv[0] == "systemctl" && argv[1] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, errors.New("fake exec: " + strings.Join(argv, " "))
		},
	}
	return c, calls
}

func run(t *testing.T, c *admin.Config, f *Fake) *Fake {
	t.Helper()
	if err := New(c, f).Run(); err != nil {
		t.Fatal(err)
	}
	if f.Raw {
		t.Fatal("terminal not restored")
	}
	return f
}

func TestEveryScreenRenders(t *testing.T) {
	c, _ := testConfig(t)
	for _, size := range [][2]int{{80, 24}, {20, 5}, {120, 40}} {
		f := NewFake(size[0], size[1])
		for i, e := range buildNets(nil) {
			f.Type(fmt.Sprint(i + 1))
			for range e.secs {
				f.Press(KeyTab, KeyDown, KeyPgDn, KeyEnd, KeyHome, KeyTab).Type("l")
			}
		}
		f.Type("?").Press(KeyEnter, KeyEsc).Type("q")
		run(t, c, f)
		last := f.Last()
		if size[0] >= 40 && !strings.Contains(last, "Actions") {
			t.Fatalf("%dx%d:\n%s", size[0], size[1], last)
		}
		if strings.Count(last, "\n") != size[1]-1 {
			t.Fatalf("%dx%d rows: %d", size[0], size[1], strings.Count(last, "\n"))
		}
	}
}

func TestStatusShowsHealthAndWifi(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(100, 40).Type(keys(netSystem, secHealth)))
	last := f.Last()
	for _, want := range []string{"nftables", "active", "wlan0", "-55 dBm", "leases 1", "wireguard  not configured", "apply      idle"} {
		if !strings.Contains(last, want) {
			t.Fatalf("missing %q:\n%s", want, last)
		}
	}
}

func TestHouseDomainAddDeleteThroughPrompts(t *testing.T) {
	c, _ := testConfig(t)
	path := filepath.Join(c.PolicyDir, "house.domains")
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a").Type("Tracker.Example").Press(KeyEnter)
	run(t, c, f)
	if got, _ := os.ReadFile(path); string(got) != "ads.example\ntracker.example\n" {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(f.Last(), "added tracker.example") {
		t.Fatal(f.Last())
	}
	// The shipped defaults are not a tab. HouseLists is the write
	// allowlist, and a tab would make shipped code editable. Tabs have
	// friendly names. The file name of the list is its heading.
	if s := f.Last(); !strings.Contains(s, "Never block") || !strings.Contains(s, "Blocked sites: house.domains") || strings.Contains(s, "house_default") {
		t.Fatalf("house tabs wrong:\n%s", s)
	}
	f = NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a").Type("not a domain").Press(KeyEnter)
	run(t, c, f)
	if !strings.Contains(f.Last(), "invalid token") {
		t.Fatal(f.Last())
	}
	f = NewFake(80, 24).Type(keys(netHouse, secFiltering) + "jd").Type("n")
	run(t, c, f)
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "tracker.example") {
		t.Fatal("deleted without confirmation")
	}
	f = NewFake(80, 24).Type(keys(netHouse, secFiltering) + "jd").Type("y")
	run(t, c, f)
	if got, _ := os.ReadFile(path); string(got) != "ads.example\n" {
		t.Fatalf("%q", got)
	}
	f = NewFake(80, 24).Type(keys(netHouse, secFiltering)+"a").Type("xyz").Press(KeyBackspace, KeyBackspace, KeyBackspace, KeyEsc)
	run(t, c, f)
	if got, _ := os.ReadFile(path); string(got) != "ads.example\n" || !strings.Contains(f.Last(), "cancelled") {
		t.Fatalf("%q %s", got, f.Last())
	}
}

func TestDevicesReserveAndDelete(t *testing.T) {
	c, calls := testConfig(t)
	f := NewFake(100, 24).Type(keys(netHouse, secDevices)+"jr").Type("phone").Press(KeyEnter, KeyEnter).Type("y")
	run(t, c, f)
	got, _ := os.ReadFile(c.HouseHosts)
	if !strings.Contains(string(got), "aa:bb:cc:dd:ee:02,10.78.0.2,phone") {
		t.Fatalf("%q\n%s", got, f.Last())
	}
	if last := (*calls)[len(*calls)-1]; strings.Join(last, " ") != "systemctl reload "+admin.HouseDNSUnit {
		t.Fatal(*calls)
	}
	f = NewFake(100, 24).Type(keys(netHouse, secDevices) + "d").Type("y")
	run(t, c, f)
	if got, _ := os.ReadFile(c.HouseHosts); strings.Contains(string(got), "ee:02") || !strings.Contains(string(got), "ee:01") {
		t.Fatalf("%q", got)
	}
}

// When the operator pins a lease, its row moves before the plain leases.
// The cursor must move with it. In one session, reserve the second device,
// then press d. The prompt and the delete must be for that device, not for
// the device that moved into the old index. Found on the Pi, 2026-09-21,
// when the reservation of the admin machine was deleted.
func TestDevicesCursorFollowsTheDeviceItActedOn(t *testing.T) {
	c, _ := testConfig(t)
	before, _ := os.ReadFile(c.HouseHosts)
	reserve := func() *Fake {
		return NewFake(100, 24).Type(keys(netHouse, secDevices)+"jr").Type("phone").Press(KeyEnter, KeyEnter).Type("n")
	}
	f := run(t, c, reserve().Type("d"))
	if !strings.Contains(f.Last(), "delete reservation phone 10.78.0.2 (aa:bb:cc:dd:ee:02)") {
		t.Fatalf("d after a reserve asks about another device:\n%s", f.Last())
	}
	os.WriteFile(c.HouseHosts, before, 0o644)
	run(t, c, reserve().Type("d").Type("y"))
	got, _ := os.ReadFile(c.HouseHosts)
	if strings.Contains(string(got), "ee:02") || !strings.Contains(string(got), "ee:01") {
		t.Fatalf("the delete took the wrong reservation:\n%s", got)
	}
}

func TestFeedsSecretsSettings(t *testing.T) {
	c, _ := testConfig(t)
	run(t, c, NewFake(80, 24).Type(keys(netSystem, secFeeds)+"e").Type("y"))
	if got, _ := os.ReadFile(filepath.Join(c.PolicyDir, "sources.json")); !strings.Contains(string(got), `"enabled": false`) {
		t.Fatalf("%s", got)
	}
	run(t, c, NewFake(80, 24).Type(settingsDown("HOUSE_IF")).Press(KeyEnter, KeyBackspace, KeyBackspace, KeyBackspace, KeyBackspace).Type("eth2").Press(KeyEnter))
	if got, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(got), "HOUSE_IF=eth2") {
		t.Fatalf("%s", got)
	}
	f := run(t, c, NewFake(80, 24).Type(keys(netAgent, secKeys)))
	if !strings.Contains(f.Last(), "no slots") {
		t.Fatal(f.Last())
	}
}

// Enter changes the house web toggles from their defaults. The Settings
// of the agent network say what the fence fixes, and edit nothing.
func TestSettingsHouseWebTogglesAndAgentSection(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(100, 40).Type(settingsDown("HOUSE_BLOCK_DIRECT_IP")).Press(KeyEnter).Type("j").Press(KeyEnter))
	got, _ := os.ReadFile(c.HouseEnv)
	for _, want := range []string{"HOUSE_BLOCK_DIRECT_IP=off\n", "HOUSE_BLOCK_HTTP=on\n"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("no %q in house.env:\n%s", want, got)
		}
	}
	if !strings.Contains(f.Last(), "Home network > Settings") {
		t.Fatalf("not on the home network's settings:\n%s", f.Last())
	}
	f = run(t, c, NewFake(120, 40).Type(keys(netAgent, secSettings)).Press(KeyEnter))
	for _, want := range []string{"Fixed by the fence", "blocked; exceptions: Filtering", "9.9.9.9"} {
		if !strings.Contains(f.Last(), want) {
			t.Fatalf("no %q on the agent network's settings:\n%s", want, f.Last())
		}
	}
	if strings.Contains(f.Last(), "saved") {
		t.Fatalf("Enter edited something on the agent network:\n%s", f.Last())
	}
	run(t, c, NewFake(100, 40).Type(settingsDown("HOUSE_BLOCK_HTTP")).Press(KeyEnter))
	if got, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(got), "HOUSE_BLOCK_HTTP=off\n") {
		t.Fatalf("second Enter did not flip back:\n%s", got)
	}
}

func TestSecretsClaimAndQuarantine(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = t.TempDir()
	_ = os.MkdirAll(filepath.Join(c.WWWDir, "claims"), 0770)
	slot, err := secrets.Open(c.SecretsPath).MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "ghp_live"})
	if err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"c"))
	last := f.Last()
	// The screen must show the one-liner that admin gives it. The curl flags
	// in that line are the concern of admin, and the admin tests assert them.
	if !strings.Contains(last, "claim code for slot "+slot) || !strings.Contains(last, "curl ") || !strings.Contains(last, "http://") || !strings.Contains(last, "expires in") || strings.Contains(last, "ghp_live") {
		t.Fatal(last)
	}
	if evs := www.ReadLedger(filepath.Join(c.WWWDir, "claims")); len(evs) != 1 || evs[0].Ev != "issued" {
		t.Fatalf("%+v", evs)
	}
	f = run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"c").Press(KeyEnter))
	if strings.Contains(f.Last(), "claim code for slot") || !strings.Contains(f.Last(), "never") {
		t.Fatal(f.Last())
	}
	f = run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"x").Type("y"))
	if !strings.Contains(f.Last(), "disabled 0d, purge in 7d") {
		t.Fatal(f.Last())
	}
	f = run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"p").Type("no").Press(KeyEnter))
	if !strings.Contains(f.Last(), "cancelled") {
		t.Fatal(f.Last())
	}
	f = run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"R"))
	if !strings.Contains(f.Last(), "active") {
		t.Fatal(f.Last())
	}
	run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"p").Type("yes").Press(KeyEnter))
	if raw, _ := os.ReadFile(c.SecretsPath); strings.Contains(string(raw), slot) {
		t.Fatal(string(raw))
	}
}

func TestRebootNeedsTypedYes(t *testing.T) {
	c, calls := testConfig(t)
	hasReboot := func() bool {
		for _, argv := range *calls {
			if strings.Join(argv, " ") == "systemctl reboot" {
				return true
			}
		}
		return false
	}
	run(t, c, NewFake(80, 24).Type(keys(netSystem, secActions)).Press(KeyEnd).Press(KeyUp).Press(KeyEnter).Type("y").Press(KeyEnter))
	if hasReboot() {
		t.Fatal("rebooted on y")
	}
	run(t, c, NewFake(80, 24).Type(keys(netSystem, secActions)).Press(KeyEnd).Press(KeyUp).Press(KeyEnter).Type("yes").Press(KeyEnter))
	if !hasReboot() {
		t.Fatal(*calls)
	}
}

func TestHouseActionsSayWhenNoHouseSegment(t *testing.T) {
	c, calls := testConfig(t)
	if f := run(t, c, NewFake(120, 24).Type(keys(netSystem, secActions))); strings.Contains(f.Last(), "not configured") {
		t.Fatalf("house configured, still flagged:\n%s", f.Last())
	}
	if err := os.WriteFile(c.HouseEnv, nil, 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(120, 24).Type(keys(netSystem, secActions)))
	if !strings.Contains(f.Last(), "reload house dns  (house segment not configured)") || !strings.Contains(f.Last(), "restart house dns  (house segment not configured)") {
		t.Fatalf("house actions not flagged:\n%s", f.Last())
	}
	for _, downs := range []int{3, 4} {
		fk := NewFake(120, 24).Type(keys(netSystem, secActions))
		for i := 0; i < downs; i++ {
			fk.Press(KeyDown)
		}
		f = run(t, c, fk.Press(KeyEnter))
		if !strings.Contains(f.Last(), "house not configured: Home network > Settings") {
			t.Fatalf("row %d: no explanation:\n%s", downs, f.Last())
		}
	}
	for _, argv := range *calls {
		if strings.Contains(strings.Join(argv, " "), admin.HouseDNSUnit) && argv[1] != "is-active" {
			t.Fatalf("ran %v with no house segment", argv)
		}
	}
}

func TestResizeRedraws(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24).Type("1")
	f.Resize(30, 8)
	run(t, c, f)
	if n := strings.Count(f.Last(), "\n"); n != 7 {
		t.Fatal(n)
	}
	if strings.Contains(f.Last(), "1 Overview") {
		t.Fatal("menu drawn on a narrow terminal")
	}
}

func TestParseKey(t *testing.T) {
	cases := []struct {
		in   string
		want KeyKind
	}{
		{"\r", KeyEnter}, {"\x7f", KeyBackspace}, {"\t", KeyTab}, {"\x03", KeyCtrlC}, {"\x12", KeyCtrlR},
		{"\x1b", KeyEsc}, {"\x1b[A", KeyUp}, {"\x1bOB", KeyDown}, {"\x1b[5~", KeyPgUp}, {"\x1b[15~", KeyF5},
		{"\x1b[Z", KeyEsc}, {"\x1bx", KeyEsc}, {"j", KeyRune},
	}
	for _, tc := range cases {
		rest := []byte(tc.in[1:])
		next := func(time.Duration) (byte, bool) {
			if len(rest) == 0 {
				return 0, false
			}
			b := rest[0]
			rest = rest[1:]
			return b, true
		}
		if got := parseKey(tc.in[0], next, nil); got.Kind != tc.want {
			t.Fatalf("%q: got %v want %v", tc.in, got.Kind, tc.want)
		}
	}
}

// Esc and a key that arrive in one read (an ssh session that bunches two
// keystrokes) are two keys, not one Esc that swallowed the second.
func TestEscThenKeyInOneReadIsTwoKeys(t *testing.T) {
	for _, in := range []string{"\x1bq", "\x1b3", "\x1b\x1b"} {
		stop := make(chan struct{})
		src := newByteSource(strings.NewReader(in), stop)
		b := <-src.ch
		// Let the pump deliver the rest. Thus it is there within escWait,
		// as it is when both bytes came in one read.
		time.Sleep(10 * time.Millisecond)
		first := parseKey(b, src.next, src.unread)
		b2, ok := src.pending()
		if !ok {
			select {
			case b2 = <-src.ch:
			case <-time.After(time.Second):
				t.Fatalf("%q: the key after Esc was lost", in)
			}
		}
		second := parseKey(b2, src.next, src.unread)
		close(stop)
		want := Key{Kind: KeyRune, Rune: rune(in[1])}
		if in[1] == 0x1b {
			want = Key{Kind: KeyEsc}
		}
		if first.Kind != KeyEsc || second != want {
			t.Fatalf("%q: got %v then %v, want Esc then %v", in, first, second, want)
		}
	}
}

func waitRun(t *testing.T, done <-chan error, limit time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(limit):
		t.Fatal("loop still running")
	}
}

func TestIdleExit(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24).Type("1")
	f.Hold = true
	a := New(c, f)
	a.Idle = 50 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	waitRun(t, done, 3*time.Second)
	if f.Raw {
		t.Fatal("terminal not restored")
	}
	if a.ctx.Err() == nil {
		t.Fatal("action context alive after exit")
	}
}

func TestIdleWaitsForRunningAction(t *testing.T) {
	c, _ := testConfig(t)
	c.PfCmd = []string{"/bin/sh", "-c", "sleep 0.3; echo slow"}
	f := NewFake(80, 24).Type(keys(netSystem, secActions)).Press(KeyEnter)
	f.Hold = true
	a := New(c, f)
	a.Idle = 50 * time.Millisecond
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- a.Run() }()
	waitRun(t, done, 3*time.Second)
	if time.Since(start) < 250*time.Millisecond || !strings.Contains(strings.Join(a.pane, "\n"), "done") {
		t.Fatal(time.Since(start), a.pane)
	}
}

func TestQuitCancelsRunningAction(t *testing.T) {
	c, _ := testConfig(t)
	c.PfCmd = []string{"/bin/sh", "-c", "sleep 30"}
	f := NewFake(80, 24).Type(keys(netSystem, secActions)).Press(KeyEnter)
	f.Hold = true
	a := New(c, f)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(f.Last(), "running...") {
		if time.Now().After(deadline) {
			t.Fatal(f.Last())
		}
		time.Sleep(5 * time.Millisecond)
	}
	a.events <- event{key: Key{Kind: KeyCtrlC}}
	waitRun(t, done, 3*time.Second)
	if a.ctx.Err() == nil {
		t.Fatal("context alive after quit")
	}
	select {
	case ev := <-a.events:
		if ev.done == nil {
			t.Fatal("unexpected event", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("apply child not killed on quit")
	}
}

func TestStatusShowsRebootRequired(t *testing.T) {
	c, _ := testConfig(t)
	c.RebootFlag = filepath.Join(t.TempDir(), "reboot-required")
	if f := run(t, c, NewFake(120, 60).Type(keys(netSystem, secHealth))); strings.Contains(f.Last(), "reboot required") {
		t.Fatal(f.Last())
	}
	if err := os.WriteFile(c.RebootFlag, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if f := run(t, c, NewFake(120, 60).Type(keys(netSystem, secHealth))); !strings.Contains(f.Last(), "reboot required") {
		t.Fatal(f.Last())
	}
	if f := run(t, c, NewFake(120, 24).Type(keys(netSystem, secActions))); !strings.Contains(f.Last(), "fence restarts if any fence input changed") {
		t.Fatal(f.Last())
	}
}

// A verb that answers with the wrong shape must set the message. It must
// not panic the seat out of raw mode while the terminal of the operator
// is in it.
func TestUnexpectedReplyShapeDoesNotPanic(t *testing.T) {
	c, _ := testConfig(t)
	a := New(c, NewFake(80, 24))
	if _, ok := typed[admin.Reservation](a, "not a reservation"); ok {
		t.Fatal("a string was accepted as a Reservation")
	}
	if !strings.Contains(a.msg, "unexpected result") {
		t.Fatalf("msg = %q", a.msg)
	}
	if _, ok := typed[admin.Claim](a, nil); ok {
		t.Fatal("nil was accepted as a Claim")
	}
	a.msg = ""
	want := admin.Reservation{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.78.0.20"}
	got, ok := typed[admin.Reservation](a, want)
	if !ok || got != want || a.msg != "" {
		t.Fatalf("a real reservation was refused: %v %v %q", got, ok, a.msg)
	}
}
