package tui

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"pi-fortress/internal/admin"
)

// setting is one row of a Settings view: the key in the file, the name that
// an operator reads, and the line that the view shows under the list while
// the row is selected. That line also shows the key, for people who edit
// the file by hand.
type setting struct{ key, label, help string }

type settingGroup struct {
	name  string
	items []setting
}

// houseGroups is each key in admin.HouseKeys, one time each (a test makes
// sure of this). The groups follow the task of an operator, not the
// position in house.env.
var houseGroups = []settingGroup{
	{"Filtering", []setting{
		{"HOUSE_BLOCK_DIRECT_IP", "Block direct-IP connections", "on drops a web connection to an address the house DNS did not hand out. Exceptions: Filtering > Direct-IP exceptions."},
		{"HOUSE_BLOCK_HTTP", "Block plain HTTP", "on rejects all unencrypted web (port 80). Can break captive portals, some TVs and printers, old mirrors."},
		{"HOUSE_BLOCK_VPN", "Block devices' own VPNs", "on drops WireGuard, OpenVPN, Tailscale, WARP and VPN/proxy domains, so no device routes around the filter."},
	}},
	{"Apps & ports", []setting{
		{"HOUSE_EGRESS", "Outbound ports", "strict: web, mail, push, NTP, ping and the switches below. audit: log what strict would drop, pass it. open: any port. Enter cycles."},
		{"HOUSE_ALLOW_WIFI_CALLING", "Wi-Fi calling", "on opens IPsec (UDP 500/4500, ESP) to anywhere; IKEv2 VPNs get through too."},
		{"HOUSE_ALLOW_CALL_UDP", "Call apps' UDP", "Meet, Zoom, Teams, WhatsApp, FaceTime media. Off, calls relay over TCP 443 with a little more delay."},
		{"HOUSE_ALLOW_WHATSAPP", "WhatsApp messages", "on lets WhatsApp's non-TLS chat reach Meta's ranges only. Off, WhatsApp messages stop on this network."},
		{"HOUSE_ALLOW_PORTS", "Extra ports", "For a game or a one-off, e.g. tcp:27015-27030 udp:3074. A TLS port named here skips the name check."},
	}},
	{"DNS & VPN", []setting{
		{"HOUSE_DNS_UPSTREAM", "Upstream DNS", "Plain DNS server for house lookups. Empty uses the box's (System > Settings); refused while the box uses DoT."},
		{"HOUSE_DOT_AUTH_NAME", "DoT provider name", "The house's own DNS-over-TLS provider, e.g. a Control D profile. Set with its addresses; both empty shares the box's."},
		{"HOUSE_DOT_IPS", "DoT provider addresses", "The house's own DNS-over-TLS provider, e.g. a Control D profile. Set with its name; both empty shares the box's."},
		{"HOUSE_PRIVATE_DNS", "Allow Private DNS", "on lets devices use your own secure-DNS endpoint (Filtering > Private DNS); the Pi then does not filter their DNS."},
		{"WG_IF", "VPN tunnel", "WireGuard interface the house leaves through, e.g. wg0. Kill switch: tunnel down, house offline. Empty: plain uplink."},
		{"WG_BYPASS_MARK", "Tunnel bypass mark", "fwmark for destinations that skip the tunnel (banks, UPI). Leave it unless you know you need it."},
	}},
	{"Network", []setting{
		{"HOUSE_IF", "Interface", "The Ethernet port cabled to the Wi-Fi router in access-point mode, e.g. eth1."},
		{"HOUSE_NET", "Subnet", "The home network's address range, e.g. 10.78.0.0/24."},
		{"HOUSE_IP", "Pi's address", "The Pi on this network: every device's gateway and DNS."},
		{"HOUSE_DHCP_START", "DHCP range start", "First address handed to a new device."},
		{"HOUSE_DHCP_END", "DHCP range end", "Last address handed to a new device."},
		{"HOUSE_ADMIN_IP", "Admin machine", "The one house address that may ssh to the Pi and the agent. Reserve it first (Devices, r). Empty: none."},
	}},
}

// netGroups are the groups of net.env.local. The first is the resolver of
// the Pi, and the uplink. The agents use that resolver, and the house
// shares it unless it has its own. The second is how the agent segment
// resolves. The third is the connection budgets of each segment class.
// All of admin.NetKeys, one time each.
var netGroups = []settingGroup{
	{"Resolver & uplink", []setting{
		{"DNS_UPSTREAM", "Upstream DNS", "Plain DNS server for the Pi and the agents, used when no DoT provider is set."},
		{"DOT_AUTH_NAME", "DoT provider name", "DNS-over-TLS for the Pi and the agents; the house shares it unless it has its own. Set with its addresses."},
		{"DOT_IPS", "DoT provider addresses", "DNS-over-TLS for the Pi and the agents; the house shares it unless it has its own. Set with its name."},
		{"UNTRUSTED_UPLINK", "Untrusted uplink", "1 closes ssh and every Pi service on the uplink, for public Wi-Fi. Way back in: a segment with ADMIN=yes."},
	}},
	{"Agent DNS", []setting{
		{"AGENT_DNS", "Agent DNS mode", "forward: real answers from upstream. fakeip: a pool address per name, nothing forwarded, so names cannot carry data out; ssh_allow by name stops. Enter flips."},
		{"FAKEIP_NET", "Fake-IP pool", "IPv4 /16 to /24 fakeip answers from, inside a private or benchmark range and clear of every segment. Empty: " + admin.DefaultFakeIPNet + "."},
	}},
	{"Connection budgets", []setting{
		{"AGENT_CONN_PER_IP", "Agent: flows per device", "Live connections one agent address may hold. 0 off; empty the default. Too low breaks npm and browsers."},
		{"AGENT_NEW_PER_IP", "Agent: new flows per device", "New connections a second one agent address may open, RATE/BURST, e.g. 50/200. 0 off."},
		{"AGENT_CONN_TOTAL", "Agent: flows in total", "Live connections the whole agent segment may hold. 0 off. Keeps one agent from filling the Pi's table."},
		{"HOUSE_CONN_PER_IP", "House: flows per device", "Live connections one house address may hold. 0 off. A phone peaks at a few hundred."},
		{"HOUSE_NEW_PER_IP", "House: new flows per device", "New connections a second one house address may open, RATE/BURST, e.g. 100/500. 0 off."},
		{"HOUSE_CONN_TOTAL", "House: flows in total", "Live connections the whole house may hold. 0 off."},
		{"HOUSE_NEW_TOTAL", "House: new flows in total", "New TCP connections a second the whole house may open, RATE/BURST, e.g. 1000/5000. 0 off. Keeps many addresses from filling the Pi's table."},
		{"SEG_CONN_PER_IP", "Segments: flows per device", "Live connections one address on a plain segment (e.g. the desk) may hold. 0 off. One value for every plain segment."},
		{"SEG_NEW_PER_IP", "Segments: new flows/device", "New connections a second one address on a plain segment may open, RATE/BURST. 0 off."},
		{"SEG_CONN_TOTAL", "Segments: flows in total", "Live connections each plain segment may hold. 0 off."},
		{"SEG_NEW_TOTAL", "Segments: new flows in total", "New TCP connections a second each plain segment may open, RATE/BURST, e.g. 300/600. 0 off. Keeps many addresses from filling the Pi's table."},
	}},
}

// netSettings is netGroups in row order.
var netSettings = func() []setting {
	var out []setting
	for _, g := range netGroups {
		out = append(out, g.items...)
	}
	return out
}()

var segmentSettings = map[string]setting{
	"IF":              {"IF", "Interface", ""},
	"NET":             {"NET", "Subnet", ""},
	"IP":              {"IP", "Pi's address", ""},
	"ADMIN":           {"ADMIN", "SSH to the Pi from here", "yes lets this network ssh to the Pi. Turning it off from here ends your session at the next apply."},
	"SSH_TO":          {"SSH_TO", "SSH to agents", "Agent addresses this network may ssh to: one address or an a-b range in the agent network. Empty: none."},
	"BLOCK_DIRECT_IP": {"BLOCK_DIRECT_IP", "Block direct-IP connections", "on drops new connections, any port, to addresses this network's DNS did not hand out. off leaves only the blocklist."},
	"PARANOID":        {"PARANOID", "Paranoid (allowlist only)", "on: this network resolves only the names in its own allowlist file, and needs Block direct-IP connections on. Apply refuses it while the file is missing or empty."},
	"DHCP":            {"DHCP", "DHCP server", "on: the Pi hands out addresses here from the range below, as on the house. Set the range first. On a house-cable VLAN the AP's own DHCP must be off."},
	"DHCP_START":      {"DHCP_START", "DHCP range start", "First address handed to a new device, inside this network. Enter asks for both ends; the Pi's own address may not fall inside."},
	"DHCP_END":        {"DHCP_END", "DHCP range end", "Last address handed to a new device. Enter asks for both ends. Fixed addresses go in the reservations file, inside the range or not."},
}

const setFmt = "  %-28s %s"

// setTarget is what Enter on a Settings row acts on: the key, and the file
// that holds it: house.env, net.env.local, or the file of one plain
// segment.
type setTarget struct {
	key  string
	net  bool
	seg  string
	help string
}

func (a *App) buildSettings() []row {
	switch a.cur.net {
	case netHouse:
		return a.houseSettings()
	case netSystem:
		return a.netSettingRows()
	case netAgent:
		return a.agentSettings()
	}
	return a.segmentSettingRows(a.cur.net)
}

func (a *App) settingRow(label, value string, t setTarget) row {
	a.setRows = append(a.setRows, t)
	return row{fmt.Sprintf(setFmt, label, value), true}
}

func (a *App) houseSettings() []row {
	env := get[map[string]string](a, "house.env.get", admin.Args{})
	rows := []row{{text: "Saved to " + a.cfg.HouseEnv + "; takes effect at the next apply (A)"}}
	for _, g := range houseGroups {
		rows = append(rows, row{text: ""}, row{text: g.name})
		for _, s := range g.items {
			rows = append(rows, a.settingRow(s.label, houseValue(s.key, env[s.key]), setTarget{key: s.key, help: s.help}))
		}
	}
	return rows
}

// houseValue names a default as a default, and says what an empty key
// means. It does not leave a blank column to interpret.
func houseValue(key, v string) string {
	if v != "" {
		return v
	}
	if def, ok := admin.HouseOnOff[key]; ok {
		return def + " (default)"
	}
	switch key {
	case "HOUSE_EGRESS":
		return "strict (default)"
	case "HOUSE_DNS_UPSTREAM", "HOUSE_DOT_AUTH_NAME", "HOUSE_DOT_IPS":
		return "(the box's)"
	case "WG_IF":
		return "(none: plain uplink)"
	}
	return "(none)"
}

// netSettingRows is the Settings of System. It shows the overlay, not the
// shipped file. DoT is intended to be enabled by an overlay edit, because
// a ship overwrites net.env and keeps net.env.local. A seat that read only
// the base file told an operator that the provider was off while the box
// ran it.
func (a *App) netSettingRows() []row {
	env := get[map[string]string](a, "net.env.get", admin.Args{})
	rows := []row{{text: "The Pi and the agents: " + a.cfg.NetEnvLocal + "; takes effect at the next apply (A)"}}
	for _, g := range netGroups {
		rows = append(rows, row{text: ""}, row{text: g.name})
		for _, s := range g.items {
			rows = append(rows, a.settingRow(s.label, netValue(s.key, env[s.key]), setTarget{key: s.key, net: true, help: s.help}))
		}
	}
	return rows
}

// netValue is houseValue for net.env. It names an absent line as the
// default that it means, and shows a budget of 0 as off.
func netValue(key, v string) string {
	if v == "" {
		if def, ok := admin.NetOnOff[key]; ok {
			return def + " (default)"
		}
		if cs, ok := admin.NetChoices[key]; ok {
			return cs[0] + " (default)"
		}
	}
	switch {
	case v == "" && slices.Contains(admin.NetDoT, key):
		return "(off: plain DNS to the upstream)"
	case v == "" && key == "FAKEIP_NET":
		return admin.DefaultFakeIPNet + " (default)"
	case isConnKey(key) && v == "":
		return "(default)"
	case isConnKey(key) && v == "0":
		return "0 (off)"
	}
	return v
}

func isConnKey(key string) bool {
	return strings.HasSuffix(key, "_CONN_PER_IP") || strings.HasSuffix(key, "_NEW_PER_IP") || strings.HasSuffix(key, "_CONN_TOTAL") || strings.HasSuffix(key, "_NEW_TOTAL")
}

// agentSettings has nothing to edit. Apart from the resolver, the rules of
// the agent network are the fence, and that is its purpose. The rows say
// what the fence does, and where the knobs that do exist are.
func (a *App) agentSettings() []row {
	env := get[map[string]string](a, "net.env.get", admin.Args{})
	dns := env["DNS_UPSTREAM"]
	if n := env["DOT_AUTH_NAME"]; n != "" {
		dns = "DoT " + n
	}
	// An absent AGENT_DNS is fakeip, the default of render. Only forward asks.
	if env["AGENT_DNS"] != "forward" {
		dns = "fake-IP from " + netValue("FAKEIP_NET", env["FAKEIP_NET"]) + "; the broker asks " + dns + " on connect"
	}
	return []row{
		{text: "Fixed by the fence; nothing here is editable."},
		{text: ""},
		{text: fmt.Sprintf(setFmt, "DNS", dns+"  (System > Settings)")},
		{text: fmt.Sprintf(setFmt, "Direct-IP connections", "blocked; exceptions: Filtering")},
		{text: fmt.Sprintf(setFmt, "Plain HTTP", "blocked; only the Pi's own page")},
		{text: fmt.Sprintf(setFmt, "IPv6, QUIC, own DNS", "blocked")},
		{text: fmt.Sprintf(setFmt, "API keys", "only to their own service (Keys)")},
	}
}

// segmentSettingRows is one plain segment: its location, read-only, and
// the keys that a seat can write.
func (a *App) segmentSettingRows(seg string) []row {
	env := get[map[string]string](a, "segment.env", admin.Args{Name: seg})
	rows := []row{{text: "Saved to " + filepath.Join(a.cfg.SegmentsDir, seg+".env") + "; takes effect at the next apply (A)"}, {text: ""}}
	for _, k := range admin.SegmentFixed {
		rows = append(rows, row{text: fmt.Sprintf(setFmt, segmentSettings[k].label, env[k])})
	}
	rows = append(rows, row{text: "  (" + strings.Join(admin.SegmentFixed, ", ") + " move the segment: edit the file and reboot)"}, row{text: ""})
	for _, k := range admin.SegmentKeys {
		s := segmentSettings[k]
		rows = append(rows, a.settingRow(s.label, segmentValue(k, env[k]), setTarget{key: k, seg: seg, help: s.help}))
		// The one setting here that removes something and says so
		// nowhere else. Off leaves the segment with the blacklist and the
		// sinkhole, and with no gate at all on an address that it was never
		// handed.
		if k == "BLOCK_DIRECT_IP" && env[k] == "off" {
			rows = append(rows, row{text: fmt.Sprintf(setFmt, "", "the resolved-address gate is off for this network")})
		}
		if k == "PARANOID" && env[k] == "on" {
			rows = append(rows, row{text: fmt.Sprintf(setFmt, "", "allowlist: "+admin.SegmentAllowPath(a.cfg.SegmentsDir, seg))})
		}
		// Reservations are a file, like the allowlist. This row names it. The
		// operator edits it by hand, and the next apply checks it.
		if k == "DHCP" && env[k] == "on" {
			rows = append(rows, row{text: fmt.Sprintf(setFmt, "", "reservations: "+admin.SegmentHostsPath(a.cfg.SegmentsDir, seg)+" (MAC,IP[,name] a line)")})
		}
	}
	return rows
}

// segmentValue is the value column. It names the default as a default,
// and shows an empty SSH_TO in words.
func segmentValue(key, v string) string {
	def, ok := admin.SegmentDefaults[key]
	switch {
	case !ok || v != def:
		return v
	case v == "":
		return "(none)"
	}
	return v + " (default)"
}

// settingHelp is the explanation of the selected row, wrapped to the lines
// that the view keeps for it under the list.
func (a *App) settingHelp() []string {
	if a.cur.sec != secSettings {
		return nil
	}
	i := a.selected()
	if i < 0 || i >= len(a.setRows) {
		return nil
	}
	t := a.setRows[i]
	// The key first: the code clips a long explanation, never the key.
	return wrap("["+t.key+"] "+t.help, a.contentWidth(), helpLines)
}

const helpLines = 3

func (a *App) contentWidth() int {
	if a.w >= 40 {
		return a.w - menuWidth
	}
	return max(a.w, 1)
}

// wrap breaks s at spaces into a maximum of n lines of w. The code clips
// the last line.
func wrap(s string, w, n int) []string {
	var out []string
	for len(s) > w && len(out) < n-1 {
		i := strings.LastIndexByte(s[:w+1], ' ')
		if i <= 0 {
			i = w
		}
		out = append(out, s[:i])
		s = strings.TrimLeft(s[i:], " ")
	}
	return append(out, clip(s, w))
}

// settingsEdit is Enter on a Settings row. The DoT keys are the reason that
// it is not one ask for each key. pf render refuses a provider name without
// its addresses, and refuses the addresses without the name. Thus Enter on
// either asks for both and sends them as one edit.
//
// Four edits ask y/N first, and only four: ADMIN of a segment,
// UNTRUSTED_UPLINK of the box, WG_IF of the house and HOUSE_EGRESS=open.
// Their cost is the way in of the operator, the way out of the full house,
// or the port filter of the full house. The cost comes at the next apply,
// not at the press. An operator who gets a question for each row reads
// none of them.
func (a *App) settingsEdit(i int) {
	if i < 0 || i >= len(a.setRows) {
		return
	}
	t := a.setRows[i]
	key := t.key
	switch {
	case t.seg != "":
		a.segmentEdit(t.seg, key)
	case t.net:
		a.netEdit(key)
	default:
		a.houseEdit(key)
	}
}

func (a *App) houseEdit(key string) {
	save := func(v string) {
		if a.do("house.env.set", admin.Args{Key: key, Value: v}, key+"="+v+" saved") {
			a.saved(applyFull)
		}
	}
	if _, ok := admin.HouseOnOff[key]; ok {
		env := get[map[string]string](a, "house.env.get", admin.Args{})
		save(houseOnOffFlip(key, env[key]))
		return
	}
	if slices.Contains(admin.HouseDoT, key) {
		a.askPair(admin.HouseDoT, "house.env.set", "house DoT provider saved")
		return
	}
	if key == "HOUSE_EGRESS" {
		env := get[map[string]string](a, "house.env.get", admin.Args{})
		v := egressNext(env[key])
		if v == "open" {
			a.confirm("open lets the house leave by any port from the next apply", func() { save(v) })
			return
		}
		save(v)
		return
	}
	env := get[map[string]string](a, "house.env.get", admin.Args{})
	a.askValue(key, env[key], func(v string) {
		// A tunnel name arms a kill-switch. With WG_IF set, the house WAN
		// path logs and drops, and does not accept. Render intentionally
		// never checks that the name is an interface that exists. Thus a typo
		// here takes the full house offline at the next apply. To clear it
		// removes the kill switch, so that also asks.
		if key == "WG_IF" && v != "" {
			a.confirm("from the next apply the house gets out through "+v+" or not at all", func() { save(v) })
			return
		}
		if key == "WG_IF" {
			a.confirm("from the next apply the house leaves without the tunnel", func() { save(v) })
			return
		}
		save(v)
	})
}

// egressNext is the value that Enter writes for HOUSE_EGRESS. It steps
// from the tightest mode to the loosest, and then to the start again.
func egressNext(cur string) string {
	switch cur {
	case "", "strict":
		return "audit"
	case "audit":
		return "open"
	}
	return "strict"
}

func (a *App) netEdit(key string) {
	save := func(v string) {
		if a.said("net.env.set", admin.Args{Env: map[string]string{key: v}}, key+"="+v+" saved") {
			a.saved(applyFull)
		}
	}
	if def, ok := admin.NetOnOff[key]; ok {
		env := get[map[string]string](a, "net.env.get", admin.Args{})
		v := netFlip(env[key], def)
		// To arm the uplink is the one change here that can end the
		// session that makes it. The operator is usually connected with ssh
		// over the same interface that the next apply closes. Off is one
		// press, because it only gives back a way in that the operator
		// already had. The prompt stays inside 80 columns, so the [y/N] stays
		// after the clip.
		if key == "UNTRUSTED_UPLINK" && v == "1" {
			a.confirm("ssh on the uplink stops at the next apply; way back: ADMIN=yes segment", func() { save(v) })
			return
		}
		save(v)
		return
	}
	if slices.Contains(admin.NetDoT, key) {
		a.askPair(admin.NetDoT, "net.env.set", "DoT provider saved")
		return
	}
	// The operator can go back from either agent DNS mode with one
	// press, and neither mode removes the way in of the seat. Thus the
	// change does not ask.
	if cs, ok := admin.NetChoices[key]; ok {
		env := get[map[string]string](a, "net.env.get", admin.Args{})
		save(choiceNext(cs, env[key]))
		return
	}
	env := get[map[string]string](a, "net.env.get", admin.Args{})
	a.askValue(key, env[key], save)
}

// choiceNext is the value after cur in cs, and then the first again. An
// absent or unknown value counts as the first, so the press writes the
// second.
func choiceNext(cs []string, cur string) string {
	i := slices.Index(cs, cur)
	if i < 0 {
		i = 0
	}
	return cs[(i+1)%len(cs)]
}

// Apply scopes: what an edit needs before it takes effect.
const (
	applyLocal = "local"
	applyFull  = "full"
)

// saved records an edit that waits for an apply. The wider scope wins: a
// list edit after a house.env edit still needs the full apply.
func (a *App) saved(scope string) {
	a.edits++
	if scope == applyFull || a.pending == "" {
		a.pending = scope
	}
	a.msg += "; A applies"
}

// applyPending is A: confirm, then run the apply that the saved edits need
// on System > Actions, where its output streams.
func (a *App) applyPending() {
	scope := a.pending
	if scope == "" {
		scope = applyFull
	}
	label := "run pf apply now"
	if scope == applyLocal {
		label = "run pf apply --local now"
	}
	a.confirm(label, func() { a.runApply(scope) })
}

func (a *App) runApply(scope string) {
	if a.paneBusy {
		a.msg = "an action is already running"
		return
	}
	title, args := "pf apply", admin.Args{}
	if scope == applyLocal {
		title, args.Local = title+" --local", true
	}
	a.goTo(netSystem, secActions)
	a.stream(title, "apply", args)
	if a.paneBusy {
		a.applying = &applyRun{scope: scope, edits: a.edits}
	}
}

// applyRun is an A apply in progress. Refer to App.applying.
type applyRun struct {
	scope string
	edits int
}
