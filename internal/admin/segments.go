package admin

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"pi-fortress/internal/observe"
	"pi-fortress/internal/render"
)

// Segment is one segmented network that this box terminates, as a screen
// needs it: the tag that the rows of the ledger carry, and the network
// behind it.
//
// Before, the front ends had their own list of two, agent and house, in
// the source. No screen could name the clients, events and settings of a
// plain segment in segments.d. The code counted and stored the rows, and
// then a tab strip with no tab for them filtered them away at the last
// step. This verb is the list. Thus there is one answer to "which segments
// are there", and the screens ask it.
type Segment struct {
	Name string `json:"name"`
	Net  string `json:"net"`
	IP   string `json:"ip"`
	// Plain says that this segment is a file in segments.d, not agent or
	// house, which belong to net.env and house.env. A screen needs this field
	// to know for which segments it can offer an editor. The answer comes from
	// here, and the caller does not compare the name against two words. A
	// segments.d file can legally have any name that the name regexp accepts.
	Plain bool `json:"plain"`
}

// Segments answers in screen order: agent first, house when it is
// configured, then segments.d by name. It reads the same files that the
// watch of the observer reads, through the same parser. Thus the screens
// can reach each segment that the ledger tags.
func (c *Config) Segments() []Segment {
	segs := observe.Segments(c.Net, []string{c.HouseEnv}, c.SegmentsDir)
	plain := map[string]bool{}
	for _, s := range observe.PlainSegments(c.SegmentsDir) {
		plain[s.Name] = true
	}
	out := make([]Segment, 0, len(segs))
	for _, s := range segs {
		out = append(out, Segment{Name: s.Name, Net: s.Net, IP: s.IP, Plain: plain[s.Name]})
	}
	return out
}

// SegmentFixed are the keys that a screen shows but does not write. Each
// one says where the segment is, and the seat that makes the change is
// usually on it. ssh to the Pi and the TUI session in it arrive over the IF
// of the desk. A screen that could write that line again could cut the
// session that makes the change, and leave nothing to repair it with. Also,
// a person must move the VLAN child behind IF by hand on the machine at the
// other end of the cable. Thus even a correct edit here would be half a
// change. For these keys, use an editor and a reboot. This is slow
// intentionally.
var SegmentFixed = []string{"IF", "NET", "IP"}

// SegmentKeys are the keys that a seat can write, in screen order. The
// three DHCP keys come after PARANOID, and the connection keys come after
// them, so the rows above them keep their positions.
var SegmentKeys = append([]string{"ADMIN", "SSH_TO", "BLOCK_DIRECT_IP", "PARANOID", "DHCP", "DHCP_START", "DHCP_END"}, SegmentConnKeys...)

// SegmentConnKeys are the connection budget of one plain segment. Each key
// that the file does not have takes the SEG_ value of net.env (render,
// segConnBudget). Thus for these keys, an empty value removes the line and
// does not write it. render reads a line that is present and empty as 0,
// and 0 turns the limit off. That is the opposite of what the operator
// asked for.
var SegmentConnKeys = []string{"CONN_PER_IP", "NEW_PER_IP", "CONN_TOTAL", "NEW_TOTAL"}

// SegmentDHCPRange is set as one edit, as HouseDoT is. pf render refuses
// each end without the other. Thus on a segment with no range yet, a
// screen that wrote one end at a time could never write either end.
var SegmentDHCPRange = []string{"DHCP_START", "DHCP_END"}

// SegmentDefaults is what an absent line means. pf render fills in the
// same value for itself. A row shows the value and says that it is the
// default. For the connection keys, the default is empty: the value then
// comes from net.env, and a screen reads it there.
var SegmentDefaults = map[string]string{"ADMIN": "no", "SSH_TO": "", "BLOCK_DIRECT_IP": "on", "PARANOID": "off", "DHCP": "off", "DHCP_START": "", "DHCP_END": "",
	"CONN_PER_IP": "", "NEW_PER_IP": "", "CONN_TOTAL": "", "NEW_TOTAL": ""}

// SegmentToggle are the keys that Enter changes with one press. Each has
// its two values, with the default first. They are not one pair of words.
// ADMIN is yes/no and BLOCK_DIRECT_IP is on/off, because pf render parses
// them so. A screen that wrote "on" into ADMIN would write a file that the
// next apply refuses.
var SegmentToggle = map[string][2]string{"ADMIN": {"no", "yes"}, "BLOCK_DIRECT_IP": {"on", "off"}, "PARANOID": {"off", "on"}, "DHCP": {"off", "on"}}

var segmentKeys = map[string]func(string) error{
	"ADMIN":           checkYesNo,
	"SSH_TO":          checkRangeOrEmpty,
	"BLOCK_DIRECT_IP": checkOnOffWord,
	"PARANOID":        checkOnOffWord,
	"DHCP":            checkOnOffWord,
	// Not empty: render refuses a DHCP_START line that is present and empty,
	// and setEnvLines cannot remove a line. Render checks whether the address
	// is inside NET, clear of IP and in order, through the candidate
	// directory. This is the same as the AGENT_NET check of SSH_TO.
	"DHCP_START": checkAddr,
	"DHCP_END":   checkAddr,
	// The same check as the SEG_ key of net.env, as render does it. Empty is
	// correct here: setSegmentLines removes the line. The candidate render
	// checks a per-device value against the total of the segment.
	"CONN_PER_IP": checkSegConn("CONN_PER_IP"),
	"NEW_PER_IP":  checkSegConn("NEW_PER_IP"),
	"CONN_TOTAL":  checkSegConn("CONN_TOTAL"),
	"NEW_TOTAL":   checkSegConn("NEW_TOTAL"),
}

func checkSegConn(key string) func(string) error {
	return func(v string) error { return render.CheckConnLimit("SEG_"+key, v) }
}

// SegmentConnInherited is the value of one of SegmentConnKeys for a
// segment file that does not have the key. It is the SEG_ value of net,
// the map that NetEnv gives. When net does not set it either, it is the
// default of render, and def is true. Thus a row shows the number that
// applies, and where it comes from.
func SegmentConnInherited(net map[string]string, key string) (v string, def bool) {
	if v := net["SEG_"+key]; v != "" {
		return v, false
	}
	return render.ConnLimitDefault("SEG_" + key), true
}

// reSegName is a copy of the one in render, not an export, for the same
// reason as reDNSName. If this accepts a name that render refuses, the
// file bricks the next apply. It is also the full path check on a segment
// name: no slash, no dot, and no leading .. gets through it. Thus nothing
// here can point at a file outside segments.d.
var reSegName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,15}$`)

// checkYesNo and checkOnOffWord refuse the empty value that the on/off keys
// of the house allow. pf render reads a segment line that is present and
// empty as neither of its two words, and refuses the full directory
// because of it. Also, setEnvLines writes a line and does not remove one.
// Thus "set it back to the default" must use the word of the default, not
// an empty value.
func checkYesNo(v string) error {
	if v != "yes" && v != "no" {
		return errors.New("want yes or no")
	}
	return nil
}

func checkOnOffWord(v string) error {
	if v != "on" && v != "off" {
		return errors.New("want on or off")
	}
	return nil
}

// checkRangeOrEmpty checks only the shape of SSH_TO. The candidate render
// below checks whether the address is inside AGENT_NET, and whether a range
// is in the correct order. Those checks belong to pf render, and a second
// copy of them here is a copy that can drift.
func checkRangeOrEmpty(v string) error {
	bad := errors.New("want an IPv4 address or a-b range inside AGENT_NET")
	if v == "" {
		return nil
	}
	ends := strings.Split(v, "-")
	if len(ends) > 2 {
		return bad
	}
	for _, e := range ends {
		if checkAddr(e) != nil {
			return bad
		}
	}
	return nil
}

// SegmentAllowPath is the paranoid allowlist of a plain segment, as render
// itself gives it. Thus a screen names the file that apply will check.
func SegmentAllowPath(segmentsDir, name string) string {
	return render.SegmentAllowPath(segmentsDir, name)
}

// SegmentHostsPath is the DHCP reservations file of a plain segment, in the
// house.hosts form, as render itself gives it, for the same reason. It is a
// file beside segments.d, not a key. Thus a screen names it, and the
// operator edits it. The candidate render below still reads it. That is
// how the code refuses DHCP=off under a reservation here, as apply does.
func SegmentHostsPath(segmentsDir, name string) string {
	return render.SegmentHostsPath(segmentsDir, name)
}

// SegmentEnv is the file of one plain segment as a screen needs it: each
// key that the file sets, plus the default for each editable key that it
// does not set. Thus a row can show "no (default)", not an empty column,
// and the operator does not have to guess what an absent line means.
func (c *Config) SegmentEnv(name string) (map[string]string, error) {
	path, err := c.segmentPath(name)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for k, v := range SegmentDefaults {
		env[k] = v
	}
	if err := render.EnvLines(path, func(_ int, key, val string) error {
		env[key] = val
		return nil
	}); err != nil {
		return nil, err
	}
	return env, nil
}

// segmentPath is segments.d/<name>.env for a name that is a segment name
// and a file that already exists. v1 creates nothing. A segment is a file,
// an interface and, for a VLAN child, a stanza on the machine at the other
// end of the cable. A screen that wrote only the first of these would
// promise a network that this box cannot terminate.
func (c *Config) segmentPath(name string) (string, error) {
	if !reSegName.MatchString(name) {
		return "", errors.New(name + " is not a segment name")
	}
	if c.SegmentsDir == "" {
		return "", errors.New("this box has no segments directory")
	}
	path := filepath.Join(c.SegmentsDir, name+".env")
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New(path + " is not a regular file")
	}
	return path, nil
}

// SetSegmentEnvKeys edits the file of one plain segment. It has the same
// shape as SetHouseEnvKeys, for the same reasons. The code checks each key
// against a table. Before it writes anything, it renders the full
// directory from a copy with the edit applied. The file keeps its comments
// and its key order.
//
// The warning that it returns is not an error, and the edit is already
// done when it comes back. There are two reasons for a warning. First, a
// box that did not render before the edit gets a message about what is
// still wrong, not a refusal. A seat that cannot repair its own fault is a
// trap. Second, ADMIN=no closes ssh to the Pi from this segment at the
// next apply. That is important to say on a segment that is often the
// seat of the operator.
func (c *Config) SetSegmentEnvKeys(name string, kv map[string]string) (string, error) {
	if len(kv) == 0 {
		return "", errors.New("nothing to set")
	}
	path, err := c.segmentPath(name)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(kv))
	for key := range kv {
		if slices.Contains(SegmentFixed, key) {
			return "", errors.New(key + " is not editable from a screen: the session making the change usually arrives over this segment, and a VLAN child has to be moved by hand at the other end; edit " + path + " and reboot")
		}
		check, okKey := segmentKeys[key]
		if !okKey {
			return "", errors.New("unknown key " + key)
		}
		kv[key] = strings.TrimSpace(kv[key])
		if err := check(kv[key]); err != nil {
			return "", errors.New(key + ": " + err.Error())
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// pf render reads segments.d from a path. Thus the code renders the
	// candidate from a copy. It does not write the file and roll it back. An
	// operator cannot act on a refusal that already changed the file.
	before := c.renderErr(c.NetEnv(), c.HouseEnv)
	cand, err := c.candidateSegments(name, kv, keys)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(cand)
	if err := c.renderErrIn(c.NetEnv(), c.HouseEnv, cand); err != nil && before == nil {
		return "", err
	}
	// Bare, never quoted: pf render parses these files and does not source
	// them. Thus a quote would stay as part of the value. Also, none of the
	// editable values can hold a space.
	if err := c.withEditLock(func() error {
		return setSegmentLines(path, kv, keys)
	}); err != nil {
		return "", err
	}
	var warn []string
	if kv["ADMIN"] == "no" {
		warn = append(warn, "ssh to the Pi from "+name+" stops at the next apply")
	}
	if kv["PARANOID"] == "on" {
		warn = append(warn, "from the next apply "+name+" reaches only the names in "+SegmentAllowPath(c.SegmentsDir, name))
	}
	if err := c.renderErr(c.NetEnv(), c.HouseEnv); err != nil {
		warn = append(warn, "the configuration still does not render: "+err.Error())
	}
	return strings.Join(warn, "; "), nil
}

// candidateSegments is segments.d with the edit applied, in a temp
// directory. Thus the render check can run over what the directory would
// become. render reads a directory, not a file, so the candidate must be a
// directory. It holds all segments, not only the edited one. Render checks
// each segment against all the others, and a directory with one file is a
// question about a box that does not exist.
//
// It is a sibling of segments.d, not a directory inside it, because
// loadSegments lists segments.d. For an apply that races this one, half a
// copy under segments.d is half a segment.
func (c *Config) candidateSegments(name string, kv map[string]string, keys []string) (string, error) {
	ents, err := os.ReadDir(c.SegmentsDir)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(filepath.Dir(c.SegmentsDir), "segments.d.check")
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".env") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.SegmentsDir, e.Name()))
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, e.Name()), raw, 0644)
		}
		if err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	if err := setSegmentLines(filepath.Join(dir, name+".env"), kv, keys); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// setSegmentLines is setEnvLines for a segments.d file, with one
// difference: an empty value of a connection key removes each line of that
// key (SegmentConnKeys). The file keeps its comments and the order of the
// other lines. It reads and writes the file one time, so an edit of more
// than one key is never half written.
func setSegmentLines(path string, kv map[string]string, keys []string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	var set []string
	for _, k := range keys {
		if kv[k] != "" || !slices.Contains(SegmentConnKeys, k) {
			set = append(set, k)
			continue
		}
		lines = slices.DeleteFunc(lines, func(l string) bool {
			name, _, cut := strings.Cut(l, "=")
			return cut && strings.TrimSpace(name) == k
		})
	}
	return writeLines(path, editEnvLines(lines, kv, set, neverQuote))
}
