// Package observe keeps the first-seen ledger of DNS names and conntrack
// flows, also the resolver log of the house segment. pf observe and
// internal/admin call it.
package observe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/leases"
	"pi-fortress/internal/policycompile"
)

const (
	maxDNS       = 4000
	maxFlows     = 4000
	maxClients   = 256 // per segment
	maxPerClient = 200 // names and dests, each
	clientIdle   = 30 * 24 * time.Hour
	maxEvents    = 1000
	// alertReserve is the number of ring rows that reservedThreat keeps
	// through a flood of other rows.
	alertReserve = maxEvents / 5
	// maxJournal is the limit on one journalctl capture. The agent causes
	// the nft log lines that this reads. Thus the output of that command is
	// a buffer that the agent sizes, and cmd.Output() held all of it.
	maxJournal = 8 << 20
	// journalWait bounds one journalctl run.
	journalWait = 5 * time.Second
	// collapseWindow folds a repeated contact (same segment, src, dst,
	// threat and detail) into the row that started it. One retry loop
	// (a Lima VM that dials a Tailscale relay by IP, 2026-09-14) must not
	// push a week of other feeds out of the ring.
	collapseWindow = time.Minute
	collapseScan   = 64
	eventTTL       = 7 * 24 * time.Hour
	seriesHours    = 168
	hourKey        = "2006-01-02T15"
)

var (
	ctOrig  = regexp.MustCompile(`src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)`)
	ctProto = regexp.MustCompile(`^\S+\s+\d+\s+(\S+)`)
	ctBytes = regexp.MustCompile(`bytes=(\d+)`)
	// The nft log line of the kernel: "pi-fortress <prefix>: IN=... SRC=a DST=b
	// ... PROTO=TCP ... DPT=443 ...", after any stamp that the journal puts
	// in front. The prefix needs a hyphen (<seg>-<kind>), so a host named
	// pi-fortress ("pi-fortress kernel: ...") does not match first.
	nftLogRe = regexp.MustCompile(`pi-fortress ([a-z0-9._-]+-[a-z0-9]+): (.*)$`)
	nftKV    = regexp.MustCompile(`\b(SRC|DST|PROTO|DPT)=(\S+)`)
)

type DNSRec struct {
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Count     int      `json:"count"`
	Qtypes    []string `json:"qtypes"`
	Sinkholed bool     `json:"sinkholed"`
	// Src is the last querier; Srcs counts every one.
	Src     string            `json:"src"`
	Srcs    map[string]uint32 `json:"srcs,omitempty"`
	Segment string            `json:"segment,omitempty"`
}

type FlowRec struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst"`
	Dport     int    `json:"dport"`
	Proto     string `json:"proto"`
	Bytes     int    `json:"bytes"`
	Segment   string `json:"segment,omitempty"`
}

// Client is one address on a segment: what
// it asked for, what it reached, how often. Keyed "<segment>/<ip>".
type Client struct {
	Segment   string            `json:"segment"`
	IP        string            `json:"ip"`
	MAC       string            `json:"mac,omitempty"`
	Name      string            `json:"name,omitempty"`
	FirstSeen string            `json:"first_seen"`
	LastSeen  string            `json:"last_seen"`
	Names     map[string]uint32 `json:"names"`
	Dests     map[string]uint32 `json:"dests"`
	Queries   uint32            `json:"queries"`
	Flows     uint32            `json:"flows"`
	Blocked   uint32            `json:"blocked"`
	// Filtered counts the queries that the policy of the resolver itself
	// suppressed with an empty answer (filter-AAAA, filter-rr, a listed name
	// asked for a type that the sinkhole has no record of). It is separate
	// from Blocked: the resolver returned no address, so it stopped no
	// contact. filter-AAAA also fires on ordinary traffic so often that a
	// merge into Blocked would hide the blocks.
	Filtered uint32 `json:"filtered,omitempty"`
}

// Event is one blocked contact: a sinkholed
// name, or an nft drop that the kernel logged. Threat is the feed id behind
// a blacklist hit ("local" for an operator entry), "pi_input" for a packet
// that the input chain of the Pi itself dropped, "killswitch" for the house
// kill switch, "direct_ip" for a client that goes directly to an IP and not
// through the resolver, "doh" for a DNS-over-HTTPS attempt, "dns_key" for a
// query name with a key in it. On the agent segment, the resolver refused
// the name. On a plain segment, the resolver can also have answered it
// (Alert). It is
// also what the Pi detected but did not stop: "arp_*" for an address claim,
// "volume" for an hour of bulk upload to one destination, "dns_tunnel" for
// a minute of query names with the shape of a payload. Newest last. The
// ring keeps 1000 rows, for 7 days.
type Event struct {
	T       time.Time `json:"t"`
	Segment string    `json:"segment"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	Threat  string    `json:"threat"`
	Detail  string    `json:"detail,omitempty"`
	// N counts the hits folded into this row; zero means one.
	N uint32 `json:"n,omitempty"`
}

// Hits is how many contacts the event stands for.
func (e Event) Hits() uint32 { return max(e.N, 1) }

// Alert says whether this row is something that the Pi detected, not
// something that it stopped. They share the ring so that all readers get
// them. But a reader that prints a "blocked" heading over them gives false
// information to the operator, so the reader asks here first.
//
// A slot_budget row is an alert even when it names a stop: the request
// that crossed the line was served, and the stop applies to all requests
// after it. A dns_key row is a block when the resolver refused or
// sinkholed the name. It is an alert when the resolver answered the name,
// as a resolver started without key rules does. The detail starts with
// the verdict (segdest.go).
func (e Event) Alert() bool {
	switch e.Threat {
	case "volume", "dns_tunnel", "slot_budget":
		return true
	case "dns_key":
		return !strings.HasPrefix(e.Detail, "refused,") && !strings.HasPrefix(e.Detail, "blocked,")
	}
	return strings.HasPrefix(e.Threat, "arp_")
}

// Bucket is one UTC hour of a segment's counts; Hour is hourKey.
type Bucket struct {
	Hour    string `json:"hour"`
	Queries uint32 `json:"queries"`
	Flows   uint32 `json:"flows"`
	Blocked uint32 `json:"blocked"`
	// Filtered is the hour's policy suppression; see Client.Filtered.
	Filtered uint32 `json:"filtered,omitempty"`
}

type State struct {
	DNS     map[string]*DNSRec  `json:"dns"`
	Flows   map[string]*FlowRec `json:"flows"`
	Clients map[string]*Client  `json:"clients,omitempty"`
	Events  []Event             `json:"events,omitempty"`
	// ARP is the MAC that last answered for an address, keyed
	// "<segment>/<ip>". It is state, not a ledger: a flip is a flip only
	// against what answered before. Thus this must outlive the process, as
	// the log offsets do.
	ARP map[string]*ARPRec `json:"arp,omitempty"`
	// Series is the hourly rollup per segment, ascending, seriesHours
	// at most. The count occurs at the source, not from the tick.
	Series map[string][]Bucket `json:"series,omitempty"`
	// Dests is each plain segment's first-seen destinations, keyed
	// segment, then "<name or address>:<port>/<proto>" (segdest.go).
	Dests   map[string]map[string]*DestRec `json:"dests,omitempty"`
	Started string                         `json:"started"`
}

// prefixFeed is one blocked-ips.map line. The slice keeps the widest mask
// first, so the first match is the longest prefix.
type prefixFeed struct {
	p    netip.Prefix
	feed string
}

type Observer struct {
	StatePath string
	JSONLPath string
	// NoticePath is where the alerts pf alert posts are written; see notice.
	NoticePath string
	DNSLog     string
	OffsetPath string
	CTPath     string
	CTCmd      []string
	NetEnvPath []string
	// NetEnvLocal is the operator overlay that apply sources after the base
	// net.env. The values that the fence was built from are the merge of the
	// two, not the base alone.
	NetEnvLocal string
	// House segment (docs/user_guide/home_network.md): read only when the env file
	// names HOUSE_IF.
	HouseEnvPath    []string
	HouseDNSLog     string
	HouseOffsetPath string
	HouseLeases     string
	HouseHosts      string
	ARPPath         string
	// ARPCmd is read when ARPPath is absent. On the Pi, ARPPath is always
	// absent: observe.service hides /proc/net from itself (ProcSubset=pid).
	ARPCmd []string
	// SegmentsDir holds one <name>.env per plain segment. Each segment has
	// its own resolver, and thus its own log and checkpoint, named for it.
	// Before this, the DNS of a plain segment was not visible here: the desk
	// seat resolved through the resolver that it configured itself, and no
	// row got to the ledger that the operator reads. The ARP watch also
	// reads it, because those devices share a broadcast domain with the Pi,
	// like all other devices.
	SegmentsDir string
	// Blocked events. The maps are
	// the name → feed and prefix → feed tables of pf compile. Observe reads
	// them again when their mtime changes. JournalCmd tails the kernel log
	// for the nft "pi-fortress <seg>-<kind>: " lines. JournalCursorPath keeps
	// the journal cursor, so a restart does not replay. An empty JournalCmd
	// reads no journal, as on a box without journald.
	DomainMapPath     string
	IPMapPath         string
	JournalCmd        []string
	JournalCursorPath string
	// Credential events (phase 2): the strip.jsonl of the broker, tailed
	// like a DNS log. Refusals and strips become credential_* events.
	StripLog        string
	StripOffsetPath string
	Interval        time.Duration
	// Writes are chunked: rows,
	// offsets and state stay in memory until FlushBytes of rows are
	// buffered, or FlushInterval passed since the last flush. If both are
	// zero, each Snapshot flushes. A crash loses the unflushed window. The
	// plan accepts that.
	FlushBytes    int
	FlushInterval time.Duration
	// VolumeMB is the hourly amount that a client can send to one destination
	// before observe raises a volume alert (internal/observe/volume.go). Zero
	// disables the signal. A zero-value Observer has this setting.
	VolumeMB int
	// TunnelNames is the number of distinct names per minute, under one
	// registrable domain and from one client, that is enough by itself for
	// the DNS tunnel heuristic (internal/observe/tunnel.go). Zero disables
	// the full signal, also the label-length and TXT rules.
	TunnelNames int
	// KeyRulesPath is the key_prefixes.rules of the fence. The dns_key check
	// on plain segments reads it (segdest.go). Empty disables the check.
	KeyRulesPath string
	Stdout       io.Writer
	// Stderr receives the reason for a journalctl failure, one time per
	// distinct reason. nil discards it.
	Stderr io.Writer
	Now    func() time.Time

	st      *State
	rows    bytes.Buffer
	offsets map[string]checkpoint
	// seenCT is the conntrack tuples of the previous poll and, per tuple,
	// the bytes that the original direction had sent by then. A present key
	// means that the connection was already open. The volume window
	// subtracts the value to get the growth of this poll.
	seenCT map[string]int64
	// ctPrimed is set after a poll has read conntrack. Until then there is
	// no previous poll, and ctSeeding tells ingestCT to learn the counters
	// but not to count them. If not, each flow that stays open across a
	// restart would put its full lifetime into one minute.
	ctPrimed, ctSeeding bool
	lastFlush           time.Time
	// self holds the segment addresses of the Pi itself: its mDNS and its
	// own lookups are not a client.
	self map[string]struct{}

	// vol is the outbound byte window per (client, destination). dstNames is
	// the address → name table that its events read. Both are working
	// memory, not ledger, so observe saves neither.
	vol      map[string]*volPair
	dstNames map[string]string
	// tun is the minute per (client, registrable domain) that the tunnel
	// heuristic reads. tunSupp is the per-client rate-limit count that its
	// detail line mentions. Also working memory, not ledger.
	tun     map[string]*tunWindow
	tunSupp map[string]*tunSuppress
	// keyFired is the dns_key debounce, per client, zone and rule.
	keyFired map[string]time.Time
	// segNames is noteAnswer per plain segment. segKeys is the key-shape
	// check that runs on their query names. keyStamp and keyErr are its
	// reload and its one complaint (segdest.go).
	segNames map[string]map[string]string
	segKeys  *segKeys
	keyStamp time.Time
	keyErr   string

	domainFeeds map[string]string
	ipFeeds     []prefixFeed
	mapStamp    [2]time.Time
	cursor      string
	cursorRead  bool
	journalErr  string
	// journalCap and journalTimeout are maxJournal and journalWait, separate
	// so that a test can make them small. Zero is the default.
	journalCap     int
	journalTimeout time.Duration
	// savedID is the inode of the state file this process last published.
	savedID fileID
}

// StateDir holds each file that pf observe writes outside its logs: the
// ledger, its lock and the checkpoints. observe.service can write only
// this directory under /var/lib/pi-fortress. The ledger and the cursor are
// replaced through a rename, so the daemon needs the directory, not only
// the files. apply.sh makes it.
const StateDir = "/var/lib/pi-fortress/observe"

// Defaults is what `pf observe` runs with. PF_OBSERVE_FLUSH_BYTES and
// PF_OBSERVE_FLUSH_INTERVAL (Go duration) override the write chunking,
// from 10 MiB and 15m. PF_OBSERVE_VOLUME_MB overrides the outbound hour
// that a client can send to one destination before a volume alert, from
// 500, 0 off. PF_OBSERVE_TUNNEL_NAMES overrides the distinct names per
// minute under one domain that are enough for the tunnel heuristic, from
// 120, 0 off. vm/pi/observe.service has all of them commented out at
// those defaults.
func Defaults() *Observer {
	o := &Observer{
		StatePath:       StateDir + "/observe.json",
		JSONLPath:       "/var/log/pi-fortress/observe.jsonl",
		NoticePath:      "/var/log/pi-fortress/notice.jsonl",
		DNSLog:          "/var/log/pi-fortress/dns.jsonl",
		OffsetPath:      StateDir + "/dns.offset",
		CTPath:          "/proc/net/nf_conntrack",
		CTCmd:           []string{"conntrack", "-L", "-o", "extended"},
		NetEnvPath:      base.NetEnvPaths(),
		NetEnvLocal:     base.NetEnvLocal,
		HouseEnvPath:    []string{"/etc/pi-fortress/house.env"},
		HouseDNSLog:     "/var/log/pi-fortress/dns-house.jsonl",
		HouseOffsetPath: StateDir + "/dns-house.offset",
		HouseLeases:     "/var/lib/pi-fortress/house.leases",
		HouseHosts:      "/etc/pi-fortress/house.hosts",
		SegmentsDir:     "/etc/pi-fortress/segments.d",
		ARPPath:         "/proc/net/arp",
		ARPCmd:          []string{"ip", "-4", "neigh", "show"},
		DomainMapPath:   "/etc/pi-fortress/blocked-domains.map",
		IPMapPath:       "/etc/pi-fortress/blocked-ips.map",
		// -g is a filter on MESSAGE. The prefix decides the rest here.
		// Use _TRANSPORT=kernel, not -k: -k also matches the current boot,
		// whose ID is in /proc/sys, which ProcSubset=pid hides.
		JournalCmd:        []string{"journalctl", "_TRANSPORT=kernel", "-o", "json", "--no-pager", "-g", "pi-fortress "},
		JournalCursorPath: StateDir + "/journal.cursor",
		StripLog:          "/var/log/pi-fortress/strip.jsonl",
		StripOffsetPath:   StateDir + "/strip.offset",
		Interval:          10 * time.Second,
		FlushBytes:        10 << 20,
		FlushInterval:     15 * time.Minute,
		VolumeMB:          500,
		TunnelNames:       120,
		KeyRulesPath:      "/etc/pi-fortress/key_prefixes.rules",
	}
	if n, err := strconv.Atoi(os.Getenv("PF_OBSERVE_FLUSH_BYTES")); err == nil && n > 0 {
		o.FlushBytes = n
	}
	if d, err := time.ParseDuration(os.Getenv("PF_OBSERVE_FLUSH_INTERVAL")); err == nil && d > 0 {
		o.FlushInterval = d
	}
	// Zero is a setting, not a missing value: an operator who does not want
	// the volume signal uses zero to disable it.
	if n, err := strconv.Atoi(os.Getenv("PF_OBSERVE_VOLUME_MB")); err == nil && n >= 0 {
		o.VolumeMB = n
	}
	if n, err := strconv.Atoi(os.Getenv("PF_OBSERVE_TUNNEL_NAMES")); err == nil && n >= 0 {
		o.TunnelNames = n
	}
	// The same override that apply.sh takes. Thus observe watches a box with
	// its segments in a different location there, and does not silently skip it.
	if dir := os.Getenv("PF_SEGMENTS_DIR"); dir != "" {
		o.SegmentsDir = dir
	}
	return o
}

func (o *Observer) buffered() bool {
	return o.FlushBytes > 0 || o.FlushInterval > 0
}

// due says whether a flush is owed: the byte limit, the interval, or no
// buffer at all.
func (o *Observer) due() bool {
	if !o.buffered() {
		return true
	}
	if o.FlushBytes > 0 && o.rows.Len() >= o.FlushBytes {
		return true
	}
	return o.FlushInterval > 0 && o.now().Sub(o.lastFlush) >= o.FlushInterval
}

func (o *Observer) now() time.Time {
	if o != nil && o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// rowTime is the time that a log row gives for its event, or now for a
// row that does not give it.
func (o *Observer) rowTime(t string) time.Time {
	if at, err := time.Parse(base.ISO, t); err == nil {
		return at
	}
	return o.now()
}

func (o *Observer) nowISO() string {
	if o == nil {
		return base.NowISO(nil)
	}
	return base.NowISO(o.Now)
}

func (o *Observer) out() io.Writer {
	if o != nil && o.Stdout != nil {
		return o.Stdout
	}
	return os.Stdout
}

func InNet(addr, cidr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return p.Contains(ip)
}

func (o *Observer) empty() *State {
	return &State{
		DNS:     map[string]*DNSRec{},
		Flows:   map[string]*FlowRec{},
		Started: o.nowISO(),
	}
}

func (o *Observer) Load() *State {
	raw, err := os.ReadFile(o.StatePath)
	if err != nil {
		return o.empty()
	}
	st := o.empty()
	if err := json.Unmarshal(raw, st); err != nil {
		return o.empty()
	}
	if st.DNS == nil {
		st.DNS = map[string]*DNSRec{}
	}
	if st.Flows == nil {
		st.Flows = map[string]*FlowRec{}
	}
	if st.Clients == nil {
		st.Clients = map[string]*Client{}
	}
	if st.Series == nil {
		st.Series = map[string][]Bucket{}
	}
	if st.ARP == nil {
		st.ARP = map[string]*ARPRec{}
	}
	if st.Started == "" {
		st.Started = o.nowISO()
	}
	expireEvents(st, o.now())
	expireSeries(st, o.now())
	return st
}

// withStateLock serialises the writers of the state file. The daemon
// flushes on a timer, while pf observe once or pf observe reset from the
// root shell of an operator publishes the same path. All three rename over
// it: the last rename won, and the ledger that the other had just built
// was lost. If this process cannot take the lock, that is not a reason to
// stop observation. Thus the work continues unserialised and says nothing
// -- the same box has bigger problems.
//
// Do not nest: flock is held per open file description. Thus a second
// exclusive lock on a new descriptor in this process would wait on the
// first lock forever.
func (o *Observer) withStateLock(fn func() error) error {
	if o.StatePath == "" {
		return fn()
	}
	if err := os.MkdirAll(filepath.Dir(o.StatePath), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(o.StatePath+".lock", os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return fn()
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fn()
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func (o *Observer) Save(st *State) error {
	return o.withStateLock(func() error { return o.save(st) })
}

func (o *Observer) save(st *State) error {
	if err := os.MkdirAll(filepath.Dir(o.StatePath), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	// The staging name is unique. Before, it was the fixed
	// observe.json.tmp, which the daemon and pf observe once from a root
	// shell both opened. The second rename published a file that the other
	// process still filled. A leftover with that name (or a directory at
	// it) stopped each of them from publishing at all.
	f, err := os.CreateTemp(filepath.Dir(o.StatePath), filepath.Base(o.StatePath)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The state names each client and what it queried: 0640 for any umask,
	// and the group of the file that it replaces. Thus pf observe once from
	// a root shell leaves it as apply set it (root:pf-fortress).
	if err := os.Chmod(tmp, 0640); err != nil {
		return err
	}
	if st, err := os.Stat(o.StatePath); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Gid != uint32(os.Getegid()) {
			_ = os.Chown(tmp, -1, int(sys.Gid))
		}
	}
	if err := os.Rename(tmp, o.StatePath); err != nil {
		return err
	}
	tmp = ""
	// Remember the inode just published. Each save renames a new file into
	// place. Thus a different inode is a publication by a different writer
	// -- most usefully, a pf observe reset. The daemon must notice it, and
	// must not overwrite it from the ledger that it cached before the
	// operator asked for a clean slate.
	if fi, err := os.Stat(o.StatePath); err == nil {
		o.savedID = idOf(fi)
	}
	return nil
}

func (o *Observer) appendJSONL(event map[string]any) {
	if o.JSONLPath == "" {
		return
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return
	}
	o.rows.Write(append(raw, '\n'))
	// Before, the code tested the byte limit only after a full Snapshot
	// returned. Thus a single pass over a log that the agent had just filled
	// held all its rows in memory, and examined the limit after that. It is
	// a limit on what is held, so the test occurs where the hold occurs. A
	// flush in the middle of a pass writes a checkpoint that lags the state
	// by the remainder of this pass. This replays first-seen rows that are
	// already recorded, and changes nothing.
	if o.FlushBytes > 0 && o.rows.Len() >= o.FlushBytes {
		_ = o.Flush()
	}
}

// prune drops the oldest entries until the table is at limit again, and
// returns what it dropped.
func prune[V any](table map[string]V, limit int, lastSeen func(V) string) []string {
	if len(table) <= limit {
		return nil
	}
	dropped := coldest(table, lastSeen, len(table)-limit)
	for _, k := range dropped {
		delete(table, k)
	}
	return dropped
}

// bump counts k in a table with a limit. When the table is full, the
// lowest count goes, ties by key: the map[string]uint32 of the plan keeps
// no time per entry, so "then oldest" has nothing to read.
func bump(m map[string]uint32, k string) {
	if _, ok := m[k]; !ok && len(m) >= maxPerClient {
		victim := ""
		for kk, n := range m {
			if victim == "" || n < m[victim] || (n == m[victim] && kk < victim) {
				victim = kk
			}
		}
		delete(m, victim)
	}
	m[k]++
}

// client finds or opens the record for ip on segment and stamps it.
func (o *Observer) client(st *State, segment, ip, ts string) *Client {
	if st.Clients == nil {
		st.Clients = map[string]*Client{}
	}
	key := segment + "/" + ip
	c := st.Clients[key]
	if c == nil {
		c = &Client{Segment: segment, IP: ip, FirstSeen: ts, LastSeen: ts, Names: map[string]uint32{}, Dests: map[string]uint32{}}
		st.Clients[key] = c
		pruneSegment(st, segment)
	}
	// Stamps are ISO-8601 UTC, so they order lexically. A journal line
	// carries a kernel stamp older than rows already ingested. When the
	// code took it as the last contact, the LastSeen of the client moved
	// backwards -- and the idle eviction and the "last seen" column of the
	// operator both read that field.
	if ts > c.LastSeen {
		c.LastSeen = ts
	}
	if c.FirstSeen == "" || ts < c.FirstSeen {
		c.FirstSeen = ts
	}
	return c
}

// pruneSegment keeps a segment at maxClients by LastSeen.
func pruneSegment(st *State, segment string) {
	seg := map[string]*Client{}
	for k, c := range st.Clients {
		if c.Segment == segment {
			seg[k] = c
		}
	}
	for _, k := range prune(seg, maxClients, func(c *Client) string { return c.LastSeen }) {
		delete(st.Clients, k)
	}
}

// evictIdle drops clients not seen for clientIdle.
func (o *Observer) evictIdle(st *State) {
	cutoff := o.now().Add(-clientIdle).UTC().Format(base.ISO)
	for k, c := range st.Clients {
		if c.LastSeen < cutoff {
			delete(st.Clients, k)
		}
	}
}

// clientSegment names the agent segment for Client keys. DNS and flow
// keys keep "" there, so existing state files read without a change.
func clientSegment(segment string) string {
	if segment == "" {
		return "agent"
	}
	return segment
}

// parseARP reads /proc/net/arp into ip → mac, any interface. Flags 0x0
// is an incomplete entry with no address yet.
func parseARP(text string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "IP" || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		out[f[0]] = strings.ToLower(f[3])
	}
	return out
}

// leaseNames reads leases and reservations into ip -> name and ip -> mac.
// The name of a reservation wins over the name that the device gave
// itself. It reads the lease file of the house, and the lease file of each
// plain segment with DHCP=on: apply keeps those next to the file of the
// house as dhcp-<name>.leases (vm/pi/lib/dhcp.sh). The addresses of the
// segments never overlap the house or each other (render refuses it), so
// one map holds them all.
func (o *Observer) leaseNames() (names, macs map[string]string) {
	names, macs = map[string]string{}, map[string]string{}
	files := []string{o.HouseLeases}
	if o.HouseLeases != "" {
		for _, s := range PlainSegments(o.SegmentsDir) {
			files = append(files, filepath.Join(filepath.Dir(o.HouseLeases), "dhcp-"+s.Name+".leases"))
		}
	}
	now := o.now()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// An expired lease is no longer the name of this address. dnsmasq
		// keeps the row in the file until it uses the address again. If the
		// code keeps the row, it labels the current holder of the address
		// with the name of the previous device -- and the operator reads
		// that column to decide whose traffic they look at.
		for _, l := range leases.ParseLeases(string(raw)) {
			if l.Expired(now) {
				continue
			}
			if l.Hostname != "" {
				names[l.IP] = l.Hostname
			}
			macs[l.IP] = l.MAC
		}
	}
	if raw, err := os.ReadFile(o.HouseHosts); err == nil {
		for _, r := range leases.ParseReservations(strings.Split(string(raw), "\n")) {
			if r.Name != "" {
				names[r.IP] = r.Name
			}
			if r.MAC != "" {
				macs[r.IP] = r.MAC
			}
		}
	}
	return names, macs
}

// enrich fills MAC from the ARP table on all segments, and Name for
// clients of the house and of plain segments, from the leases above.
// Agent clients have no names (plan §Decisions).
func (o *Observer) enrich(st *State) {
	if len(st.Clients) == 0 {
		return
	}
	arp := o.arpTable()
	names, macs := o.leaseNames()
	for _, c := range st.Clients {
		mac := arp[c.IP]
		if mac == "" && c.Segment != "agent" {
			mac = macs[c.IP]
		}
		// The address moved to a different device. Its names and
		// destinations belong to the previous holder. If they stay, they
		// attribute the browsing of one household member to a different member.
		if mac != "" && c.MAC != "" && mac != c.MAC {
			c.Name, c.Names, c.Dests = "", map[string]uint32{}, map[string]uint32{}
		}
		if mac != "" {
			c.MAC = mac
		}
		// Assigned, not merged: a name that no live lease or reservation
		// supports is the name of the previous tenant. If it stays, the
		// operator reads a device name for a device that left the house
		// weeks ago.
		if c.Segment != "agent" {
			c.Name = names[c.IP]
		}
	}
}

// cleanName keeps a queried name printable. The resolver logs what the
// agent asked for, and that text shows on the terminal of the operator
// and in the tui. 253 bytes is the DNS limit.
func cleanName(name string) string {
	if len(name) > 253 {
		name = name[:253]
	}
	b := []byte(name)
	for i, c := range b {
		if c <= ' ' || c > '~' {
			b[i] = '?'
		}
	}
	return string(b)
}

// printable is s with each byte outside printable ASCII changed to '?'.
// Space stays. The content of an alert goes to pf alert, a webhook and
// terminals. A byte from a query name or a log row must not become a
// control sequence on the way.
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' || c > '~' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] < ' ' || b[j] > '~' {
					b[j] = '?'
				}
			}
			return string(b)
		}
	}
	return s
}

// event appends to the ring, with the oldest out past maxEvents, and counts
// the hour: all blocked sources (sinkhole, nft, credential) come here.
func (o *Observer) event(st *State, ev Event) {
	bucket(st, ev.Segment, ev.T).Blocked++
	o.push(st, ev)
}

// alert records something that the Pi detected and did not stop. It shares
// the event ring, so pf observe, internal/admin and the tui all see it at
// no cost. But it does not change the Blocked count of the hour: nothing
// was blocked. If that count included the address claim of a neighbour as
// a block, the operator would read a spike in a number that means
// something completely different.
func (o *Observer) alert(st *State, ev Event) {
	ev.Segment, ev.Src, ev.Dst, ev.Detail = printable(ev.Segment), printable(ev.Src), printable(ev.Dst), printable(ev.Detail)
	o.push(st, ev)
	o.notice(ev)
}

// trackKey raises dns_key for a name that the resolver refused because a
// key was in it (internal/dnsd keyshape.go). Nothing left the box. But an
// agent that tried is an agent that got an instruction to try, so the
// operator gets the message immediately. It sends one time per client,
// zone and rule in tunnelDebounce, so an injected loop is one message, not
// one message per query.
func (o *Observer) trackKey(st *State, segment string, ev dnslog.Event) {
	o.keyAlert(st, segment, ev.Src, ev.Name, ev.Rule, "refused, rule "+ev.Rule)
}

func (o *Observer) keyAlert(st *State, segment, src, zone, rule, detail string) {
	// The zone is what is left of a name the agent chose.
	if zone != "" {
		zone = cleanName(zone)
	}
	now := o.now()
	key := src + "/" + zone + "/" + rule
	if now.Sub(o.keyFired[key]) < tunnelDebounce {
		return
	}
	if o.keyFired == nil || len(o.keyFired) >= maxTunnelSupp {
		o.keyFired = map[string]time.Time{}
	}
	o.keyFired[key] = now
	if zone == "" {
		zone = "(redacted)"
	}
	o.alert(st, Event{T: now.UTC(), Segment: clientSegment(segment), Src: src, Dst: zone, Threat: "dns_key", Detail: detail})
}

// notice gives a volume or dns_tunnel alert to pf alert. pf alert owns the
// webhook and tails NoticePath next to the strip log of the broker. The
// row is written immediately, not with the batch: it is rare, and an
// operator who learns about an upload one hour late has learned nothing.
// The arp_ alerts stay only in the ring: a flapping neighbour is not worth
// a message per claim.
func (o *Observer) notice(ev Event) {
	if o.NoticePath == "" || (ev.Threat != "volume" && ev.Threat != "dns_tunnel" && ev.Threat != "dns_key") {
		return
	}
	raw, err := json.Marshal(map[string]any{
		"t": ev.T.UTC().Format(time.RFC3339), "threat": ev.Threat, "rule": "observe",
		"where": ev.Segment, "client_ip": ev.Src, "host": ev.Dst, "detail": ev.Detail,
	})
	if err != nil {
		return
	}
	_ = appendRows(o.NoticePath, append(raw, '\n'))
}

func (o *Observer) push(st *State, ev Event) {
	// Journal lines carry kernel stamps and can be behind a row stamped
	// now. Thus the window is measured in both directions, and the scan is
	// by position, not by time.
	for i := len(st.Events) - 1; i >= 0 && i >= len(st.Events)-collapseScan; i-- {
		e := &st.Events[i]
		if e.Segment != ev.Segment || e.Src != ev.Src || e.Dst != ev.Dst || e.Threat != ev.Threat || e.Detail != ev.Detail {
			continue
		}
		if ev.T.Sub(e.T).Abs() > collapseWindow {
			break
		}
		e.N = e.Hits() + 1
		return
	}
	st.Events = append(st.Events, ev)
	if len(st.Events) > maxEvents {
		st.Events = trimRing(st.Events)
	}
}

// reservedThreat is a row that the ring keeps through a flood of the other
// rows: what the Pi detected and told the operator (notice), and the
// canary. A flood is made of the drops that anyone on a segment can cause
// at will. These drops no longer push the reserved rows out.
func reservedThreat(t string) bool {
	return t == "dns_key" || t == "volume" || t == "dns_tunnel" || t == "canary"
}

// trimRing drops the oldest rows past maxEvents. It skips reserved rows
// while there are no more than alertReserve of them. It makes a copy, as
// the old trim did: the slice of the state is shared with the snapshot readers.
func trimRing(evs []Event) []Event {
	over := len(evs) - maxEvents
	held := 0
	for _, e := range evs {
		if reservedThreat(e.Threat) {
			held++
		}
	}
	out := make([]Event, 0, maxEvents)
	for _, e := range evs {
		if over > 0 {
			if !reservedThreat(e.Threat) {
				over--
				continue
			}
			if held > alertReserve {
				held--
				over--
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// expireEvents drops what is older than eventTTL. Load and Flush call it.
// It walks the full ring, not only its expired prefix. The ring is in
// arrival order, and a journal line carries a kernel stamp that can be
// behind rows already ingested. Thus, before, one late arrival in front of
// the expired rows stopped the scan, and kept all rows behind it in place
// while the box stayed up.
func expireEvents(st *State, now time.Time) {
	cutoff := now.Add(-eventTTL)
	keep := st.Events[:0]
	dropped := false
	for _, e := range st.Events {
		if e.T.Before(cutoff) {
			dropped = true
			continue
		}
		keep = append(keep, e)
	}
	if dropped {
		st.Events = append([]Event(nil), keep...)
	}
}

// bucket finds or inserts the entry of the segment for the UTC hour of t.
// A late line older than the tail goes in, in order. A line older than the
// window before the newest hour, or pushed out by the limit, counts
// against a throwaway.
func bucket(st *State, seg string, t time.Time) *Bucket {
	if seg == "" {
		return &Bucket{}
	}
	if st.Series == nil {
		st.Series = map[string][]Bucket{}
	}
	hour := t.UTC().Format(hourKey)
	s := st.Series[seg]
	if n := len(s); n > 0 && s[n-1].Hour > hour {
		if newest, _ := time.Parse(hourKey, s[n-1].Hour); t.UTC().Before(newest.Add(-seriesHours * time.Hour)) {
			return &Bucket{}
		}
	}
	i, found := slices.BinarySearchFunc(s, hour, func(b Bucket, h string) int { return strings.Compare(b.Hour, h) })
	if found {
		return &s[i]
	}
	s = slices.Insert(s, i, Bucket{Hour: hour})
	if len(s) > seriesHours {
		s = append([]Bucket(nil), s[1:]...)
		i--
	}
	st.Series[seg] = s
	if i < 0 {
		return &Bucket{}
	}
	return &s[i]
}

// Day is one local day of a segment's counts, Day as MM-DD.
type Day struct {
	Day     string `json:"day"`
	Queries uint32 `json:"queries"`
	Flows   uint32 `json:"flows"`
	Blocked uint32 `json:"blocked"`
}

// Days sums the hourly series into the seven local days that end today,
// oldest first, zero-filled. Agent and house are always present, so a
// view laid out on them stays stable.
func Days(st *State, now time.Time, loc *time.Location) map[string][]Day {
	out := map[string][]Day{"agent": nil, "house": nil}
	for seg := range st.Series {
		out[seg] = nil
	}
	today := now.In(loc)
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, loc)
	idx := map[string]int{}
	for seg := range out {
		days := make([]Day, 7)
		for i := range days {
			d := today.AddDate(0, 0, i-6)
			days[i].Day = d.Format("01-02")
			idx[d.Format("2006-01-02")] = i
		}
		for _, b := range st.Series[seg] {
			t, err := time.Parse(hourKey, b.Hour)
			if err != nil {
				continue
			}
			if i, ok := idx[t.In(loc).Format("2006-01-02")]; ok {
				days[i].Queries += b.Queries
				days[i].Flows += b.Flows
				days[i].Blocked += b.Blocked
			}
		}
		out[seg] = days
	}
	return out
}

// expireSeries drops hours older than seriesHours; Load and Flush call it.
func expireSeries(st *State, now time.Time) {
	cutoff := now.UTC().Add(-seriesHours * time.Hour).Format(hourKey)
	for seg, s := range st.Series {
		i := 0
		for i < len(s) && s[i].Hour < cutoff {
			i++
		}
		switch {
		case i == len(s):
			delete(st.Series, seg)
		case i > 0:
			st.Series[seg] = append([]Bucket(nil), s[i:]...)
		}
	}
}

// loadMaps reads the feed maps again when the mtime of either file changed.
// A missing file is an empty map, so each hit reads as local.
func (o *Observer) loadMaps() {
	for i, path := range []string{o.DomainMapPath, o.IPMapPath} {
		if path == "" {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.ModTime().Equal(o.mapStamp[i]) {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		o.mapStamp[i] = fi.ModTime()
		m := policycompile.ParseMap(string(raw))
		if i == 0 {
			o.domainFeeds = m
		} else {
			o.ipFeeds = prefixFeeds(m)
		}
	}
}

func prefixFeeds(m map[string]string) []prefixFeed {
	out := make([]prefixFeed, 0, len(m))
	for item, feed := range m {
		if !strings.Contains(item, "/") {
			item += "/32"
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			continue
		}
		out = append(out, prefixFeed{p.Masked(), feed})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].p.Bits() != out[j].p.Bits() {
			return out[i].p.Bits() > out[j].p.Bits()
		}
		return out[i].p.Addr().Less(out[j].p.Addr())
	})
	return out
}

// feedForName walks from the name through its parents, because an
// address= line sinkholes each subdomain of what it names.
func feedForName(m map[string]string, name string) string {
	for name != "" {
		if feed, ok := m[name]; ok {
			return feed
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			break
		}
		name = rest
	}
	return "local"
}

func feedForIP(feeds []prefixFeed, ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "local"
	}
	for _, f := range feeds {
		if f.p.Contains(a) {
			return f.feed
		}
	}
	return "local"
}

// touchDNSSeg records a first-seen name. Agent names keep their bare key,
// so existing state files and pf tui read without a change. Other segments
// use the key "<segment>/<name>" and carry the segment field.
func (o *Observer) touchDNSSeg(st *State, segment, name, src, qtype string, sinkholed bool) {
	name = cleanName(name)
	name = strings.ToLower(strings.TrimRight(name, "."))
	key := name
	if segment != "" {
		key = segment + "/" + name
	}
	ts := o.nowISO()
	rec := st.DNS[key]
	if rec == nil {
		rec = &DNSRec{FirstSeen: ts, LastSeen: ts, Qtypes: []string{}, Src: src, Segment: segment}
		st.DNS[key] = rec
		ev := map[string]any{"t": ts, "kind": "dns", "name": name, "qtype": qtype, "src": src}
		if segment != "" {
			ev["segment"] = segment
		}
		o.appendJSONL(ev)
	}
	rec.LastSeen = ts
	rec.Count++
	rec.Src = src
	if rec.Srcs == nil {
		rec.Srcs = map[string]uint32{}
	}
	rec.Srcs[src]++
	c := o.client(st, clientSegment(segment), src, ts)
	c.Queries++
	bucket(st, c.Segment, o.now()).Queries++
	bump(c.Names, name)
	// A sinkholed name answers 0.0.0.0, so no flow and no nft drop
	// follows it. A blacklist drop hits an address that a name resolved to.
	// The two event sources never see the same contact, so each
	// counts Blocked one time.
	if sinkholed {
		c.Blocked++
		o.event(st, Event{T: o.now().UTC(), Segment: c.Segment, Src: src, Dst: name, Threat: feedForName(o.domainFeeds, name), Detail: "dns " + qtype})
	}
	found := false
	for _, q := range rec.Qtypes {
		if q == qtype {
			found = true
			break
		}
	}
	if !found {
		rec.Qtypes = append(rec.Qtypes, qtype)
	}
	if sinkholed {
		rec.Sinkholed = true
	}
	prune(st.DNS, maxDNS, func(r *DNSRec) string { return r.LastSeen })
}

// touchFilteredSeg counts one query that the resolver policy suppressed
// with an empty answer. touchDNSSeg already counted the query itself. Thus
// this adds only the policy column: on the client and on the hourly bucket
// of the segment, never on Blocked and never as an Event. filter-AAAA fires
// on ordinary names, and an event per empty AAAA would push a week of real
// blocks out of the thousand-row ring.
func (o *Observer) touchFilteredSeg(st *State, segment, src string) {
	seg := clientSegment(segment)
	bucket(st, seg, o.now()).Filtered++
	if _, err := netip.ParseAddr(src); err != nil {
		return
	}
	o.client(st, seg, src, o.nowISO()).Filtered++
}

// touchSuppressedSeg folds the "suppressed N queries" summary of the
// resolver itself into the counters that the dropped queries would have
// made: Queries on the client and on the hourly Series bucket of the
// segment, plus Blocked on both for the config (sinkhole-list) variant.
// It raises no per-query Event. A thousand-line ring has no room for a
// count that can go into the overflow of the budget. The summary line
// itself is also not worth one Event. Thus a suppression run is visible
// only as a bump in the totals. "from untracked" (the source table of the
// resolver was full) and all other sources that netip cannot parse count
// only to Series. This agrees with the rule that observe never creates a
// client for a source with no real address.
func (o *Observer) touchSuppressedSeg(st *State, segment string, ev dnslog.Event) {
	seg := clientSegment(segment)
	if _, err := netip.ParseAddr(ev.Src); err != nil {
		b := bucket(st, seg, o.now())
		b.Queries += uint32(ev.N)
		if ev.Listed {
			b.Blocked += uint32(ev.N)
		}
		return
	}
	ts := o.nowISO()
	c := o.client(st, seg, ev.Src, ts)
	c.Queries += uint32(ev.N)
	b := bucket(st, c.Segment, o.now())
	b.Queries += uint32(ev.N)
	if ev.Listed {
		c.Blocked += uint32(ev.N)
		b.Blocked += uint32(ev.N)
	}
}

// touchFlow records a first-seen src → dst:port. Keys are
// "<src>><dst>:<port>/<proto>", house keys under "house/". fresh says that
// the conntrack entry was not in the previous poll, so it counts as one
// more connection for the client.
func (o *Observer) touchFlow(st *State, segment, src, dst string, dport int, proto string, bytesTotal int, fresh bool) {
	port := strconv.Itoa(dport)
	key := src + ">" + dst + ":" + port + "/" + proto
	if segment != "" {
		key = segment + "/" + key
	}
	ts := o.nowISO()
	rec := st.Flows[key]
	if rec == nil {
		rec = &FlowRec{FirstSeen: ts, LastSeen: ts, Src: src, Dst: dst, Dport: dport, Proto: proto, Segment: segment}
		st.Flows[key] = rec
		ev := map[string]any{"t": ts, "kind": "flow", "src": src, "dst": dst, "dport": dport, "proto": proto}
		if segment != "" {
			ev["segment"] = segment
		}
		o.appendJSONL(ev)
	}
	rec.LastSeen = ts
	if bytesTotal > rec.Bytes {
		rec.Bytes = bytesTotal
	}
	if fresh {
		c := o.client(st, clientSegment(segment), src, ts)
		c.Flows++
		bucket(st, c.Segment, o.now()).Flows++
		bump(c.Dests, dst+":"+port)
	}
	prune(st.Flows, maxFlows, func(r *FlowRec) string { return r.LastSeen })
}

func (o *Observer) ingestDNS(st *State, agentNet string) {
	o.ingestDNSLog(st, o.DNSLog, o.OffsetPath, agentNet, "")
}

// fileID names an inode. An offset has a meaning only against the file
// that it was counted in. logrotate renames dns.jsonl and the resolver
// opens a new file. The new file passes the old offset within minutes.
// Thus a size compare sees nothing, and each name resolved before the new
// file grew past the old offset is permanently missing from the ledger.
type fileID struct{ dev, ino uint64 }

func idOf(fi os.FileInfo) fileID {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{uint64(sys.Dev), uint64(sys.Ino)}
}

func (id fileID) String() string {
	return strconv.FormatUint(id.dev, 10) + ":" + strconv.FormatUint(id.ino, 10)
}

func parseID(s string) fileID {
	dev, ino, ok := strings.Cut(s, ":")
	if !ok {
		return fileID{}
	}
	d, err1 := strconv.ParseUint(dev, 10, 64)
	i, err2 := strconv.ParseUint(ino, 10, 64)
	if err1 != nil || err2 != nil {
		return fileID{}
	}
	return fileID{d, i}
}

// maxLogLine is the limit on one log record. The agent chooses what the
// resolver logs and what the broker writes to strip.jsonl. Thus a run of
// bytes with no newline was an allocation with a hostile author.
// ReadString would have grown to hold all of it.
const maxLogLine = 1 << 20

// checkpoint is the point that a log was read up to, and the inode that
// those bytes were counted in.
type checkpoint struct {
	off int64
	id  fileID
}

// tail reads logPath past the checkpoint kept under offsetPath (in memory
// since the last Flush, or on disk before that), and gives each complete
// line to fn. tail leaves a record that the writer did not complete for
// the next pass. If it gave the prefix to a parser and then moved the
// checkpoint past the remainder, the record would be lost completely. The
// checkpoint goes to disk with its state, at Flush.
func (o *Observer) tail(logPath, offsetPath string, fn func(line string)) {
	if logPath == "" {
		return
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		return
	}
	id := idOf(fi)
	if o.offsets == nil {
		o.offsets = map[string]checkpoint{}
	}
	cp, ok := o.offsets[offsetPath]
	if !ok {
		cp = loadCheckpoint(offsetPath)
	}
	switch {
	case cp.id != (fileID{}) && cp.id != id:
		cp.off = 0
	case cp.off > fi.Size():
		cp.off = 0
	}
	cp.id = id
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(cp.off, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, maxLogLine)
	for {
		line, n, dropped, err := readLogLine(r)
		if err != nil {
			break
		}
		if !dropped {
			fn(line)
		}
		cp.off += n
	}
	o.offsets[offsetPath] = cp
}

func loadCheckpoint(offsetPath string) checkpoint {
	raw, err := os.ReadFile(offsetPath)
	if err != nil {
		return checkpoint{}
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return checkpoint{}
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return checkpoint{}
	}
	cp := checkpoint{off: n}
	if len(f) > 1 {
		cp.id = parseID(f[1])
	}
	return cp
}

// readLogLine returns the next complete line with its newline, the bytes
// it consumed, and whether it ran past maxLogLine and was dropped. A
// final line with no newline returns an error and consumes nothing, so
// the next pass reads it whole.
func readLogLine(r *bufio.Reader) (line string, n int64, dropped bool, err error) {
	var chunk []byte
	for {
		c, e := r.ReadSlice('\n')
		n += int64(len(c))
		if e == bufio.ErrBufferFull {
			dropped = true
			continue
		}
		if e != nil {
			return "", 0, dropped, e
		}
		if !dropped {
			chunk = c
		}
		return string(chunk), n, dropped, nil
	}
}

// ingestDNSLog tails one query log from its saved offset and records
// queries whose source is inside net, tagged with segment.
func (o *Observer) ingestDNSLog(st *State, logPath, offsetPath, net, segment string) {
	// One row is one transaction, so the reader holds nothing between
	// lines, and this loop correlates nothing. All input that is not a row
	// is discarded -- for example the two lines of dnsmasq on a box whose
	// log is older than the cutover, or a line read while half-written.
	var r dnslog.Reader
	o.tail(logPath, offsetPath, func(line string) {
		for _, ev := range r.Feed(line) {
			o.record(st, segment, net, ev)
		}
	})
	// Only the text arm returns something: the queries that it still held
	// when the file ended.
	for _, ev := range r.Flush() {
		o.record(st, segment, net, ev)
	}
}

// record folds one transaction into the ledger.
func (o *Observer) record(st *State, segment, net string, ev dnslog.Event) {
	if _, me := o.self[ev.Src]; me {
		return
	}
	if ev.Act == dnslog.ActSuppressed {
		// The summary counts queries from a source, and the resolver
		// writes it about its own segment. There is no name to compare with
		// net, and "from untracked" is not an address at all.
		o.touchSuppressedSeg(st, segment, ev)
		// A client that gets throttled while it floods one domain is part
		// of the same picture. Thus the count stays for the minute that the
		// tunnel heuristic can report on.
		o.trackSuppressedAt(segment, ev.Src, ev.N, o.rowTime(ev.T))
		return
	}
	if !InNet(ev.Src, net) {
		return
	}
	// The verdict is stated. Thus the reader no longer has to tell an
	// upstream NXDOMAIN (typos, the random probes of Chrome) from a
	// sinkhole by the address that both of them answer with.
	name := ev.Name
	if ev.Rule != "" {
		o.trackKey(st, segment, ev)
	} else if plainSegment(segment) && o.segKeys != nil {
		name = o.checkSegKey(st, segment, ev)
	}
	o.touchDNSSeg(st, segment, name, ev.Src, ev.QType, ev.Act == dnslog.ActBlocked)
	// An answer is also the only name that the box will ever have for the
	// address that a flow will reach. Thus a volume alert can say which
	// bucket a client filled, not which number.
	if ev.Act == dnslog.ActResolved {
		o.noteAnswer(name, ev.Answer)
		if plainSegment(segment) {
			o.noteSegAnswer(segment, name, ev.Answer)
		}
	}
	// All verdicts count here. The zone of a tunnel answers. But the same
	// traffic against a name that the sinkhole holds, or a name that
	// upstream calls nonexistent, still carried its labels off the box.
	o.trackTunnelAt(st, segment, ev.Name, ev.Src, ev.QType, o.rowTime(ev.T))
	// Policy that suppressed the query, and did not answer it, also counts,
	// in its own column. It is a deliberate action, not traffic that did
	// not resolve by chance.
	if ev.Act == dnslog.ActFiltered {
		o.touchFilteredSeg(st, segment, ev.Src)
	}
}

// stripRow is the part of a strip.jsonl line that observe reads. A refusal
// carries ev and cause. A strip carries only rule (internal/jsonl).
type stripRow struct {
	T        string `json:"t"`
	Ev       string `json:"ev"`
	Host     string `json:"host"`
	SNI      string `json:"sni"`
	Rule     string `json:"rule"`
	Cause    string `json:"cause"`
	ClientIP string `json:"client_ip"`
	Threat   string `json:"threat"`
}

// ingestStrip changes the strip and refused rows of the broker into agent
// events. Rows from before client_ip existed have no source, and count
// against no client.
func (o *Observer) ingestStrip(st *State) {
	o.tail(o.StripLog, o.StripOffsetPath, func(line string) {
		var r stripRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return
		}
		// The count of the writer for the strips of one client that it
		// dropped over its budget (internal/jsonl) is not a strip: no host, no rule.
		if r.Ev == "strip_suppressed" {
			return
		}
		t, err := time.Parse(base.ISO, r.T)
		if err != nil {
			t = o.now().UTC()
		}
		ev := Event{T: t, Segment: "agent", Src: r.ClientIP, Dst: r.Host, Threat: "credential_strip", Detail: r.Rule}
		if r.Ev == "substitution_refused" {
			ev.Threat, ev.Detail = "credential_refused", r.Cause
		}
		// A row that the broker gave a threat name keeps that name: the
		// canary (docs/challenge_rules.md), and the per-slot hourly budget.
		// The budget is not a strip or a refusal. It is the fence that
		// reports a rate (internal/broker/budget.go). Any other name is from
		// a producer that this reader does not know, and it stays the strip
		// or refusal above. The detail does not change: a budget row carries
		// no ev, so it already holds the rule, which is the threshold and the slot.
		switch r.Threat {
		case "canary", "slot_budget":
			ev.Threat = r.Threat
		}
		if ev.Dst == "" {
			ev.Dst = r.SNI
		}
		if r.ClientIP != "" {
			o.client(st, "agent", r.ClientIP, t.Format(base.ISO)).Blocked++
		}
		o.event(st, ev)
	})
}

// Raspberry Pi kernels ship without CONFIG_NF_CONNTRACK_PROCFS, so the
// proc file is absent there. `conntrack -L -o extended` prints the same
// line layout over ctnetlink.
func (o *Observer) readCT() ([]byte, error) {
	raw, err := os.ReadFile(o.CTPath)
	if err == nil || !os.IsNotExist(err) || len(o.CTCmd) == 0 {
		return raw, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.CTCmd[0], o.CTCmd[1:]...)
	cmd.Stderr = io.Discard
	return cmd.Output()
}

// ingestCT records the original direction of each conntrack entry whose
// source is on net, tagged segment. self is the address of the Pi on that
// segment. seen collects the tuples of this poll, so the next poll can
// tell a new connection from a connection that is still open.
func (o *Observer) ingestCT(st *State, raw, segment, net, self string, skip []string, seen map[string]int64) {
	for line := range strings.SplitSeq(raw, "\n") {
		m := ctOrig.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		src, dst := m[1], m[2]
		if !InNet(src, net) {
			continue
		}
		if src == self || dst == self {
			continue
		}
		skipDst := false
		for _, cidr := range skip {
			if InNet(dst, cidr) {
				skipDst = true
				break
			}
		}
		if skipDst {
			continue
		}
		proto := "ip"
		if pm := ctProto.FindStringSubmatch(line); pm != nil {
			proto = strings.ToLower(pm[1])
		}
		dport, _ := strconv.Atoi(m[4])
		sum, sent := 0, int64(0)
		for i, b := range ctBytes.FindAllStringSubmatch(line, -1) {
			n, _ := strconv.Atoi(b[1])
			sum += n
			// conntrack prints the counters of each direction immediately
			// after the tuple of that direction. ctOrig matched the original
			// tuple, whose src is the client; if not, the InNet above would
			// have dropped the line. Thus the first bytes= is what the
			// client sent, and the second is what came back. The volume
			// signal uses only the first. A kernel with nf_conntrack_acct
			// off prints neither and sends nothing here. This is why
			// vm/pi/apply.sh sets it.
			if i == 0 {
				sent = int64(n)
			}
		}
		tuple := proto + " " + m[0]
		prev, open := o.seenCT[tuple]
		if seen != nil {
			seen[tuple] = sent
		}
		o.touchFlow(st, segment, src, dst, dport, proto, sum, !open)
		if !open && plainSegment(segment) {
			o.touchDest(st, segment, src, dst, dport, proto)
		}
		// Only the growth since the last poll is traffic that the window
		// did not count yet. A counter that went backwards is a tuple that
		// the kernel used again, not a rewind, so it counts in full. A flow
		// that opens and closes inside one poll is never seen. The poll is
		// ten seconds, and a dump large enough for an alert does not fit
		// in one.
		delta := sent
		if open && sent >= prev {
			delta = sent - prev
		}
		if !o.ctSeeding {
			o.trackVolume(st, segment, src, dst, delta)
		}
	}
}

// nftLog is one kernel log line from an nft log rule.
type nftLog struct {
	T                       time.Time
	Prefix, Src, Dst, Proto string
	Dport                   string
}

// parseNftLog reads a journalctl -o short-iso line ("<stamp> <host>
// kernel: pi-fortress <prefix>: SRC=... DST=... PROTO=... DPT=..."), or
// the MESSAGE of an -o json entry, which is the same from "pi-fortress"
// on. A missing or foreign stamp leaves T zero. The caller stamps it
// from the entry, or now.
func parseNftLog(line string) (nftLog, bool) {
	m := nftLogRe.FindStringSubmatch(line)
	if m == nil {
		return nftLog{}, false
	}
	l := nftLog{Prefix: m[1]}
	for _, kv := range nftKV.FindAllStringSubmatch(m[2], -1) {
		switch kv[1] {
		case "SRC":
			l.Src = kv[2]
		case "DST":
			l.Dst = kv[2]
		case "PROTO":
			l.Proto = strings.ToLower(kv[2])
		case "DPT":
			l.Dport = kv[2]
		}
	}
	if l.Src == "" || l.Dst == "" {
		return nftLog{}, false
	}
	if stamp, _, ok := strings.Cut(line, " "); ok {
		// systemd 257 prints +05:30 where older ones print +0530.
		for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339} {
			if t, err := time.Parse(layout, stamp); err == nil {
				l.T = t.UTC()
				break
			}
		}
	}
	return l, true
}

// capWriter keeps the first n bytes and reports the rest as written, so
// the child sees no short write and keeps running to its exit status.
type capWriter struct {
	b *bytes.Buffer
	n int
}

func (w *capWriter) Write(p []byte) (int, error) {
	// The function reports all of p as written. A report of only the kept
	// bytes was a short write. That ended the copy, closed the pipe and
	// killed journalctl with SIGPIPE at the limit: a failure that dropped
	// the cursor and skipped the backlog behind it.
	n := len(p)
	if room := w.n - w.b.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		w.b.Write(p)
	}
	return n, nil
}

// classify maps an nft log prefix to segment and threat:
//
//   - "-blacklist": the feed behind the address.
//   - "-drop": the input chain of the Pi itself (a client that pokes the
//     gateway on a closed port).
//   - "-killswitch": the house VPN kill switch.
//   - "-directip": a client that dials an IP directly, past the resolver.
//   - "-doh": a DNS-over-HTTPS attempt.
//   - "-http": plain HTTP with HOUSE_BLOCK_HTTP=on.
//   - "-vpn": the VPN of a device itself, with HOUSE_BLOCK_VPN on.
//   - "-sni": a 443 flow to an address that the house did not give out,
//     whose TLS name failed the check of pf dns.
//   - "-port": a port that strict HOUSE_EGRESS does not allow.
//   - "-audit": a port that it would not allow (passed).
//   - "-local": a private address, also the LAN of the uplink.
//   - "-connlimit": a new flow over the connection budget of the device
//     or of the segment (render/connlimit.go).
//   - "-spoof": a source outside the subnet of the segment itself
//     (render antiSpoof).
//
// All other prefixes (ssh-allow) are not a block.
func (o *Observer) classify(l nftLog) (segment, threat string, ok bool) {
	i := strings.LastIndex(l.Prefix, "-")
	if i <= 0 {
		return "", "", false
	}
	segment = l.Prefix[:i]
	switch l.Prefix[i+1:] {
	case "blacklist":
		return segment, feedForIP(o.ipFeeds, l.Dst), true
	case "drop":
		return segment, "pi_input", true
	case "killswitch":
		return segment, "killswitch", true
	case "directip":
		return segment, "direct_ip", true
	case "doh":
		return segment, "doh", true
	case "http":
		return segment, "http", true
	case "vpn":
		return segment, "vpn", true
	case "sni":
		return segment, "sni", true
	case "port":
		return segment, "port", true
	case "local":
		// Not "local": that threat is an operator blacklist hit, and a house
		// device that tries to reach the uplink router is a different thing.
		return segment, "lan", true
	case "audit":
		return segment, "audit_port", true
	case "connlimit":
		return segment, "conn_limit", true
	case "spoof":
		return segment, "spoof", true
	}
	return "", "", false
}

// ingestJournal reads the kernel log past the saved cursor and records an
// Event per nft drop line. With no cursor yet, it reads the last 500
// matching lines. It drops a cursor that journalctl rejects (rotated
// away), so the next tick starts again the same way. The cursor goes to
// disk at Flush with the offsets. A box without journalctl reads nothing, silently.
func (o *Observer) ingestJournal(st *State) {
	if len(o.JournalCmd) == 0 {
		return
	}
	if !o.cursorRead {
		o.cursorRead = true
		if raw, err := os.ReadFile(o.JournalCursorPath); err == nil {
			o.cursor = strings.TrimSpace(string(raw))
		}
	}
	args := append(slices.Clone(o.JournalCmd[1:]), "--show-cursor")
	if o.cursor != "" {
		args = append(args, "--after-cursor="+o.cursor)
	} else {
		args = append(args, "-n", "500")
	}
	wait := o.journalTimeout
	if wait <= 0 {
		wait = journalWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.JournalCmd[0], args...)
	cmd.WaitDelay = time.Second
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	// cmd.Output() held each byte that journalctl printed, and the agent
	// decides how many nft drop lines there are to print. Past the limit,
	// the remainder of the capture is dropped, and with it the trailing
	// "-- cursor: " line. Under -o json, each entry carries its own
	// cursor. Thus the next tick continues after the last whole entry
	// read, and does not ask for the same window again forever.
	limit := o.journalCap
	if limit <= 0 {
		limit = maxJournal
	}
	cmd.Stdout = &capWriter{b: &stdout, n: limit}
	err := cmd.Run()
	out := stdout.Bytes()
	if err != nil && ctx.Err() != nil {
		// Out of time is not a rejected cursor: what was read stays. The
		// next tick continues after it, and does not skip to the last 500
		// lines over the backlog between.
		o.journalErr = ""
		o.journalLines(st, out, false)
		return
	}
	if err != nil {
		// With nothing past the cursor, journalctl exits 1: with "-- No
		// entries --" in the short formats, and with only the cursor line
		// and nothing on stderr under -o json (systemd 252). A rejected
		// cursor gives the reason on stderr. Only a real failure drops it.
		var exit *exec.ExitError
		quiet := errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(stderr.Bytes())) == 0
		if quiet || bytes.Contains(append(out, stderr.Bytes()...), []byte("-- No entries --")) {
			return
		}
		o.cursor = ""
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return
		}
		msg, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		if msg == "" {
			msg = err.Error()
		}
		if msg != o.journalErr && o.Stderr != nil {
			fmt.Fprintf(o.Stderr, "observe: journalctl: %s\n", msg)
		}
		o.journalErr = msg
		return
	}
	o.journalErr = ""
	o.journalLines(st, out, true)
}

// journalEntry is the part of a journalctl -o json entry this reads.
// MESSAGE is a string, or an array of bytes when it is not valid UTF-8.
type journalEntry struct {
	Cursor   string          `json:"__CURSOR"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
	Message  json.RawMessage `json:"MESSAGE"`
}

func (e journalEntry) message() (string, bool) {
	var s string
	if json.Unmarshal(e.Message, &s) == nil {
		return s, true
	}
	var b []byte
	var ints []int
	if json.Unmarshal(e.Message, &ints) != nil {
		return "", false
	}
	for _, i := range ints {
		b = append(b, byte(i))
	}
	return string(b), true
}

// journalLines records the nft drop lines in one capture and moves the
// cursor past them: to the trailing "-- cursor: " line when the capture
// is whole, or else to the last entry that arrived whole. A line cut by
// the limit or the timeout parses as nothing and moves nothing. With whole
// false, it ignores the last line, which a killed journalctl can cut
// short. It also ignores each text line, which has no cursor to move past it.
func (o *Observer) journalLines(st *State, out []byte, whole bool) {
	text := string(out)
	if !whole {
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			text = text[:i]
		} else {
			text = ""
		}
	}
	for line := range strings.SplitSeq(text, "\n") {
		if c, ok := strings.CutPrefix(line, "-- cursor: "); ok {
			o.cursor = strings.TrimSpace(c)
			continue
		}
		var at time.Time
		if strings.HasPrefix(line, "{") {
			var e journalEntry
			if json.Unmarshal([]byte(line), &e) != nil || e.Cursor == "" {
				continue
			}
			o.cursor = e.Cursor
			msg, ok := e.message()
			if !ok {
				continue
			}
			if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
				at = time.UnixMicro(us).UTC()
			}
			line = msg
		} else if !whole {
			// A text line carries no cursor. Thus if a cut capture recorded
			// it, it would record it again for a new request of the same window.
			continue
		}
		l, ok := parseNftLog(line)
		if !ok {
			continue
		}
		if l.T.IsZero() {
			l.T = at
		}
		segment, threat, ok := o.classify(l)
		if !ok {
			continue
		}
		t := l.T
		if t.IsZero() {
			t = o.now().UTC()
		}
		detail := l.Proto
		if l.Dport != "" {
			detail += " " + l.Dport
		}
		if _, me := o.self[l.Src]; !me {
			o.client(st, segment, l.Src, t.Format(base.ISO)).Blocked++
		}
		o.event(st, Event{T: t, Segment: segment, Src: l.Src, Dst: l.Dst, Threat: threat, Detail: strings.TrimSpace(detail)})
	}
}

// stateReplaced says whether a different writer published the state file
// after this process last did. pf observe reset writes an empty ledger
// and rewinds the checkpoints. Before, the running daemon kept the ledger
// that it had cached and put it back on the next flush. Thus the reset
// that the operator asked for lasted only until the next tick.
func (o *Observer) stateReplaced() bool {
	if o.StatePath == "" || o.savedID == (fileID{}) {
		return false
	}
	fi, err := os.Stat(o.StatePath)
	if err != nil {
		return true
	}
	return idOf(fi) != o.savedID
}

func (o *Observer) Snapshot() *State {
	env := base.LoadEnvOverlay(o.NetEnvPath, o.NetEnvLocal)
	agentNet := env["AGENT_NET"]
	if agentNet == "" {
		agentNet = "10.77.0.0/24"
	}
	piIP := env["PI_IP"]
	if piIP == "" {
		piIP = "10.77.0.1"
	}
	o.self = map[string]struct{}{piIP: {}}
	skip := []string{env["VBOX_NAT_NET"], agentNet}
	if skip[0] == "" {
		skip[0] = "10.0.2.0/24"
	}
	if o.st == nil || !o.buffered() || o.stateReplaced() {
		o.st = o.Load()
		o.offsets = nil
		o.cursorRead = false
		o.lastFlush = o.now()
	}
	st := o.st
	o.loadMaps()
	o.ingestDNS(st, agentNet)
	ct := ""
	raw, ctErr := o.readCT()
	if ctErr == nil {
		ct = string(raw)
	}
	o.ctSeeding = !o.ctPrimed
	seen := map[string]int64{}
	o.ingestCT(st, ct, "", agentNet, piIP, skip, seen)
	// House segment, when /etc/pi-fortress/house.env (or HouseEnvPath)
	// names one. Queries are tagged so pf tui can group by segment.
	house := base.LoadEnvFirst(o.HouseEnvPath)
	if house["HOUSE_IF"] != "" {
		houseNet := house["HOUSE_NET"]
		if houseNet == "" {
			houseNet = "10.78.0.0/24"
		}
		houseIP := house["HOUSE_IP"]
		if houseIP == "" {
			houseIP = "10.78.0.1"
		}
		o.self[houseIP] = struct{}{}
		o.ingestDNSLog(st, o.HouseDNSLog, o.HouseOffsetPath, houseNet, "house")
		o.ingestCT(st, ct, "house", houseNet, houseIP, []string{skip[0], houseNet}, seen)
	}
	// Plain segments, each with its own resolver, log and checkpoint.
	// Use plainSegments, not segments: agent and house are read above, and
	// a second read of either would count each row in it twice.
	plain := PlainSegments(o.SegmentsDir)
	if len(plain) > 0 {
		o.loadKeyRules()
	}
	for _, s := range plain {
		o.self[s.IP] = struct{}{}
		o.ingestDNSLog(st, o.segDNSLog(s.Name), o.segOffset(s.Name), s.Net, s.Name)
		o.ingestCT(st, ct, s.Name, s.Net, s.IP, []string{skip[0], s.Net}, seen)
	}
	o.seenCT = seen
	o.ctSeeding = false
	if ctErr == nil {
		o.ctPrimed = true
	}
	o.ingestJournal(st)
	o.ingestStrip(st)
	o.evictIdle(st)
	// After the segments are known, and before enrich rewrites the MAC
	// that this reads from the same table. enrich forgets what a moved
	// address did before. This is correct for the stats, but silent about the move.
	o.watchARP(st)
	o.enrich(st)
	if o.due() {
		_ = o.Flush()
	}
	return st
}

// Flush appends the first-seen rows and then saves the state. Only after
// that state is on disk does it advance the checkpoints that describe it.
// The old order wrote the offsets and the journal cursor first. Thus a
// failed Save -- a full disk is the usual cause -- left checkpoints that
// pointed past a ledger that never recorded what they had already
// consumed, and nothing read that window again. Also, the ledger append
// is no longer silent: a first-seen row that could not be written is the
// record that the operator is asked to trust. Run calls this on shutdown.
func (o *Observer) Flush() error {
	o.lastFlush = o.now()
	if o.st == nil {
		return nil
	}
	return o.withStateLock(o.flush)
}

func (o *Observer) flush() error {
	st := o.st
	if o.rows.Len() > 0 && o.JSONLPath != "" {
		if err := appendRows(o.JSONLPath, o.rows.Bytes()); err != nil {
			return err
		}
		o.rows.Reset()
	}
	expireEvents(st, o.now())
	expireSeries(st, o.now())
	expireDests(st, o.now())
	if err := o.save(st); err != nil {
		return err
	}
	var err error
	for path, cp := range o.offsets {
		if e := writeCheckpoint(path, cp); e != nil && err == nil {
			err = e
		}
	}
	if o.cursor != "" && o.JournalCursorPath != "" {
		if e := os.MkdirAll(filepath.Dir(o.JournalCursorPath), 0755); e != nil && err == nil {
			err = e
		} else if e := writeAtomic(o.JournalCursorPath, []byte(o.cursor+"\n"), 0644); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func appendRows(path string, rows []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	if _, err := f.Write(rows); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writeCheckpoint(path string, cp checkpoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	mark := strconv.FormatInt(cp.off, 10)
	if cp.id != (fileID{}) {
		mark += " " + cp.id.String()
	}
	return writeAtomic(path, []byte(mark+"\n"), 0644)
}

// writeAtomic replaces path with data through a temp file renamed over it.
// Thus a crash or a full disk leaves the old file or the new file, never a
// torn file from which a restart would read a wrong offset or cursor.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chmod(perm)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// showEvents prints one section of the ring, newest 40, oldest first.
func showEvents(w io.Writer, heading string, evs []Event) {
	fmt.Fprintf(w, "%s (%d)\n", heading, len(evs))
	if len(evs) == 0 {
		fmt.Fprintln(w, "  (none yet)")
	}
	start := 0
	if len(evs) > 40 {
		start = len(evs) - 40
	}
	for _, e := range evs[start:] {
		times := ""
		if e.N > 1 {
			times = fmt.Sprintf(" ×%d", e.N)
		}
		fmt.Fprintf(w, "  %-22s %-5s %-15s %-40s %s %s%s\n", e.T.Format(base.ISO), e.Segment, e.Src, e.Dst, e.Threat, e.Detail, times)
	}
}

func (o *Observer) Show(st *State) {
	type dnsRow struct {
		name string
		rec  *DNSRec
	}
	dns := make([]dnsRow, 0, len(st.DNS))
	for n, r := range st.DNS {
		dns = append(dns, dnsRow{n, r})
	}
	sort.Slice(dns, func(i, j int) bool { return dns[i].rec.FirstSeen < dns[j].rec.FirstSeen })
	type flowRow struct {
		key string
		rec *FlowRec
	}
	flows := make([]flowRow, 0, len(st.Flows))
	for k, r := range st.Flows {
		flows = append(flows, flowRow{k, r})
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].rec.FirstSeen < flows[j].rec.FirstSeen })
	w := o.out()
	fmt.Fprintf(w, "observe started %s\n", st.Started)
	fmt.Fprintf(w, "DNS first-seen (%d)\n", len(dns))
	if len(dns) == 0 {
		fmt.Fprintln(w, "  (none yet)")
	}
	start := 0
	if len(dns) > 40 {
		start = len(dns) - 40
	}
	for _, row := range dns[start:] {
		flag := ""
		if row.rec.Sinkholed {
			flag = " sinkhole"
		}
		fmt.Fprintf(w, "  %-22s %-40s n=%d%s\n", row.rec.FirstSeen, row.name, row.rec.Count, flag)
	}
	fmt.Fprintf(w, "FLOWS first-seen (%d)\n", len(flows))
	if len(flows) == 0 {
		fmt.Fprintln(w, "  (none yet)")
	}
	start = 0
	if len(flows) > 40 {
		start = len(flows) - 40
	}
	for _, row := range flows[start:] {
		fmt.Fprintf(w, "  %-22s %-28s bytes=%d\n", row.rec.FirstSeen, row.key, row.rec.Bytes)
	}
	if len(st.Dests) > 0 {
		showDests(w, st)
	}
	clients := make([]*Client, 0, len(st.Clients))
	for _, c := range st.Clients {
		clients = append(clients, c)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Queries+clients[i].Flows > clients[j].Queries+clients[j].Flows })
	fmt.Fprintf(w, "CLIENTS (%d)\n", len(clients))
	if len(clients) == 0 {
		fmt.Fprintln(w, "  (none yet)")
	}
	if len(clients) > 40 {
		clients = clients[:40]
	}
	for _, c := range clients {
		fmt.Fprintf(w, "  %-22s %-5s %-15s %-17s %-20s q=%d f=%d b=%d\n", c.LastSeen, c.Segment, c.IP, c.MAC, c.Name, c.Queries, c.Flows, c.Blocked)
	}
	// The ring holds both, and the two headings have different meanings:
	// under BLOCKED, the Pi stopped something. Under ALERTS, it only saw
	// it. A neighbour that claims an address still succeeds.
	var blocked, alerts []Event
	for _, e := range st.Events {
		if e.Alert() {
			alerts = append(alerts, e)
		} else {
			blocked = append(blocked, e)
		}
	}
	showEvents(w, "BLOCKED", blocked)
	showEvents(w, "ALERTS", alerts)
	days := Days(st, o.now(), time.Local)
	segs := make([]string, 0, len(days))
	for seg := range days {
		segs = append(segs, seg)
	}
	sort.Strings(segs)
	fmt.Fprintln(w, "SERIES 7d (local days)")
	for _, seg := range segs {
		for _, d := range days[seg] {
			fmt.Fprintf(w, "  %-5s %-5s q=%d f=%d b=%d\n", d.Day, seg, d.Queries, d.Flows, d.Blocked)
		}
	}
}

// Reset is the clean slate of the operator: an empty ledger and each
// checkpoint moved to the end of its log. It holds the state lock for all
// of that. Thus a daemon flush cannot occur between the empty ledger and
// the rewound checkpoints and publish again what was just discarded.
func (o *Observer) Reset() error {
	if err := o.withStateLock(o.reset); err != nil {
		return err
	}
	fmt.Fprintln(o.out(), "observe state reset")
	return nil
}

func (o *Observer) reset() error {
	if err := os.MkdirAll(filepath.Dir(o.StatePath), 0755); err != nil {
		return err
	}
	if err := o.save(o.empty()); err != nil {
		return err
	}
	// Each checkpoint, not only the agent checkpoint. When the house
	// resolver offset and the journal cursor stayed where they were, the
	// next run rebuilt a ledger with a hole of exactly the size of what
	// reset had just claimed to discard.
	pairs := [][2]string{
		{o.DNSLog, o.OffsetPath},
		{o.StripLog, o.StripOffsetPath},
		{o.HouseDNSLog, o.HouseOffsetPath},
	}
	for _, s := range PlainSegments(o.SegmentsDir) {
		pairs = append(pairs, [2]string{o.segDNSLog(s.Name), o.segOffset(s.Name)})
	}
	for _, l := range pairs {
		if l[1] == "" {
			continue
		}
		cp := checkpoint{}
		if fi, err := os.Stat(l[0]); err == nil {
			cp = checkpoint{off: fi.Size(), id: idOf(fi)}
		}
		if err := writeCheckpoint(l[1], cp); err != nil {
			return err
		}
	}
	if o.JournalCursorPath != "" {
		if err := os.Remove(o.JournalCursorPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	o.st, o.offsets, o.seenCT = nil, nil, nil
	o.ctPrimed = false
	o.vol, o.dstNames, o.segNames = nil, nil, nil
	o.tun, o.tunSupp = nil, nil
	o.cursor, o.cursorRead = "", false
	o.rows.Reset()
	return nil
}

// Once is what `pf observe once` runs. It prints the snapshot in both
// cases, because the purpose of the command is a report that the operator
// can read. But it returns the flush error and does not drop it: a run
// that could not write the ledger advanced nothing. A report of success
// let the next run read the same input again, with no sign of a problem.
func (o *Observer) Once() error {
	st := o.Snapshot()
	err := o.Flush()
	o.Show(st)
	return err
}

func (o *Observer) Run(ctx context.Context) error {
	iv := o.Interval
	if iv < 2*time.Second {
		iv = 2 * time.Second
	}
	o.Snapshot()
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return o.Flush()
		case <-t.C:
			o.Snapshot()
		}
	}
}
