// Package fetch downloads the blocklist feeds named in sources.json and parses
// them into domain and IP lists on disk. pf fetch, the TUI and internal/admin
// call it.
package fetch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/policycompile"
)

type Spec struct {
	Comment    string `json:"comment,omitempty"`
	UserAgent  string `json:"user_agent"`
	TimeoutSec int    `json:"timeout_sec"`
	MaxIPs     int    `json:"max_ips"`
	MaxDomains int    `json:"max_domains"`
	// MinIPPrefix is the widest prefix that an IP feed can add to the
	// blocklist (8 to 32). pf compile drops a wider one. 0 means
	// policycompile.FeedMinBits.
	MinIPPrefix int    `json:"min_ip_prefix,omitempty"`
	Feeds       []Feed `json:"feeds"`
	// Seeded is each feed id that a ship has offered this box. MergeSeed
	// adds a shipped feed only when its id is not here, so a feed that the
	// operator deleted stays deleted.
	Seeded []string `json:"seeded,omitempty"`
}

type Feed struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Format string `json:"format"`
	URL    string `json:"url"`
	// Segment "house" keeps a domains feed off the agent segment: ads and
	// trackers are a family concern, not a blocklist feed.
	// Empty
	// means every segment.
	Segment string `json:"segment,omitempty"`
	// Role "vpn" puts a house feed in its own list
	// (policycompile.HouseVPNFile). The house resolver serves that list
	// only while HOUSE_BLOCK_VPN is on. So when the key is off, VPN apps
	// resolve again, and the ad feeds stay on.
	Role string `json:"role,omitempty"`
	// nil means enabled. The field is written only when an operator
	// disables a feed.
	Enabled *bool  `json:"enabled,omitempty"`
	License string `json:"license,omitempty"`
	Why     string `json:"why,omitempty"`
}

func (f Feed) On() bool { return f.Enabled == nil || *f.Enabled }

// validate refuses a sources.json that decodes but does not mean
// anything. JSON decoding only proves the types, and each value below
// changes what a feed is. A misspelled segment selector reads as the
// shared one, and sends a full ad-blocking category to the agents. An
// unrecognised format quietly falls through to the plain parser, and reads
// a hosts file as one name per line. A negative cap slices the merged list
// backwards, and crashes the process. None of these show at fetch time. So
// they are refused before any download, cache or write.
//
// The one mismatch that is not refused here is a house feed that is not
// domains. Run reports that as a SKIP, so the rest of the run continues.
// A house selector on an IP feed is the one combination that an operator
// selects by accident, and it costs nothing else.
func (s *Spec) validate() error {
	for _, x := range []struct {
		key string
		val int
	}{{"max_ips", s.MaxIPs}, {"max_domains", s.MaxDomains}, {"timeout_sec", s.TimeoutSec}} {
		if x.val < 0 {
			return fmt.Errorf("sources.json: %s=%d is negative", x.key, x.val)
		}
	}
	if p := s.MinIPPrefix; p != 0 && (p < 8 || p > 32) {
		return fmt.Errorf("sources.json: min_ip_prefix=%d is not 8 to 32", p)
	}
	seen := map[string]bool{}
	for _, f := range s.Feeds {
		if _, ok := cacheName(f.ID); !ok {
			return fmt.Errorf("sources.json: '%s' is not a feed id; letters, digits, dot, dash and underscore, up to 64 of them", f.ID)
		}
		if seen[f.ID] {
			return fmt.Errorf("sources.json: two feeds are called '%s'; the id names the feed's last-good copy, so both would overwrite one file", f.ID)
		}
		seen[f.ID] = true
		if f.URL == "" {
			return fmt.Errorf("sources.json: feed '%s' has no url", f.ID)
		}
		if f.Kind != "domains" && f.Kind != "ips" {
			return fmt.Errorf("sources.json: feed '%s' has kind '%s'; it is domains or ips", f.ID, f.Kind)
		}
		switch f.Format {
		case "", "plain":
		case "hosts":
			if f.Kind != "domains" {
				return fmt.Errorf("sources.json: feed '%s' is format hosts and kind %s; a hosts file carries names", f.ID, f.Kind)
			}
		case "spamhaus":
			if f.Kind != "ips" {
				return fmt.Errorf("sources.json: feed '%s' is format spamhaus and kind %s; that list carries addresses", f.ID, f.Kind)
			}
		default:
			return fmt.Errorf("sources.json: feed '%s' has format '%s'; it is plain, hosts or spamhaus", f.ID, f.Format)
		}
		if f.Segment != "" && !knownSegment(f.Segment) {
			return fmt.Errorf("sources.json: feed '%s' names segment '%s', which is not a segment; leave it out for every segment", f.ID, f.Segment)
		}
		if f.Role != "" && (f.Role != "vpn" || f.Segment != policycompile.SegmentFor(policycompile.AllowByDefault).Name || f.Kind != "domains") {
			return fmt.Errorf("sources.json: feed '%s' has role '%s'; the only role is vpn, on a house domains feed", f.ID, f.Role)
		}
	}
	return nil
}

func knownSegment(name string) bool {
	for _, s := range policycompile.Segments {
		if s.Name == name {
			return true
		}
	}
	return false
}

// ParseHosts reads hosts-file format ("0.0.0.0 example.com") into
// domains.
//
// A hosts record can carry several names for one address, and the feed
// asks to block each of them. When only the first name was read, the rest
// stayed reachable, but the report counted the record as taken. So the
// coverage of the feed was quietly smaller than what it said. A name that
// does not parse is skipped alone. Before, one numeric or malformed alias
// cost the record each valid name behind it.
func ParseHosts(body string) []string { return slices.Collect(hostsSeq(body)) }

func hostsSeq(body string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range strings.SplitSeq(body, "\n") {
			tok := policycompile.StripLine(line)
			if tok == "" {
				continue
			}
			f := strings.Fields(tok)
			if len(f) < 2 || !sinkAddr(f[0]) {
				continue
			}
			for _, name := range f[1:] {
				if parsed, ok := hostName(name); ok && !yield(parsed) {
					return
				}
			}
		}
	}
}

// sinkAddr says if a token is an address that a hosts file sends a blocked
// name to: the unspecified address or a loopback address (127.0.0.0/8,
// ::1). A line with a different address maps a name; it does not block it.
func sinkAddr(tok string) bool {
	a, err := netip.ParseAddr(tok)
	return err == nil && (a.IsUnspecified() || a.IsLoopback())
}

// hostName parses one name of a hosts line.
func hostName(token string) (string, bool) {
	parsed, ok := parseDomain(token)
	if !ok {
		return "", false
	}
	// "0.0.0.0 0.0.0.0" and similar: an address is not a name, although
	// four numeric labels satisfy the domain grammar. The check is on the
	// parsed name, so "*.0.0.0.0" and "0.0.0.0." are also not names.
	if _, err := netip.ParseAddr(parsed); err == nil {
		return "", false
	}
	return parsed, true
}

type Fetcher struct {
	PolicyDir string
	OutDir    string
	// Get, when set, replaces the HTTP client fully. The final URL is
	// then taken to be the requested one.
	Get func(url, ua string, timeout time.Duration) (string, error)
	// Now dates a stale feed against its cached copy; nil means time.Now.
	Now func() time.Time
	web *client
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func Defaults(policyDir, outDir string) *Fetcher {
	return &Fetcher{PolicyDir: policyDir, OutDir: outDir}
}

const (
	maxHops = 3
	maxBody = 8 << 20
)

var testNet1 = netip.MustParsePrefix("192.0.2.0/24")

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if !a.Is4() {
		return a.IsGlobalUnicast()
	}
	if testNet1.Contains(a) {
		return false
	}
	for _, p := range policycompile.Reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// client resolves each host itself, and dials only addresses that passed
// the public check. So a rebinding resolver cannot pass the check with one
// answer and steer the dial with a different answer. An address that does
// not pass is skipped. A host with no public address fails.
type client struct {
	public func(netip.Addr) bool
	tls    *tls.Config
	// lookup and dialTo replace the resolver and the dialer in a test. nil
	// means the system resolver and a net.Dialer.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dialTo func(ctx context.Context, network, addr string) (net.Conn, error)
}

type page struct {
	body  string
	final string
}

func (c *client) dial(ctx context.Context, network, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	lookup := c.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	dialTo := c.dialTo
	if dialTo == nil {
		d := net.Dialer{Timeout: 10 * time.Second}
		dialTo = d.DialContext
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	// A host can publish a private or ULA address beside its public ones.
	// dial skips that address, and it fails only when no address is
	// public. The error names the first address that it skipped.
	var public []netip.Addr
	var skipped netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if c.public(a) {
			public = append(public, a)
		} else if !skipped.IsValid() {
			skipped = a
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("%s resolves to %s: not public", host, skipped)
	}
	for _, a := range public {
		conn, derr := dialTo(ctx, network, net.JoinHostPort(a.String(), port))
		if derr == nil {
			return conn, nil
		}
		err = derr
	}
	return nil, err
}

func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%s: only https", u.Redacted())
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%s: no host", u.Redacted())
	}
	return nil
}

func (c *client) get(rawURL, ua string, timeout time.Duration) (page, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return page{}, err
	}
	if err := checkURL(req.URL); err != nil {
		return page{}, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	hc := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         c.dial,
			TLSClientConfig:     c.tls,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHops {
				return fmt.Errorf("more than %d redirects", maxHops)
			}
			return checkURL(req.URL)
		},
	}
	resp, err := hc.Do(req)
	if err != nil {
		return page{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return page{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if !framed(resp) {
		return page{}, fmt.Errorf("answer has no Content-Length and is not chunked, so its end cannot be checked")
	}
	// One byte past the cap, so the code can tell a body that reaches the cap
	// from a body that stops just under it. LimitReader alone gives back an
	// ordinary EOF at the boundary, and then a truncated feed looks like a
	// complete one. All after the cut is silently no longer blocked. The
	// token where the cut landed can still satisfy the domain grammar, and
	// block a name that the publisher never listed. A feed that grew past
	// the cap is a failure like all others. So the run uses the last copy
	// that was whole.
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return page{}, err
	}
	if len(b) > maxBody {
		return page{}, fmt.Errorf("feed is larger than %d bytes", maxBody)
	}
	return page{body: string(b), final: resp.Request.URL.String()}, nil
}

// framed says if the answer marks where its body ends, so that net/http
// can tell a whole body from one that the connection cut.
//
// An HTTP/1.1 body with no Content-Length and no chunked encoding ends when
// the server closes the connection. crypto/tls gives a clean io.EOF for a
// TCP close at a TLS record boundary, also when no close_notify came first.
// The client does not show if close_notify came. So such a body that a
// dropped connection cuts reads as whole, with no error. The cut can land
// at a line end, and then each line parses. fetch thus requires framing:
//   - Content-Length: net/http gives io.ErrUnexpectedEOF for a body that
//     is shorter.
//   - chunked: the body must end with the last chunk of size 0.
//   - gzip that the Transport decoded (Uncompressed): the gzip trailer has
//     the length and the CRC of the data, and a cut gives an error. The
//     Transport removes Content-Length in this case.
//   - HTTP/2 and later: each stream ends with an END_STREAM flag.
func framed(resp *http.Response) bool {
	return resp.ContentLength >= 0 || slices.Contains(resp.TransferEncoding, "chunked") || resp.Uncompressed || resp.ProtoMajor >= 2
}

func parseDomain(token string) (string, bool) {
	got, ok := policycompile.ParseDomain(token)
	if !ok {
		return "", false
	}
	if strings.HasSuffix(got, ".localhost") || strings.HasSuffix(got, ".local") {
		return "", false
	}
	return got, true
}

func parseToken(token, kind string) (string, bool) {
	if kind == "ips" {
		return policycompile.ParseIPv4(token)
	}
	return parseDomain(token)
}

// ParsePlain reads one entry from each line: the first field.
//
// A domains feed with no format key reads as plain. When that feed is a
// hosts file, the first field is the address, and the feed blocked 0.0.0.0
// in place of its names. So a line that starts with a sink address and has
// a name after it gives the name, and an address is not a name, as in
// ParseHosts. All other lines give the first field. A line that is only an
// address stays an entry if pf compile can block it: it refuses a private
// or reserved address, as in an IP feed. A line keeps one entry: a hosts
// feed with aliases needs format hosts.
func ParsePlain(body, kind string) []string { return slices.Collect(plainSeq(body, kind)) }

func plainSeq(body, kind string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range strings.SplitSeq(body, "\n") {
			tok := policycompile.StripLine(line)
			if tok == "" {
				continue
			}
			f := strings.Fields(tok)
			parsed, ok := "", false
			if kind == "domains" && len(f) > 1 && sinkAddr(f[0]) {
				parsed, ok = hostName(f[1])
			} else {
				parsed, ok = parseToken(f[0], kind)
			}
			if _, err := netip.ParseAddr(parsed); ok && kind == "domains" && err == nil {
				_, ok = policycompile.ParseIPv4(parsed)
			}
			if ok && !yield(parsed) {
				return
			}
		}
	}
}

func ParseSpamhaus(body string) []string { return slices.Collect(spamhausSeq(body)) }

func spamhausSeq(body string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for raw := range strings.SplitSeq(body, "\n") {
			if strings.HasPrefix(strings.TrimLeft(raw, " \t"), ";") {
				continue
			}
			tok := policycompile.StripLine(raw)
			if tok == "" {
				continue
			}
			token := strings.Fields(tok)[0]
			if parsed, ok := policycompile.ParseIPv4(token); ok && !yield(parsed) {
				return
			}
		}
	}
}

// readListFile reads a never_block file of the operator. pf compile reads
// the same file with policycompile.LoadTokens, so each line goes through
// the parser that LoadTokens uses for kind. Before, a domain line that did
// not parse was kept as written. It then shielded nothing, or, as a single
// label, it shielded names in fetch that compile still blocked. A skipped
// line is a mistake of the operator, so it goes in the report as a WARN.
func readListFile(path, kind string, report *[]string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	parse, what := policycompile.ParseDomain, "a domain"
	if kind == "ips" {
		parse, what = policycompile.ParseIPv4, "an IPv4 address or prefix"
	}
	var out []string
	seen := map[string]struct{}{}
	n := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		n++
		tok := policycompile.StripLine(line)
		if tok == "" {
			continue
		}
		parsed, ok := parse(tok)
		if !ok {
			*report = append(*report, fmt.Sprintf("WARN %s line %d: %q is not %s; skipped", filepath.Base(path), n, tok, what))
			continue
		}
		if _, dup := seen[parsed]; dup {
			continue
		}
		seen[parsed] = struct{}{}
		out = append(out, parsed)
	}
	return out
}

func neverIPSet(tokens []string) []netip.Prefix {
	var out []netip.Prefix
	for _, t := range tokens {
		if p, err := netip.ParsePrefix(t); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil && a.Is4() {
			out = append(out, netip.PrefixFrom(a, 32))
		}
	}
	return out
}

func uniq(items []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	return out
}

func readSpec(policy string) (Spec, error) {
	var spec Spec
	raw, err := os.ReadFile(filepath.Join(policy, "sources.json"))
	if err != nil {
		return spec, err
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return spec, err
	}
	return spec, spec.validate()
}

// settings gives the run values of the spec, with each zero replaced by
// its default.
func (s *Spec) settings() (ua string, timeout time.Duration, maxIPs, maxDoms int) {
	ua = s.UserAgent
	if ua == "" {
		ua = "pi-fortress/0.1"
	}
	// 60 s per feed: hagezi-pro is about 5 MB. On 2026-09-25, 30 s timed out
	// on the Wi-Fi uplink of the Pi, but the same file took 2 s a minute
	// later. A miss only causes a fallback to the last good copy.
	timeout = time.Duration(s.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	maxIPs, maxDoms = s.MaxIPs, s.MaxDomains
	if maxIPs == 0 {
		maxIPs = 20000
	}
	if maxDoms == 0 {
		maxDoms = 50000
	}
	return ua, timeout, maxIPs, maxDoms
}

func toSet(items []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func (f *Fetcher) get(u, ua string, timeout time.Duration) (page, error) {
	if f.Get != nil {
		body, err := f.Get(u, ua, timeout)
		return page{body: body, final: u}, err
	}
	web := f.web
	if web == nil {
		web = &client{public: publicAddr}
	}
	return web.get(u, ua, timeout)
}

// parseFeed gives the distinct entries of a feed, in feed order, and stops
// after limit of them. cut is true when the body has more distinct entries
// than limit.
//
// The cap of the list applies to each feed while it is parsed, not only
// after the merge. A body of 8 MiB can hold more than a million short
// names, and each of them used memory in the parse, the shrink check, the
// cache and the merge before capShare kept max of them. Now a feed keeps at
// most max+1 entries. The merged list is the same: in capShare a feed never
// gives more than max entries, so the entries after the first max+1 do not
// change which entries it keeps. The one entry past max makes capShare
// report the cut. The cache keeps the entries that the parse kept, before
// never_block, as before.
func parseFeed(feed Feed, body string, limit int) (items []string, cut bool) {
	var seq iter.Seq[string]
	switch feed.Format {
	case "spamhaus":
		seq = spamhausSeq(body)
	case "hosts":
		seq = hostsSeq(body)
	default:
		seq = plainSeq(body, feed.Kind)
	}
	seen := map[string]struct{}{}
	for it := range seq {
		if _, dup := seen[it]; dup {
			continue
		}
		if len(items) >= limit {
			return items, true
		}
		seen[it] = struct{}{}
		items = append(items, it)
	}
	return items, false
}

// feedItems downloads and parses one feed, and keeps at most limit distinct
// entries; cut says that the feed has more. When that fails, it gives the
// last-good copy, and stale tells why. ok is false when the feed has no
// last-good copy.
func (f *Fetcher) feedItems(outDir, ua string, timeout time.Duration, feed Feed, limit int, report *[]string) (items []string, stale string, cut, ok bool) {
	why := ""
	pg, gerr := f.get(feed.URL, ua, timeout)
	if gerr != nil {
		why = gerr.Error()
	} else {
		if pg.final != feed.URL {
			*report = append(*report, "REDIRECT "+feed.ID+": "+pg.final)
		}
		items, cut = parseFeed(feed, pg.body, limit)
		// A feed that answers with an error page parses to nothing.
		// To treat that as a feed with no entries would drop each
		// name that it carries, so it is a failure like all others.
		if len(items) == 0 {
			why = "answered with nothing to parse"
		} else {
			why = f.shrunk(outDir, feed, items, report)
		}
	}
	if why == "" {
		if err := writeCache(outDir, feed, items); err != nil {
			// This is not a failure of this run: the feed answered, and its
			// names are in the lists below. The next run suffers, with no
			// fallback. So the operator learns about it now, and does not
			// discover it during an outage.
			*report = append(*report, "WARN "+feed.ID+": last-good copy not saved: "+err.Error())
		}
		return items, "", cut, true
	}
	cached, when, ok := readCache(outDir, feed)
	if !ok {
		*report = append(*report, "FAIL "+feed.ID+": "+why)
		return nil, "", false, false
	}
	return cached, " (last good " + Ago(f.now().Sub(when)) + ": " + why + ")", false, true
}

// shrinkFloor and shrinkHold bound the check in shrunk. A feed whose last
// good copy has fewer than shrinkFloor entries can shrink freely: a small
// feed of live addresses can lose half of them on a normal day.
const (
	shrinkFloor = 100
	shrinkHold  = 72 * time.Hour
)

// shrunk says why a fresh answer must not replace the last good copy, or
// "". An answer that parses to a few entries is the same failure as one
// that parses to none: an error page with one name in it, a body cut
// short, or a feed server that is not what it was. Each one silently stops
// the blocking of all the other entries, and it overwrites the copy that is
// the fallback. So an answer with less than half the distinct entries of
// the copy fails, and the copy serves.
//
// A feed can also really shrink. Once the copy is shrinkHold old, the
// smaller answer replaces it, with a WARN line. So the operator sees three
// days of STALE first, and the feed does not stay stale until somebody
// deletes its copy.
func (f *Fetcher) shrunk(outDir string, feed Feed, items []string, report *[]string) string {
	cached, when, ok := readCache(outDir, feed)
	if !ok {
		return ""
	}
	had, n := len(uniq(cached)), len(uniq(items))
	if had < shrinkFloor || n*2 >= had {
		return ""
	}
	if f.now().Sub(when) >= shrinkHold {
		*report = append(*report, fmt.Sprintf("WARN %s: answer of %d entries replaces a last good copy of %d", feed.ID, n, had))
		return ""
	}
	return fmt.Sprintf("answered with %d entries; the last good copy has %d", n, had)
}

func dropNever(items []string, kind string, neverNets []netip.Prefix, neverDoms map[string]struct{}) []string {
	var kept []string
	for _, item := range items {
		if kind == "ips" && policycompile.IsNeverIP(item, neverNets) {
			continue
		}
		if kind == "domains" && policycompile.IsNeverDomain(item, neverDoms) {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

func anyFail(report []string) bool {
	for _, line := range report {
		if strings.HasPrefix(line, "FAIL") {
			return true
		}
	}
	return false
}

func (f *Fetcher) Run() (report []string, nIPs, nDoms int, err error) {
	policy := f.PolicyDir
	outDir := f.OutDir
	if outDir == "" {
		outDir = filepath.Join(policy, "generated")
	}
	spec, err := readSpec(policy)
	if err != nil {
		return nil, 0, 0, err
	}
	ua, timeout, maxIPs, maxDoms := spec.settings()
	agent := policycompile.SegmentFor(policycompile.DenyByDefault)
	house := policycompile.SegmentFor(policycompile.AllowByDefault)
	neverNets := neverIPSet(readListFile(filepath.Join(policy, agent.File("never_block.ips")), "ips", &report))
	neverDomList := readListFile(filepath.Join(policy, agent.File("never_block.domains")), "domains", &report)
	// An address on never_block.domains also shields the IP feeds, as in
	// pf compile (policycompile.ipShields).
	neverNets = append(neverNets, neverIPSet(neverDomList)...)
	neverDoms := toSet(neverDomList)
	houseNever := toSet(readListFile(filepath.Join(policy, house.File("never_block.domains")), "domains", &report))
	// Each list holds the kept items of each feed apart, so capShare can
	// give each feed its share of the cap.
	var ips, domains, houseDomains, houseVPN [][]string
	// Each cut flag says that a feed of that list had more entries than the
	// cap, and that the parse did not read the rest.
	var cutIPs, cutDoms, cutHouse, cutVPN bool
	sample := ""
	seen := map[string]bool{}
	// feedOf remembers which feed carried each item, and the first feed wins.
	// feeds.map gives it to pf compile.
	feedOf := map[string]string{}
	for _, feed := range spec.Feeds {
		seen[feed.ID] = true
		if !feed.On() {
			report = append(report, "SKIP "+feed.ID+": disabled")
			continue
		}
		toHouse := feed.Segment == house.Name
		if toHouse && feed.Kind != "domains" {
			report = append(report, "SKIP "+feed.ID+": "+house.Name+" segment feeds must be domains")
			continue
		}
		limit := maxDoms
		if feed.Kind == "ips" {
			limit = maxIPs
		}
		items, stale, cut, ok := f.feedItems(outDir, ua, timeout, feed, limit+1, &report)
		if !ok {
			continue
		}
		never, label := neverDoms, feed.Kind
		if toHouse {
			never, label = houseNever, house.Name+" domains"
		}
		kept := uniq(dropNever(items, feed.Kind, neverNets, never))
		for _, item := range kept {
			if _, dup := feedOf[item]; !dup {
				feedOf[item] = feed.ID
			}
		}
		verb := "OK"
		if stale != "" {
			verb = "STALE"
		}
		note := ""
		if cut {
			note = fmt.Sprintf(" (more than the cap of %d; the rest not read)", limit)
		}
		report = append(report, fmt.Sprintf("%s %s: %d %s%s%s", verb, feed.ID, len(kept), label, note, stale))
		switch {
		case toHouse && feed.Role == "vpn":
			houseVPN = append(houseVPN, kept)
			cutVPN = cutVPN || cut
		case toHouse:
			houseDomains = append(houseDomains, kept)
			cutHouse = cutHouse || cut
		case feed.Kind == "ips":
			ips = append(ips, kept)
			cutIPs = cutIPs || cut
		default:
			domains = append(domains, kept)
			cutDoms = cutDoms || cut
			// Compile blocks an address as an address, not in the name
			// sinkhole. Thus the sample is the first name.
			for _, item := range kept {
				if _, err := netip.ParseAddr(item); sample == "" && err != nil {
					sample = item
					break
				}
			}
		}
	}
	pruneCache(outDir, seen)
	ipOut := capShare(ips, maxIPs, cutIPs, "ips", &report)
	domOut := capShare(domains, maxDoms, cutDoms, "domains", &report)
	houseOut := capShare(houseDomains, maxDoms, cutHouse, house.Name+" domains", &report)
	vpnOut := capShare(houseVPN, maxDoms, cutVPN, house.Name+" vpn domains", &report)
	repText := lines(report)
	// houseOut also counts. A run in which only the house feeds answered
	// used to be called a total failure, and the house list that it did
	// fetch was discarded with the rest. So the ad and tracker blocks, which
	// are the reason for the family segment, stopped because an unrelated
	// agent feed was down.
	if anyFail(report) && len(ipOut) == 0 && len(domOut) == 0 && len(houseOut) == 0 && len(vpnOut) == 0 {
		// Lists stay as they were. Only the report records the outage,
		// so the Feeds screen does not show the OK lines of yesterday.
		_ = commit(outDir, []struct{ name, text string }{{"fetch.report", repText}})
		return report, 0, 0, fmt.Errorf("all feeds failed")
	}
	sampleText := ""
	if sample != "" {
		sampleText = sample + "\n"
	}
	files := []struct {
		name string
		text string
	}{
		{agent.Sinkhole("ips"), lines(ipOut)},
		{agent.Sinkhole("domains"), lines(domOut)},
		{house.Sinkhole("domains"), lines(houseOut)},
		{filepath.Base(policycompile.HouseVPNFile), lines(vpnOut)},
		{FeedsMap, feedsMap(feedOf, ipOut, domOut, houseOut, vpnOut)},
		{"sample.domain", sampleText},
		{"fetch.report", repText},
	}
	if err := commit(outDir, files); err != nil {
		return report, 0, 0, err
	}
	return report, len(ipOut), len(domOut), nil
}

// capShare joins the lists of the feeds, without duplicates, and keeps at
// most max items. Under the cap, that is all items in feed order. Over it,
// the cap once kept the first max items, so the first feed in sources.json
// could fill the full cap and put every item of the feeds after it out of
// the list. Now the feeds give one new item each in turn until the cap is
// full: each feed gets an equal share, and a share that a feed does not use
// goes to the others. The kept items stay in feed order.
//
// cut says that the parse of a feed stopped at the cap. That feed had more
// entries than lists shows, so the TRUNCATED line says "had more than".
// The line is also written when never_block made the list fit, because
// entries of the feed were still not read.
func capShare(lists [][]string, max int, cut bool, label string, report *[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	all = uniq(all)
	had := fmt.Sprint(len(all))
	if cut {
		had = "more than " + had
	}
	if len(all) <= max {
		if cut {
			*report = append(*report, fmt.Sprintf("TRUNCATED %s to %d (had %s)", label, len(all), had))
		}
		return all
	}
	*report = append(*report, fmt.Sprintf("TRUNCATED %s to %d (had %s)", label, max, had))
	keep := make(map[string]struct{}, max)
	next := make([]int, len(lists))
	for more := true; more && len(keep) < max; {
		more = false
		for i, l := range lists {
			for next[i] < len(l) && len(keep) < max {
				it := l[next[i]]
				next[i]++
				if _, dup := keep[it]; !dup {
					keep[it] = struct{}{}
					more = true
					break
				}
			}
		}
	}
	out := make([]string, 0, max)
	for _, it := range all {
		if _, ok := keep[it]; ok {
			out = append(out, it)
		}
	}
	return out
}

// FeedsMap is the generated file that names the feed behind each item that
// the lists carry: "<item>\t<feed id>" per line, in list order.
const FeedsMap = "feeds.map"

func feedsMap(feedOf map[string]string, lists ...[]string) string {
	var b strings.Builder
	for _, items := range lists {
		for _, item := range items {
			if id, ok := feedOf[item]; ok {
				b.WriteString(item + "\t" + id + "\n")
			}
		}
	}
	return b.String()
}

func lines(items []string) string {
	text := strings.Join(items, "\n")
	if text != "" {
		text += "\n"
	}
	return text
}

// commit stages each file in a temp dir inside outDir, and renames each
// file over its target. So a run that dies half way leaves the previous
// generated set in place.
func commit(outDir string, files []struct{ name, text string }) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(outDir, ".fetch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmp, f.name), []byte(f.text), 0644); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := os.Rename(filepath.Join(tmp, f.name), filepath.Join(outDir, f.name)); err != nil {
			return err
		}
	}
	return nil
}

// CountWarnings reads the report lines of a run, and says how many feeds
// did not come back fresh. FAIL is a feed with nothing to fall back on.
// STALE is a feed served from its last copy. TRUNCATED is a list that its
// cap cut, so items that the feeds carry are not in it. Run returns a nil
// error for each run in which something answered. So callers that need one
// number for the log (the audit entry, the seat) count from here. They do
// not parse the report again with their own idea of the verbs.
func CountWarnings(report []string) (fails, stale, truncated int) {
	for _, line := range report {
		verb, _, _ := strings.Cut(line, " ")
		switch verb {
		case "FAIL":
			fails++
		case "STALE":
			stale++
		case "TRUNCATED":
			truncated++
		}
	}
	return fails, stale, truncated
}
