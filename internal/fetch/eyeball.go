package fetch

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/eyeball"
)

// EyeballSpec is the eyeball section of sources.json. pf fetch builds the
// table of the eyeball networks from it (eyeball.TableFile). The broker
// loads that table. It has no network, so it cannot fetch it itself.
//
// The table needs two kinds of data. Ranges maps each IPv4 range to the
// ASN that announces it. Each feed in ASNs says which ASNs are eyeball
// networks. An ASN is in the table when one of those feeds includes it and
// none excludes it.
type EyeballSpec struct {
	Comment string `json:"comment,omitempty"`
	// UserAgent replaces the user_agent of the spec for these feeds. Some
	// publishers ask for a contact in it.
	UserAgent string `json:"user_agent,omitempty"`
	// MaxRanges caps the ranges that the ranges feed can give. 0 means
	// defaultEyeballRanges.
	MaxRanges int           `json:"max_ranges,omitempty"`
	Ranges    EyeballFeed   `json:"ranges"`
	ASNs      []EyeballFeed `json:"asns"`
}

// EyeballFeed is one feed of the eyeball section. Its kind follows from
// its place in the section, so it has no kind field.
type EyeballFeed struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	URL    string `json:"url"`
	// nil means enabled, as for Feed.
	Enabled *bool  `json:"enabled,omitempty"`
	License string `json:"license,omitempty"`
	Why     string `json:"why,omitempty"`
}

func (e EyeballFeed) feed(kind string) Feed {
	return Feed{ID: e.ID, Kind: kind, Format: e.Format, URL: e.URL, Enabled: e.Enabled, License: e.License, Why: e.Why}
}

// The kinds of the eyeball feeds. Only code sets them, never sources.json.
// They go into the stamp of the last-good copy, so a copy of a ranges feed
// cannot serve as a copy of an ASN feed.
const (
	kindRanges = "asn_ranges"
	kindASNs   = "asns"
)

const (
	// defaultEyeballRanges is above the about 460,000 announced IPv4
	// ranges of ip2asn-v4 in 2026, after the join of adjacent ranges.
	defaultEyeballRanges = 1_000_000
	// maxASNs is above the about 120,000 ASNs that are announced.
	maxASNs = 400_000
	// maxEyeballBody caps one download. ip2asn-v4.tsv.gz was 7 MB in 2026,
	// the bgp.tools asns.csv 5.6 MB, and the PeeringDB net list 3.6 MB.
	maxEyeballBody = 32 << 20
	// maxEyeballRaw caps the bytes after gunzip: ip2asn-v4 was 31 MB.
	maxEyeballRaw = 128 << 20
)

func (e *EyeballSpec) validate(ids map[string]bool) error {
	if e.MaxRanges < 0 || e.MaxRanges > eyeball.MaxRanges {
		return fmt.Errorf("sources.json: eyeball max_ranges=%d is not 0 to %d", e.MaxRanges, eyeball.MaxRanges)
	}
	check := func(f EyeballFeed, formats ...string) error {
		if _, ok := cacheName(f.ID); !ok {
			return fmt.Errorf("sources.json: eyeball feed '%s' is not a feed id; letters, digits, dot, dash and underscore, up to 64 of them", f.ID)
		}
		if ids[f.ID] {
			return fmt.Errorf("sources.json: two feeds are called '%s'; the id names the feed's last-good copy, so both would overwrite one file", f.ID)
		}
		ids[f.ID] = true
		if f.URL == "" {
			return fmt.Errorf("sources.json: eyeball feed '%s' has no url", f.ID)
		}
		for _, ok := range formats {
			if f.Format == ok {
				return nil
			}
		}
		return fmt.Errorf("sources.json: eyeball feed '%s' has format '%s'; it is %s", f.ID, f.Format, strings.Join(formats, ", "))
	}
	if err := check(e.Ranges, "ip2asn"); err != nil {
		return err
	}
	for _, f := range e.ASNs {
		if err := check(f, "bgptools", "peeringdb", "asn"); err != nil {
			return err
		}
	}
	return nil
}

// parseRanges reads the ip2asn TSV (start, end, ASN, country, name), plain
// or gzip. It keeps the IPv4 ranges with an ASN. ASN 0 marks a range that
// nobody announces. It gives the ranges as table lines, after Normalize,
// and at most limit of them. cut is true when there were more.
func parseRanges(body string, limit int) (items []string, cut bool, err error) {
	var r io.Reader = strings.NewReader(body)
	if strings.HasPrefix(body, "\x1f\x8b") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		r = io.LimitReader(zr, maxEyeballRaw+1)
	}
	cr := &countReader{r: r}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	var rs []eyeball.Range
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 3 {
			continue
		}
		rg, ok := eyeball.ParseRange(f[0], f[1], f[2])
		if !ok {
			continue
		}
		// Twice the cap before the join, so a feed of many small adjacent
		// ranges still fills the cap after the join.
		if len(rs) >= 2*limit+1 {
			cut = true
			break
		}
		rs = append(rs, rg)
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	if cr.n > maxEyeballRaw {
		return nil, false, fmt.Errorf("feed is larger than %d bytes after gunzip", maxEyeballRaw)
	}
	rs = eyeball.Normalize(rs)
	if len(rs) > limit {
		rs, cut = rs[:limit], true
	}
	items = make([]string, len(rs))
	for i, rg := range rs {
		items[i] = rg.String()
	}
	return items, cut, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// parseASNs reads an ASN feed. An item is "+<asn>" for an ASN that the
// feed includes, or "-<asn>" for one that it excludes.
//
//   - bgptools: the asns.csv of bgp.tools (asn, name, class, cc). Class
//     Eyeball includes. Class Content excludes: a content network that
//     an other feed calls an ISP is a host of servers, and a dial to it is
//     the normal case for an agent.
//   - peeringdb: the JSON of the PeeringDB API /api/net. Type
//     "Cable/DSL/ISP" includes.
//   - asn: the first field of each line is an ASN, and includes it. This
//     reads the tag lists of bgp.tools (dsl, mobile) and a list that the
//     operator keeps.
func parseASNs(feed Feed, body string) ([]string, error) {
	var items []string
	add := func(sign byte, asn uint32) {
		if len(items) < maxASNs {
			items = append(items, string(sign)+strconv.FormatUint(uint64(asn), 10))
		}
	}
	switch feed.Format {
	case "bgptools":
		cr := csv.NewReader(strings.NewReader(body))
		cr.FieldsPerRecord = -1
		cr.LazyQuotes = true
		cr.ReuseRecord = true
		head, err := cr.Read()
		if err != nil {
			return nil, err
		}
		asnCol, classCol := -1, -1
		for i, h := range head {
			switch strings.TrimSpace(strings.ToLower(h)) {
			case "asn":
				asnCol = i
			case "class":
				classCol = i
			}
		}
		if asnCol < 0 || classCol < 0 {
			return nil, errors.New("no asn and class columns")
		}
		for {
			rec, err := cr.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if len(rec) <= asnCol || len(rec) <= classCol {
				continue
			}
			asn, ok := eyeball.ParseASN(rec[asnCol])
			if !ok {
				continue
			}
			switch strings.TrimSpace(rec[classCol]) {
			case "Eyeball":
				add('+', asn)
			case "Content":
				add('-', asn)
			}
		}
	case "peeringdb":
		var doc struct {
			Data []struct {
				ASN       uint32   `json:"asn"`
				InfoType  string   `json:"info_type"`
				InfoTypes []string `json:"info_types"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			return nil, err
		}
		for _, n := range doc.Data {
			isp := n.InfoType == "Cable/DSL/ISP"
			for _, t := range n.InfoTypes {
				isp = isp || t == "Cable/DSL/ISP"
			}
			if isp && n.ASN != 0 {
				add('+', n.ASN)
			}
		}
	default:
		for _, line := range strings.Split(body, "\n") {
			line, _, _ = strings.Cut(line, "#")
			first := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' })
			if len(first) == 0 {
				continue
			}
			if asn, ok := eyeball.ParseASN(first[0]); ok {
				add('+', asn)
			}
		}
	}
	return uniq(items), nil
}

// parseEyeballToken checks one line of a last-good copy, as parseToken
// does for the blocklist feeds.
func parseEyeballToken(token, kind string) (string, bool) {
	switch kind {
	case kindRanges:
		f := strings.Fields(token)
		if len(f) != 3 {
			return "", false
		}
		rg, ok := eyeball.ParseRange(f[0], f[1], f[2])
		if !ok {
			return "", false
		}
		return rg.String(), true
	case kindASNs:
		if len(token) < 2 || (token[0] != '+' && token[0] != '-') {
			return "", false
		}
		asn, ok := eyeball.ParseASN(token[1:])
		if !ok {
			return "", false
		}
		return string(token[0]) + strconv.FormatUint(uint64(asn), 10), true
	}
	return "", false
}

// eyeballItems is feedItems for one eyeball feed: a download, else the
// last-good copy. when is the time of the data: now for a fresh answer,
// the time of the copy otherwise. ok is false when there is neither.
func (f *Fetcher) eyeballItems(outDir, ua string, timeout time.Duration, feed Feed, limit int, report *[]string) (items []string, when time.Time, ok bool) {
	why := ""
	cut := false
	pg, gerr := f.getLimit(feed.URL, ua, timeout, maxEyeballBody)
	if gerr != nil {
		why = gerr.Error()
	} else {
		if pg.final != feed.URL {
			*report = append(*report, "REDIRECT "+feed.ID+": "+pg.final)
		}
		var err error
		if feed.Kind == kindRanges {
			items, cut, err = parseRanges(pg.body, limit)
		} else {
			items, err = parseASNs(feed, pg.body)
		}
		switch {
		case err != nil:
			why = "does not parse: " + err.Error()
		case len(items) == 0:
			why = "answered with nothing to parse"
		default:
			why = f.shrunk(outDir, feed, items, report)
		}
	}
	if why == "" {
		if err := writeCache(outDir, feed, items); err != nil {
			*report = append(*report, "WARN "+feed.ID+": last-good copy not saved: "+err.Error())
		}
		note := ""
		if cut {
			note = fmt.Sprintf(" (more than the cap of %d; the rest not read)", limit)
		}
		*report = append(*report, fmt.Sprintf("OK %s: %d %s%s", feed.ID, len(items), eyeballLabel(feed.Kind), note))
		return items, f.now(), true
	}
	cached, when, ok := readCache(outDir, feed)
	if !ok {
		*report = append(*report, "FAIL "+feed.ID+": "+why)
		return nil, time.Time{}, false
	}
	*report = append(*report, fmt.Sprintf("STALE %s: %d %s (last good %s: %s)", feed.ID, len(cached), eyeballLabel(feed.Kind), Ago(f.now().Sub(when)), why))
	return cached, when, true
}

func eyeballLabel(kind string) string {
	if kind == kindRanges {
		return "asn ranges"
	}
	return "asns"
}

// runEyeball fetches the eyeball feeds and gives the text of the table.
// It gives "" when there is no table to write: no section, the ranges
// feed has no data, or no ASN feed has data. Then the old table stays in
// place, and its age stops its use in the broker in time
// (eyeball.DefaultMaxAge).
func (f *Fetcher) runEyeball(spec Spec, outDir, ua string, timeout time.Duration, seen map[string]bool, report *[]string) string {
	e := spec.Eyeball
	if e == nil {
		return ""
	}
	seen[e.Ranges.ID] = true
	for _, a := range e.ASNs {
		seen[a.ID] = true
	}
	if !e.Ranges.feed(kindRanges).On() {
		*report = append(*report, "SKIP "+e.Ranges.ID+": disabled; no eyeball table")
		return ""
	}
	if e.UserAgent != "" {
		ua = e.UserAgent
	}
	limit := e.MaxRanges
	if limit == 0 {
		limit = defaultEyeballRanges
	}
	include, exclude := map[uint32]bool{}, map[uint32]bool{}
	var oldest time.Time
	older := func(t time.Time) {
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	nASN := 0
	for _, ef := range e.ASNs {
		a := ef.feed(kindASNs)
		if !a.On() {
			*report = append(*report, "SKIP "+a.ID+": disabled")
			continue
		}
		items, when, ok := f.eyeballItems(outDir, ua, timeout, a, 0, report)
		if !ok {
			continue
		}
		nASN++
		older(when)
		for _, it := range items {
			asn, _ := eyeball.ParseASN(it[1:])
			if it[0] == '+' {
				include[asn] = true
			} else {
				exclude[asn] = true
			}
		}
	}
	rf := e.Ranges.feed(kindRanges)
	items, when, ok := f.eyeballItems(outDir, ua, timeout, rf, limit, report)
	if !ok || nASN == 0 {
		*report = append(*report, "FAIL eyeball: no table built; the broker keeps the last table until it is too old")
		return ""
	}
	older(when)
	var rs []eyeball.Range
	for _, it := range items {
		fl := strings.Fields(it)
		if len(fl) != 3 {
			continue
		}
		if rg, ok := eyeball.ParseRange(fl[0], fl[1], fl[2]); ok {
			rs = append(rs, rg)
		}
	}
	rs = eyeball.Select(eyeball.Normalize(rs), func(asn uint32) bool { return include[asn] && !exclude[asn] })
	var b bytes.Buffer
	if err := eyeball.Write(&b, oldest, rs); err != nil {
		*report = append(*report, "FAIL eyeball: "+err.Error())
		return ""
	}
	*report = append(*report, fmt.Sprintf("OK eyeball: %d ranges in %s", len(rs), eyeball.TableFile))
	return b.String()
}

// commitEyeball writes the table apart from the other lists. A run in
// which all blocklist feeds failed still gets a new table, and the reverse.
func commitEyeball(outDir, text string) error {
	if text == "" {
		return nil
	}
	return commit(outDir, []struct{ name, text string }{{eyeball.TableFile, text}})
}
