// Package feedstage is the contract between the feed download and root.
//
// pf fetch runs in pi-fortress-feeds.service as pf-feeds. It downloads and
// parses the feeds, and writes the lists into a stage directory that only
// it can write. Root then reads that directory with Import. Import checks
// each staged line strictly, refuses the whole set when one line fails, and
// writes the lists into generated/ in canonical form. pf compile reads them
// from there, as before.
//
// This package does no network I/O and parses no feed format. It must not
// import net/http, crypto/tls, a compress package, encoding/csv or
// internal/fetch (deps_test.go checks that).
package feedstage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pi-fortress/internal/eyeball"
	"pi-fortress/internal/policycompile"
)

// The fixed paths of the download unit (vm/pi/feeds.service). Root writes
// InputDir. The unit writes StateDir.
const (
	// InputDir holds the copies of the policy files that the download
	// reads, and the request. Root writes it; the unit reads it only.
	InputDir = "/var/lib/pi-fortress/feeds-in"
	// StateDir is the StateDirectory of the unit. Only pf-feeds writes it.
	StateDir = "/var/lib/pi-fortress-feeds"
	// StageName and CacheName are the two directories in StateDir.
	StageName = "stage"
	CacheName = "cache"
	// SeedName is a directory in InputDir with old last-good copies. The
	// download reads a copy from it when its own cache has none.
	SeedName = "seed"
	// RequestFile is the name of the request in InputDir.
	RequestFile = "request"
	// Unit is the systemd unit of the download.
	Unit = "pi-fortress-feeds.service"
	// Account is the user of the unit.
	Account = "pf-feeds"
)

// The default caps of the lists, when sources.json does not set them.
// internal/fetch uses the same values.
const (
	DefaultMaxIPs     = 20000
	DefaultMaxDomains = 50000
)

// The names of the staged files. Each list has the name that pf compile
// reads in generated/.
var (
	IPsFile          = policycompile.SegmentFor(policycompile.DenyByDefault).Sinkhole("ips")
	DomainsFile      = policycompile.SegmentFor(policycompile.DenyByDefault).Sinkhole("domains")
	HouseDomainsFile = policycompile.SegmentFor(policycompile.AllowByDefault).Sinkhole("domains")
	HouseVPNFile     = filepath.Base(policycompile.HouseVPNFile)
)

const (
	FeedsMapFile = "feeds.map"
	ReportFile   = "fetch.report"
	SampleFile   = "sample.domain"
	// RunFile holds the run id of the request that made the staged set.
	// The download writes it last.
	RunFile = "run"
)

// EyeballFile is the staged table of the eyeball networks.
var EyeballFile = eyeball.TableFile

// InputFiles are the policy files that root copies into InputDir. A
// missing one is not copied: the download then reads no such file, as it
// reads no file that is missing in the policy directory.
func InputFiles() []string {
	agent := policycompile.SegmentFor(policycompile.DenyByDefault)
	house := policycompile.SegmentFor(policycompile.AllowByDefault)
	return []string{
		"sources.json",
		agent.File("never_block.ips"),
		agent.File("never_block.domains"),
		house.File("never_block.domains"),
	}
}

// Request is what root asks of one run of the download.
type Request struct {
	// Fresh lets a feed whose last-good copy is younger than Fresh serve
	// from that copy (fetch.Fetcher.FreshFor). Zero always downloads.
	Fresh time.Duration
	// Run is 32 lowercase hex digits. The download writes it to RunFile,
	// so root can tell the set of this run from an older one.
	Run string
}

// maxFresh is the largest Fresh that a request can carry.
const maxFresh = 24 * time.Hour

// Bytes gives the request file: two lines, "fresh <duration>" and
// "run <id>".
func (r Request) Bytes() []byte {
	return []byte("fresh " + r.Fresh.String() + "\nrun " + r.Run + "\n")
}

// ParseRequest reads a request file. It accepts only the form of Bytes.
func ParseRequest(b []byte) (Request, error) {
	if len(b) > 128 {
		return Request{}, errors.New("request: larger than 128 bytes")
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != 3 || lines[2] != "" {
		return Request{}, errors.New("request: not two lines")
	}
	fresh, ok := strings.CutPrefix(lines[0], "fresh ")
	if !ok {
		return Request{}, errors.New("request: line 1 is not 'fresh <duration>'")
	}
	d, err := time.ParseDuration(fresh)
	if err != nil || d < 0 || d > maxFresh {
		return Request{}, fmt.Errorf("request: fresh %q is not a duration from 0 to %s", fresh, maxFresh)
	}
	run, ok := strings.CutPrefix(lines[1], "run ")
	if !ok || !ValidRun(run) {
		return Request{}, errors.New("request: line 2 is not 'run <32 lowercase hex digits>'")
	}
	return Request{Fresh: d, Run: run}, nil
}

// NewRun gives a new run id: 16 random bytes as 32 lowercase hex digits.
func NewRun() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidRun says if s is a run id.
func ValidRun(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Limits are the caps and feed ids that root takes from its own
// sources.json. The staged set must stay inside them.
type Limits struct {
	MaxIPs, MaxDomains int
	// FeedIDs are the ids of the blocklist feeds. Each feed that
	// feeds.map names must be one of them.
	FeedIDs map[string]bool
}

// ReadLimits reads sources.json in policyDir. A cap of 0 or no cap gives
// the default, as in pf fetch.
func ReadLimits(policyDir string) (Limits, error) {
	raw, err := os.ReadFile(filepath.Join(policyDir, "sources.json"))
	if err != nil {
		return Limits{}, err
	}
	var spec struct {
		MaxIPs     int `json:"max_ips"`
		MaxDomains int `json:"max_domains"`
		Feeds      []struct {
			ID string `json:"id"`
		} `json:"feeds"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return Limits{}, fmt.Errorf("sources.json: %w", err)
	}
	if spec.MaxIPs < 0 || spec.MaxDomains < 0 {
		return Limits{}, errors.New("sources.json: a negative cap")
	}
	l := Limits{MaxIPs: spec.MaxIPs, MaxDomains: spec.MaxDomains, FeedIDs: map[string]bool{}}
	if l.MaxIPs == 0 {
		l.MaxIPs = DefaultMaxIPs
	}
	if l.MaxDomains == 0 {
		l.MaxDomains = DefaultMaxDomains
	}
	for _, f := range spec.Feeds {
		if ValidFeedID(f.ID) {
			l.FeedIDs[f.ID] = true
		}
	}
	return l, nil
}

// ValidFeedID is the id rule of sources.json: letters, digits, dot, dash
// and underscore, 1 to 64 of them, and not only dots.
func ValidFeedID(id string) bool {
	if id == "" || len(id) > 64 || strings.Trim(id, ".") == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// File is one file of a commit.
type File struct {
	Name string
	Text []byte
}

// Commit writes each file into a new temp directory in outDir, and then
// renames each one over its target. A run that stops half way leaves the
// earlier set in place. Each file gets mode 0644.
func Commit(outDir string, files []File) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(outDir, ".fetch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, f := range files {
		if filepath.Base(f.Name) != f.Name || f.Name == "." || f.Name == ".." {
			return fmt.Errorf("commit: %q is not a file name", f.Name)
		}
		p := filepath.Join(tmp, f.Name)
		if err := os.WriteFile(p, f.Text, 0644); err != nil {
			return err
		}
		if err := os.Chmod(p, 0644); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := os.Rename(filepath.Join(tmp, f.Name), filepath.Join(outDir, f.Name)); err != nil {
			return err
		}
	}
	return nil
}
