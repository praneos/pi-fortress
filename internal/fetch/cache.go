package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A feed that the fetcher cannot reach adds nothing to the run, and the
// compiled lists are rebuilt from the feeds that did answer. So one
// unreachable feed at 3am would silently shrink the blocklist. Each name
// that it carried is no longer blocked, no file records that it was
// blocked, and the next fetch adds it again as if nothing occurred.
//
// The cache is the first half of the answer. The parsed tokens of each
// feed are kept as they were last read. A feed that fails is served from
// its own last copy, not from silence. The cache stores the parsed tokens
// *before* never_block applies. So a never_block entry that an operator
// adds today is honoured against a stale copy fetched a week ago.
//
// The cache covers a feed that answered before. A feed with no valid
// cache still adds nothing, and the run still publishes the smaller set.
// That is the decided trade: a dead feed must not freeze all other lists.
// And it is announced, not silent. The report records FAIL (nothing to
// fall back on) or STALE (served from the last copy). The audit entry
// carries the counts, and the seat shows the warning until a fetch is
// clean again.
func cacheDir(outDir string) string { return filepath.Join(outDir, "feeds") }

// cacheName makes sure that a feed id cannot name a path. Ids come from
// sources.json. An operator edits it by hand, and the TUI does not
// validate it. So "../../etc/pi-fortress/net.env" is a possible id.
func cacheName(id string) (string, bool) {
	if id == "" || len(id) > 64 || strings.Trim(id, ".") == "" {
		return "", false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return "", false
		}
	}
	return id + ".list", true
}

// stamp is the hash of all that a feed means. Before, the id alone named
// the copy. But the id is the one part of a declaration that an operator
// keeps while all else about it changes. An operator can point the same id
// at a different publisher, change a house ad category into a shared one,
// or read a hosts file as plain. Then the next failure served the tokens
// of the old source under the interpretation of the new declaration. Two
// feeds that share an id by accident did the same thing to each other.
//
// A hash, not the stored fields, keeps one fixed-width line in front of
// the tokens. It also keeps a URL with a credential in it out of a file
// that an operator may paste into a bug report.
func stamp(f Feed) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.URL, f.Kind, f.Format, f.Segment}, "\x00")))
	return hex.EncodeToString(sum[:])
}

const stampPrefix = "# feed "

// writeCache replaces the last copy of a feed. It returns the error, and
// does not drop it. A run whose copy did not land has no fallback for the
// next outage. A report that says OK in that state is the silent shrink
// that this full file exists to prevent.
//
// An empty list is not written. A feed that answers 200 with an error
// page parses to nothing, and that is the actual shape of the 3am
// failure. If it overwrote the copy that would have covered it, it would
// destroy the fallback at exactly the moment that the fallback is needed.
func writeCache(outDir string, feed Feed, items []string) error {
	name, ok := cacheName(feed.ID)
	if !ok || len(items) == 0 {
		return nil
	}
	dir := cacheDir(outDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".feed-")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(stampPrefix + stamp(feed) + "\n" + lines(items))
	cerr := tmp.Close()
	err = errors.Join(werr, cerr, os.Chmod(tmp.Name(), 0644))
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// readCache returns the last copy of a feed, and when it was read. A copy
// whose stamp is not the stamp of this feed is no copy at all. Nor is a
// copy written before stamps existed. To serve it would be exactly the
// substitution that the stamp is there to catch. So it reads as a miss,
// and the feed fails honestly.
//
// The tokens are parsed again on the way out. They were parsed for the
// kind that the declaration had when they were written. The stamp now
// guarantees that the kind has not changed. But the grammar that the
// compiler accepts is code that does change. A token that this build would
// refuse must not reach the generated lists only because an older build wrote it.
func readCache(outDir string, feed Feed) ([]string, time.Time, bool) {
	name, ok := cacheName(feed.ID)
	if !ok {
		return nil, time.Time{}, false
	}
	p := filepath.Join(cacheDir(outDir), name)
	st, err := os.Stat(p)
	if err != nil {
		return nil, time.Time{}, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, time.Time{}, false
	}
	head, rest, ok := strings.Cut(string(raw), "\n")
	if !ok || head != stampPrefix+stamp(feed) {
		return nil, time.Time{}, false
	}
	var items []string
	for _, l := range strings.Split(rest, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		if parsed, ok := parseToken(l, feed.Kind); ok {
			items = append(items, parsed)
		}
	}
	if len(items) == 0 {
		return nil, time.Time{}, false
	}
	return items, st.ModTime(), true
}

// pruneCache drops copies of feeds that are no longer in sources.json. A
// feed that is only disabled keeps its copy, so when it is enabled again,
// it does not start from nothing.
func pruneCache(outDir string, keep map[string]bool) {
	ents, err := os.ReadDir(cacheDir(outDir))
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".list") || keep[strings.TrimSuffix(n, ".list")] {
			continue
		}
		os.Remove(filepath.Join(cacheDir(outDir), n))
	}
}

// Ago is Age with its suffix, so a fresh run reads "just now" and not
// "just now ago".
func Ago(d time.Duration) string {
	if a := Age(d); a != "just now" {
		return a + " ago"
	}
	return "just now"
}

// Age is for an operator who reads fetch.report quickly, so it stops at
// two units and never says "0s". It is exported because the warning line
// of the TUI must say the same thing as the report.
func Age(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}
