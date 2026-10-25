package nftsets

// An element of a resolved set is an address and a timeout. It does not
// name the DNS name that gave it. Thus, when the DNS policy of a segment
// changes, nothing can tell which elements the new policy still allows.
// A name that the new policy blocks keeps its addresses in the set until
// they expire, for up to 2h.
//
// Policy gives a fingerprint of the policy that fills each set: the
// segment of the pf dns config, and the contents of each list file that
// it names. apply keeps the last fingerprints. When a fingerprint
// changes, apply stops pf dns, flushes that set, and starts pf dns on the
// new config. Thus each element of the set comes from an answer under the
// new policy. A set whose fingerprint did not change keeps its elements.
//
// The flush is at the restart of pf dns, not in the carry across the
// ruleset load. The load comes before apply installs the new lists, and
// the old pf dns adds addresses under the old policy until it stops.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strings"
)

// policyFiles are the keys of a pf dns segment that name a file with
// names, addresses or rules that decide what the segment answers.
var policyFiles = []string{"sinkhole", "allow", "core_hosts", "key_rules", "dns_types_allow", "sni_ech_ips", "sni_opaque_ips"}

// notPolicy are the keys of a pf dns segment that name an output or a
// state file. A change to them does not change what the segment answers.
// Each other key counts, also a key that is not known here. Thus a new
// key flushes the set one time, and never keeps an old element.
var notPolicy = []string{"log", "fakeip_journal"}

// Policy reads a pf dns config and gives the fingerprint of the policy of
// each carried set that a segment names in nft_set. read gets the list
// files. A file that does not exist counts as one value. pf dns -check
// refuses a config that needs it.
func Policy(config []byte, read func(string) ([]byte, error)) (map[string]string, error) {
	var c struct {
		Segments []map[string]json.RawMessage `json:"segments"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, fmt.Errorf("pf dns config: %w", err)
	}
	fps := map[string]string{}
	for i, seg := range c.Segments {
		var set string
		if raw, ok := seg["nft_set"]; ok {
			if err := json.Unmarshal(raw, &set); err != nil {
				return nil, fmt.Errorf("pf dns config segment %d: nft_set: %w", i, err)
			}
		}
		if set == "" || !Carried(set) {
			continue
		}
		if _, dup := fps[set]; dup {
			return nil, fmt.Errorf("pf dns config: two segments name set %s", set)
		}
		h := sha256.New()
		io.WriteString(h, "resolved-policy-v1\n")
		// encoding/json writes the keys of a map in sorted order. Thus the
		// order of the keys in the file does not change the fingerprint.
		// The keys of outputs and state are not policy.
		policy := maps.Clone(seg)
		for _, k := range notPolicy {
			delete(policy, k)
		}
		whole, err := json.Marshal(policy)
		if err != nil {
			return nil, err
		}
		h.Write(whole)
		io.WriteString(h, "\n")
		for _, key := range policyFiles {
			paths, err := pathsOf(seg[key])
			if err != nil {
				return nil, fmt.Errorf("pf dns config set %s: %s: %w", set, key, err)
			}
			for _, p := range paths {
				sum := "missing"
				data, err := read(p)
				switch {
				case err == nil:
					s := sha256.Sum256(data)
					sum = hex.EncodeToString(s[:])
				case !errors.Is(err, fs.ErrNotExist):
					return nil, fmt.Errorf("pf dns config set %s: %w", set, err)
				}
				fmt.Fprintf(h, "%s %q %s\n", key, p, sum)
			}
		}
		fps[set] = hex.EncodeToString(h.Sum(nil)[:16])
	}
	return fps, nil
}

// pathsOf reads a key that holds one path or a list of paths.
func pathsOf(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil, nil
		}
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list, func(s string) bool { return s == "" }), nil
}

// FormatState writes the fingerprints, one `<set> <fingerprint>` line for
// each set, in the order of the set names.
func FormatState(w io.Writer, fps map[string]string) error {
	names := make([]string, 0, len(fps))
	for n := range fps {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("# pi-fortress DNS policy of each resolved-address set\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s %s\n", n, fps[n])
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ParseState reads what FormatState wrote. A line that it cannot read
// is skipped. Its set then counts as changed, which flushes the set.
func ParseState(r io.Reader) (map[string]string, error) {
	fps := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || strings.HasPrefix(f[0], "#") || !Carried(f[0]) {
			continue
		}
		fps[f[0]] = f[1]
	}
	return fps, sc.Err()
}

// Changed gives, in sorted order, each set in now that has no fingerprint
// in before or has a different one.
func Changed(before, now map[string]string) []string {
	var out []string
	for n, fp := range now {
		if old, ok := before[n]; !ok || old != fp {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Flush removes all elements from each named set that is carried and that
// the table has. A set that the table does not have is skipped. All of it
// is one nft transaction. It returns the sets that it flushed.
func Flush(run Runner, table string, sets []string) ([]string, error) {
	names, err := Names(run, table)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	var done []string
	for _, s := range sets {
		if !Carried(s) || !slices.Contains(names, s) {
			continue
		}
		fmt.Fprintf(&b, "flush set %s %s\n", table, s)
		done = append(done, s)
	}
	if len(done) == 0 {
		return nil, nil
	}
	if _, err := run(b.String(), "-f", "-"); err != nil {
		return nil, err
	}
	return done, nil
}
