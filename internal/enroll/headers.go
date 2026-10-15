package enroll

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pi-fortress/internal/corepolicy"
)

const coreLocal = "core.hosts.local"

// headerPlan is what mint --header will write to core.hosts.local: the
// full new file, and, for the operator, the line per host that it binds.
type headerPlan struct {
	path    string
	body    string
	lines   []string
	changed bool
}

// parseHeaderFlag splits --header H[,H...], and holds each name to the
// rule that core.hosts is parsed under. So a name that mint writes is a
// name that apply will take.
func parseHeaderFlag(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for h := range strings.SplitSeq(raw, ",") {
		h = strings.TrimSpace(h)
		if err := corepolicy.ValidHeader(h); err != nil {
			return nil, err
		}
		if !seen[strings.ToLower(h)] {
			seen[strings.ToLower(h)] = true
			out = append(out, h)
		}
	}
	return out, nil
}

// planHeaders finds each core.hosts entry, shipped or local, whose line
// binds kind by name, and declares hdrs for that host and kind in
// core.hosts.local. An existing KIND token there gains the names that it
// does not have. If there is no such token, a line is added. A "*" line
// does not count as a binding: the operator names the host.
func planHeaders(dir, kind string, hdrs []string) (headerPlan, error) {
	local := filepath.Join(dir, coreLocal)
	pol, err := corepolicy.LoadFiles(filepath.Join(dir, "core.hosts"), local)
	if err != nil {
		return headerPlan{}, err
	}
	var entries []string
	for host, kinds := range pol.HostKinds {
		if _, ok := kinds[kind]; ok {
			entries = append(entries, host)
		}
	}
	for host, kinds := range pol.SuffixKinds {
		if _, ok := kinds[kind]; ok {
			entries = append(entries, "*."+host)
		}
	}
	if len(entries) == 0 {
		return headerPlan{}, fmt.Errorf("%s is bound to no host, so no header can carry it; add `<host> %s` to %s first", kind, kind, local)
	}
	sort.Strings(entries)
	raw, err := os.ReadFile(local)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return headerPlan{}, err
	}
	text := string(raw)
	var lines []string
	if text != "" {
		lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	plan := headerPlan{path: local}
	for _, entry := range entries {
		at, tok := findBinding(lines, entry, kind)
		if at < 0 {
			line := entry + " " + kind + ":" + strings.Join(hdrs, ",")
			lines = append(lines, line)
			plan.lines = append(plan.lines, line)
			continue
		}
		lines[at] = mergeBinding(lines[at], tok, hdrs)
		plan.lines = append(plan.lines, strings.TrimSpace(stripComment(lines[at])))
	}
	plan.body = strings.Join(lines, "\n") + "\n"
	plan.changed = plan.body != text
	return plan, nil
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// findBinding is the first line for entry with a column that names kind,
// and the index of that column among the fields of the line.
func findBinding(lines []string, entry, kind string) (int, int) {
	for i, line := range lines {
		bits := strings.Fields(stripComment(line))
		if len(bits) == 0 || normEntry(bits[0]) != entry {
			continue
		}
		for j, b := range bits[1:] {
			if k, _, _ := strings.Cut(b, ":"); k == kind {
				return i, j + 1
			}
		}
	}
	return -1, 0
}

func normEntry(s string) string {
	return strings.TrimRight(strings.ToLower(s), ".")
}

// mergeBinding adds the names that hdrs has and column tok does not have.
// It keeps the names and order of the column, and any comment on the line.
func mergeBinding(line string, tok int, hdrs []string) string {
	body, comment := line, ""
	if i := strings.IndexByte(line, '#'); i >= 0 {
		body, comment = line[:i], line[i:]
	}
	bits := strings.Fields(body)
	kind, list, _ := strings.Cut(bits[tok], ":")
	var have []string
	seen := map[string]bool{}
	if list != "" {
		for h := range strings.SplitSeq(list, ",") {
			have = append(have, h)
			seen[strings.ToLower(h)] = true
		}
	}
	grew := false
	for _, h := range hdrs {
		if !seen[strings.ToLower(h)] {
			have = append(have, h)
			seen[strings.ToLower(h)] = true
			grew = true
		}
	}
	if !grew {
		return line
	}
	bits[tok] = kind + ":" + strings.Join(have, ",")
	out := strings.Join(bits, " ")
	if comment != "" {
		out += " " + comment
	}
	return out
}

// write puts the file in place whole or not at all. pf apply and the next
// mint read core.hosts.local, and a half-written file is a policy that
// nobody wrote.
func (p headerPlan) write() error {
	tmp, err := os.CreateTemp(filepath.Dir(p.path), "."+coreLocal+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(p.body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p.path)
}
