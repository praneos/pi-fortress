package corepolicy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// GitPush is git_push.allow: for each host, the repositories that a git
// smart-HTTP push can reach (docs/git_push.md). An empty, missing or nil
// GitPush refuses all pushes. It holds repos in lowercase without a ".git"
// suffix. internal/fence gives the repo of a request to Allowed in that form.
type GitPush struct {
	exact map[string]map[string]struct{}
	// owner holds the entries written as "<dir>/*": each repo exactly one
	// segment below dir.
	owner map[string]map[string]struct{}
	n     int
}

func LoadGitPush(path string) (*GitPush, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &GitPush{}, nil
		}
		return nil, err
	}
	defer f.Close()
	g, err := ParseGitPush(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

// ParseGitPush reads "<host> <owner>/<repo>" or "<host> <owner>/*" lines.
// A malformed line is an error. ParseGitPush never skips it. A list that
// the operator thinks has one meaning, and that the fence reads with a
// different meaning, is worse than an apply that stops.
func ParseGitPush(r io.Reader) (*GitPush, error) {
	g := &GitPush{exact: map[string]map[string]struct{}{}, owner: map[string]map[string]struct{}{}}
	sc := bufio.NewScanner(r)
	for ln := 1; sc.Scan(); ln++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		bits := strings.Fields(line)
		if len(bits) == 0 {
			continue
		}
		if len(bits) != 2 {
			return nil, fmt.Errorf("line %d: want <host> <owner>/<repo>", ln)
		}
		host := normHost(bits[0])
		if !validName(host) {
			return nil, fmt.Errorf("line %d: bad host %q", ln, bits[0])
		}
		repo, wild, ok := gitRepoPattern(bits[1])
		if !ok {
			return nil, fmt.Errorf("line %d: bad repo %q", ln, bits[1])
		}
		table := g.exact
		if wild {
			table = g.owner
		}
		if table[host] == nil {
			table[host] = map[string]struct{}{}
		}
		if _, dup := table[host][repo]; !dup {
			table[host][repo] = struct{}{}
			g.n++
		}
	}
	return g, sc.Err()
}

// gitRepoPattern lowercases p. It checks that p has two or more segments
// of [a-z0-9._-]. No segment is "." or "..". "*" is allowed only as the
// full last segment. For a wildcard, the returned repo is the directory.
// Else it is the path with one ".git" removed.
func gitRepoPattern(p string) (repo string, wild, ok bool) {
	segs := strings.Split(strings.ToLower(p), "/")
	if len(segs) < 2 {
		return "", false, false
	}
	if segs[len(segs)-1] == "*" {
		wild = true
		segs = segs[:len(segs)-1]
	} else {
		segs[len(segs)-1] = strings.TrimSuffix(segs[len(segs)-1], ".git")
	}
	for _, s := range segs {
		if !gitSegment(s) {
			return "", false, false
		}
	}
	return strings.Join(segs, "/"), wild, true
}

func gitSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// Allowed reports whether a push to repo on host is listed. repo is in
// lowercase, with no ".git". Allowed normalizes host.
func (g *GitPush) Allowed(host, repo string) bool {
	if g == nil || g.n == 0 {
		return false
	}
	host = normHost(host)
	if _, ok := g.exact[host][repo]; ok {
		return true
	}
	i := strings.LastIndexByte(repo, '/')
	if i <= 0 {
		return false
	}
	_, ok := g.owner[host][repo[:i]]
	return ok
}

// Len is the number of entries.
func (g *GitPush) Len() int {
	if g == nil {
		return 0
	}
	return g.n
}
