package ship

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// signerOpt matches one option at the start of the options field of an
// allowed_signers line: a name, then an optional quoted value, then a
// comma or the end.
var signerOpt = regexp.MustCompile(`^([A-Za-z-]+)(?:="([^"]*)")?(?:,|$)`)

// CheckSigners refuses an ssh allowed_signers file unless each key line
// has namespaces="<namespace>" as its one namespaces option. ssh-keygen
// -Y verify lets a key on a line with no namespaces option sign in each
// namespace. The ship key (pi-fortress-release) and the release key
// (pi-fortress-dist) must each verify only in their own namespace.
// provision.sh (check_signers) applies the same rule to the file it
// installs. A file with no key line is also refused.
func CheckSigners(path, namespace string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	keys := 0
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys++
		var opts string
		if f := signerFields(line); len(f) > 1 {
			opts = f[1]
		}
		count, val := 0, ""
		for {
			m := signerOpt.FindStringSubmatch(opts)
			if m == nil || m[0] == "" {
				break
			}
			if strings.EqualFold(m[1], "namespaces") {
				count++
				val = m[2]
			}
			opts = opts[len(m[0]):]
		}
		switch {
		case count == 0:
			return fmt.Errorf("%s line %d has no namespaces= option; add namespaces=%q after the principal", path, n, namespace)
		case count > 1 || val != namespace:
			return fmt.Errorf("%s line %d has namespaces=%q; this file needs namespaces=%q only", path, n, val, namespace)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if keys == 0 {
		return fmt.Errorf("%s holds no key line", path)
	}
	return nil
}

// signerFields splits a line at white space that is not in double quotes.
func signerFields(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case !quoted && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
