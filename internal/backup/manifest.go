package backup

import (
	"runtime/debug"
	"strings"
)

// Schema is the archive format. A restore refuses an archive from a
// later schema, and does not guess at it. A backup read wrongly is
// worse than a backup that does not open, because the operator finds
// the problem later, from a symptom.
const Schema = 1

const ManifestName = "manifest.json"

type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Manifest is the account of the archive about itself. It is the first
// entry, so `tar xzf - manifest.json` is cheap.
type Manifest struct {
	Schema int    `json:"schema"`
	Taken  string `json:"taken"`
	Host   string `json:"host"`
	// Revision is the pf build that wrote the archive, from the VCS stamp of
	// the binary. So a restore that behaves strangely is traceable to a build,
	// not to a guess about which build was deployed.
	Revision  string            `json:"revision,omitempty"`
	Dirty     bool              `json:"dirty,omitempty"`
	EtcDir    string            `json:"etc_dir"`
	PolicyDir string            `json:"policy_dir"`
	Ifaces    map[string]string `json:"ifaces,omitempty"`
	Files     []File            `json:"files"`
	Excluded  []Exclusion       `json:"excluded"`
}

// revision reads the build stamp that Go puts in each binary built inside a
// work tree. It costs nothing and needs no ldflags plumbing.
func revision() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return rev, dirty
}

// envValues reads a few named settings from KEY=VALUE files, for the
// hardware note of the manifest. A later file wins. It is intentionally
// not a shell parser: it omits all that it cannot read plainly, and
// nothing downstream depends on the answer.
func envValues(want []string, texts ...string) map[string]string {
	keep := map[string]bool{}
	for _, k := range want {
		keep[k] = true
	}
	out := map[string]string{}
	for _, text := range texts {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
			if !ok || !keep[k] {
				continue
			}
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			if strings.ContainsAny(v, "$`\n") {
				continue
			}
			out[k] = v
		}
	}
	return out
}
