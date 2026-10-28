// Package enroll is pf enroll: it mints, lists, migrates and deletes
// slotted credentials, and makes the paste block that an agent gets.
// internal/cli calls it. It never prints a live value on list.
package enroll

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"pi-fortress/internal/agentcreds"
	"pi-fortress/internal/secrets"
)

const (
	OATPrefix = "sk-ant-oat01-"
	ORTPrefix = "sk-ant-ort01-"
)

func RedactLive(value string, head, tail int) string {
	if value == "" {
		return "(empty)"
	}
	n := len(value)
	if n <= head+tail {
		// Too short for head and tail to leave anything hidden. A
		// maximum of two characters, and none below eight. That is enough
		// to tell a pasted key from a typo, never enough to narrow the rest.
		show := 0
		if n >= 8 {
			show = 2
		}
		return value[:show] + "…  len=" + strconv.Itoa(n)
	}
	return value[:head] + "…" + value[n-tail:] + "  len=" + strconv.Itoa(n)
}

func ClaudeMintErrors(oat, ort string) []string {
	var errors []string
	if oat == "" {
		errors = append(errors, "--oat is required for CLAUDE")
	} else if !strings.HasPrefix(oat, OATPrefix) {
		errors = append(errors, "--oat must start with "+OATPrefix+" (got "+RedactLive(oat, 8, 4)+")")
	}
	if ort == "" {
		errors = append(errors, "--ort is required for CLAUDE")
	} else if !strings.HasPrefix(ort, ORTPrefix) {
		errors = append(errors, "--ort must start with "+ORTPrefix+" (got "+RedactLive(ort, 8, 4)+"; that looks like an access token)")
	}
	if oat != "" && ort != "" && oat == ort {
		errors = append(errors, "--oat and --ort are the same string; refresh is sk-ant-ort01-… from credentials.json")
	}
	return errors
}

func hasClaudeOAT(kinds []string) bool {
	for _, k := range kinds {
		if k == "CLAUDE_OAT" {
			return true
		}
	}
	return false
}

func AgentPaste(slot string, kinds []string) string {
	if hasClaudeOAT(kinds) {
		raw, _ := json.MarshalIndent(agentcreds.Doc(slot), "", "  ")
		return "AGENT file: ~/.claude/.credentials.json (replace the file; no live tokens)\n" +
			"expiresAt=0 forces a refresh on first use; the Pi harvests.\n" +
			string(raw)
	}
	lines := []string{"AGENT env (no live tokens):"}
	for _, kind := range kinds {
		lines = append(lines, "export "+kind+"='"+secrets.Placeholder(slot, kind)+"'")
	}
	return strings.Join(lines, "\n")
}

func WriteAgentPaste(slot string, kinds []string, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	var text string
	if hasClaudeOAT(kinds) {
		raw, err := json.MarshalIndent(agentcreds.Doc(slot), "", "  ")
		if err != nil {
			return err
		}
		text = string(raw) + "\n"
	} else {
		var lines []string
		for _, kind := range kinds {
			lines = append(lines, "export "+kind+"='"+secrets.Placeholder(slot, kind)+"'")
		}
		text = strings.Join(lines, "\n") + "\n"
	}
	return writeOwnerOnly(dest, []byte(text))
}

// writeOwnerOnly writes the paste file 0600. A placeholder is a capability,
// so other local users must not read it. WriteFile keeps the mode of a file
// that is already there. Thus the chmod comes before the write, and an
// older 0644 copy also becomes 0600.
func writeOwnerOnly(dest string, data []byte) error {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
