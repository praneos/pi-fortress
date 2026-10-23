package install

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// UpsertEnv rewrites path so that each key in kv has the given value, as a
// plain KEY=VALUE line. It replaces an existing "KEY=" or "#KEY=" line
// (commented-out example) in place. It appends a key that has no line yet.
// The order of kv is important only for newly appended keys. Callers use it
// on /etc/pi-fortress/net.env.local and house.env. net.env.local.example and
// house.env.example document both as overlays that people edit by hand.
// Thus a second run of the wizard must not overwrite lines that it was not
// asked to change. It refuses a value with a line break, because that value
// adds a line of its own; it writes nothing then.
func UpsertEnv(path string, kv map[string]string, header string) error {
	for _, k := range sortedKeys(kv) {
		if strings.ContainsAny(kv[k], "\r\n") {
			return fmt.Errorf("%s: %s=%q has a line break; a value must be one line", path, k, kv[k])
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		raw = []byte(header)
	}
	lines := strings.Split(string(raw), "\n")
	set := make(map[string]bool, len(kv))
	for i, line := range lines {
		trimmed := strings.TrimPrefix(strings.TrimSpace(line), "#")
		for k, v := range kv {
			if strings.HasPrefix(trimmed, k+"=") {
				lines[i] = k + "=" + v
				set[k] = true
			}
		}
	}
	// Stable order: iterate kv through a fixed key list. The caller controls
	// it, because it only passes the same map shape (WAN/agent, or house).
	// Thus the diff of a second run is only the values, not the order.
	for _, k := range sortedKeys(kv) {
		if !set[k] {
			lines = append(lines, k+"="+kv[k])
		}
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	// A fresh box has no /etc/pi-fortress yet: pf install runs before apply.
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0644)
}

func sortedKeys(kv map[string]string) []string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	// Small, fixed sets (2-6 keys). A simple insertion sort keeps this
	// package free of dependencies. It does not import sort for four items.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

const netEnvLocalHeader = `# Operator overlay, written by pf install and sourced by apply after
# net.env. Nothing in the tree ships or copies over this file, so a value
# set here survives a ship; see vm/pi/net.env.local.example for the rest
# of what may go here (DoT, AGENT_DNS, connection budgets, ...).
`

// WriteNetEnvLocal sets INT_IF (the agent NIC) and WAN_IF (the uplink) in
// /etc/pi-fortress/net.env.local, the only overlay of apply.sh for these
// (vm/pi/apply.sh, NET_ENV_LOCAL; docs/user_guide/pi_setup.md). An empty wan or
// agent does not change that key (detection stays automatic for it).
func WriteNetEnvLocal(path, wan, agent string) error {
	kv := map[string]string{}
	if agent != "" {
		kv["INT_IF"] = agent
	}
	if wan != "" {
		kv["WAN_IF"] = wan
	}
	if len(kv) == 0 {
		return nil
	}
	return UpsertEnv(path, kv, netEnvLocalHeader)
}

// WriteGatewayRole marks this box as a box that pf install made a gateway.
// apply.sh refuses a host that is not a Pi, a lab VM or the appliance. On
// any other supported box, this file lets the first apply, and each later
// apply, run. An empty path writes nothing.
func WriteGatewayRole(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("pf install\n"), 0644)
}

// SaveReleaseSigners keeps the allowed_signers file that pf install verified
// the bundle with at dst, where pf upgrade reads it. install.sh gives pf
// install a temporary copy. Without this, a box could install one time and
// never upgrade. It does nothing for the same path, or an empty dst.
func SaveReleaseSigners(src, dst string) error {
	if dst == "" || src == dst {
		return nil
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0644)
}

// CheckReleaseURL refuses a release base URL that is not https. The
// signature checks the bytes. But over plain http, anyone on the path
// selects which signed bytes arrive.
func CheckReleaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("PF_RELEASE_URL %q is not an https:// URL; releases are fetched over https only", raw)
	}
	return nil
}

// SaveReleaseURL keeps the PF_RELEASE_URL that install.sh downloaded from at
// dst (ReleaseURLPath). Thus a later `pf upgrade -version <tag>` finds it
// without the variable. An offline PF_BUNDLE install has no URL, and it does
// not change an existing file.
func SaveReleaseURL(raw, dst string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || dst == "" {
		return nil
	}
	if err := CheckReleaseURL(raw); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, []byte(raw+"\n"), 0644)
}

const houseEnvHeader = `# House segment (docs/user_guide/home_network.md), written by pf install. Delete
# this file and run pf apply to remove the segment. Full key list:
# vm/pi/house.env.example.
`

// WriteHouseEnv writes HOUSE_IF. Only when the file is new, it also
// writes the defaults that house.env.example ships (10.78.0.0/24).
// The other keys of an existing file belong to the operator, and it
// does not change them, the same as UpsertEnv at all other locations.
func WriteHouseEnv(path, houseIf string) error {
	if houseIf == "" {
		return nil
	}
	_, err := os.Stat(path)
	fresh := os.IsNotExist(err)
	kv := map[string]string{"HOUSE_IF": houseIf}
	if fresh {
		kv["HOUSE_NET"] = "10.78.0.0/24"
		kv["HOUSE_IP"] = "10.78.0.1"
		kv["HOUSE_DHCP_START"] = "10.78.0.100"
		kv["HOUSE_DHCP_END"] = "10.78.0.199"
	}
	return UpsertEnv(path, kv, houseEnvHeader)
}

// RemoveLabMarker deletes /etc/pi-fortress/lab if present. A release
// install is never a lab box (the lab marker cannot
// ship). Only the provisioner of lab.sh may write it.
func RemoveLabMarker(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("pf install: removing lab marker %s: %w", path, err)
	}
	return nil
}
