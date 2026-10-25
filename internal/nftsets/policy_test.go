package nftsets

import (
	"bytes"
	"io/fs"
	"slices"
	"testing"
)

// policyBox is a pf dns config with the agent and one plain segment, and
// the list files that they name.
type policyBox struct {
	config string
	files  map[string]string
}

func newPolicyBox() *policyBox {
	return &policyBox{
		config: `{"listen": 53, "segments": [
  {"iface": "eth1", "ip": "10.77.0.1", "upstream": "9.9.9.9:53", "sinkhole": ["/etc/pi-fortress/blocked-domains.conf", "/etc/pi-fortress/doh-domains.conf"], "nft_set": "resolved_v4", "log": "/var/log/pi-fortress/dns.jsonl", "key_rules": "/etc/pi-fortress/key_prefixes.rules"},
  {"name": "desk", "iface": "eth3", "ip": "10.79.0.1", "upstream": "9.9.9.9:53", "sinkhole": ["/etc/pi-fortress/blocked-domains.conf"], "nft_set": "resolved_desk_v4", "log": "/var/log/pi-fortress/dns-desk.jsonl", "paranoid": true, "allow": "/etc/pi-fortress/allow.desk.domains"},
  {"name": "stub-main", "iface": "lo", "ip": "127.0.0.53", "upstream": "", "sinkhole": [], "nft_set": "", "log": ""}
]}`,
		files: map[string]string{
			"/etc/pi-fortress/blocked-domains.conf": "address=/bad.example/0.0.0.0\n",
			"/etc/pi-fortress/doh-domains.conf":     "address=/doh.example/0.0.0.0\n",
			"/etc/pi-fortress/key_prefixes.rules":   "openai\tsk-[A-Za-z0-9]{20,}\tOPENAI_API_KEY\n",
			"/etc/pi-fortress/allow.desk.domains":   "github.com\n",
		},
	}
}

func (b *policyBox) read(p string) ([]byte, error) {
	s, ok := b.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(s), nil
}

func (b *policyBox) policy(t *testing.T) map[string]string {
	t.Helper()
	fps, err := Policy([]byte(b.config), b.read)
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	return fps
}

func TestPolicyGivesAFingerprintForEachResolvedSetOnly(t *testing.T) {
	fps := newPolicyBox().policy(t)
	if len(fps) != 2 || fps["resolved_v4"] == "" || fps["resolved_desk_v4"] == "" {
		t.Fatalf("fingerprints %v, want resolved_v4 and resolved_desk_v4 only", fps)
	}
	if fps["resolved_v4"] == fps["resolved_desk_v4"] {
		t.Fatal("two segments with different policies have one fingerprint")
	}
}

// Each change that can block a name changes the fingerprint of the set that
// the change applies to, and only that set.
func TestAPolicyChangeChangesOnlyTheSetsThatUseIt(t *testing.T) {
	base := newPolicyBox().policy(t)
	for _, c := range []struct {
		name string
		edit func(*policyBox)
		want []string
	}{
		{"a name in the shared blocklist", func(b *policyBox) {
			b.files["/etc/pi-fortress/blocked-domains.conf"] += "address=/new.example/0.0.0.0\n"
		}, []string{"resolved_desk_v4", "resolved_v4"}},
		{"a name in the agent DoH list", func(b *policyBox) {
			b.files["/etc/pi-fortress/doh-domains.conf"] += "address=/doh2.example/0.0.0.0\n"
		}, []string{"resolved_v4"}},
		{"a name out of the desk allowlist", func(b *policyBox) {
			b.files["/etc/pi-fortress/allow.desk.domains"] = ""
		}, []string{"resolved_desk_v4"}},
		{"a key rule", func(b *policyBox) {
			b.files["/etc/pi-fortress/key_prefixes.rules"] += "acme\tacme_[a-z]{9}\tACME\n"
		}, []string{"resolved_v4"}},
		{"paranoid on for the agent", func(b *policyBox) {
			b.config = replaceOnce(t, b.config, `"key_rules": "/etc/pi-fortress/key_prefixes.rules"}`,
				`"key_rules": "/etc/pi-fortress/key_prefixes.rules", "paranoid": true, "allow": "/etc/pi-fortress/allow.domains"}`)
		}, []string{"resolved_v4"}},
		{"a list file that is gone", func(b *policyBox) {
			delete(b.files, "/etc/pi-fortress/allow.desk.domains")
		}, []string{"resolved_desk_v4"}},
	} {
		b := newPolicyBox()
		c.edit(b)
		if got := Changed(base, b.policy(t)); !slices.Equal(got, c.want) {
			t.Errorf("%s: changed %v, want %v", c.name, got, c.want)
		}
	}
}

func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	i := bytes.Index([]byte(s), []byte(old))
	if i < 0 {
		t.Fatalf("%q not in config", old)
	}
	return s[:i] + new + s[i+len(old):]
}

// The log file of a segment is output, not policy. The order and spacing
// of the keys are not policy either.
func TestTheSameEffectivePolicyKeepsItsFingerprint(t *testing.T) {
	base := newPolicyBox().policy(t)
	b := newPolicyBox()
	b.config = replaceOnce(t, b.config, `{"name": "desk", "iface": "eth3"`, `{  "iface": "eth3",   "name": "desk"`)
	b.config = replaceOnce(t, b.config, `"/var/log/pi-fortress/dns-desk.jsonl"`, `"/var/log/pi-fortress/desk.jsonl"`)
	if got := Changed(base, b.policy(t)); len(got) != 0 {
		t.Fatalf("changed %v for the same policy", got)
	}
}

func TestPolicyRefusesAConfigItCannotRead(t *testing.T) {
	for _, bad := range []string{
		`{"segments": [`,
		`{"segments": [{"nft_set": 7}]}`,
		`{"segments": [{"nft_set": "resolved_v4", "sinkhole": 7}]}`,
		`{"segments": [{"nft_set": "resolved_v4"}, {"nft_set": "resolved_v4"}]}`,
	} {
		if _, err := Policy([]byte(bad), newPolicyBox().read); err == nil {
			t.Errorf("Policy accepted %s", bad)
		}
	}
}

func TestStateRoundTripsAndAMissingOrBadLineCountsAsChanged(t *testing.T) {
	fps := newPolicyBox().policy(t)
	var b bytes.Buffer
	if err := FormatState(&b, fps); err != nil {
		t.Fatal(err)
	}
	back, err := ParseState(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got := Changed(back, fps); len(got) != 0 {
		t.Fatalf("a round trip changed %v", got)
	}
	back, err = ParseState(bytes.NewBufferString("resolved_v4 " + fps["resolved_v4"] + "\nresolved_desk_v4\nblacklist_v4 00\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Changed(back, fps); !slices.Equal(got, []string{"resolved_desk_v4"}) {
		t.Fatalf("changed %v, want resolved_desk_v4", got)
	}
	if got := Changed(nil, fps); len(got) != 2 {
		t.Fatalf("with no state, changed %v, want both sets", got)
	}
}

// Flush empties only the named resolved sets that the table has, in one
// transaction. It never empties a compiled set.
func TestFlushEmptiesOnlyTheNamedResolvedSets(t *testing.T) {
	f := twoSegmentBox()
	done, err := Flush(f.run, "inet fortress", []string{"resolved_desk_v4", "blacklist_v4", "resolved_gone_v4"})
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !slices.Equal(done, []string{"resolved_desk_v4"}) {
		t.Fatalf("flushed %v, want resolved_desk_v4", done)
	}
	if f.script != "flush set inet fortress resolved_desk_v4\n" {
		t.Fatalf("script %q", f.script)
	}
	f = twoSegmentBox()
	if done, err := Flush(f.run, "inet fortress", nil); err != nil || len(done) != 0 || f.script != "" {
		t.Fatalf("an empty flush ran %q, %v, %v", f.script, done, err)
	}
	f = twoSegmentBox()
	f.failOn = "-f"
	if _, err := Flush(f.run, "inet fortress", []string{"resolved_v4"}); err == nil {
		t.Fatal("a refused flush reported success")
	}
}
