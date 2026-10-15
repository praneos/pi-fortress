package fetch

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const seedShipped = `{"user_agent":"ua","timeout_sec":60,"max_ips":1,"max_domains":1,"feeds":[
{"id":"a","kind":"domains","format":"plain","url":"https://a.example/"},
{"id":"b","kind":"domains","format":"plain","url":"https://b.example/"},
{"id":"new","kind":"domains","format":"plain","url":"https://new.example/"}]}`

func feedIDs(t *testing.T, raw []byte) (ids []string, off map[string]bool, s Spec) {
	t.Helper()
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	off = map[string]bool{}
	for _, f := range s.Feeds {
		ids = append(ids, f.ID)
		off[f.ID] = !f.On()
	}
	return ids, off, s
}

// A feed that is new in git reaches a box whose sources.json the ship
// keeps. A feed that the operator disabled stays disabled. A feed that
// they deleted stays deleted after the box was offered it.
func TestMergeSeedAddsOnlyFeedsNeverOffered(t *testing.T) {
	kept := `{"user_agent":"mine","timeout_sec":30,"max_ips":1,"max_domains":1,"feeds":[
{"id":"a","kind":"domains","format":"plain","url":"https://a.example/","enabled":false}]}`
	out, changed, err := MergeSeed([]byte(kept), []byte(seedShipped))
	if err != nil || !changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	ids, off, s := feedIDs(t, out)
	if strings.Join(ids, " ") != "a b new" || !off["a"] || off["new"] {
		t.Fatalf("ids %v off %v", ids, off)
	}
	if s.UserAgent != "mine" || s.TimeoutSec != 30 || strings.Join(s.Seeded, " ") != "a b new" {
		t.Fatalf("the box's own settings changed or seeded is wrong: %+v", s)
	}

	// The operator deletes b. The next ship does not add it again, and with
	// nothing new, the file stays byte for byte the same.
	s.Feeds = s.Feeds[:1]
	again, _ := json.MarshalIndent(s, "", "  ")
	out, changed, err = MergeSeed(again, []byte(seedShipped))
	if err != nil || changed || string(out) != string(again) {
		t.Fatalf("a deleted feed came back or the file was rewritten: changed %v err %v\n%s", changed, err, out)
	}
}

// A box copy that does not parse is for the operator to fix. The ship
// leaves it as it is, and does not replace it.
func TestMergeSeedLeavesABrokenCopyAlone(t *testing.T) {
	out, changed, err := MergeSeed([]byte("{not json"), []byte(seedShipped))
	if err != nil || changed || string(out) != "{not json" {
		t.Fatalf("%q %v %v", out, changed, err)
	}
}

// The shipped sources.json is in the form that the seat writes back
// (admin.SetFeedEnabled, MergeSeed). So when a feed is disabled and then
// enabled again, the file stays byte for byte the same, with no new key order.
func TestShippedSourcesAreCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../vm/policy/sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	out, _ := json.MarshalIndent(s, "", "  ")
	if string(append(out, '\n')) != string(raw) {
		t.Fatal("vm/policy/sources.json is not in MarshalIndent form; rewrite it (json.MarshalIndent of fetch.Spec, two spaces, trailing newline)")
	}
}
