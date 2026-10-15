package secrets

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func tmpStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return Open(path)
}

func TestParseEnvKey(t *testing.T) {
	slot, kind, ok := ParseEnvKey("a1b2c3d4e5f67890_CLAUDE_OAT")
	if !ok || slot != "a1b2c3d4e5f67890" || kind != "CLAUDE_OAT" {
		t.Fatalf("%s %s %v", slot, kind, ok)
	}
	if _, _, ok := ParseEnvKey("CLAUDE_OAT"); ok {
		t.Fatal("unslotted")
	}
	if _, _, ok := ParseEnvKey("abc_CLAUDE_OAT"); ok {
		t.Fatal("short slot")
	}
	if Placeholder("a1b2c3d4e5f67890", "CLAUDE_OAT") != "pf_a1b2c3d4e5f67890_CLAUDE_OAT" {
		t.Fatal("placeholder")
	}
	kinds, err := KindsFor("CLAUDE")
	if err != nil || len(kinds) != 2 || kinds[0] != "CLAUDE_OAT" || kinds[1] != "CLAUDE_ORT" {
		t.Fatalf("%v %v", kinds, err)
	}
	kinds, err = KindsFor("CLAUDE_OAT")
	if err != nil || len(kinds) != 2 {
		t.Fatalf("%v %v", kinds, err)
	}
	kinds, err = KindsFor("canary")
	if err != nil || len(kinds) != 1 || kinds[0] != "CANARY" {
		t.Fatalf("%v %v", kinds, err)
	}
}

func TestMintUnique(t *testing.T) {
	taken := map[string]struct{}{}
	slots := map[string]struct{}{}
	for range 200 {
		slot, err := MintSlot(taken, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(slot) != 16 {
			t.Fatal(slot)
		}
		if _, err := hex.DecodeString(slot); err != nil {
			t.Fatal(slot)
		}
		if _, ok := slots[slot]; ok {
			t.Fatal("dup")
		}
		slots[slot] = struct{}{}
		taken[slot] = struct{}{}
	}
}

func TestMintCollision(t *testing.T) {
	taken := map[string]struct{}{"aaaaaaaaaaaaaaaa": {}}
	seq := []string{"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"}
	i := 0
	slot, err := MintSlot(taken, func() string {
		s := seq[i]
		i++
		return s
	})
	if err != nil {
		t.Fatal(err)
	}
	if slot != "bbbbbbbbbbbbbbbb" {
		t.Fatal(slot)
	}
}

func TestFindPlaceholders(t *testing.T) {
	hits := FindPlaceholders("Bearer  pf_a1b2c3d4e5f67890_CLAUDE_OAT trailing")
	if len(hits) != 1 || hits[0][0] != "a1b2c3d4e5f67890" || hits[0][1] != "CLAUDE_OAT" {
		t.Fatalf("%v", hits)
	}
	if len(FindPlaceholders("pf_CLAUDE_OAT")) != 0 {
		t.Fatal("unslotted")
	}
}

func TestEnrollAndHarvest(t *testing.T) {
	st := tmpStore(t)
	slot1, err := st.MintKinds([]string{"CLAUDE_OAT", "CLAUDE_ORT"}, map[string]string{"CLAUDE_OAT": "oat-a", "CLAUDE_ORT": "ort-a"})
	if err != nil {
		t.Fatal(err)
	}
	slot2, err := st.MintKinds([]string{"CLAUDE_OAT", "CLAUDE_ORT"}, map[string]string{"CLAUDE_OAT": "oat-b", "CLAUDE_ORT": "ort-b"})
	if err != nil {
		t.Fatal(err)
	}
	if slot1 == slot2 {
		t.Fatal("slots equal")
	}
	live, err := st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	if live[EnvKey(slot1, "CLAUDE_OAT")] != "oat-a" || live[EnvKey(slot1, "CLAUDE_ORT")] != "ort-a" {
		t.Fatal(live)
	}
	if live[EnvKey(slot2, "CLAUDE_OAT")] != "oat-b" {
		t.Fatal(live)
	}
	got, err := st.HarvestClaude("oat-a-new", "ort-a-new", slot1)
	if err != nil {
		t.Fatal(err)
	}
	if got != slot1 {
		t.Fatal(got)
	}
	live, _ = st.LiveMap()
	if live[EnvKey(slot1, "CLAUDE_OAT")] != "oat-a-new" {
		t.Fatal(live)
	}
	if live[EnvKey(slot2, "CLAUDE_OAT")] != "oat-b" {
		t.Fatal(live)
	}
	minted, err := st.HarvestClaude("oat-c", "ort-c", "")
	if err != nil {
		t.Fatal(err)
	}
	if minted == slot1 || minted == slot2 {
		t.Fatal(minted)
	}
	live, _ = st.LiveMap()
	if live[EnvKey(minted, "CLAUDE_OAT")] != "oat-c" {
		t.Fatal(live)
	}
	forged := "dddddddddddddddd"
	got, err = st.HarvestClaude("oat-d", "ort-d", forged)
	if err != nil {
		t.Fatal(err)
	}
	if got == forged {
		t.Fatal("forged slot taken")
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap[EnvKey(forged, "CLAUDE_OAT")]; ok {
		t.Fatal("forged present")
	}
	listed, err := st.ListSlots()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range listed {
		for _, key := range row.Keys {
			if key.Dummy == "" || key.State == "" {
				t.Fatalf("%+v", key)
			}
			if key.Kind == "value" {
				t.Fatal("value field")
			}
		}
	}
	gone, err := st.DeleteSlot(slot1)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gone, ",")
	if !strings.Contains(joined, "CLAUDE_OAT") || !strings.Contains(joined, "CLAUDE_ORT") {
		t.Fatal(gone)
	}
	live, _ = st.LiveMap()
	if _, ok := live[EnvKey(slot2, "CLAUDE_OAT")]; !ok {
		t.Fatal(live)
	}
	if _, ok := live[EnvKey(slot1, "CLAUDE_OAT")]; ok {
		t.Fatal(live)
	}
	again, err := st.DeleteSlot(slot1)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatal(again)
	}
}

func TestConcurrentWrites(t *testing.T) {
	st := tmpStore(t)
	slotA, err := st.MintKinds([]string{"CLAUDE_OAT", "CLAUDE_ORT"}, map[string]string{"CLAUDE_OAT": "a0", "CLAUDE_ORT": "ar0"})
	if err != nil {
		t.Fatal(err)
	}
	slotB, err := st.MintKinds([]string{"CLAUDE_OAT", "CLAUDE_ORT"}, map[string]string{"CLAUDE_OAT": "b0", "CLAUDE_ORT": "br0"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var errs []error
	addErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	const rounds = 40
	var wg sync.WaitGroup
	worker := func(slot, prefix string) {
		defer wg.Done()
		for i := range rounds {
			_, err := st.HarvestClaude(prefix+"-oat-"+strconv.Itoa(i), prefix+"-ort-"+strconv.Itoa(i), slot)
			addErr(err)
		}
	}
	wg.Add(2)
	go worker(slotA, "A")
	go worker(slotB, "B")
	wg.Wait()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	live, err := st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live[EnvKey(slotA, "CLAUDE_OAT")]; !ok {
		t.Fatal(live)
	}
	if _, ok := live[EnvKey(slotB, "CLAUDE_OAT")]; !ok {
		t.Fatal(live)
	}
	if !strings.HasPrefix(live[EnvKey(slotA, "CLAUDE_OAT")], "A-oat-") {
		t.Fatal(live[EnvKey(slotA, "CLAUDE_OAT")])
	}
	if !strings.HasPrefix(live[EnvKey(slotB, "CLAUDE_OAT")], "B-oat-") {
		t.Fatal(live[EnvKey(slotB, "CLAUDE_OAT")])
	}
	if len(live) != 4 {
		t.Fatal(live)
	}

	var minted []string
	wg.Add(24)
	for range 24 {
		go func() {
			defer wg.Done()
			slot, err := st.MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "g"})
			addErr(err)
			if err == nil {
				mu.Lock()
				minted = append(minted, slot)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(minted) != 24 {
		t.Fatal(len(minted))
	}
	uniq := map[string]struct{}{}
	for _, s := range minted {
		uniq[s] = struct{}{}
	}
	if len(uniq) != 24 {
		t.Fatal(len(uniq))
	}
	live, _ = st.LiveMap()
	n := 0
	for k := range live {
		if strings.HasSuffix(k, "_GITHUB_TOKEN") {
			n++
		}
	}
	if n != 24 {
		t.Fatal(n)
	}
}

func TestMigrate(t *testing.T) {
	st := tmpStore(t)
	raw := "# keep\nCLAUDE_OAT=live-oat\nCLAUDE_ORT=live-ort\nGITHUB_TOKEN=live-gh\nOPENAI_API_KEY=\naaaaaaaaaaaaaaaa_XAI_API_KEY=already\n"
	if err := os.WriteFile(st.path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	moved, err := st.MigrateUnslotted()
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(st.path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	if strings.Contains(body, "OPENAI_API_KEY=") {
		t.Fatal(body)
	}
	live, err := st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	if live["aaaaaaaaaaaaaaaa_XAI_API_KEY"] != "already" {
		t.Fatal(live)
	}
	kinds := map[string]struct{}{}
	var oatSlot, ortSlot, ghSlot string
	for _, m := range moved {
		kinds[m.Old+"|"+m.Kind] = struct{}{}
		switch m.Kind {
		case "CLAUDE_OAT":
			oatSlot = m.Slot
		case "CLAUDE_ORT":
			ortSlot = m.Slot
		case "GITHUB_TOKEN":
			ghSlot = m.Slot
		}
	}
	if _, ok := kinds["CLAUDE_OAT|CLAUDE_OAT"]; !ok {
		t.Fatal(moved)
	}
	if _, ok := kinds["CLAUDE_ORT|CLAUDE_ORT"]; !ok {
		t.Fatal(moved)
	}
	if _, ok := kinds["GITHUB_TOKEN|GITHUB_TOKEN"]; !ok {
		t.Fatal(moved)
	}
	if oatSlot == "" || oatSlot != ortSlot {
		t.Fatalf("oat=%s ort=%s", oatSlot, ortSlot)
	}
	if ghSlot == "" || ghSlot == oatSlot {
		t.Fatal(ghSlot)
	}
	if live[EnvKey(oatSlot, "CLAUDE_OAT")] != "live-oat" {
		t.Fatal(live)
	}
	again, err := st.MigrateUnslotted()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatal(again)
	}
}
