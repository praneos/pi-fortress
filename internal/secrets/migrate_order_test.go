package secrets

import (
	"os"
	"strings"
	"testing"
)

func TestMigrateOrderAndKeptRows(t *testing.T) {
	st := tmpStore(t)
	raw := "# keep\nZED_TOKEN=z1\nCLAUDE_ORT=only-ort\nlower_key=x1\nA_TOKEN=a1\nbbbbbbbbbbbbbbbb_A_TOKEN=held\n"
	if err := os.WriteFile(st.path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	moved, err := st.MigrateUnslotted()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range moved {
		got = append(got, m.Old+"|"+m.Kind)
		if m.Slot == "bbbbbbbbbbbbbbbb" {
			t.Fatal("reused a taken slot", moved)
		}
	}
	if strings.Join(got, ",") != "CLAUDE_ORT|CLAUDE_ORT,A_TOKEN|A_TOKEN,ZED_TOKEN|ZED_TOKEN" {
		t.Fatal(got)
	}
	if moved[0].Slot == moved[1].Slot || moved[1].Slot == moved[2].Slot {
		t.Fatal(moved)
	}
	text, err := os.ReadFile(st.path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	if !strings.HasPrefix(body, "# keep\nbbbbbbbbbbbbbbbb_A_TOKEN=held\nlower_key=x1\n") {
		t.Fatalf("%q", body)
	}
	live, err := st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	if live[EnvKey(moved[0].Slot, "CLAUDE_ORT")] != "only-ort" || live[EnvKey(moved[2].Slot, "ZED_TOKEN")] != "z1" {
		t.Fatal(live)
	}
	if _, ok := live[EnvKey(moved[0].Slot, "CLAUDE_OAT")]; ok {
		t.Fatal(live)
	}
}
