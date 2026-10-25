package render

import (
	"strings"
	"testing"
)

// SSH_FROM arrives only on the house or on a different plain segment, and
// the source check of each drops a source outside its own network. Thus an
// SSH_FROM outside HOUSE_NET and outside the NET of each other segment
// renders a rule that never matches. Load refuses it, and names the
// networks where it can be.
func TestSSHFromMustBeInsideTheHouseOrASegment(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth2\n")
	guest := "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n"
	for _, from := range []string{"10.78.0.20", "10.81.0.7"} {
		segs := segDir(t, map[string]string{"desk.env": deskBase + "SSH_FROM=" + from + "\n", "guest.env": guest})
		load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house})
	}
	for _, tc := range []struct {
		name, from, house string
		segs              map[string]string
		want              []string
	}{
		{"public address", "8.8.8.8", house, map[string]string{"guest.env": guest},
			[]string{"segment desk", "SSH_FROM=8.8.8.8", "HOUSE_NET 10.78.0.0/24", "NET 10.81.0.0/24 of segment guest"}},
		{"private address on no network", "192.168.1.5", house, nil,
			[]string{"SSH_FROM=192.168.1.5", "HOUSE_NET 10.78.0.0/24"}},
		{"house address with no house", "10.78.0.20", "/nonexistent/house.env", map[string]string{"guest.env": guest},
			[]string{"SSH_FROM=10.78.0.20", "NET 10.81.0.0/24 of segment guest"}},
		{"no house and no other segment", "10.78.0.20", "/nonexistent/house.env", nil,
			[]string{"SSH_FROM=10.78.0.20", "no house and no other segment"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"desk.env": deskBase + "SSH_FROM=" + tc.from + "\n"}
			for k, v := range tc.segs {
				files[k] = v
			}
			_, err := Load(Options{Net: lab, SegmentsDir: segDir(t, files), HouseEnv: tc.house})
			if err == nil {
				t.Fatal("Load accepted it")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
		})
	}
	// The usual box: no SSH_FROM at all.
	segs := segDir(t, map[string]string{"desk.env": deskBase})
	load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
	load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house})
}
