package render

import (
	"os"
	"path/filepath"
	"testing"
)

// apply.sh reads these files with `source`. Thus a quoted value is the
// value without its quotes, and the whitespace around an assignment is
// not part of it. EnvLines kept the quotes and the spaces. Thus each
// reader that compares what apply did with what the file says
// compared `1` with `"1"`.
func TestEnvLinesReadsWhatSourceReads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "net.env")
	body := "" +
		"  # an indented comment\n" +
		"FEED_REFRESH=\"1\"\n" +
		"INT_IF='eth0'\n" +
		"  PI_IP = 10.77.0.1  \n" +
		"DOT_IPS=\"9.9.9.9 149.112.112.112\"\n" +
		"RULE=\"a#b\"\n" +
		"NESTED=\"'x'\"\n" +
		"BARE=\"\n" +
		"EMPTY=\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	if err := EnvLines(p, func(_ int, k, v string) error { got[k] = v; return nil }); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"FEED_REFRESH": "1", "INT_IF": "eth0", "PI_IP": "10.77.0.1",
		"DOT_IPS": "9.9.9.9 149.112.112.112", "RULE": "a#b",
		"NESTED": "'x'", "BARE": "\"", "EMPTY": "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestEnvLinesStillRefusesALineThatIsNotAnAssignment(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "net.env")
	if err := os.WriteFile(p, []byte("PI_IP=10.77.0.1\nno equals sign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnvLines(p, func(int, string, string) error { return nil }); err == nil {
		t.Fatal("a bare line was accepted")
	}
}
