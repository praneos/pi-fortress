package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/jsonl"
)

func TestNopasswdAll(t *testing.T) {
	cases := []struct {
		text           string
		want, complete bool
	}{
		{"pi ALL=(ALL) NOPASSWD: ALL\n", true, true},
		{"%sudo ALL=(ALL:ALL) NOPASSWD:ALL", true, true},
		{"pi ALL = NOPASSWD: SETENV: ALL", true, true},
		{"pi ALL=(ALL) NOPASSWD: /usr/bin/apt, ALL", true, true},
		{"pi ALL=(ALL) \\\n    NOPASSWD: ALL", true, true},
		{"Defaults !authenticate", true, true},
		{"Defaults:pi ! authenticate", true, true},
		{"%sudo ALL=(ALL:ALL) ALL", false, true},
		{"pi ALL=(ALL) NOPASSWD: /usr/bin/apt", false, true},
		{"pi ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: ALL", false, true},
		{"pi ALL=(ALL) NOPASSWD: ALLOW_ME", false, true},
		{"# pi ALL=(ALL) NOPASSWD: ALL", false, true},
		// Skipped, so the parser is not entitled to say "no".
		{"#includedir /etc/sudoers.d\n@includedir /etc/sudoers.d", false, false},
		{"Cmnd_Alias EVERY = ALL", false, false},
		{"Defaults env_reset\nDefaults secure_path=\"/usr/bin\"", false, true},
		{"", false, true},
	}
	for _, c := range cases {
		got, complete := NopasswdAll(c.text)
		if got != c.want || complete != c.complete {
			t.Errorf("NopasswdAll(%q) = %v, %v, want %v, %v", c.text, got, complete, c.want, c.complete)
		}
	}
}

// An includedir of the directory that the caller reads whole is not a
// skipped file, so it leaves the answer complete. Any other include still
// does not.
func TestNopasswdAllCoveredIncludedir(t *testing.T) {
	const d = "/etc/sudoers.d"
	cases := []struct {
		text     string
		complete bool
	}{
		{"@includedir /etc/sudoers.d", true},
		{"#includedir /etc/sudoers.d", true},
		{"@includedir\t/etc/sudoers.d", true},
		{"@includedir", false},
		{"@includedir /etc/sudoers.d/", true},
		{`@includedir "/etc/sudoers.d"`, true},
		{"@includedir /etc/other.d", false},
		{"@includedir sudoers.d", false},
		{"@include /etc/sudoers.d/extra", false},
		{"#include /etc/sudoers.local", false},
	}
	for _, c := range cases {
		got, complete := NopasswdAll(c.text, d)
		if got || complete != c.complete {
			t.Errorf("NopasswdAll(%q, %q) = %v, %v, want false, %v", c.text, d, got, complete, c.complete)
		}
	}
	if got, complete := NopasswdAll("@includedir /etc/sudoers.d\npi ALL=(ALL) NOPASSWD: ALL", d); !got || !complete {
		t.Errorf("a grant beside a covered includedir: %v, %v", got, complete)
	}
}

func TestSudoRung(t *testing.T) {
	etc := t.TempDir()
	os.MkdirAll(filepath.Join(etc, "sudoers.d"), 0755)
	os.WriteFile(filepath.Join(etc, "sudoers"), []byte("%sudo ALL=(ALL:ALL) ALL\n@includedir "+filepath.Join(etc, "sudoers.d")+"\n"), 0440)
	os.WriteFile(filepath.Join(etc, "sudoers.d", "README"), []byte("# nothing\n"), 0440)
	os.WriteFile(filepath.Join(etc, "sudoers.d", "old.bak"), []byte("pi ALL=(ALL) NOPASSWD: ALL\n"), 0440)
	os.WriteFile(filepath.Join(etc, "sudoers.d", "x~"), []byte("pi ALL=(ALL) NOPASSWD: ALL\n"), 0440)
	files, err := SudoersFiles(etc)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files %v", files)
	}
	// The @includedir names the same sudoers.d whose files SudoersFiles reads
	// in full. Stock Debian and Pi OS ship this way, so a clean box
	// can be called clean.
	if r, ok := SudoRung(files, nil); !ok || r.Status != OK || r.Detail != "no passwordless sudo for ALL" {
		t.Fatalf("clean: %+v", r)
	}
	// An includedir of any other directory is one that nobody read.
	other := filepath.Join(etc, "sudoers.d", "other")
	os.WriteFile(other, []byte("@includedir /etc/elsewhere.d\n"), 0440)
	if r, ok := SudoRung(SudoersFiles(etc)); !ok || r.Status != Warn || !strings.Contains(r.Detail, "inconclusive") {
		t.Fatalf("other includedir: %+v", r)
	}
	os.Remove(other)
	nopw := filepath.Join(etc, "sudoers.d", "010_pi-nopasswd")
	os.WriteFile(nopw, []byte("pi ALL=(ALL) NOPASSWD: ALL\n"), 0440)
	r, ok := SudoRung(SudoersFiles(etc))
	if !ok || r.Status != Warn || !strings.Contains(r.Detail, "010_pi-nopasswd") {
		t.Fatalf("nopasswd: %+v", r)
	}
	if _, ok := SudoRung([]string{filepath.Join(etc, "absent")}, nil); ok {
		t.Fatal("rung for a box without sudoers")
	}
}

func TestShipRung(t *testing.T) {
	if _, ok := ShipRung(jsonl.Ship{}, false); ok {
		t.Fatal("rung without a log")
	}
	r, _ := ShipRung(jsonl.Ship{T: "2026-09-13T10:00:00Z", Version: 7, SHA: "abc", Result: "ok"}, true)
	if r.Status != OK || !strings.Contains(r.Detail, "version 7 abc") {
		t.Fatalf("%+v", r)
	}
	r, _ = ShipRung(jsonl.Ship{T: "2026-09-13T10:00:00Z", Result: "bad_sig", Reason: "no"}, true)
	if r.Status != Warn || !strings.Contains(r.Detail, "bad_sig") {
		t.Fatalf("%+v", r)
	}
}
