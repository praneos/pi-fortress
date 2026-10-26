package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

func TestClaimIssuesOneCode(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets.env")
	slot, err := secrets.Open(sec).MintKinds([]string{"CANARY"}, map[string]string{"CANARY": "AKIALIVECANARYVALUE"})
	if err != nil {
		t.Fatal(err)
	}
	www := filepath.Join(dir, "www")
	if err := os.MkdirAll(filepath.Join(www, "claims"), 0o770); err != nil {
		t.Fatal(err)
	}
	// pf claim issues no code while there is no setup.sh or ca.pem to serve.
	for name, body := range map[string]string{"setup.sh": "#!/bin/sh\n", "ca.pem": "-----BEGIN CERTIFICATE-----\n"} {
		if err := os.WriteFile(filepath.Join(www, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"claim", "-secrets", sec, "-www", www, "-audit", filepath.Join(dir, "audit.jsonl")}

	var out, errb bytes.Buffer
	if code := Main(append(base, "-slot", slot), &out, &errb); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	var claim string
	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "code="); ok {
			claim = v
		}
	}
	if claim == "" || !strings.Contains(out.String(), "slot="+slot) {
		t.Fatalf("output %q", out.String())
	}
	if strings.Contains(out.String(), "AKIALIVECANARYVALUE") {
		t.Fatal("claim output carries the live value")
	}
	if _, err := os.Stat(filepath.Join(www, "claims", claim+".json")); err != nil {
		t.Fatalf("claim file: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"no slot", base, 2},
		{"unknown slot", append(base, "-slot", "0000000000000000"), 1},
	} {
		out.Reset()
		errb.Reset()
		if code := Main(tc.args, &out, &errb); code != tc.code {
			t.Fatalf("%s: code=%d stderr=%q", tc.name, code, errb.String())
		}
	}
}
