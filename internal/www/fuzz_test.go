package www

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// lineMax is the longest ledger line that decodeEvents reads (the default
// token size of bufio.Scanner). AppendEvent never writes a line near it.
const lineMax = bufio.MaxScanTokenSize - 1

// FuzzDecodeEvents: the ledger is group-writable, so its text is not
// trusted. decodeEvents must not panic, gives only events with a kind,
// and gives at most one event for each line. An event that AppendEvent
// encodes after any text comes back as the last event, unless a line of
// that text is longer than the scanner reads.
func FuzzDecodeEvents(f *testing.F) {
	f.Add([]byte(`{"ev":"issued","t":"2026-10-01T00:00:00Z","code":"ABCDEF","slot":"s1","uid":0}`+"\n"), "redeemed", "ABCDEF", "s1", "10.77.0.10", "", 0)
	f.Add([]byte("{\"ev\":\"\"}\n{not json\n\n{\"ev\":1}\r\n"), "setup", "", "", "10.78.0.20", "/setup.sh", 0)
	f.Add([]byte(`{"ev":"x","uid":99999999999999999999}`), "issued", "a\nb", "\"", "", " ", -1)
	f.Fuzz(func(t *testing.T, data []byte, kind, code, slot, ip, path string, uid int) {
		out := decodeEvents(bufio.NewReader(bytes.NewReader(data)))
		if lines := bytes.Count(data, []byte("\n")) + 1; len(out) > lines {
			t.Fatalf("%d events from %d lines", len(out), lines)
		}
		for _, ev := range out {
			if ev.Ev == "" {
				t.Fatalf("event with no kind: %+v", ev)
			}
		}

		for _, s := range []string{kind, code, slot, ip, path} {
			if !utf8.ValidString(s) {
				return // json.Marshal changes invalid UTF-8; no exact round trip
			}
		}
		want := Event{Ev: kind, T: "2026-10-01T00:00:00Z", Code: code, Slot: slot, IP: ip, UID: uid, Path: path}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if kind == "" || len(raw) > lineMax {
			return
		}
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			if len(line) > lineMax {
				return
			}
		}
		buf := append(append(append([]byte(nil), data...), '\n'), raw...)
		buf = append(buf, '\n')
		got := decodeEvents(bufio.NewReader(bytes.NewReader(buf)))
		if len(got) == 0 || got[len(got)-1] != want {
			t.Fatalf("event lost after %q: got %+v, want %+v", data, got, want)
		}
	})
}

// FuzzReadClaim: readClaim reads at most claimMax bytes of a claim file,
// whatever its size, and gives the start of the file unchanged.
func FuzzReadClaim(f *testing.F) {
	f.Add([]byte(`{"code":"ABCDEF","slot":"s1","kinds":["anthropic"]}`), 0)
	f.Add([]byte{}, claimMax+1)
	f.Add([]byte("x"), 3*claimMax)
	f.Fuzz(func(t *testing.T, data []byte, pad int) {
		if pad < 0 || pad > 4*claimMax {
			pad = 0
		}
		body := append(append([]byte(nil), data...), bytes.Repeat([]byte{'A'}, pad)...)
		dir := t.TempDir()
		path := filepath.Join(dir, "ABCDEF.json")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readClaim(dir, path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > claimMax {
			t.Fatalf("read %d bytes, limit %d", len(got), claimMax)
		}
		if !bytes.Equal(got, body[:min(len(body), claimMax)]) {
			t.Fatalf("read is not the start of the file")
		}
	})
}

// FuzzRedeemClaimCode: the code comes from the URL of a LAN client. With
// no claim issued, no code redeems, and no code makes a file anywhere.
func FuzzRedeemClaimCode(f *testing.F) {
	for _, s := range []string{"ABCDEF", "abcdef", " ABCDEF ", "../../x", "ABCDE/", "ABC\x00EF", "ÄBCDEF", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, code string) {
		root := t.TempDir()
		claims := filepath.Join(root, "claims")
		for _, d := range []string{claims, RedeemedDir(claims)} {
			if err := os.MkdirAll(d, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := RedeemClaim(claims, code); err != ErrNoClaim {
			t.Fatalf("code %q: err %v, want ErrNoClaim", code, err)
		}
		var made []string
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				made = append(made, strings.TrimPrefix(p, root))
			}
			return nil
		})
		if len(made) != 0 {
			t.Fatalf("code %q made files: %v", code, made)
		}
	})
}
