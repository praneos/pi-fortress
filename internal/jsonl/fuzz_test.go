package jsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// FuzzLastShip: no ship log makes LastShip panic. A row that the encoder
// writes after any text is the row that LastShip gives, when the row fits
// in the 64 KiB tail that it reads.
func FuzzLastShip(f *testing.F) {
	f.Add([]byte(`{"t":"2026-10-01T00:00:00Z","version":3,"result":"ok"}`+"\n"), int64(4), "abc", "bad_sig", "")
	f.Add([]byte("{\"result\":\"\"}\n{torn"), int64(0), "", "ok", "a\nb")
	f.Add([]byte("\n\n\r\n"), int64(-1), "\"", "rollback", " ")
	f.Fuzz(func(t *testing.T, data []byte, version int64, sha, result, reason string) {
		path := filepath.Join(t.TempDir(), "ship.jsonl")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if ev, ok := LastShip(path); ok && ev.Result == "" {
			t.Fatalf("row with no result: %+v", ev)
		}

		for _, s := range []string{sha, result, reason} {
			if !utf8.ValidString(s) {
				return // json.Marshal changes invalid UTF-8; no exact round trip
			}
		}
		want := Ship{T: "2026-10-01T00:00:00Z", Version: version, SHA: sha, Result: result, Reason: reason}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if result == "" || len(raw)+1 > 64<<10 {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(append(append([]byte("\n"), raw...), '\n'))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := LastShip(path); !ok || got != want {
			t.Fatalf("got %+v %v, want %+v", got, ok, want)
		}
	})
}
