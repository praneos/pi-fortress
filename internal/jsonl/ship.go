package jsonl

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// Ship is one pf ship install attempt. Result is "ok" or the refusal class
// (bad_sig, rollback, bad_bundle, apply_failed, ...).
type Ship struct {
	T       string `json:"t"`
	Version int64  `json:"version,omitempty"`
	SHA     string `json:"sha,omitempty"`
	Result  string `json:"result"`
	Reason  string `json:"reason,omitempty"`
}

func AppendShip(path string, ev Ship) error {
	w := &Writer{}
	if ev.T == "" {
		ev.T = w.stamp()
	}
	return w.append(path, ev)
}

// LastShip returns the newest row of a ship log. ok is false when there
// is no row.
func LastShip(path string) (Ship, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Ship{}, false
	}
	defer f.Close()
	const tail = 64 << 10
	if st, err := f.Stat(); err == nil && st.Size() > tail {
		f.Seek(st.Size()-tail, io.SeekStart)
	}
	raw, err := io.ReadAll(io.LimitReader(f, tail))
	if err != nil {
		return Ship{}, false
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var ev Ship
		if json.Unmarshal(lines[i], &ev) == nil && ev.Result != "" {
			return ev, true
		}
	}
	return Ship{}, false
}
