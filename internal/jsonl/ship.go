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

// shipTail is how much of the end of a ship log the readers below look
// at. A ship log gets a small number of rows a week.
const shipTail = 64 << 10

// LastShip returns the newest row of a ship log. ok is false when there
// is no row.
func LastShip(path string) (Ship, bool) {
	return FindShip(path, func(Ship) bool { return true })
}

// FindShip returns the newest row of a ship log for which match is true.
// It looks only at the last 64 KiB. ok is false when no row there
// matches.
func FindShip(path string, match func(Ship) bool) (Ship, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Ship{}, false
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > shipTail {
		f.Seek(st.Size()-shipTail, io.SeekStart)
	}
	raw, err := io.ReadAll(io.LimitReader(f, shipTail))
	if err != nil {
		return Ship{}, false
	}
	rows := shipRows(raw)
	for i := len(rows) - 1; i >= 0; i-- {
		if match(rows[i]) {
			return rows[i], true
		}
	}
	return Ship{}, false
}

// ShipLogSize is the length of a ship log in bytes, or 0 when there is
// no log. ShipsAfter takes it as its mark.
func ShipLogSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// ShipsAfter returns the rows that were appended to a ship log after
// ShipLogSize gave mark, oldest first. A log that is now shorter than
// mark was rotated after the mark. Then all of its rows are new.
func ShipsAfter(path string, mark int64) []Ship {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() < mark {
		mark = 0
	}
	if _, err := f.Seek(mark, io.SeekStart); err != nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, shipTail))
	if err != nil {
		return nil
	}
	return shipRows(raw)
}

// shipRows parses the lines of raw. It skips a line that is not a whole
// row.
func shipRows(raw []byte) []Ship {
	var rows []Ship
	for _, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		var ev Ship
		if json.Unmarshal(line, &ev) == nil && ev.Result != "" {
			rows = append(rows, ev)
		}
	}
	return rows
}
