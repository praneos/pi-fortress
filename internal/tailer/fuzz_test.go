package tailer

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// FuzzReadLine: readLine gives each complete line that fits the buffer
// with its newline, drops a longer one, and counts each byte that it reads
// once. Text after the last newline comes back as io.EOF with its count.
// A 16-byte buffer (the bufio minimum) stands in for maxLine.
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("{\"a\":1}\n{\"b\":2}\n"))
	f.Add([]byte("0123456789abcdef\nshort\n0123456789abcdefg\ntorn"))
	f.Add([]byte("\n\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		const size = 16
		r := bufio.NewReaderSize(bytes.NewReader(data), size)
		rest := data
		var total int64
		for {
			line, n, dropped, err := readLine(r)
			total += n
			i := bytes.IndexByte(rest, '\n')
			if err != nil {
				if err != io.EOF || i >= 0 || n != int64(len(rest)) || line != "" {
					t.Fatalf("end: err %v, n %d, %d bytes left, newline at %d", err, n, len(rest), i)
				}
				break
			}
			seg := rest[:i+1]
			rest = rest[i+1:]
			if n != int64(len(seg)) {
				t.Fatalf("line of %d bytes counted %d", len(seg), n)
			}
			if dropped != (len(seg) > size) {
				t.Fatalf("line of %d bytes: dropped %v", len(seg), dropped)
			}
			if !dropped && line != string(seg) {
				t.Fatalf("line %q, want %q", line, seg)
			}
			if dropped && line != "" {
				t.Fatalf("dropped line kept %q", line)
			}
		}
		if total != int64(len(data)) {
			t.Fatalf("counted %d of %d bytes", total, len(data))
		}
	})
}
