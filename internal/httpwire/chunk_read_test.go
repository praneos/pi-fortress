package httpwire

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// One Read gives the data of all the chunks that are in the buffer, up to
// the size of p. Before, it gave one chunk. Thus a body in chunks of one
// byte cost one call for each byte in each filter above the reader.
func TestChunkedReadTakesAllBufferedChunks(t *testing.T) {
	wire := strings.Repeat("1\r\na\r\n", 1000) + "0\r\n\r\n"
	cr := newChunkedReader(bufio.NewReaderSize(strings.NewReader(wire), 64<<10))
	p := make([]byte, 4096)
	n, err := cr.Read(p)
	if err != nil || n != 1000 {
		t.Fatalf("first read: %d bytes, %v; want all 1000 chunks", n, err)
	}
	if n, err := cr.Read(p); n != 0 || err != io.EOF {
		t.Fatalf("second read: %d, %v; want EOF", n, err)
	}

	// p sets the limit, and the next call continues inside the same chunk.
	cr = newChunkedReader(bufio.NewReader(strings.NewReader("3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")))
	var got []byte
	for {
		n, err := cr.Read(p[:5])
		got = append(got, p[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 || n > 5 {
			t.Fatalf("read %d, %v", n, err)
		}
	}
	if string(got) != "abcdefg" {
		t.Fatalf("got %q", got)
	}
}

// A framing error after good data comes in the call after that data, as
// when each call read one chunk. The data goes out first.
func TestChunkedReadErrorAfterData(t *testing.T) {
	for _, c := range []struct {
		name, wire string
		err        error
	}{
		{"bad size", "2\r\nok\r\nzz\r\n", ErrBadRequest},
		{"no CRLF after the data", "2\r\nokX\r\n1\r\na\r\n0\r\n\r\n", ErrBadRequest},
		{"long size line", "2\r\nok\r\n1;" + strings.Repeat("x", maxChunkLine) + "\r\na\r\n", ErrHeaderLimit},
		{"bad trailer", "2\r\nok\r\n0\r\nno colon\r\n\r\n", ErrBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			cr := newChunkedReader(bufio.NewReaderSize(strings.NewReader(c.wire), 64<<10))
			p := make([]byte, 64)
			n, err := cr.Read(p)
			if err != nil || string(p[:n]) != "ok" {
				t.Fatalf("first read: %q, %v", p[:n], err)
			}
			if n, err := cr.Read(p); n != 0 || !errors.Is(err, c.err) {
				t.Fatalf("second read: %d, %v; want %v", n, err, c.err)
			}
			if _, err := cr.Read(p); !errors.Is(err, c.err) {
				t.Fatalf("third read: %v; the error must stay", err)
			}
		})
	}
}

// readWithin is r.Read, but the test fails if the call does not return
// within d.
func readWithin(t *testing.T, r io.Reader, p []byte, d time.Duration) (int, error) {
	t.Helper()
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := r.Read(p)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(d):
		t.Fatal("Read waits for input that has not come")
		return 0, nil
	}
}

// A Read that has data never waits for more input: not for the size line
// of the next chunk, not for its data, and not for the trailers after the
// last chunk. A stream of small chunks, as in server-sent events, must
// pass immediately.
func TestChunkedReadDoesNotWaitForMoreInput(t *testing.T) {
	for _, c := range []struct{ name, first, rest string }{
		{"chunk only", "5\r\nhello\r\n", "3\r\nabc\r\n0\r\n\r\n"},
		{"part of the next size line", "5\r\nhello\r\n3", "\r\nabc\r\n0\r\n\r\n"},
		{"next size line without data", "5\r\nhello\r\n3\r\n", "abc\r\n0\r\n\r\n"},
		{"last chunk without trailers", "5\r\nhello\r\n0\r\n", "\r\n"},
		{"no CRLF after the data yet", "5\r\nhello", "\r\n0\r\n\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pw.Close() })
			go func() { _, _ = io.WriteString(pw, c.first) }()
			cr := newChunkedReader(bufio.NewReader(pr))
			p := make([]byte, 64)
			n, err := readWithin(t, cr, p, 5*time.Second)
			if err != nil || string(p[:n]) != "hello" {
				t.Fatalf("first read: %q, %v", p[:n], err)
			}
			go func() { _, _ = io.WriteString(pw, c.rest) }()
			got, err := io.ReadAll(cr)
			if err != nil || (string(got) != "abc" && string(got) != "") {
				t.Fatalf("rest: %q, %v", got, err)
			}
		})
	}
}

// The response side: a scrubbed chunked stream gives a small event to the
// client before the origin sends more.
func TestScrubbedResponseDoesNotWaitForMoreInput(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	go func() {
		_, _ = io.WriteString(pw, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\na\r\ndata: hi\n\n\r\n")
	}()
	resp, err := ReadResponseHead(bufio.NewReader(pr), false)
	if err != nil {
		t.Fatal(err)
	}
	sc := NewScrubber(resp.Stream, [][2][]byte{{[]byte("live-secret-value"), []byte("redacted-value-xx")}})
	p := make([]byte, 1024)
	n, err := readWithin(t, sc, p, 5*time.Second)
	if err != nil || string(p[:n]) != "data: hi\n\n" {
		t.Fatalf("first event: %q, %v", p[:n], err)
	}
}
