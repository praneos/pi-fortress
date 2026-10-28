package fence

import (
	"bufio"
	"bytes"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"pi-fortress/internal/httpwire"
)

// chunkedBy frames body as chunks of n bytes.
func chunkedBy(body string, n int) string {
	var sb strings.Builder
	for i := 0; i < len(body); i += n {
		j := min(i+n, len(body))
		sb.WriteString(strconv.FormatInt(int64(j-i), 16) + "\r\n" + body[i:j] + "\r\n")
	}
	return sb.String() + "0\r\n\r\n"
}

// streamCost is the time to stream body as a chunked upload in chunks of
// n bytes. With oneByte, each read of the wire also gives one byte, as
// small TCP segments do. The copy fails when it passes limit, so a slow
// case fails fast and does not run for minutes.
func streamCost(t *testing.T, body string, n int, oneByte bool, limit time.Duration) time.Duration {
	t.Helper()
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	var src io.Reader = strings.NewReader("POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunkedBy(body, n))
	if oneByte {
		src = iotest.OneByteReader(src)
	}
	req, err := httpwire.ReadRequest(bufio.NewReaderSize(src, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := DecideStream(*ctx, req, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 32<<10)
	for {
		_, err := req.Body.Read(p)
		if d := time.Since(start); d > limit {
			t.Fatalf("chunk size %d, reads of one byte %v: %v and not done, limit %v", n, oneByte, d, limit)
		}
		if err == io.EOF {
			return time.Since(start)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// fastest is the least of three runs of f.
func fastest(f func() time.Duration) time.Duration {
	d := f()
	for range 2 {
		d = min(d, f())
	}
	return d
}

// The scan cost for each byte does not depend on the size of the chunks or
// of the reads. The body is long token-shaped runs, so the token stream
// holds about one window at most reads. Before, each read gave one chunk,
// and each read ran the regexp again over that window. The limits are
// loose, because the time also has a fixed part for each read, and
// machines differ.
func TestScanCostIndependentOfChunkSize(t *testing.T) {
	unit := "ghp_" + strings.Repeat("a", 3500) + " "
	held := strings.Repeat(unit, 38)[:128<<10]
	plain := strings.Repeat("plain words with no prefix in them, ", 4000)[:128<<10]
	const ratio, slack = 8, 50 * time.Millisecond
	forever := time.Hour

	big := fastest(func() time.Duration { return streamCost(t, held, 16<<10, false, forever) })
	tiny := streamCost(t, held, 1, false, ratio*big+slack)
	t.Logf("chunks of 16 KiB %v, chunks of one byte %v", big, tiny)

	// Reads of one byte have a fixed cost that does not come from the scan.
	// Thus the reference here is a body with nothing to hold, in the same
	// reads.
	base := fastest(func() time.Duration { return streamCost(t, plain, 1, true, forever) })
	slow := streamCost(t, held, 1, true, ratio*base+slack)
	t.Logf("reads of one byte: nothing held %v, a window held %v", base, slow)
}

// A token that comes in chunks of one byte, and in reads of one byte,
// leaves the stream as it leaves the buffered path. The tokens start after
// the first streamHead bytes, so each of them crosses many reads.
func TestStreamTokenInOneByteChunksAndReads(t *testing.T) {
	inner := strings.Repeat("x", streamHead+512) + " " + ghp + " mid " + liveOAT() + " " +
		"AKIA" + strings.Repeat("Q", 16) + " end " + ghp + strings.Repeat("y", 3000)
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	buf := parseReq(t, postReq("example.com", inner))
	if _, _, err := DecideStream(*ctx, buf, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(buf.Body)
	if err != nil {
		t.Fatal(err)
	}
	head := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
	ref := parseReq(t, head+chunked(inner))
	_, refSt, err := DecideStream(*ctx, ref, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(ref.Body); err != nil {
		t.Fatal(err)
	}
	raw := head + chunkedBy(inner, 1)
	for _, oneByte := range []bool{false, true} {
		var src io.Reader = strings.NewReader(raw)
		if oneByte {
			src = iotest.OneByteReader(src)
		}
		req, err := httpwire.ReadRequest(bufio.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		_, st, err := DecideStream(*ctx, req, pol, labSlots())
		if err != nil || st == nil {
			t.Fatalf("body did not stream: %v", err)
		}
		got, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("reads of one byte %v: stream and buffered disagree (%d vs %d bytes)", oneByte, len(got), len(want))
		}
		if bytes.Contains(got, []byte(ghp[:12])) {
			t.Fatalf("reads of one byte %v: a token survived", oneByte)
		}
		if got, want := st.Events(), refSt.Events(); len(want) == 0 || !slices.Equal(got, want) {
			t.Fatalf("reads of one byte %v: strip events %v, in large chunks %v", oneByte, got, want)
		}
	}
}

// readSoon is r.Read, but the test fails if the call does not return
// within a few seconds.
func readSoon(t *testing.T, r io.Reader, p []byte) []byte {
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
		if r.err != nil {
			t.Fatal(r.err)
		}
		return p[:r.n]
	case <-time.After(5 * time.Second):
		t.Fatal("the stream waits for input that has not come")
		return nil
	}
}

// Small writes of a streamed upload leave as soon as the stream can judge
// them. The stream does not wait for more input than the old scan did: a
// read that releases bytes still releases them at once. This includes a
// prefix whose run ends short when the next write comes.
func TestStreamForwardsSmallWritesWithoutMoreInput(t *testing.T) {
	ts := benchTokenSet(t)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	write := func(s string) {
		go func() { _, _ = io.WriteString(pw, strconv.FormatInt(int64(len(s)), 16)+"\r\n"+s+"\r\n") }()
	}
	go func() {
		_, _ = io.WriteString(pw, "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n")
	}()
	req, err := httpwire.ReadRequest(bufio.NewReader(pr))
	if err != nil {
		t.Fatal(err)
	}
	tok := newTokenStream(newPlaceholderGuard(req.Body), ts, false)
	p := make([]byte, 4096)
	margin := ts.maxPrefix - 1

	first := "plain words that hold no token at all, then ghp_ab"
	write(first)
	if got := readSoon(t, tok, p); string(got) != first[:len(first)-margin] {
		t.Fatalf("first write: got %q", got)
	}
	// The run after the prefix ends short. Thus it is not a token, and all
	// but the last margin bytes can leave.
	second := " and then more plain words, so the run above ended short"
	write(second)
	all := first + second
	if got := readSoon(t, tok, p); string(got) != all[len(first)-margin:len(all)-margin] {
		t.Fatalf("second write: got %q", got)
	}
}
