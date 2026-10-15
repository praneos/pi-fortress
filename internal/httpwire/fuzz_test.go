package httpwire

import (
	"bufio"
	"bytes"
	"io"
	"math/rand"
	"strings"
	"testing"
)

// naiveReplace is the contract, one position at a time. The longest
// pattern at the leftmost position wins. It also covers a pattern that
// starts inside the replaced bytes and runs past them. Its replacement
// is cut to its tail when it is length-preserving.
func naiveReplace(src []byte, pairs [][2][]byte) []byte {
	longestAt := func(s, past int) (int, int) {
		bi, be := -1, past
		for i, p := range pairs {
			if e := s + len(p[0]); len(p[0]) > 0 && e > be && bytes.HasPrefix(src[s:], p[0]) {
				bi, be = i, e
			}
		}
		return bi, be
	}
	var out []byte
	for i := 0; i < len(src); {
		bi, end := longestAt(i, i)
		if bi < 0 {
			out = append(out, src[i])
			i++
			continue
		}
		out = append(out, pairs[bi][1]...)
		for s := i + 1; s < end; s++ {
			if j, e := longestAt(s, end); j >= 0 {
				r := pairs[j][1]
				if len(r) == len(pairs[j][0]) {
					r = r[len(r)-(e-end):]
				}
				out = append(out, r...)
				end = e
			}
		}
		i = end
	}
	return out
}

func pairsFrom(a, b, c string) [][2][]byte {
	return [][2][]byte{{[]byte(a), []byte("<A>")}, {[]byte(b), []byte("")}, {[]byte(c), []byte("<CCCCCCCC>")}}
}

func FuzzReplaceAll(f *testing.F) {
	f.Add("abcd bcd cd abcabc", "abc", "bcd", "cd")
	f.Add("ssss sk-ant sk-ant-oat", "sk-ant-oat", "sk", "s")
	f.Fuzz(func(t *testing.T, src, a, b, c string) {
		pairs := pairsFrom(a, b, c)
		got := ReplaceAll(nil, []byte(src), pairs, nil)
		want := naiveReplace([]byte(src), pairs)
		if !bytes.Equal(got, want) {
			t.Fatalf("ReplaceAll(%q, %q %q %q) = %q, want %q", src, a, b, c, got, want)
		}
	})
}

func FuzzIndex(f *testing.F) {
	f.Add("hello world", "o w")
	f.Add("sssssk-ant-oat01-AAAA", "sk-ant-oat01-AAAA")
	f.Fuzz(func(t *testing.T, src, needle string) {
		if got, want := Index([]byte(src), []byte(needle)), bytes.Index([]byte(src), []byte(needle)); got != want {
			t.Fatalf("Index(%q, %q) = %d, want %d", src, needle, got, want)
		}
	})
}

func FuzzScrubber(f *testing.F) {
	f.Add("abc SECRET abc SECRET", "SECRET", "abc", int64(1))
	f.Fuzz(func(t *testing.T, src, a, b string, seed int64) {
		if a == "" && b == "" {
			return
		}
		pairs := [][2][]byte{{[]byte(a), []byte("[a]")}, {[]byte(b), []byte("")}}
		want := ReplaceAll(nil, []byte(src), pairs, nil)
		rnd := rand.New(rand.NewSource(seed))
		sc := NewScrubber(&randReader{r: bytes.NewReader([]byte(src)), rnd: rnd}, pairs)
		got, err := io.ReadAll(sc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("scrubber %q, want %q", got, want)
		}
	})
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"))
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			return
		}
		req.SetBody(body)
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		again, err := ReadRequest(bufio.NewReader(&out))
		if err != nil {
			t.Fatalf("re-read of own output failed: %v\n%q", err, out.Bytes())
		}
		if again.Method != req.Method || again.Target != req.Target || len(again.Fields) != len(req.Fields) {
			t.Fatalf("round trip changed request: %+v vs %+v", again, req)
		}
		b2, _ := io.ReadAll(again.Body)
		if !bytes.Equal(b2, body) {
			t.Fatalf("round trip changed body %q -> %q", body, b2)
		}
	})
}

func FuzzReadResponseHead(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	f.Add([]byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		resp, err := ReadResponseHead(bufio.NewReader(bytes.NewReader(raw)), false)
		if err != nil {
			return
		}
		if err := resp.Buffer(1 << 20); err != nil {
			return
		}
		var out bytes.Buffer
		if _, err := resp.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		again, err := ReadResponseHead(bufio.NewReader(&out), false)
		if err != nil {
			t.Fatalf("re-read failed: %v\n%q", err, out.Bytes())
		}
		if again.Code != resp.Code {
			t.Fatalf("code %d -> %d", resp.Code, again.Code)
		}
	})
}

func FuzzChunkedRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		var wire bytes.Buffer
		cw := NewChunkedWriter(&wire)
		n := int(size) + 1
		for i := 0; i < len(data); i += n {
			end := min(i+n, len(data))
			if _, err := cw.Write(data[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := cw.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(newChunkedReader(bufio.NewReader(&wire)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("chunked round trip %q -> %q", data, got)
		}
	})
}

func FuzzChunkedReaderGarbage(f *testing.F) {
	f.Add([]byte("3\r\nabc\r\n0\r\n\r\n"))
	f.Add([]byte("3;ext=1\r\nabc\r\n0\r\nTrailer: x\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = io.ReadAll(io.LimitReader(newChunkedReader(bufio.NewReader(bytes.NewReader(raw))), 1<<20))
	})
}

var _ = strings.Repeat
