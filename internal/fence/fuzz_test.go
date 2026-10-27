package fence

import (
	"bufio"
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
)

// FuzzForeignNeverLeaks: for all that the agent puts in the headers, URL or
// body of a request to a non-core host, no live value that we hold can come
// out. fuzzPost frames body as a POST to target, chunked or not.
func fuzzPost(target, host, field, value, body string, chunkedBody bool) string {
	head := "POST " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + field + ": " + value + "\r\n"
	if chunkedBody {
		return head + "Transfer-Encoding: chunked\r\n\r\n" + chunked(body)
	}
	return head + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func FuzzForeignNeverLeaks(f *testing.F) {
	f.Add("/x?q=1", "Bearer tok", "plain body", uint16(3), true)
	f.Add("/oauth/token", "x", `{"a":"`+liveOAT()+`"}`, uint16(7), false)
	f.Add("/o/r.git/git-receive-pack", "Basic eDpsYWJfZmVuY2VfZ2l0aHVi", "0000", uint16(10), true)
	re, pol := testPolicy(f)
	f.Fuzz(func(t *testing.T, target, hdr, body string, where uint16, chunkedBody bool) {
		if target == "" || strings.ContainsAny(target, " \r\n") || strings.ContainsAny(hdr, "\r\n") {
			return
		}
		lives := []string{liveOAT(), "lab_fence_github", "sk-ant-ort01-" + strings.Repeat("B", 64), canaryLive}
		live := lives[int(where)%len(lives)]
		pos := int(where) % (len(body) + 1)
		body = body[:pos] + live + body[pos:]
		if where%5 == 0 {
			hdr += " " + live
		}
		if where%7 == 0 {
			target += live
		}
		raw := fuzzPost(target, "example.com", "X-Fuzz", hdr, body, chunkedBody)
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		_, _, err = DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, canarySlots())
		if urlRefusal(err) {
			// The fence refuses a target that it cannot decode to a stable
			// form, or whose decoded form holds a value that the raw target
			// does not show. A refused request writes nothing to the origin.
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		o := decodedWire(t, req, raw)
		for _, l := range lives {
			if bytes.Contains(o, []byte(l)) {
				t.Fatalf("live value leaked to a foreign host\nraw=%q\nout=%q", raw, o)
			}
		}
	})
}

// urlRefusal reports a refusal that holds only encoded_url_token rows for
// the target. Each other error, and a refusal with any other row, is false.
func urlRefusal(err error) bool {
	var ref *RefusedError
	if !errors.As(err, &ref) || len(ref.Refusals) == 0 {
		return false
	}
	for _, r := range ref.Refusals {
		if r.Cause != CauseEncodedURLToken || r.Where != "url" {
			return false
		}
	}
	return true
}

func FuzzTokenWindows(f *testing.F) {
	f.Add("ghp_" + strings.Repeat("A", 36) + " and sk-" + strings.Repeat("b", 48))
	re, err := LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	if err != nil {
		f.Fatal(err)
	}
	ts := tokensFor(re)
	f.Fuzz(func(t *testing.T, s string) {
		b := []byte(s)
		want := re.FindAllIndex(b, -1)
		got := ts.matches(b)
		if len(got) != len(want) {
			t.Fatalf("%q: %d matches, regexp %d", s, len(got), len(want))
		}
		for i := range got {
			if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
				t.Fatalf("%q: %v vs %v", s, got[i][:2], want[i])
			}
		}
		// The matches of the whole-text regexp, each cut down to the group
		// of its rule. The lead of a bounded rule matches but never strips.
		// ReplaceAllString drops the lead, so it is not the reference.
		var ref []byte
		pos := 0
		for _, m := range re.FindAllSubmatchIndex(b, -1) {
			lo, hi := ts.token(m)
			ref = append(append(ref, b[pos:lo]...), stripRepl...)
			pos = hi
		}
		if ref = append(ref, b[pos:]...); string(ts.replace(b, stripRepl)) != string(ref) {
			t.Fatalf("%q: replace differs", s)
		}
	})
}
