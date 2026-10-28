package doh

import (
	"bufio"
	"fmt"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
)

// FuzzHTTPFields: an agent writes the target and the headers. A spelling
// that an origin server reads the same must not change a DoH verdict to
// "not DoH". The test fails if HTTPFields panics, or if one of these
// changes the verdict:
//
//   - ASCII case of the path, of Content-Type or of Accept;
//   - the order of the query parameters, or a repeat of all of them;
//   - one Accept field split into one field per media range;
//   - the absolute form of the same target.
//
// It also fails if a DoH target stops being DoH when the agent
// percent-encodes it one more time. That check applies only when the
// decodings of the target reach their fixed point inside the rounds that
// decodings tries. A target that is encoded deeper is a known limit.
//
// These checks apply only to a target that httpwire accepts, because the
// broker refuses all other targets before it classifies them.
func FuzzHTTPFields(f *testing.F) {
	const wire = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	for _, s := range [][4]string{
		{"/dns-query", "dns=" + wire, "", ""},
		{"/resolve", "name=example.com&type=A", "", ""},
		{"/dns-json", "%6Eame=x", "", ""},
		{"/dns-quer%79", "", "", ""},
		{"/dns-quer%2579", "", "", ""},
		{"/dns-query;v=1/.", "", "", ""},
		{"/a/b/../dns-query/", "", "", ""},
		{"/q", "x=1;dns=" + wire, "", ""},
		{"/upload", "name=file.txt", "multipart/form-data; boundary=x", "*/*"},
		{"/foo", "", "Application/DNS-Message", ""},
		{"/foo", "", "", "text/html, application/dns-json;q=0.9"},
		{"/foo", "", "", "application/dns-message-summary"},
		{"", "", "", ""},
	} {
		f.Add(s[0], s[1], s[2], s[3], []byte{0x55})
	}
	// Mask 0x10 encodes byte 4: the "/" that ends the empty authority.
	f.Add("a:///dns-query", "", "", "", []byte{0x10})
	f.Fuzz(func(t *testing.T, p, q, ct, acc string, mask []byte) {
		// The path has no query or fragment delimiter, and the query has
		// no fragment. Thus each part below stays the same part.
		p = strings.Map(func(r rune) rune {
			if r == '?' || r == '#' {
				return -1
			}
			return r
		}, p)
		q = strings.ReplaceAll(q, "#", "")
		target := func(p, q string) string {
			if q == "" {
				return p
			}
			return p + "?" + q
		}
		got := HTTPFields(target(p, q), []string{ct}, []string{acc})
		// The broker calls HTTPFields only with a target that
		// httpwire.ReadRequest accepted. The checks below apply to such a
		// target. Others, as "?a://b/dns-query" or "0://b/dns-query", get a
		// 400 before the classifier, and no origin server sees them. The call
		// above still tests them for a panic.
		if !forwarded(target(p, q)) {
			return
		}
		same := func(what, p2, q2 string, ct2, acc2 []string) {
			t.Helper()
			if g := HTTPFields(target(p2, q2), ct2, acc2); g != got {
				t.Fatalf("%s: %v, was %v\n  target %q ct %q accept %q\n  then   %q ct %q accept %q",
					what, g, got, target(p, q), ct, acc, target(p2, q2), ct2, acc2)
			}
		}

		same("path case", flipCase(p), q, []string{ct}, []string{acc})
		same("header case", p, q, []string{flipCase(ct)}, []string{strings.ToLower(acc)})
		same("header case", p, q, []string{strings.ToLower(ct)}, []string{flipCase(acc)})
		same("accept fields", p, q, []string{ct}, strings.Split(acc, ","))
		same("content-type fields", p, q, strings.Split(ct, ","), []string{acc})

		parts := strings.Split(q, "&")
		slices.Reverse(parts)
		same("reordered query", p, strings.Join(parts, "&"), []string{ct}, []string{acc})
		if q != "" {
			same("repeated query", p, q+"&"+q, []string{ct}, []string{acc})
		}
		if strings.HasPrefix(p, "/") {
			same("absolute form", "https://dns.example"+p, q, []string{ct}, []string{acc})
		}

		// One more round of percent-encoding. Each "%" is encoded, so one
		// decoding gives back exactly p and q.
		if !got || len(decodings(p)) > 3 || len(decodings(q)) > 3 {
			return
		}
		// An origin server splits an absolute-form target into its scheme,
		// authority and path on the raw bytes. An encoded delimiter is data
		// (RFC 3986 section 2.2). Thus a "/" after "://" that is encoded moves
		// the path into the authority, and the origin server routes on "/".
		// That target is not DoH to any origin server. The scheme, the
		// authority and the "/" after it stay as they are. Each byte after
		// them gets the extra encoding.
		k := authorityEnd(p)
		ep, eq := p[:k]+encode(p[k:], mask), encode(q, mask[min(len(mask), 1):])
		if HTTPFields(target(ep, eq), []string{ct}, []string{acc}) != true {
			t.Fatalf("encoded again, DoH is not seen:\n  target %q\n  then   %q", target(p, q), target(ep, eq))
		}
	})
}

// forwarded reports whether httpwire.ReadRequest accepts target in a
// request line, as the broker does before it calls HTTPFields.
func forwarded(target string) bool {
	raw := "GET " + target + " HTTP/1.1\r\nHost: a\r\n\r\n"
	_, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	return err == nil
}

// authorityEnd is the offset after the scheme, the authority and the "/"
// that ends the authority of an absolute-form target, as originForm reads
// it. It is 0 for a target in origin-form.
func authorityEnd(p string) int {
	i := strings.Index(p, "://")
	if i < 0 || strings.IndexByte(p[:i], '/') >= 0 {
		return 0
	}
	if j := strings.IndexByte(p[i+3:], '/'); j >= 0 {
		return i + 3 + j + 1
	}
	return len(p)
}

// flipCase swaps the case of each ASCII letter and of nothing else.
func flipCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
			b[i] = c ^ 0x20
		}
	}
	return string(b)
}

// encode percent-encodes each "%" in s, and each byte i where bit i%8 of
// mask[i/8%len(mask)] is set.
func encode(s string, mask []byte) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || len(mask) > 0 && mask[i/8%len(mask)]>>(i%8)&1 == 1 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
