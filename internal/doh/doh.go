// Package doh identifies a DNS-over-HTTPS request from its path, its query
// and its content types, so the broker can refuse it. internal/broker calls
// it.
//
// The agent writes the request line, and the fence forwards it with no
// change. Thus the question is never "is this the canonical spelling of
// /dns-query". The question is "can the origin server read this as DoH".
// The two readings are different where the origin server normalises and
// the classifier does not:
//   - /dns-quer%79 and /dns-query are the same resource to each server that
//     decodes its target.
//   - /dns-query;v=1 is the same to a servlet container that strips path
//     parameters.
//   - %6Eame is the same query key to all code that decodes before it looks
//     up the key.
//
// A miss here is a resolver that the fence never sees. Thus the code
// normalises the target as an origin server would, before it compares it.
//
// The normalisation is intentionally wide. The code tests the raw target
// and each percent-decoding of it up to a fixed point. Some origin servers
// decode one time, and some origin servers (and proxy chains) decode again.
// A match that is too wide costs one refused request. The agent can see it
// and try again with an honest target. A match that is too narrow costs
// the full DNS pin.
package doh

import (
	"encoding/base64"
	"path"
	"strings"

	"pi-fortress/internal/pctdecode"
)

// The RFC 8484 wire-format type, the two JSON spellings that Google and
// Cloudflare answer to, and the pre-RFC draft name that resolvers still
// accept for old clients.
var types = []string{
	"application/dns-message",
	"application/dns-json",
	"application/dns+json",
	"application/dns-udpwireformat",
}

// HTTP classifies a request with a Content-Type and an Accept that each
// arrived as one field. Call HTTPFields when the full field list is
// available. This function stays for callers that hold only one of
// each.
func HTTP(target, contentType, accept string) bool {
	return HTTPFields(target, []string{contentType}, []string{accept})
}

// HTTPFields classifies a request from its target and each Content-Type
// and Accept field in it.
//
// The two headers have list values. A client can send a list as one
// comma-separated field or as more than one repeated field. A proxy can
// change one form into the other. A classifier that took one string each
// could get only the first field. Thus a DNS media type in a second
// Accept line was a resolver that the fence never saw.
func HTTPFields(target string, contentType, accept []string) bool {
	if dohMedia(contentType, accept) {
		return true
	}
	t := target
	// The origin server does not route on a fragment, and a request target
	// must not have one. Thus the code cuts it. It does not let it hide
	// the end of the path.
	if i := strings.IndexByte(t, '#'); i >= 0 {
		t = t[:i]
	}
	t = originForm(t)
	// The code finds the query delimiter before it decodes. An origin server
	// also splits the raw target. Thus %3F is a path byte to it, and must
	// stay a path byte here.
	rawPath, rawQuery, _ := strings.Cut(t, "?")
	paths, queries := decodings(rawPath), decodings(rawQuery)

	resolver := false
	for _, p := range paths {
		p = cleanPath(p)
		if p == "/dns-query" || strings.HasSuffix(p, "/dns-query") {
			return true
		}
		resolver = resolver || strings.HasSuffix(p, "/resolve") || strings.HasSuffix(p, "/dns-json")
	}
	for _, q := range queries {
		for _, kv := range params(q) {
			k, v := kv[0], kv[1]
			// The JSON resolvers get the name in a "name" parameter, but
			// only on their own paths. A match on the key on all paths
			// would refuse each upload that names a file.
			if resolver && k == "name" && v != "" {
				return true
			}
			// RFC 8484 lets a resolver publish any URI template. Thus the
			// path tells nothing about a GET. The parameter shows it: a
			// "dns" parameter with a value that decodes to a DNS query is
			// a resolver call, on all paths.
			if k == "dns" && isDNSQuery(v) {
				return true
			}
		}
	}
	return false
}

// dohMedia reports if one of the media types named in these fields is a
// DNS media type.
//
// Before, the code searched Accept as a substring. A media type is not a
// substring. Thus a longer token that contained a listed type
// ("application/dns-message-summary", "x-application/dns-json") was read
// as a resolver call, and the agent got a 403 for an ordinary upload. The
// listed types are full tokens. Thus the code compares full tokens, one
// media range at a time, with its parameters removed.
func dohMedia(contentType, accept []string) bool {
	for _, fields := range [][]string{contentType, accept} {
		for _, f := range fields {
			for _, r := range strings.Split(f, ",") {
				m, _, _ := strings.Cut(r, ";")
				m = strings.ToLower(strings.TrimSpace(m))
				for _, t := range types {
					if t == m {
						return true
					}
				}
			}
		}
	}
	return false
}

// originForm removes the scheme and authority of an absolute-form target.
// A proxy request can be "GET https://dns.google/dns-query". The origin
// server routes on the path after the authority.
func originForm(t string) string {
	i := strings.Index(t, "://")
	if i < 0 || strings.IndexByte(t[:i], '/') >= 0 {
		return t
	}
	rest := t[i+3:]
	j := strings.IndexAny(rest, "/?")
	switch {
	case j < 0:
		return "/"
	case rest[j] == '?':
		return "/" + rest[j:]
	default:
		return rest[j:]
	}
}

// cleanPath is the path in the form that the code compares:
//   - Path parameters removed from each segment, as Servlet-style
//     containers remove them.
//   - Dot segments resolved.
//   - No trailing slash, so "/dns-query/" and "/dns-query" are the same.
//   - Lowercase.
//
// The lowercase does not mean that origin servers route without case.
// They do not: a path is case-sensitive, but the scheme and the host are
// not. /DNS-Query is a different resource to nginx, to Go and to all
// servers on a case-sensitive filesystem. The lowercase is here for the
// same reason as all other code in this file. The classifier answers "can
// the origin server read this as DoH". Some origin servers (IIS, a CDN
// route that ignores case, a case-insensitive filesystem) do serve
// /DNS-Query from /dns-query. A case-sensitive comparison would be more
// correct for the average origin server. But it would cost the DNS pin on
// the others. This package must not have that failure. A miss is a
// resolver that the fence never sees. A false match is one 403 that the
// agent can see and try again. TestCaseVariedPathIsStillDoH pins this
// trade-off.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		p = strings.Join(segs, "/")
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return strings.TrimRight(strings.ToLower(path.Clean(p)), "/")
}

// params splits one query string into key and value pairs, as a server
// does. It accepts "&" and the older ";" as separators. The software of
// the origin server reads the target that the agent writes. No one
// canonical parser reads it. A repeated key keeps all values. Some origin
// servers read the first value and some read the last. Thus each value is
// one that the origin server can use.
func params(q string) [][2]string {
	var out [][2]string
	for _, kv := range strings.FieldsFunc(q, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(kv, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		// Trim it like the key. An origin server that trims the two
		// reads "dns=%20<query>" as the query.
		if k != "" {
			out = append(out, [2]string{k, strings.TrimSpace(v)})
		}
	}
	return out
}

// isDNSQuery reports if v is the base64url of a possible DNS query: a
// header that asks and does not answer, exactly one question, no answer
// records, and a name that parses inside the message. The check is this
// strict so that an ordinary parameter with the name "dns" and the value
// of a word, an identifier or a hostname is not read as a resolver call.
func isDNSQuery(v string) bool {
	if len(v) < 16 || len(v) > 4096 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil || len(b) < 17 {
		return false
	}
	flags := b[2]
	qd := int(b[4])<<8 | int(b[5])
	an := int(b[6])<<8 | int(b[7])
	if flags&0x80 != 0 || flags>>3&0x0f != 0 || qd != 1 || an != 0 {
		return false
	}
	i := 12
	for b[i] != 0 {
		n := int(b[i])
		// A length byte with its top bits set is a compression pointer.
		// It must not be in the one question of a new query.
		if n > 63 {
			return false
		}
		i += n + 1
		if i >= len(b) {
			return false
		}
	}
	// The question ends with its type and class.
	return i+5 <= len(b)
}

// decodings is the raw string and then each percent-decoding of it up to
// a fixed point. This code does not decide how many rounds the origin
// server does. It gives each possible round to the comparison.
func decodings(s string) []string {
	out := []string{s}
	for range 3 {
		d := pctdecode.Once(s)
		if d == s {
			break
		}
		out = append(out, d)
		s = d
	}
	return out
}
