package doh

import "testing"

// The agent writes the request line. Thus the question is never if the
// target is canonical, but if an origin server can read it as DoH. An
// origin server resolves each target here to /dns-query or to a JSON
// resolver call. The classifier compares the bytes that it got. Thus, before
// the normalisation was added, each target got to the origin with no change.
func TestHTTPTargetNormalisation(t *testing.T) {
	// The RFC 8484 §4.1.1 example query for www.example.com A.
	const wire = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

	cases := []struct {
		name          string
		path, ct, acc string
		want          bool
	}{
		// Canonical targets, then the non-canonical ones.
		{"plain path", "/resolver/dns-query?dns=AA", "", "", true},
		{"wire media type", "/foo", "application/dns-message", "", true},
		{"resolve with name", "/resolve?name=example.com&type=A", "", "", true},
		{"dns-json with name", "/dns-json?name=x", "", "", true},
		{"percent encoded letter", "/dns-quer%79", "", "", true},
		{"percent encoded hyphen", "/dns%2Dquery", "", "", true},
		{"percent encoded separator", "/resolver%2Fdns-query?dns=AA", "", "", true},
		{"double encoded letter", "/dns-quer%2579", "", "", true},
		{"dot segment", "/dns-query/.", "", "", true},
		{"parent segment", "/a/b/../dns-query", "", "", true},
		{"path parameter", "/dns-query;v=1", "", "", true},
		{"fragment", "/dns-query#x", "", "", true},
		{"uppercase escape", "/DNS-QUER%79", "", "", true},
		{"absolute form encoded", "https://dns.google/dns-quer%79", "", "", true},
		{"absolute form resolve", "https://dns.google/resolve?name=example.com", "", "", true},
		{"encoded query key", "/resolve?%6Eame=example.com", "", "", true},
		{"encoded query key json", "/dns-json?%6eAME=example.com", "", "", true},
		{"draft media type", "/foo", "application/dns-udpwireformat", "", true},
		{"draft media type accept", "/foo", "", "application/dns-udpwireformat", true},
		{"wireformat get off path", "/q?dns=" + wire, "", "", true},
		{"wireformat get absolute", "https://doh.example/q?dns=" + wire, "", "", true},
		{"wireformat get padded with spaces", "/q?dns=%20" + wire + "%20", "", "", true},
		{"wireformat get before a repeated key", "/q?dns=" + wire + "&dns=x", "", "", true},
		{"resolve name before an empty repeat", "/resolve?name=example.com&name=", "", "", true},

		// Ordinary traffic that the fence must continue to forward. The
		// last two show the cost of a bare "name=" substring match. A
		// filename parameter is not a resolver call. A "dns" parameter
		// with a value that is not a DNS query is also not one.
		{"plain api", "/v1/messages", "application/json", "", false},
		{"git refs", "/repos/x/y/git/refs?service=git-upload-pack", "", "", false},
		{"resolve without name", "/resolve", "", "", false},
		{"resolve with filename", "/api/resolve?filename=cat.png", "", "", false},
		{"dns parameter not a query", "/download?dns=readme", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HTTP(c.path, c.ct, c.acc); got != c.want {
				t.Errorf("HTTP(%q, %q, %q) = %v, want %v", c.path, c.ct, c.acc, got, c.want)
			}
		})
	}
}

// Before, the code searched Accept as a substring. Thus a media type
// that contains a listed one (a longer token, a vendor suffix) was
// read as a DoH request, and the agent got a 403 for an ordinary
// upload. The listed types are tokens, so the code compares tokens.
func TestAcceptIsMatchedAsATokenNotASubstring(t *testing.T) {
	if HTTP("/upload", "application/octet-stream", "application/dns-message-summary") {
		t.Error("a longer media type containing a listed one was classified as DoH")
	}
	if HTTP("/upload", "application/octet-stream", "x-application/dns-json") {
		t.Error("a media type with a listed one as its suffix was classified as DoH")
	}
	// And the listed types still match, in all positions in the list
	// and with all parameters.
	if !HTTP("/upload", "", "text/html;q=0.9, Application/DNS-Message ;q=1") {
		t.Error("a genuine wire-format Accept was missed")
	}
}

// Accept and Content-Type have list values, and a client can send
// them as repeated fields. A classifier that takes one string each can
// get only the first. Thus a DNS media type in a later field is a
// resolver that the fence never sees.
func TestARepeatedFieldIsStillSeen(t *testing.T) {
	if !HTTPFields("/upload", nil, []string{"text/html", "application/dns-message"}) {
		t.Error("a DNS media type in a second Accept field was missed")
	}
	if !HTTPFields("/upload", []string{"text/plain", "application/dns-message"}, nil) {
		t.Error("a DNS media type in a second Content-Type field was missed")
	}
}

// A path that is only a path parameter is empty after the parameter is
// removed. The classifier reads it as "/", as it reads an empty path.
func TestAPathOfOnlyAParameterIsTheRoot(t *testing.T) {
	for _, target := range []string{";", ";v=1", ";?x=1", ";%3B"} {
		if HTTPFields(target, nil, nil) {
			t.Errorf("%q: read as DoH", target)
		}
	}
	if got := cleanPath(";"); got != cleanPath("/") {
		t.Errorf(`cleanPath(";") = %q, want %q`, got, cleanPath("/"))
	}
}
