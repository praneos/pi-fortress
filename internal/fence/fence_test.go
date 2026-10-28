package fence

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/testsupport"
	"pi-fortress/internal/tokenrules"
)

func loadPol(t *testing.T) *corepolicy.Policy {
	t.Helper()
	p, err := corepolicy.Load(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func labSlots() map[string]secrets.Slot {
	a := "a1b2c3d4e5f67890"
	b := "b0b1b2b3b4b5b6b7"
	c := "c0c1c2c3c4c5c6c7"
	oatA := "sk-ant-oat01-" + strings.Repeat("A", 64)
	gh := "lab_fence_github"
	oatB := "sk-ant-oat01-" + strings.Repeat("C", 64)
	return map[string]secrets.Slot{
		secrets.EnvKey(a, "GITHUB_TOKEN"): {ID: a, Kind: "GITHUB_TOKEN", Dummy: secrets.Placeholder(a, "GITHUB_TOKEN"), Live: gh},
		secrets.EnvKey(b, "CLAUDE_OAT"):   {ID: b, Kind: "CLAUDE_OAT", Dummy: secrets.Placeholder(b, "CLAUDE_OAT"), Live: oatA},
		secrets.EnvKey(b, "CLAUDE_ORT"):   {ID: b, Kind: "CLAUDE_ORT", Dummy: secrets.Placeholder(b, "CLAUDE_ORT"), Live: "sk-ant-ort01-" + strings.Repeat("B", 64)},
		secrets.EnvKey(c, "CLAUDE_OAT"):   {ID: c, Kind: "CLAUDE_OAT", Dummy: secrets.Placeholder(c, "CLAUDE_OAT"), Live: oatB},
	}
}

func parseReq(t *testing.T, raw string) *httpwire.Request {
	t.Helper()
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func decide(t *testing.T, sni, raw string) *httpwire.Request {
	t.Helper()
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	req := parseReq(t, raw)
	_, err = Decide(Ctx{SNI: sni, TokenRE: re}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestBodylessRequestGainsNoContentLength(t *testing.T) {
	for _, c := range []struct{ sni, raw, want string }{
		{"example.com", "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n", ""},
		{"pf-core-echo.test", "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n", ""},
		{"example.com", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n", "0"},
		{"example.com", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nhi", "2"},
	} {
		req := decide(t, c.sni, c.raw)
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		got := req.Get("Content-Length")
		if got != c.want || strings.Count(out.String(), "Content-Length") != len(c.want) {
			t.Fatalf("%s: Content-Length %q, want %q:\n%q", c.raw, got, c.want, out.String())
		}
	}
}

func TestEchoInjectsSlotAOnly(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
	req := decide(t, "pf-core-echo.test", raw)
	auth := req.Get("Authorization")
	if !strings.Contains(auth, strings.Repeat("A", 8)) || strings.Contains(auth, strings.Repeat("C", 8)) {
		t.Fatal(auth)
	}
}

// A placeholder aimed at a host with no authority for its kind went to the
// origin without a change before. This gave the destination the slot ID
// and the kind, and let the 401 of the origin say what the fence would
// not say. Now the fence refuses it.
func TestOpenRefusesDummy(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "pf-open-echo.test", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseKindNotAllowed || rs[0].Slot != "a1b2c3d4e5f67890" || rs[0].Kind != "GITHUB_TOKEN" || rs[0].Where != "header" {
		t.Fatalf("%+v", rs)
	}
}

// The fence refuses a slot past its deadline exactly like a disabled slot:
// the same single response, and its own cause in the strip log.
func TestExpiredSlotRefusedLikeDisabled(t *testing.T) {
	slots := labSlots()
	key := secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	sl := slots[key]
	sl.Expired, sl.Live = true, ""
	slots[key] = sl
	raw := "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), slots)
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseSlotExpired || rs[0].Slot != "b0b1b2b3b4b5b6b7" || rs[0].Kind != "CLAUDE_OAT" {
		t.Fatalf("%+v", rs)
	}
	if !strings.Contains(req.Get("Authorization"), "pf_") {
		t.Fatalf("rewritten: %s", req.Get("Authorization"))
	}
}

func mustRE(t *testing.T) *regexp.Regexp {
	t.Helper()
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	return re
}

func refusalsOf(t *testing.T, err error) []Refusal {
	t.Helper()
	var ref *RefusedError
	if !errors.As(err, &ref) {
		t.Fatalf("want a refusal, got %v", err)
	}
	return ref.Refusals
}

func TestOpenStripsLiveOAT(t *testing.T) {
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer " + oat + "\r\n\r\n"
	req := decide(t, "example.com", raw)
	if strings.Contains(req.Get("Authorization"), oat) {
		t.Fatal("live oat not stripped")
	}
	if !strings.Contains(req.Get("Authorization"), StripRepl) {
		t.Fatal(req.Get("Authorization"))
	}
}

func TestBodyStripGhp(t *testing.T) {
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	tok := "ghp_" + strings.Repeat("A", 36)
	body := `{"token":"` + tok + `"}`
	raw := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	req := parseReq(t, raw)
	ev, err := Decide(Ctx{SNI: "example.com", TokenRE: re}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(req.Body)
	if strings.Contains(string(got), tok) {
		t.Fatal(string(got))
	}
	found := false
	for _, e := range ev {
		if e.Where == "body" && e.Rule == "github_classic" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v body=%s", ev, got)
	}
}

func TestStripEventsGithubClassic(t *testing.T) {
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer ghp_" + strings.Repeat("A", 36) + "\r\n\r\n"
	req := parseReq(t, raw)
	ev, err := Decide(Ctx{SNI: "example.com", TokenRE: re}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range ev {
		if e.Where == "header" && e.Rule == "github_classic" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", ev)
	}
}

func TestKindIsolationSameBlob(t *testing.T) {
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	gh := "lab_fence_github"
	dummyOat := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	dummyGH := secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN")
	rawFor := func(host, auth string) string {
		return "GET / HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: " + auth + "\r\n\r\n"
	}

	// Each core host substitutes the kind it owns and nothing else.
	for _, tc := range []struct{ sni, dummy, want, notWant string }{
		{"api.anthropic.com", dummyOat, oat, gh},
		{"github.com", dummyGH, gh, oat},
	} {
		out := decideAuth(t, tc.sni, rawFor(tc.sni, "Bearer "+tc.dummy))
		if !strings.Contains(out, tc.want) || strings.Contains(out, tc.notWant) {
			t.Fatalf("%s: %s", tc.sni, out)
		}
	}

	// No host can serve one blob that names both kinds. For each kind that
	// a host can inject, the other kind is a placeholder that it cannot
	// carry. That refuses the full request. The fence does not forward the
	// remainder for the origin to answer.
	blob := "Bearer " + dummyOat + " tok " + dummyGH
	for _, tc := range []struct{ sni, host string }{
		{"api.anthropic.com", "api.anthropic.com"},
		{"github.com", "github.com"},
		{"evil.example", "evil.example"},
		{"evil.example", "api.anthropic.com"},
	} {
		req := parseReq(t, rawFor(tc.host, blob))
		_, err := Decide(Ctx{SNI: tc.sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
		for _, r := range refusalsOf(t, err) {
			if r.Cause != CauseKindNotAllowed {
				t.Fatalf("%s -> %s: %+v", tc.sni, tc.host, r)
			}
		}
		if got := req.Get("Authorization"); strings.Contains(got, oat) || strings.Contains(got, gh) {
			t.Fatalf("%s -> %s: a refused request was rewritten: %s", tc.sni, tc.host, got)
		}
	}
}

func decideAuth(t *testing.T, sni, raw string) string {
	t.Helper()
	req := decide(t, sni, raw)
	return req.Get("Authorization")
}

// The fence replaces the claude placeholder only for the claude core name,
// reached under its own sni. It refuses a spoofed Host and a github
// request, and does not change the request.
func TestPlaceholderRefusedOnAHostMiss(t *testing.T) {
	for _, tc := range []struct{ name, sni, host string }{
		{"host spoof", "evil.example", "api.anthropic.com"},
		{"github", "github.com", "github.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "GET / HTTP/1.1\r\nHost: " + tc.host + "\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
			req := parseReq(t, raw)
			_, err := Decide(Ctx{SNI: tc.sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			rs := refusalsOf(t, err)
			if len(rs) != 1 || rs[0].Cause != CauseKindNotAllowed {
				t.Fatalf("%+v", rs)
			}
			if !strings.Contains(req.Get("Authorization"), "pf_") {
				t.Fatalf("rewritten: %s", req.Get("Authorization"))
			}
		})
	}
}

func TestInjectSurvivesTokenRE(t *testing.T) {
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + oat + "\r\nContent-Length: 0\r\n\r\n"
	req := decide(t, "api.anthropic.com", raw)
	if !strings.Contains(req.Get("Authorization"), oat) {
		t.Fatal("TOKEN_RE ate injected oat")
	}
}

func TestOAuthBodyInject(t *testing.T) {
	dummy := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_ORT")
	body := `{"grant_type":"refresh_token","refresh_token":"` + dummy + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	req := decide(t, "pf-core-echo.test", raw)
	got, _ := io.ReadAll(req.Body)
	if strings.Contains(string(got), "pf_") {
		t.Fatal(string(got))
	}
	if !strings.Contains(string(got), "sk-ant-ort01-") {
		t.Fatal(string(got))
	}
}

func TestUnslottedIgnored(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_CLAUDE_OAT\r\n\r\n"
	req := decide(t, "pf-core-echo.test", raw)
	if req.Get("Authorization") != "Bearer pf_CLAUDE_OAT" {
		t.Fatal(req.Get("Authorization"))
	}
}

func TestStreamsEchoFixtures(t *testing.T) {
	dir := filepath.Join(testsupport.RepoRoot(t), "testdata", "streams")
	matches, err := filepath.Glob(filepath.Join(dir, "echo_*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no echo_ fixtures")
	}
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	pol := loadPol(t)
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		req, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		sni := req.Get("Host")
		_, err = Decide(Ctx{SNI: sni, TokenRE: re}, req, pol, labSlots())
		// A fixture named refuse carries a placeholder that its host cannot
		// substitute. The fence must end the request there.
		if strings.Contains(filepath.Base(path), "refuse") {
			refusalsOf(t, err)
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestStreamPrefixPreserved(t *testing.T) {
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("0123456789abcdef"), (maxBodyBuf+4096)/16)
	raw := "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
	req := parseReq(t, raw)
	if _, err := Decide(Ctx{SNI: "example.com", TokenRE: re}, req, loadPol(t), labSlots()); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) || req.ContentLength != int64(len(body)) {
		t.Fatalf("forwarded %d of %d, cl=%d", len(got), len(body), req.ContentLength)
	}
}

// StripCore decides what a core host does with a token of a kind that it
// does not inject. With the switch off, an OpenAI key pasted into a Claude
// prompt leaves the Pi live. With the switch on, the fence strips it. The
// kind that the host does inject must survive in both cases. If not, the
// fence would strip the credential that it just substituted.
func TestStripCoreOffKinds(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	openai := "sk-" + strings.Repeat("A", 48)
	ghp := "ghp_" + strings.Repeat("B", 36)
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	for _, tc := range []struct {
		name, sni, body string
		stripCore       bool
		want            bool
	}{
		{"foreign kind stripped on a core host", "api.anthropic.com", openai, true, true},
		{"foreign kind kept with the switch off", "api.anthropic.com", openai, false, false},
		{"github kind stripped on the claude host", "api.anthropic.com", ghp, true, true},
		{"github kind kept on its own host", "api.github.com", ghp, true, false},
		{"injected kind survives on its host", "api.anthropic.com", oat, true, false},
		{"non-core host strips regardless", "example.com", openai, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "POST /v1/x HTTP/1.1\r\nHost: " + tc.sni + "\r\nContent-Type: application/json\r\nContent-Length: " +
				strconv.Itoa(len(tc.body)) + "\r\n\r\n" + tc.body
			req := parseReq(t, raw)
			ctx := Ctx{SNI: tc.sni, Rules: rules, StripCore: tc.stripCore}
			if _, err := Decide(ctx, req, loadPol(t), labSlots()); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if got := !strings.Contains(string(body), tc.body); got != tc.want {
				t.Fatalf("stripped=%v want %v: %q", got, tc.want, body)
			}
		})
	}
}

// The fence substitutes the refresh token and the broker arms the harvest
// from the same test of the target. An absolute-form target names the
// refresh endpoint, so it is a refresh path. A target that is not already
// the exact path is not a refresh path. There the fence refuses the
// refresh token, so no pair is minted that the scrub snapshot does not
// know.
func TestR02OAuthPathNoncanonicalForms(t *testing.T) {
	for _, target := range []string{
		"https://platform.claude.com/v1/oauth/token",
		"http://api.anthropic.com/oauth/token?grant_type=refresh_token",
	} {
		if !IsOAuthPath(target) {
			t.Errorf("IsOAuthPath(%q) = false, it is the refresh endpoint", target)
		}
	}
	for _, target := range []string{
		"/v1/messages",
		"/v1/oauth/tokens",
		"https://platform.claude.com/v1/oauth/tokenize",
		"/oauth",
		"/v1/oauth/%74oken",
		"/v1/%6frg/../oauth/token",
		"/v1/oauth/token#anchor",
	} {
		if IsOAuthPath(target) {
			t.Errorf("IsOAuthPath(%q) = true, it is not the refresh endpoint", target)
		}
	}
}

// D. On a host whose line is "*", all kinds except CANARY are allowed.
// Thus no rule that detects one of them belongs in the strip set of that
// host. Except matched the literal tag instead. The streamed path then
// stripped the credential that the fence had just injected, while the
// buffered path, which injects after it strips, kept it. Now the one body
// that a credential goes into is the body of the refresh token. The fence
// buffers it for all framings. Both framings must still keep it.
func TestWildcardKindSurvivesEitherFraming(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	const sni = "pf-core-echo.test"
	ort := labSlots()[secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_ORT")].Live
	body := `{"refresh_token":"` + "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT" + `"}`
	for _, tc := range []struct{ name, raw string }{
		{"buffered", "POST /v1/oauth/token HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body},
		{"chunked", "POST /v1/oauth/token HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := parseReq(t, tc.raw)
			if _, _, err := DecideStream(Ctx{SNI: sni, Rules: rules, StripCore: true}, req, loadPol(t), labSlots()); err != nil {
				t.Fatal(err)
			}
			out, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), ort) {
				t.Fatalf("the injected credential did not survive this framing: %q", out)
			}
		})
	}
}
