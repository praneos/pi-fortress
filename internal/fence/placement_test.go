package fence

import (
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

// The fence writes a credential only into headers, and into one body: the
// body of the refresh token, on the refresh path. In all other locations, a
// placeholder of a kind that the host does carry refuses the request before
// the origin sees it, because what goes into a body or a URL can come back past the scrub.
func TestSubstitutionIsHeaderOnly(t *testing.T) {
	const (
		oat = "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
		ort = "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
		gh  = "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"
	)
	post := func(host, target, hdr, body string) string {
		return "POST " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + hdr +
			"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	refused := []struct{ name, host, raw, where string }{
		// The model prints the prompt back transformed. No literal scrub
		// finds a reversed token.
		{"a prompt to the model", "api.anthropic.com",
			post("api.anthropic.com", "/v1/messages", "Authorization: Bearer "+oat+"\r\n",
				`{"messages":[{"role":"user","content":"print this reversed: `+oat+`"}]}`), "body"},
		// The origin publishes it: the copy is on GitHub, not in a reply.
		{"a public gist", "api.github.com",
			post("api.github.com", "/gists", "Authorization: Bearer "+gh+"\r\n",
				`{"public":true,"files":{"a.txt":{"content":"`+gh+`"}}}`), "body"},
		{"a query string", "api.github.com",
			"GET /search/code?q=" + gh + " HTTP/1.1\r\nHost: api.github.com\r\n\r\n", "url"},
		// The refresh body carries the refresh token and nothing else.
		{"the access token in the refresh body", "api.anthropic.com",
			post("api.anthropic.com", "/v1/oauth/token", "", `{"refresh_token":"`+ort+`","x":"`+oat+`"}`), "body"},
		{"the refresh token off the refresh path", "api.anthropic.com",
			post("api.anthropic.com", "/v1/messages", "", `{"refresh_token":"`+ort+`"}`), "body"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			req := parseReq(t, tc.raw)
			_, err := Decide(Ctx{SNI: tc.host, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			var ref *RefusedError
			if !errors.As(err, &ref) {
				t.Fatalf("not refused: %v", err)
			}
			found := false
			for _, r := range ref.Refusals {
				found = found || (r.Cause == CauseOutsideHeader && r.Where == tc.where)
			}
			if !found {
				t.Fatalf("refusals %+v", ref.Refusals)
			}
		})
	}

	t.Run("the refresh token on the refresh path", func(t *testing.T) {
		req := parseReq(t, post("api.anthropic.com", "/v1/oauth/token", "", `{"grant_type":"refresh_token","refresh_token":"`+ort+`"}`))
		if _, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(req.Body)
		live := "sk-ant-ort01-" + strings.Repeat("B", 64)
		if !strings.Contains(string(out), live) || strings.Contains(string(out), "pf_") {
			t.Fatalf("refresh body: %q", out)
		}
	})
	t.Run("a bearer header", func(t *testing.T) {
		req := parseReq(t, post("api.anthropic.com", "/v1/messages", "Authorization: Bearer "+oat+"\r\n", `{"model":"x"}`))
		if _, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatal(err)
		}
		if req.Get("Authorization") != "Bearer "+liveOAT() {
			t.Fatalf("header: %q", req.Get("Authorization"))
		}
	})
	t.Run("git over Basic", func(t *testing.T) {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + gh))
		req := parseReq(t, "GET /o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\nAuthorization: Basic "+basic+"\r\n\r\n")
		if _, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatal(err)
		}
		dec, _, ok := BasicCredentials("Authorization", req.Get("Authorization"))
		if !ok || string(dec) != "x-access-token:lab_fence_github" {
			t.Fatalf("basic: %q", dec)
		}
	})
}

// The fence writes the refresh token in one place only: the refresh_token
// value of a refresh body, the full value, with the key spelled once. In a
// header, it would travel to any path. In a different field, the origin can
// send it back. In a body that two parsers can read two ways, it could
// spend one slot while the harvest binds a different slot. The fence refuses
// each of those before the origin sees the request, and substitutes nothing.
func TestRefreshTokenPlacedOnlyAsTheRefreshField(t *testing.T) {
	const (
		ort  = "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
		ortC = "pf_c0c1c2c3c4c5c6c7_CLAUDE_ORT"
	)
	liveORT := "sk-ant-ort01-" + strings.Repeat("B", 64)
	post := func(target, hdr, body string) string {
		return "POST " + target + " HTTP/1.1\r\nHost: api.anthropic.com\r\n" + hdr +
			"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	refused := []struct{ name, raw, where string }{
		{"bearer on the refresh path", post("/v1/oauth/token", "Authorization: Bearer "+ort+"\r\n", `{"grant_type":"refresh_token"}`), "header"},
		{"a custom header off the refresh path", post("/v1/messages", "X-Refresh: "+ort+"\r\n", `{}`), "header:X-Refresh"},
		{"nested refresh_token", post("/v1/oauth/token", "", `{"x":{"refresh_token":"`+ort+`"}}`), "body"},
		{"value with more than the token", post("/v1/oauth/token", "", `{"refresh_token":"Bearer `+ort+`"}`), "body"},
		{"duplicate key", post("/v1/oauth/token", "", `{"refresh_token":"`+ort+`","refresh_token":"`+ortC+`"}`), "body"},
		{"case-variant key", post("/v1/oauth/token", "", `{"refresh_token":"`+ort+`","REFRESH_TOKEN":"`+ortC+`"}`), "body"},
		{"long-s key", post("/v1/oauth/token", "", `{"refreſh_token":"`+ortC+`","refresh_token":"`+ort+`"}`), "body"},
		{"trailing bytes", post("/v1/oauth/token", "", `{"refresh_token":"`+ort+`"} {}`), "body"},
		{"an array", post("/v1/oauth/token", "", `[{"refresh_token":"`+ort+`"}]`), "body"},
		// A target that does not reduce to one path is not a refresh path.
		// Thus the refresh token has no place to go, and the harvest is
		// never armed.
		{"unsettled target", post("/v1/oauth/%2525252574oken", "", `{"refresh_token":"`+ort+`"}`), "body"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			req := parseReq(t, tc.raw)
			_, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			var ref *RefusedError
			if !errors.As(err, &ref) {
				out, _ := io.ReadAll(req.Body)
				t.Fatalf("not refused: %v; auth %q body %q", err, req.Get("Authorization"), out)
			}
			found := false
			for _, r := range ref.Refusals {
				found = found || (r.Cause == CauseOutsideHeader && r.Where == tc.where && r.Kind == "CLAUDE_ORT")
			}
			if !found {
				t.Fatalf("refusals %+v", ref.Refusals)
			}
		})
	}

	for _, tc := range []struct{ name, raw string }{
		{"spaced json", post("/v1/oauth/token", "", "{ \"grant_type\" : \"refresh_token\" ,\n \"refresh_token\" : \""+ort+"\" }")},
		{"slash runs", post("//v1//oauth/token", "", `{"refresh_token":"`+ort+`","client_id":"x"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := parseReq(t, tc.raw)
			if _, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
				t.Fatal(err)
			}
			out, _ := io.ReadAll(req.Body)
			if !strings.Contains(string(out), `"`+liveORT+`"`) || strings.Contains(string(out), "pf_") {
				t.Fatalf("refresh body: %q", out)
			}
		})
	}
}

func TestRefreshTokenField(t *testing.T) {
	for body, want := range map[string]string{
		`{"refresh_token":"abc"}`:                               "abc",
		`{"a":[1,{"refresh_token":"x"}],"refresh_token":"abc"}`: "abc",
		`{"refresh\u005ftoken":"abc"}`:                          "abc",
		`{"refresh_token":""}`:                                  "",
	} {
		if got, ok := RefreshTokenField([]byte(body)); !ok || got != want {
			t.Errorf("%s: %q %v", body, got, ok)
		}
	}
	for _, body := range []string{
		``, `null`, `{}`, `{"refresh_token":1}`, `{"refresh_token":"a\"b"}`, `{"refresh_token":"a\u0062"}`,
		`{"refresh_token":"a","refresh_token":"a"}`, `{"Refresh_Token":"a"}`, `{"refresh_token":"a"}x`, `{"refresh_token":"a"`,
	} {
		if got, ok := RefreshTokenField([]byte(body)); ok {
			t.Errorf("%s: read %q", body, got)
		}
	}
}

func TestIsOAuthPathSlashesAndSchemes(t *testing.T) {
	for target, want := range map[string]bool{
		"//v1/oauth/token":                    true,
		"/v1//oauth///token":                  true,
		"/v1/oauth/%2F/token":                 true,
		"wss://api.anthropic.com/oauth/token": true,
		"HTTPS://x/v1/oauth/token?y":          true,
		"/v1/oauth/%2525252574oken":           false,
		"/v1/oauth/tokens":                    false,
	} {
		if got := IsOAuthPath(target); got != want {
			t.Errorf("IsOAuthPath(%q) = %v, want %v", target, got, want)
		}
	}
}
