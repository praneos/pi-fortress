package fence

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

// A3. A placeholder bound to a host was substituted into any header to
// that host. User-Agent and Referer go into access logs and come back in
// audit APIs (the GitHub audit API returns user_agent), past the literal
// response scrub. The origin can echo any X-anything header. Now only the
// credential headers of the kind carry it. A placeholder in any other
// location refuses the request, and the fence substitutes nothing.
func TestPlaceholderOutsideCredentialHeaderRefused(t *testing.T) {
	for _, name := range []string{"User-Agent", "Referer", "X-Note", "Cookie", "x-forwarded-for", "Accept"} {
		t.Run(name, func(t *testing.T) {
			raw := "GET /user HTTP/1.1\r\nHost: api.github.com\r\n" +
				"Authorization: Bearer " + phGH + "\r\n" +
				name + ": tool/1.0 " + phGH + "\r\n\r\n"
			req := parseReq(t, raw)
			_, err := Decide(Ctx{SNI: "api.github.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			var ref *RefusedError
			if !errors.As(err, &ref) {
				t.Fatalf("not refused: %v; %s=%q", err, name, req.Get(name))
			}
			want := Refusal{Cause: CauseOutsideHeader, Slot: "a1b2c3d4e5f67890", Kind: "GITHUB_TOKEN", Where: "header:" + name}
			if len(ref.Refusals) != 1 || ref.Refusals[0] != want {
				t.Fatalf("refusals %+v, want %+v", ref.Refusals, want)
			}
			if v := req.Get(name); strings.Contains(v, "lab_fence_github") || !strings.Contains(v, phGH) {
				t.Fatalf("%s rewritten: %q", name, v)
			}
			if v := req.Get("Authorization"); v != "Bearer "+phGH {
				t.Fatalf("a refused request was substituted into: %q", v)
			}
		})
	}
}

func kindSlots() map[string]secrets.Slot {
	m := labSlots()
	for kind, live := range map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-api03-live-anthropic",
		"OPENAI_API_KEY":    "sk-live-openai-value",
		"XAI_API_KEY":       "xai-live-value",
		"GITLAB_TOKEN":      "glpat-live-gitlab",
		"API_KEY":           "live-api-key",
	} {
		m[secrets.EnvKey(kindSlot, kind)] = secrets.Slot{ID: kindSlot, Kind: kind, Dummy: secrets.Placeholder(kindSlot, kind), Live: live}
	}
	return m
}

const kindSlot = "e0e1e2e3e4e5e6e7"

// Every shipped kind works with no core.hosts.local: Bearer, Basic and
// x-api-key are the default credential headers. The header name matches
// in any letter case.
func TestDefaultCredentialHeadersPerShippedKind(t *testing.T) {
	ph := func(kind string) string { return secrets.Placeholder(kindSlot, kind) }
	cases := []struct{ sni, field, value, want string }{
		{"api.github.com", "Authorization", "Bearer " + phGH, "Bearer lab_fence_github"},
		{"github.com", "authorization", "token " + phGH, "token lab_fence_github"},
		{"api.anthropic.com", "Authorization", "Bearer " + phOATb, "Bearer " + liveOAT()},
		{"platform.claude.com", "Authorization", "Bearer " + phOATb, "Bearer " + liveOAT()},
		{"api.anthropic.com", "x-api-key", ph("ANTHROPIC_API_KEY"), "sk-ant-api03-live-anthropic"},
		{"api.anthropic.com", "X-Api-Key", ph("ANTHROPIC_API_KEY"), "sk-ant-api03-live-anthropic"},
		{"api.openai.com", "Authorization", "Bearer " + ph("OPENAI_API_KEY"), "Bearer sk-live-openai-value"},
		{"api.x.ai", "Authorization", "Bearer " + ph("XAI_API_KEY"), "Bearer xai-live-value"},
		{"pf-core-echo.test", "Authorization", "Bearer " + phGH, "Bearer lab_fence_github"},
		{"pf-core-echo.test", "X-API-KEY", phGH, "lab_fence_github"},
	}
	for _, c := range cases {
		raw := "GET / HTTP/1.1\r\nHost: " + c.sni + "\r\n" + c.field + ": " + c.value + "\r\n\r\n"
		req := parseReq(t, raw)
		if _, err := Decide(Ctx{SNI: c.sni, TokenRE: mustRE(t)}, req, loadPol(t), kindSlots()); err != nil {
			t.Fatalf("%s %s: %v", c.sni, c.field, err)
		}
		if got := req.Get(c.field); got != c.want {
			t.Fatalf("%s %s = %q, want %q", c.sni, c.field, got, c.want)
		}
	}
	basic := b64("x-access-token:" + phGH)
	req := parseReq(t, "GET /o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\nAuthorization: Basic "+basic+"\r\n\r\n")
	if _, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), kindSlots()); err != nil {
		t.Fatal(err)
	}
	if dec, _, ok := BasicCredentials("Authorization", req.Get("Authorization")); !ok || string(dec) != "x-access-token:lab_fence_github" {
		t.Fatalf("basic %q", dec)
	}
}

func headerPolicy(t *testing.T, body string) *corepolicy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core.hosts")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := corepolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A header that core.hosts declares for a binding carries that kind toward
// that host, and to no other: not toward host B, which binds the kind but
// does not declare the header, and not for a different kind on host A.
func TestDeclaredCredentialHeaderPerBinding(t *testing.T) {
	pol := headerPolicy(t, "gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN API_KEY\nb.example GITLAB_TOKEN\nc.example API_KEY:api-key,X-Auth-Token\n")
	phGL := secrets.Placeholder(kindSlot, "GITLAB_TOKEN")
	phAK := secrets.Placeholder(kindSlot, "API_KEY")
	run := func(sni, field, value string) (*httpwire.Request, error) {
		req := parseReq(t, "GET / HTTP/1.1\r\nHost: "+sni+"\r\n"+field+": "+value+"\r\n\r\n")
		_, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, pol, kindSlots())
		return req, err
	}
	for _, c := range []struct{ sni, field, value, want string }{
		{"gitlab.com", "PRIVATE-TOKEN", phGL, "glpat-live-gitlab"},
		{"gitlab.com", "private-token", phGL, "glpat-live-gitlab"},
		{"gitlab.com", "Authorization", "Bearer " + phGL, "Bearer glpat-live-gitlab"},
		{"b.example", "Authorization", "Bearer " + phGL, "Bearer glpat-live-gitlab"},
		{"c.example", "api-key", phAK, "live-api-key"},
		{"c.example", "X-Auth-Token", "k=" + phAK, "k=live-api-key"},
	} {
		req, err := run(c.sni, c.field, c.value)
		if err != nil {
			t.Fatalf("%s %s: %v", c.sni, c.field, err)
		}
		if got := req.Get(c.field); got != c.want {
			t.Fatalf("%s %s = %q, want %q", c.sni, c.field, got, c.want)
		}
	}
	for _, c := range []struct{ sni, field, value, kind string }{
		{"b.example", "PRIVATE-TOKEN", phGL, "GITLAB_TOKEN"},
		{"gitlab.com", "PRIVATE-TOKEN", phAK, "API_KEY"},
		{"gitlab.com", "Cookie", phGL, "GITLAB_TOKEN"},
		{"c.example", "X-Goog-Api-Key", phAK, "API_KEY"},
	} {
		req, err := run(c.sni, c.field, c.value)
		want := Refusal{Cause: CauseOutsideHeader, Slot: kindSlot, Kind: c.kind, Where: "header:" + c.field}
		if rs := refusalsOf(t, err); len(rs) != 1 || rs[0] != want {
			t.Fatalf("%s %s: %+v", c.sni, c.field, rs)
		}
		if got := req.Get(c.field); got != c.value {
			t.Fatalf("%s %s rewritten to %q", c.sni, c.field, got)
		}
	}
}

// The strip behaviour does not change: a live value of a kind that the
// host does not bind strips from any header, a credential header or not.
func TestLiveValueStillStrippedInEveryHeader(t *testing.T) {
	for _, field := range []string{"User-Agent", "Referer", "X-Note", "Authorization", "PRIVATE-TOKEN"} {
		for _, sni := range []string{"api.github.com", "example.com"} {
			req := parseReq(t, "GET / HTTP/1.1\r\nHost: "+sni+"\r\n"+field+": a "+liveOAT()+" b\r\n\r\n")
			strips, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			if err != nil {
				t.Fatalf("%s %s: %v", sni, field, err)
			}
			if v := req.Get(field); strings.Contains(v, liveOAT()) || !strings.Contains(v, StripRepl) {
				t.Fatalf("%s %s = %q", sni, field, v)
			}
			if len(strips) == 0 || strips[0].Where != "header" {
				t.Fatalf("%s %s strips %+v", sni, field, strips)
			}
		}
	}
}

// FuzzPlaceholderOnlyInCredentialHeaders: toward a host that binds the
// kind, the fence either substitutes a placeholder in a field because the
// field is a default credential header, or refuses the request. Its live
// value never gets to the wire in any other field.
func FuzzPlaceholderOnlyInCredentialHeaders(f *testing.F) {
	f.Add("User-Agent", "curl/8 ")
	f.Add("authorization", "Bearer ")
	f.Add("X-Api-Key", "")
	f.Add("Referer", "https://x/?")
	f.Add("Cookie", "a=")
	re, pol := testPolicy(f)
	f.Fuzz(func(t *testing.T, name, prefix string) {
		switch strings.ToLower(name) {
		case "host", "connection", "content-length", "transfer-encoding":
			return
		}
		if strings.ContainsAny(name+prefix, "\r\n:") || strings.Contains(prefix, "pf_") {
			return
		}
		raw := "GET /user HTTP/1.1\r\nHost: api.github.com\r\n" + name + ": " + prefix + " " + phGH + "\r\n\r\n"
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		_, _, err = DecideStream(Ctx{SNI: "api.github.com", TokenRE: re}, req, pol, labSlots())
		var out bytes.Buffer
		if _, werr := req.WriteTo(&out); werr != nil {
			return
		}
		leaked := bytes.Contains(out.Bytes(), []byte("lab_fence_github"))
		if !corepolicy.DefaultHeader(name) {
			var ref *RefusedError
			if !errors.As(err, &ref) || leaked {
				t.Fatalf("placeholder in %q: err %v leaked %v\nout=%q", name, err, leaked, out.Bytes())
			}
			return
		}
		if err != nil || !leaked {
			t.Fatalf("credential header %q not substituted\nout=%q", name, out.Bytes())
		}
	})
}
