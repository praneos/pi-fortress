package fence

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

func TestHostAndConnectionNeverInjected(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	raw := "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\n" +
		"Connection: close, " + live + "\r\n" +
		"X-Note: " + live + "\r\n" +
		"Authorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
	req := parseReq(t, raw)
	strips, err := Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if v := req.Get("Connection"); strings.Contains(v, live) || !strings.Contains(v, StripRepl) {
		t.Fatalf("connection %q", v)
	}
	if v := req.Get("X-Note"); v != live {
		t.Fatalf("an allowed kind on a core host must survive in a normal header: %q", v)
	}
	if v := req.Get("Authorization"); v != "Bearer lab_fence_github" {
		t.Fatalf("authorization %q", v)
	}
	found := false
	for _, ev := range strips {
		if ev.Where == "header" && strings.HasPrefix(ev.Rule, "secret:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no header strip event: %+v", strips)
	}
	// Keep-Alive is not a credential header: the placeholder refuses the
	// request, and the fence writes nothing in.
	raw = "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nKeep-Alive: pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
	req = parseReq(t, raw)
	_, err = Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots())
	if rs := refusalsOf(t, err); len(rs) != 1 || rs[0].Cause != CauseOutsideHeader || rs[0].Where != "header:Keep-Alive" {
		t.Fatalf("keep-alive refusals %+v", rs)
	}
	if v := req.Get("Keep-Alive"); v != "pf_a1b2c3d4e5f67890_GITHUB_TOKEN" {
		t.Fatalf("keep-alive %q", v)
	}
	// Host and Connection are also never inject targets. A placeholder in
	// one of them refuses the request, and does not pass silently.
	for _, name := range []string{"Connection", "Host"} {
		raw = "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\n" + name + ": pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
		if name == "Host" {
			raw = "GET / HTTP/1.1\r\nHost: pf_a1b2c3d4e5f67890_GITHUB_TOKEN.pf-core-echo.test\r\n\r\n"
		}
		req = parseReq(t, raw)
		_, err = Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots())
		rs := refusalsOf(t, err)
		// A placeholder inside Host also moves the authority off the core
		// binding. Thus the fence refuses it as a kind that the host cannot carry.
		if name == "Host" && (len(rs) == 0 || rs[0].Cause != CauseKindNotAllowed) ||
			name == "Connection" && (len(rs) == 0 || rs[0].Cause != CauseOutsideHeader || rs[0].Where != "header:Connection") {
			t.Fatalf("%s refusals %+v", name, rs)
		}
		if v := req.Get(name); strings.Contains(v, "lab_fence_github") {
			t.Fatalf("placeholder in %s was injected: %q", name, v)
		}
	}
}

// The origin routes by the Host that it gets. A strip there sends the
// request to a name that the fence did not judge. Thus a live value or a
// token-prefix match in Host refuses the request, on a core host and on a
// foreign host, also for a kind that the core host injects. The fence
// writes nothing into the request, and the Host stays as the agent sent it.
func TestLiveValueInHostRefused(t *testing.T) {
	re, pol := testPolicy(t)
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	ghp := "ghp_" + strings.Repeat("A", 36)
	auth := "Authorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n"
	for _, tc := range []struct {
		name, sni, host string
		slot, kind      string
	}{
		{"core, injected kind", "pf-core-echo.test", "lab_fence_github.pf-core-echo.test", "a1b2c3d4e5f67890", "GITHUB_TOKEN"},
		{"core, with port", "pf-core-echo.test", "lab_fence_github.pf-core-echo.test:443", "a1b2c3d4e5f67890", "GITHUB_TOKEN"},
		{"core, other slot", "pf-core-echo.test", oat + ".pf-core-echo.test", "b0b1b2b3b4b5b6b7", "CLAUDE_OAT"},
		{"foreign", "evil.example", "lab_fence_github.evil.example", "a1b2c3d4e5f67890", "GITHUB_TOKEN"},
		{"token prefix", "evil.example", ghp + ".evil.example", "", ""},
		{"token prefix, core", "pf-core-echo.test", ghp + ".pf-core-echo.test", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "GET / HTTP/1.1\r\nHost: " + tc.host + "\r\n" + auth + "\r\n"
			req := parseReq(t, raw)
			injected := false
			_, err := Decide(Ctx{SNI: tc.sni, TokenRE: re, OnInject: func(string) { injected = true }}, req, pol, labSlots())
			want := Refusal{Cause: CauseLiveInHost, Slot: tc.slot, Kind: tc.kind, Where: "header:Host"}
			found := false
			for _, r := range refusalsOf(t, err) {
				found = found || r == want
			}
			if !found {
				t.Fatalf("refusals %+v, want %+v", refusalsOf(t, err), want)
			}
			if injected || req.Get("Host") != tc.host || strings.Contains(req.Get("Authorization"), "lab_fence_github") {
				t.Fatalf("the fence changed the request: injected=%v host=%q auth=%q", injected, req.Get("Host"), req.Get("Authorization"))
			}
		})
	}
	// A Host with no live value and no token-prefix match goes out as it came.
	for _, host := range []string{"pf-core-echo.test", "pf-core-echo.test:443", "a.pf-core-echo.test"} {
		req := parseReq(t, "GET / HTTP/1.1\r\nHost: "+host+"\r\n"+auth+"\r\n")
		if _, err := Decide(Ctx{SNI: "pf-core-echo.test", TokenRE: re}, req, pol, labSlots()); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if req.Get("Host") != host || req.Get("Authorization") != "Bearer lab_fence_github" {
			t.Fatalf("%s: host %q auth %q", host, req.Get("Host"), req.Get("Authorization"))
		}
	}
}

func TestIsOAuthPathExact(t *testing.T) {
	for p, want := range map[string]bool{
		"/v1/oauth/token":          true,
		"/oauth/token":             true,
		"/v1/oauth/token?x=1":      true,
		"/V1/OAuth/Token":          false,
		"/oauth/token-status":      false,
		"/v1/foo/oauth/token":      false,
		"/v1/oauth/token/":         false,
		"/v1/oauth/tokens":         false,
		"/v1/oauth/token/../other": false,
	} {
		if got := IsOAuthPath(p); got != want {
			t.Fatalf("IsOAuthPath(%q)=%v want %v", p, got, want)
		}
	}
}

func TestBufferedBodyOverflowRefused(t *testing.T) {
	body := strings.Repeat("x", maxBodyBuf+1)
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots())
	if !errors.Is(err, httpwire.ErrBodyLimit) {
		t.Fatalf("err=%v", err)
	}
	raw = "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body[:maxBodyBuf])
	req = parseReq(t, raw)
	if _, err := Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots()); err != nil {
		t.Fatalf("exact fit: %v", err)
	}
	if req.ContentLength != maxBodyBuf || req.Chunked {
		t.Fatalf("cl=%d chunked=%v", req.ContentLength, req.Chunked)
	}
}

// A body cut off at exactly the buffer limit fills the buffer and then
// fails the overflow probe. The code dropped the error of the probe. Thus
// the body looked like a body that ended there, and went out whole under a
// rewritten length.
func TestBufferedBodyTruncatedAtLimitRefused(t *testing.T) {
	body := strings.Repeat("x", maxBodyBuf)
	for name, raw := range map[string]string{
		"chunked": "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
			strings.TrimSuffix(chunked(body), "0\r\n\r\n"),
		"content_length": "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Length: " +
			strconv.Itoa(maxBodyBuf+10) + "\r\n\r\n" + body,
	} {
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "pf-core-echo.test"}, req, loadPol(t), labSlots())
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

// C. The 1 MiB read limit applies to the input, not to the output. Each
// placeholder takes its own bytes, and a full live value replaces it.
// Thus the fence could forward a header, or the body of the refresh token,
// that the parser accepted, in a shape that no parser would read back.
func TestInjectionGrowthRefused(t *testing.T) {
	slots := func(n int) map[string]secrets.Slot {
		s := labSlots()
		k := secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN")
		sl := s[k]
		sl.Live = strings.Repeat("g", n)
		s[k] = sl
		return s
	}
	t.Run("header", func(t *testing.T) {
		value := "Bearer " + strings.Repeat(phGH+",", 20)
		raw := "GET / HTTP/1.1\r\nHost: github.com\r\nAuthorization: " + value + "\r\n\r\n"
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), slots(500))
		if !errors.Is(err, httpwire.ErrHeaderLimit) {
			t.Fatalf("err %v, field grew to %d bytes", err, len(req.Get("Authorization")))
		}
	})
	t.Run("target", func(t *testing.T) {
		// Never grows: the fence does not write into a URL. Thus it refuses
		// the placeholder before a substitution could make the line longer.
		raw := "GET /?" + strings.Repeat(phGH+"&", 20) + " HTTP/1.1\r\nHost: github.com\r\n\r\n"
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), slots(500))
		var re *RefusedError
		if !errors.As(err, &re) || re.Refusals[0].Cause != CauseOutsideHeader {
			t.Fatalf("err %v, target grew to %d bytes", err, len(req.Target))
		}
	})
	t.Run("buffered body", func(t *testing.T) {
		// The body of the refresh token is the one body that the fence writes
		// into, and only at its one refresh_token value. Thus one live value
		// is what makes it grow.
		s := labSlots()
		k := secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_ORT")
		sl := s[k]
		sl.Live = strings.Repeat("r", 1<<20)
		s[k] = sl
		body := `{"refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
		raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), s)
		if !errors.Is(err, httpwire.ErrBodyLimit) {
			out, _ := io.ReadAll(req.Body)
			t.Fatalf("err %v, body grew to %d bytes", err, len(out))
		}
	})
	t.Run("chunked body", func(t *testing.T) {
		body := strings.Repeat(phGH+" filler ", 40)
		raw := "POST /x HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
		req := parseReq(t, raw)
		if _, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), slots(1<<16)); err != nil {
			t.Fatal(err)
		}
		out, err := io.ReadAll(req.Body)
		if !errors.Is(err, ErrPlaceholderInStream) {
			t.Fatalf("err %v, stream grew to %d bytes", err, len(out))
		}
	})
}

// E. Refusals are the feedback channel of the agent. Thus the agent can
// mint distinct refusals as fast as it can write placeholders. Each refusal
// that the fence keeps costs the broker a synchronous log write on the
// credential path.
func TestRefusalsBounded(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString("pf_" + fmt.Sprintf("%016x", i) + "_GITHUB_TOKEN ")
	}
	body := sb.String()
	raw := "POST /x HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "api.anthropic.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	var ref *RefusedError
	if !errors.As(err, &ref) {
		t.Fatalf("err %v", err)
	}
	if len(ref.Refusals) > maxRefusals {
		t.Fatalf("one request produced %d refusal rows", len(ref.Refusals))
	}
	if len(ref.Refusals) == 0 {
		t.Fatal("the cause must still reach the operator")
	}
}
