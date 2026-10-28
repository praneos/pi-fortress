package fence

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/placeholder"
	"pi-fortress/internal/secrets"
)

const (
	phGH      = "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"
	liveGH    = "lab_fence_github"
	phOATb    = "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	phUnknown = "pf_ffffffffffffffff_GITHUB_TOKEN"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func authReq(host, auth string) string {
	return "GET /o/r.git/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: " + auth + "\r\n\r\n"
}

func decideErr(t *testing.T, sni, raw string) (*httpwire.Request, []StripEvent, error) {
	t.Helper()
	req := parseReq(t, raw)
	strips, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	return req, strips, err
}

func TestBasicInjects(t *testing.T) {
	for _, tc := range []struct{ name, prefix, cred, token, want string }{
		{"password", "Basic ", "x-access-token:" + phGH, "", "x-access-token:" + liveGH},
		{"username", "Basic ", phGH + ":x-oauth-basic", "", liveGH + ":x-oauth-basic"},
		{"uppercase slot hex", "Basic ", "x:pf_A1B2C3D4E5F67890_GITHUB_TOKEN", "", "x:" + liveGH},
		{"lowercase scheme, whitespace", "basic \t  ", "x-access-token:" + phGH, "", "x-access-token:" + liveGH},
		{"unpadded", "BASIC ", "x:" + phGH, base64.RawStdEncoding.EncodeToString([]byte("x:" + phGH)), "x:" + liveGH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.token
			if tok == "" {
				tok = b64(tc.cred)
			}
			req, _, err := decideErr(t, "github.com", authReq("github.com", tc.prefix+tok))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := req.Get("Authorization"), tc.prefix+b64(tc.want); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

// A Basic credential gets the same refusals as a plain header: the same
// causes, the same records, and no rewrite.
func TestBasicRefusedLikePlain(t *testing.T) {
	for _, tc := range []struct {
		name, sni, ph string
		cause         RefusalCause
	}{
		{"foreign sni", "evil.example", phGH, CauseKindNotAllowed},
		{"unknown slot", "github.com", phUnknown, CauseSlotUnknown},
		{"kind not allowed for sni", "github.com", phOATb, CauseKindNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, perr := decideErr(t, tc.sni, authReq(tc.sni, "Bearer "+tc.ph))
			plain := refusalsOf(t, perr)
			auth := "Basic " + b64("x-access-token:"+tc.ph)
			req, _, err := decideErr(t, tc.sni, authReq(tc.sni, auth))
			basic := refusalsOf(t, err)
			if len(basic) != 1 || basic[0].Cause != tc.cause || !reflect.DeepEqual(plain, basic) {
				t.Fatalf("plain %+v basic %+v", plain, basic)
			}
			if req.Get("Authorization") != auth {
				t.Fatalf("refused request rewritten: %q", req.Get("Authorization"))
			}
		})
	}
}

func TestBasicStripsLikePlain(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a", 36)
	for _, secret := range []string{ghp, liveGH} {
		_, plain, err := decideErr(t, "example.com", authReq("example.com", "Bearer "+secret))
		if err != nil {
			t.Fatal(err)
		}
		req, basic, err := decideErr(t, "example.com", authReq("example.com", "Basic "+b64("x-access-token:"+secret)))
		if err != nil {
			t.Fatal(err)
		}
		if len(plain) != 1 || !reflect.DeepEqual(plain, basic) {
			t.Fatalf("plain %+v basic %+v", plain, basic)
		}
		if got, want := req.Get("Authorization"), "Basic "+b64("x-access-token:"+StripRepl); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

// A token that is not base64 is scanned raw, exactly as before.
func TestBasicMalformedRawScan(t *testing.T) {
	req, _, err := decideErr(t, "api.anthropic.com", authReq("api.anthropic.com", "Basic "+phOATb))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Get("Authorization"); got != "Basic "+liveOAT() {
		t.Fatalf("raw placeholder not injected: %q", got)
	}
	_, _, err = decideErr(t, "evil.example", authReq("evil.example", "Basic !!"+phGH))
	if rs := refusalsOf(t, err); len(rs) != 1 || rs[0].Cause != CauseKindNotAllowed {
		t.Fatalf("%+v", rs)
	}
	req, _, err = decideErr(t, "github.com", authReq("github.com", "Basic abc$"))
	if err != nil || req.Get("Authorization") != "Basic abc$" {
		t.Fatalf("%v %q", err, req.Get("Authorization"))
	}
}

func TestBasicOnlyForBasicAuthorization(t *testing.T) {
	tok := b64("x-access-token:" + phGH)
	for _, raw := range []string{
		authReq("github.com", "Bearer "+tok),
		authReq("github.com", "token "+tok),
		authReq("github.com", "Basicx "+tok),
		authReq("github.com", "Basic"),
		"GET / HTTP/1.1\r\nHost: github.com\r\nX-Auth: Basic " + tok + "\r\n\r\n",
	} {
		req, _, err := decideErr(t, "github.com", raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if wire := wireOf(t, req); !strings.Contains(wire, "\r\n\r\n") || strings.Contains(wire, b64("x-access-token:"+liveGH)) {
			t.Fatalf("%q decoded: %q", raw, wire)
		}
	}
}

func wireOf(t *testing.T, req *httpwire.Request) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A Basic value that the fence has no reason to change goes out as it came
// in, also the spacing after the colon. A rewritten field would lose it.
func TestBasicUnchangedIsByteIdentical(t *testing.T) {
	for _, line := range []string{
		"Authorization:   BASIC\t" + base64.RawStdEncoding.EncodeToString([]byte("user:pass")),
		"Authorization:  Basic " + b64("x-access-token:"+liveGH),
	} {
		raw := "GET / HTTP/1.1\r\nHost: github.com\r\n" + line + "\r\n\r\n"
		req, _, err := decideErr(t, "github.com", raw)
		if err != nil {
			t.Fatal(err)
		}
		if wire := wireOf(t, req); !strings.Contains(wire, "\r\n"+line+"\r\n") {
			t.Fatalf("rewritten: %q", wire)
		}
	}
}

func TestBasicGrowthPastLineLimit(t *testing.T) {
	slots := labSlots()
	k := secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN")
	sl := slots[k]
	sl.Live = strings.Repeat("g", 7000)
	slots[k] = sl
	req := parseReq(t, authReq("github.com", "Basic "+b64("x:"+phGH)))
	_, err := Decide(Ctx{SNI: "github.com", TokenRE: mustRE(t)}, req, loadPol(t), slots)
	if !errors.Is(err, httpwire.ErrHeaderLimit) {
		t.Fatalf("err %v", err)
	}
}

// FuzzBasicNeverLeaks: for any user and password, scheme case, whitespace
// and destination, a forwarded Basic credential decodes to no placeholder,
// and to no live value that the destination cannot carry.
func FuzzBasicNeverLeaks(f *testing.F) {
	f.Add("x-access-token", "", uint8(0), uint8(0), uint8(0), uint8(1))
	f.Add("", ":x-oauth-basic", uint8(0x1f), uint8(1), uint8(1), uint8(2))
	f.Add("u", "p", uint8(3), uint8(2), uint8(2), uint8(7))
	f.Add(liveGH, "sk-ant-oat01-"+strings.Repeat("A", 64), uint8(9), uint8(5), uint8(4), uint8(3))
	re, pol := testPolicy(f)
	phs := []string{phGH, "pf_A1B2C3D4E5F67890_GITHUB_TOKEN", phOATb, phUnknown, "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT", ""}
	snis := []string{"github.com", "api.anthropic.com", "evil.example"}
	spaces := []string{" ", "\t", "  \t "}
	f.Fuzz(func(t *testing.T, user, pass string, casing, ws, sniSel, sel uint8) {
		scheme := []byte("basic")
		for i := range scheme {
			if casing&(1<<i) != 0 {
				scheme[i] -= 'a' - 'A'
			}
		}
		ph := phs[int(sel)%len(phs)]
		if sel&0x40 != 0 {
			user += ph
		} else {
			pass += ph
		}
		cred := []byte(user + ":" + pass)
		tok := base64.StdEncoding.EncodeToString(cred)
		if sel&0x80 != 0 {
			tok = base64.RawStdEncoding.EncodeToString(cred)
		}
		sni := snis[int(sniSel)%len(snis)]
		raw := authReq(sni, string(scheme)+spaces[int(ws)%len(spaces)]+tok)
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		_, _, err = DecideStream(Ctx{SNI: sni, TokenRE: re}, req, pol, labSlots())
		var refused *RefusedError
		if errors.As(err, &refused) {
			return
		}
		if err != nil {
			t.Fatalf("%v\nraw=%q", err, raw)
		}
		_ = decodedWire(t, req, raw)
		auth := req.Get("Authorization")
		dec, _, ok := BasicCredentials("Authorization", auth)
		if !ok {
			t.Fatalf("forwarded credential no longer decodes\nraw=%q\nauth=%q", raw, auth)
		}
		if len(placeholder.FindPlaceholderSpans(dec)) > 0 || len(placeholder.FindPlaceholderSpans([]byte(auth))) > 0 {
			t.Fatalf("placeholder forwarded\nraw=%q\ndec=%q", raw, dec)
		}
		kinds := pol.KindsFor(sni)
		for _, sl := range labSlots() {
			if pol.Authority(sni, sni) && containsKind(kinds, sl.Kind) {
				continue
			}
			if bytes.Contains(dec, []byte(sl.Live)) || strings.Contains(auth, sl.Live) {
				t.Fatalf("live %s leaked to %s\nraw=%q\ndec=%q", sl.Kind, sni, raw, dec)
			}
		}
	})
}

func containsKind(kinds []string, k string) bool {
	for _, have := range kinds {
		if have == k || have == "*" {
			return true
		}
	}
	return false
}
