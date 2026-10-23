package fence

import (
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

func jsonPost(host, contentType, body string) string {
	var ct string
	if contentType != "" {
		ct = "Content-Type: " + contentType + "\r\n"
	}
	return "POST /x HTTP/1.1\r\nHost: " + host + "\r\n" + ct +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// The origin unescapes a JSON string. Thus a placeholder written with \u
// escapes refuses the request as a literal one in the body does. This holds
// for a key, for any letter case, for a body that only parses as JSON, and
// for a JSON string inside a JSON string.
func TestJSONEscapedPlaceholderRefused(t *testing.T) {
	esc := `\u0070\u0066\u005fa1b2c3d4e5f67890\u005fGITHUB_TOKEN`
	for name, c := range map[string]struct{ ct, body string }{
		"value":       {"application/json", `{"note":"` + esc + `"}`},
		"key":         {"application/json; charset=utf-8", `{"` + esc + `":1}`},
		"upper case":  {"application/json", `{"note":"\u0050F_A1B2C3D4E5F67890_GITHUB_TOKEN"}`},
		"no type":     {"", `["` + esc + `"]`},
		"vendor type": {"application/vnd.api+json", `{"note":"pf\u005fa1b2c3d4e5f67890_GITHUB_TOKEN"}`},
		"nested":      {"application/json", `{"arguments":"{\"note\":\"\\u0070f_a1b2c3d4e5f67890_GITHUB_TOKEN\"}"}`},
	} {
		t.Run(name, func(t *testing.T) {
			req := parseReq(t, jsonPost("api.github.com", c.ct, c.body))
			_, err := Decide(Ctx{SNI: "api.github.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
			rs := refusalsOf(t, err)
			if len(rs) != 1 || rs[0].Cause != CauseOutsideHeader || !strings.EqualFold(rs[0].Slot, "a1b2c3d4e5f67890") || rs[0].Where != "body" {
				t.Fatalf("%+v", rs)
			}
		})
	}
}

// A stored live value or a token-prefix match that shows only after the
// unescape refuses the request. The fence cannot strip it in place.
func TestJSONEscapedLiveValueRefused(t *testing.T) {
	slots := labSlots()
	d := "d0d1d2d3d4e5f6a7"
	slots[secrets.EnvKey(d, "GITHUB_TOKEN")] = secrets.Slot{ID: d, Kind: "GITHUB_TOKEN", Dummy: secrets.Placeholder(d, "GITHUB_TOKEN"), Live: "lab/fence/stored/value"}
	t.Run("slash escape", func(t *testing.T) {
		req := parseReq(t, jsonPost("example.com", "application/json", `{"note":"lab\/fence\/stored\/value"}`))
		_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), slots)
		rs := refusalsOf(t, err)
		if len(rs) != 1 || rs[0].Cause != CauseEncodedBodyToken || rs[0].Slot != d || rs[0].Where != "body" {
			t.Fatalf("%+v", rs)
		}
	})
	t.Run("token shape", func(t *testing.T) {
		tok := `\u0067hp_` + strings.Repeat("D", 36)
		req := parseReq(t, jsonPost("example.com", "application/json", `{"note":"`+tok+`"}`))
		_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), slots)
		rs := refusalsOf(t, err)
		if len(rs) != 1 || rs[0].Cause != CauseEncodedBodyToken || rs[0].Where != "body" {
			t.Fatalf("%+v", rs)
		}
	})
}

// A literal live value in a string that also holds an escape strips as
// before. The unescape scan reads the body after the strip.
func TestJSONLiteralLiveValueStillStrips(t *testing.T) {
	req := parseReq(t, jsonPost("example.com", "application/json", `{"note":"a\nlab_fence_github"}`))
	ev, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || strings.Contains(wireOf(t, req), "lab_fence_github") {
		t.Fatalf("%+v\n%s", ev, wireOf(t, req))
	}
}

// The fence forwards a clean JSON body with escapes exactly as the agent
// sent it. The unescape is only for the scan.
func TestJSONEscapedCleanBodyForwardedByteIdentical(t *testing.T) {
	raw := jsonPost("example.com", "application/json", `{"note":"line\none \"q\" \u00e9 \/ \\u0070f_","n":[1,"\t"]}`)
	req := parseReq(t, raw)
	if _, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
		t.Fatal(err)
	}
	if got := wireOf(t, req); got != raw {
		t.Fatalf("body rewritten:\ngot  %q\nwant %q", got, raw)
	}
}
