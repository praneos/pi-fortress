package broker

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// tokenUpstream answers the token endpoint with a fresh oat/ort pair.
func tokenUpstream(t *testing.T, b *Broker) {
	t.Helper()
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"sk-ant-oat01-` + strings.Repeat("E", 64) + `","refresh_token":"sk-ant-ort01-` + strings.Repeat("F", 64) + `"}`))
	})
}

func TestOAuthHarvestNonCoreIgnored(t *testing.T) {
	b, path := testBroker(t)
	before, _ := os.ReadFile(path)
	tokenUpstream(t, b)
	body := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
	for _, tc := range []struct{ sni, host string }{
		{"evil.example", "evil.example"},
		{"evil.example", "platform.claude.com"},
		{"github.com", "github.com"},
	} {
		p := preamble.Preamble{SNI: tc.sni, OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
		raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: " + tc.host + "\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		_ = roundtrip(t, b, p, raw)
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatalf("%s/%s harvested:\n%s", tc.sni, tc.host, after)
		}
	}
}

// The fence excludes a slot after its deadline from harvest, the same as a
// disabled slot. The fence refuses the placeholder before bindHarvest runs
// (CauseSlotExpired, the same as CauseSlotDisabled). Thus no refresh gets
// to the origin, and secrets.env does not change.
func TestOAuthHarvestExpiredSlotIgnored(t *testing.T) {
	b, path := testBroker(t)
	tokenUpstream(t, b)
	slot := "b0b1b2b3b4b5b6b7"
	if err := b.Store.SetExpiry(slot, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	body := `{"grant_type":"refresh_token","refresh_token":"pf_` + slot + `_CLAUDE_ORT"}`
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	_ = roundtrip(t, b, p, raw)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatalf("expired slot was harvested:\n%s", after)
	}
}

func TestHarvestNeverCreatesSlot(t *testing.T) {
	b, path := testBroker(t)
	tokenUpstream(t, b)
	body := `{"grant_type":"refresh_token","refresh_token":"pf_ffffffffffffffff_CLAUDE_ORT"}`
	p := preamble.Preamble{SNI: "platform.claude.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	_ = roundtrip(t, b, p, raw)
	env, _ := os.ReadFile(path)
	if strings.Contains(string(env), "ffffffffffffffff") || strings.Contains(string(env), strings.Repeat("E", 8)) {
		t.Fatal(string(env))
	}
}

func TestGzipOAuthResponseHarvested(t *testing.T) {
	b, path := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(gz(t, []byte(`{"access_token":"`+newOAT+`","token_type":"Bearer"}`)))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	ort := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	reqBody := `{"grant_type":"refresh_token","refresh_token":"` + ort + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	resp, body := roundtripStream(t, b, p, raw)
	if resp.Code != 200 {
		t.Fatalf("code %d", resp.Code)
	}
	if resp.Get("Content-Encoding") == "gzip" {
		body = gunzip(t, body)
	}
	if !strings.Contains(string(body), "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT") || strings.Contains(string(body), newOAT) {
		t.Fatalf("response echoed the live token or lost the placeholder: %q", body)
	}
	env, _ := os.ReadFile(path)
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT="+newOAT) {
		t.Fatalf("harvest through gzip failed:\n%s", env)
	}
}

// rotateConn runs fn one time, inline, when the broker writes the 100
// Continue. That write occurs between the snapshot that the fence
// substitutes from and the hold on the refresh slot. In this window, a
// rotation by a different handler can leave this request with a spent
// token.
type rotateConn struct {
	net.Conn
	once sync.Once
	fn   func()
}

func (c *rotateConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("100 Continue")) {
		c.once.Do(c.fn)
	}
	return c.Conn.Write(p)
}

// Two refreshes of one slot. The second refresh is delayed until after the
// first. An old version held the slot only from after the substitution.
// Thus the delayed refresh substituted the refresh token that the first
// refresh had already spent, and sent it to the origin. The origin
// rejected it, and the slot that the agent still trusted named a dead
// credential. Now the broker does not send the spent token. The agent
// gets a 429 while the slot is contended.
func TestRefreshSpentByAnotherHandlerNotSent(t *testing.T) {
	b, _ := testBroker(t)
	slot := "b0b1b2b3b4b5b6b7"
	spent := "sk-ant-ort01-" + strings.Repeat("B", 64)
	rotated := "sk-ant-ort01-" + strings.Repeat("R", 64)
	var sawSpent atomic.Bool
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), spent) {
			sawSpent.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"sk-ant-oat01-` + strings.Repeat("N", 64) + `","refresh_token":"sk-ant-ort01-` + strings.Repeat("S", 64) + `"}`))
	})
	rotate := func() {
		err := b.Store.Harvest(slot, func(cur []secrets.Slot) ([]secrets.Slot, error) {
			return []secrets.Slot{{ID: slot, Kind: "CLAUDE_ORT", Live: rotated}}, nil
		})
		if err != nil {
			t.Error(err)
		}
	}
	reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_` + slot + `_CLAUDE_ORT"}`
	hdr := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: " +
		strconv.Itoa(len(reqBody)) + "\r\n\r\n"
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), &rotateConn{Conn: c2, fn: rotate}) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, hdr); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "100 Continue") {
		t.Fatalf("continue=%q err=%v", line, err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, reqBody); err != nil {
		t.Fatal(err)
	}
	resp, err := httpwire.ReadResponse(br, 1<<20, false)
	c1.Close()
	<-errc
	if err != nil {
		t.Fatal(err)
	}
	if sawSpent.Load() {
		t.Fatal("the origin was sent a refresh token another handler had already spent")
	}
	if resp.Code != 429 {
		t.Fatalf("code %d, want the 429 the agent gets while the slot is contended", resp.Code)
	}
}

// The broker recognises the refresh from the literal target. The wire
// parser accepts an absolute-form target, and each origin resolves it to
// the same endpoint. Thus an absolute-form refresh spends the refresh token
// but does not arm the harvest. The pair that the origin mints back is in
// no snapshot that the scrub holds, so the agent gets it as the origin
// wrote it.
func TestR02AbsoluteFormRefreshLeaksMintedPair(t *testing.T) {
	b, _ := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	newORT := "sk-ant-ort01-" + strings.Repeat("R", 64)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + newOAT + `","refresh_token":"` + newORT + `"}`))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
	raw := "POST https://api.anthropic.com/v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	got := roundtrip(t, b, p, raw)
	if strings.Contains(got, newOAT) || strings.Contains(got, newORT) {
		t.Fatalf("the minted pair reached the agent:\n%s", got)
	}
}

// The rewrite that scrubs the refresh response reads the slots from a
// second Snapshot, and drops its error. If a slot is disabled between the
// harvest write and that second read, the read gives an empty Live. Then
// scrubPairs builds nothing, and the rewrite writes the new pair out
// verbatim. That pair is the one value in the full exchange that the agent
// must never see. The redaction path fails open.
func TestR03ResnapshotFailureLeavesResponseUnscrubbed(t *testing.T) {
	b, _ := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	newORT := "sk-ant-ort01-" + strings.Repeat("R", 64)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		// The store becomes unreadable for this slot while the request is in
		// flight. To the second read, a disable or a re-seal that races a refresh
		// looks like this.
		if err := b.Store.Disable("b0b1b2b3b4b5b6b7"); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + newOAT + `","refresh_token":"` + newORT + `"}`))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	got := roundtrip(t, b, p, raw)
	if strings.Contains(got, newOAT) || strings.Contains(got, newORT) {
		t.Fatalf("the minted pair reached the agent:\n%s", got)
	}
}

// If two parsers can read a refresh body in two ways, the body binds no
// slot. As placeholders, the fence refuses it before the origin. As live
// values, the strict bind finds no refresh_token, and the harvest refuses.
// encoding/json folds case and keeps the last duplicate. Thus each of the
// two forms bound the second slot before, while an origin that read the
// first key rotated the first slot.
func TestRefreshWithAmbiguousKeysBindsNothing(t *testing.T) {
	b, path := testBroker(t)
	rawUpstream(t, b, func(_ int, req *httpwire.Request, _ net.Conn) bool {
		t.Errorf("origin saw %s %s", req.Method, req.Target)
		return false
	})
	before, _ := os.ReadFile(path)
	liveB, liveC := "sk-ant-ort01-"+strings.Repeat("B", 64), "sk-ant-ort01-"+strings.Repeat("D", 64)
	for _, tc := range []struct {
		body string
		code int
		resp string
	}{
		{`{"refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT","REFRESH_TOKEN":"pf_c0c1c2c3c4c5c6c7_CLAUDE_ORT"}`, 503, RefusedBody},
		{`{"refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT","refresh_token":"pf_c0c1c2c3c4c5c6c7_CLAUDE_ORT"}`, 503, RefusedBody},
		{`{"refresh_token":"` + liveB + `","Refresh_Token":"` + liveC + `"}`, 403, "harvest\n"},
	} {
		s := open(t, b, anthropic)
		s.send("POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(tc.body)) + "\r\n\r\n" + tc.body)
		if resp := s.read(); resp.Code != tc.code || string(resp.Body) != tc.resp {
			t.Fatalf("%s: code %d body %q", tc.body, resp.Code, resp.Body)
		}
		s.close()
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("the store changed:\n%s", after)
	}
}

func TestBindRefreshSlotStrict(t *testing.T) {
	b, _ := testBroker(t)
	slots, err := b.Store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	liveB, liveC := "sk-ant-ort01-"+strings.Repeat("B", 64), "sk-ant-ort01-"+strings.Repeat("D", 64)
	for body, want := range map[string]string{
		`{"refresh_token":"` + liveC + `"}`:                                  "c0c1c2c3c4c5c6c7",
		`{"note":"` + liveB + `","refresh_token":"` + liveC + `"}`:           "c0c1c2c3c4c5c6c7",
		`{"refresh_token":"` + liveB + `","REFRESH_TOKEN":"` + liveC + `"}`:  "",
		`{"refresh_token":"` + liveB + `","refresh_token":"` + liveC + `"}`:  "",
		`{"Refresh_token":"` + liveC + `"}`:                                  "",
		`{"refresh_token":"` + liveC + `"}{"refresh_token":"` + liveB + `"}`: "",
	} {
		if got := bindRefreshSlot("", []byte(body), slots); got != want {
			t.Errorf("%s: bound %q want %q", body, got, want)
		}
	}
}

// The broker refuses a refresh response that the harvest cannot read, and
// one that keeps a token shape after the scrub. Each refusal writes one
// strip row with the alert flag, so the operator sees it.
func TestRefusedRefreshResponseAlerts(t *testing.T) {
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	for name, body := range map[string]string{
		"unreadable": `{"access_token":"","token_type":"Bearer"}`,
		"shape left": `{"access_token":"` + newOAT + `","note":"ghp_` + strings.Repeat("Q", 36) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := testBroker(t)
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
			raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
			got := roundtrip(t, b, p, raw)
			if !strings.Contains(got, "harvest\n") {
				t.Fatalf("response %q", got)
			}
			n := 0
			for _, row := range strings.Split(stripRows(t, b.Logs.StripPath), "\n") {
				if strings.Contains(row, `"cause":"harvest_leftover"`) {
					if !strings.Contains(row, `"alert":true`) || !strings.Contains(row, `"slot":"b0b1b2b3b4b5b6b7"`) {
						t.Fatalf("row %s", row)
					}
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d harvest_leftover rows:\n%s", n, stripRows(t, b.Logs.StripPath))
			}
		})
	}
}

// Some servers send an empty or null refresh_token when they do not rotate
// it. The broker stores the new access token only and keeps the old refresh
// token. A refresh_token with a value that the store cannot keep still
// refuses the response.
func TestRefreshResponseEmptyRefreshToken(t *testing.T) {
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	oldORT := "b0b1b2b3b4b5b6b7_CLAUDE_ORT=sk-ant-ort01-" + strings.Repeat("B", 64)
	for _, tc := range []struct {
		ort    string
		code   int
		stored bool
	}{
		{`""`, 200, true},
		{`null`, 200, true},
		{`"bad#value"`, 502, false},
	} {
		t.Run(tc.ort, func(t *testing.T) {
			b, path := testBroker(t)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"` + newOAT + `","refresh_token":` + tc.ort + `}`))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
			raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
			resp, body := roundtripStream(t, b, p, raw)
			if resp.Code != tc.code || strings.Contains(string(body), newOAT) {
				t.Fatalf("code %d body %q", resp.Code, body)
			}
			env, _ := os.ReadFile(path)
			if strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT="+newOAT) != tc.stored || !strings.Contains(string(env), oldORT) {
				t.Fatalf("store:\n%s", env)
			}
		})
	}
}

// Only a 200 is the new pair. An error answer can carry token fields too.
// The broker does not store them: the slot keeps the pair that it had, and
// the agent does not get the values.
func TestRefreshResponseNot200StoresNothing(t *testing.T) {
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	newORT := "sk-ant-ort01-" + strings.Repeat("R", 64)
	for _, code := range []int{400, 401, 500} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			b, path := testBroker(t)
			before, _ := os.ReadFile(path)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","access_token":"` + newOAT + `","refresh_token":"` + newORT + `"}`))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
			raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
			got := roundtrip(t, b, p, raw)
			if strings.Contains(got, newOAT) || strings.Contains(got, newORT) {
				t.Fatalf("the values reached the agent:\n%s", got)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatalf("a %d answer changed the store:\n%s", code, after)
			}
		})
	}
}

// A refresh answer other than a 200 stores nothing. When its body has a
// token field, it could carry a pair of a shape that no token rule knows.
// The broker does not forward such a body: the agent gets the harvest
// refusal, and the operator gets the alert row. An error answer with no
// token field goes to the agent as the origin sent it.
func TestRefreshResponseNot200WithTokenFieldRefused(t *testing.T) {
	one, two := "opaque-value-one", "opaque-value-two"
	for _, tc := range []struct {
		name, ct, body string
		code           int
		refused        bool
	}{
		{"pair", "application/json", `{"error":"x","access_token":"` + one + `","refresh_token":"` + two + `"}`, 400, true},
		{"nested", "application/json", `{"error":{"type":"x"},"data":{"Refresh_Token":"` + two + `"}}`, 401, true},
		{"escaped key", "application/json", `{"access\u005ftoken":"` + one + `"}`, 400, true},
		{"in a list", "application/json", `[{"access_token":"` + one + `"}]`, 500, true},
		{"form", "application/x-www-form-urlencoded", "access_token=" + one + "&refresh_token=" + two, 400, true},
		{"not json", "text/plain", "{ACCESS_TOKEN: " + one, 400, true},
		{"created", "application/json", `{"access_token":"` + one + `"}`, 201, true},
		{"error", "application/json", `{"error":"invalid_grant","error_description":"refresh_token is not valid"}`, 400, false},
		{"html", "text/html", "<html><body>busy</body></html>", 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, path := testBroker(t)
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
			before, _ := os.ReadFile(path)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
			raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
			resp, body := roundtripStream(t, b, p, raw)
			rows := stripRows(t, b.Logs.StripPath)
			if tc.refused {
				if resp.Code != 502 || string(body) != "harvest\n" || !strings.Contains(rows, `"cause":"harvest_leftover"`) {
					t.Fatalf("code %d body %q rows %s", resp.Code, body, rows)
				}
			} else if resp.Code != tc.code || string(body) != tc.body {
				t.Fatalf("code %d body %q", resp.Code, body)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatalf("the store changed:\n%s", after)
			}
		})
	}
}
