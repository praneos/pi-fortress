package broker

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/preamble"
)

// A refresh response that harvest cannot fully read never gives the agent
// a live token. Each body below holds a live token that harvest does not
// store, or stores in a form that the scrub does not find in the raw
// bytes. The broker may refuse the response (502) or scrub it. The test
// checks only that the token does not reach the agent.
func TestRefreshResponseHarvestCannotReadKeepsTokensFromAgent(t *testing.T) {
	liveOAT := "sk-ant-oat01-" + strings.Repeat("L", 64)
	liveORT := "sk-ant-ort01-" + strings.Repeat("M", 64)
	decoy := "sk-ant-oat01-" + strings.Repeat("D", 64)
	okORT := "sk-ant-ort01-" + strings.Repeat("S", 64)
	bigOAT := "sk-ant-oat01-" + strings.Repeat("L", 5000)
	escOAT := "sk-ant-oat01-" + strings.Repeat("L", 32) + `\/` + strings.Repeat("L", 32)
	for _, tc := range []struct{ name, body string }{
		{"nested object", `{"data":{"access_token":"` + liveOAT + `","refresh_token":"` + liveORT + `"}}`},
		{"oversize access token", `{"access_token":"` + bigOAT + `","refresh_token":"` + okORT + `"}`},
		{"escaped access token", `{"access_token":"` + escOAT + `","refresh_token":"` + okORT + `"}`},
		{"duplicate key", `{"access_token":"` + liveOAT + `","access_token":"` + decoy + `","refresh_token":"` + okORT + `"}`},
		{"case-variant key", `{"ACCESS_TOKEN":"` + liveOAT + `","access_token":"` + decoy + `","refresh_token":"` + okORT + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			reqBody := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
			raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
			got := roundtrip(t, b, p, raw)
			// The run of L or M is only in a token that the agent must not see.
			if strings.Contains(got, strings.Repeat("L", 32)) || strings.Contains(got, strings.Repeat("M", 32)) {
				t.Fatalf("a live token that harvest did not read reached the agent:\n%.400s", got)
			}
		})
	}
}
