package broker

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"

	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

var (
	echoCore = netip.MustParseAddr("192.0.2.2")
	echoOpen = netip.MustParseAddr("192.0.2.3")
)

// isEcho is the two fixture addresses and not the net that contains them.
// echoRole names only those two and answers "open" for all other
// addresses. Thus, when this matched the full prefix, each unassigned
// address in it was an ungated echo, and an echo that reflected its
// input. The net is carved out of the agent's direct-IP drop as a whole,
// so all 254 were dialable. The fixtures need only two addresses.
func isEcho(dst netip.AddrPort) bool {
	if !dst.IsValid() {
		return false
	}
	a := dst.Addr()
	return a == echoCore || a == echoOpen
}

func echoHost(sni, host string) bool {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if i := strings.LastIndex(name, ":"); i > 0 && !strings.Contains(name, "]") {
		name = name[:i]
	}
	if name == "" {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	}
	switch name {
	case "pf-core-echo.test", "pf-open-echo.test":
		return true
	}
	sni = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	return sni == "pf-core-echo.test" || sni == "pf-open-echo.test"
}

func echoRole(p *preamble.Preamble, req *httpwire.Request) string {
	if p.OrigDst.IsValid() {
		switch p.OrigDst.Addr() {
		case echoCore:
			return "core"
		case echoOpen:
			return "open"
		}
	}
	host := strings.ToLower(strings.TrimSuffix(req.Get("Host"), "."))
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	switch {
	case sni == "pf-core-echo.test" || host == "pf-core-echo.test":
		return "core"
	case sni == "pf-open-echo.test" || host == "pf-open-echo.test":
		return "open"
	default:
		return "open"
	}
}

func jsonBody(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return b
}

func (b *Broker) echo(w io.Writer, p *preamble.Preamble, req *httpwire.Request, slots map[string]secrets.Slot, harvestSlot string) error {
	role := echoRole(p, req)
	if role == "core" && fence.IsOAuthPath(req.Target) {
		payload := map[string]any{
			"access_token":  "sk-ant-oat01-" + strings.Repeat("N", 64),
			"refresh_token": "sk-ant-ort01-" + strings.Repeat("R", 64),
			"expires_in":    3600,
			"token_type":    "Bearer",
		}
		resp := &httpwire.Response{Proto: "HTTP/1.1", Status: "200 OK", Code: 200, Body: jsonBody(payload)}
		resp.SetInPlace("Content-Type", "application/json")
		minted, err := b.harvest(harvestSlot, resp)
		if err != nil {
			return err
		}
		if _, err := rewriteResponse(resp, withMinted(slots, minted)); err != nil {
			return err
		}
		_, err = resp.WriteTo(w)
		return err
	}
	auth := req.Get("Authorization")
	host := req.Get("Host")
	var payload map[string]any
	if role == "core" {
		payload = map[string]any{
			"authorization": auth,
			"host":          host,
			"substituted":   auth != "" && len(secrets.FindPlaceholderSpans([]byte(auth))) == 0,
			"sni":           p.SNI,
		}
	} else {
		payload = map[string]any{
			"authorization": auth,
			"host":          host,
			"stripped":      strings.Contains(auth, fence.StripRepl),
		}
	}
	resp := &httpwire.Response{Proto: "HTTP/1.1", Status: "200 OK", Code: 200, Body: jsonBody(payload)}
	resp.SetInPlace("Content-Type", "application/json")
	if role != "core" {
		// The core fixture is lab-only and reflects its input on purpose. The
		// lab shows the substituted value to prove that substitution occurred
		// at all. This fixture is reachable from a shipped box. Thus the same
		// reflection would give the agent the credential that the placeholder
		// must keep from it. Scrub it the same as each origin response. Then the
		// invariant does not depend on which fixture was selected.
		if _, err := rewriteResponse(resp, slots); err != nil {
			return err
		}
	}
	_, err := resp.WriteTo(w)
	return err
}
