package broker

import (
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/preamble"
)

// Echo selection and substitution read different identities. The broker
// selects the echo from the original destination. The fence substitutes
// against the SNI and the Host. A connection to the address of the open
// fixture, with the SNI and Host of a permitted origin, must not get the
// credential substituted in, because the open echo reflects
// Authorization back. The broker answers it with the uniform refusal
// and never dials. Selection is the two fixture addresses only (isEcho),
// and dest.Allowed admits only those two from 192.0.2.0/24. Thus an
// unassigned address in the fixture net gets the ssrf refusal at the
// preamble: no echo, no dial, no fence.
func TestOpenEchoReflectsSubstitutedCredential(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	raw := "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Authorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
	newBroker := func(t *testing.T) (*Broker, *atomic.Bool) {
		b, _ := testBroker(t)
		b.LabEcho = false
		var dialed atomic.Bool
		b.DialTLS = noDial(&dialed)
		return b, &dialed
	}

	t.Run("open fixture address", func(t *testing.T) {
		// The resolver publishes it outside the lab too, and it is carved out of
		// the agent's direct-IP drop. Thus the agent can reach it by address.
		b, dialed := newBroker(t)
		p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("192.0.2.3:443")}
		got := roundtrip(t, b, p, raw)
		if strings.Contains(got, live) {
			t.Fatalf("live credential reflected to the agent:\n%s", got)
		}
		if got != RefusedBody {
			t.Fatalf("want the substitution refusal, got:\n%s", got)
		}
		if dialed.Load() {
			t.Fatal("the open fixture dialled out")
		}
	})

	t.Run("unassigned address in the fixture net", func(t *testing.T) {
		b, dialed := newBroker(t)
		p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("192.0.2.7:443")}
		body, err := refusedAtPreamble(t, b, p)
		if body != "ssrf\n" || !errors.Is(err, ErrSSRF) {
			t.Fatalf("body=%q err=%v", body, err)
		}
		if dialed.Load() {
			t.Fatal("dialled an address outside the two fixtures")
		}
	})
}

// The fence examines the Host as well as the SNI. Thus it refuses an
// echo Host over a permitted SNI and does not substitute. This guard
// holds. The echo selection above goes around it through the original
// destination.
func TestEchoHostOverPermittedSNIRefused(t *testing.T) {
	b, _ := testBroker(t)
	b.LabEcho = false
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "GET /v1/messages HTTP/1.1\r\nHost: pf-open-echo.test\r\n" +
		"Authorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
	if got := roundtrip(t, b, p, raw); !strings.Contains(got, RefusedBody) {
		t.Fatalf("want the substitution refusal, got:\n%s", got)
	}
}
