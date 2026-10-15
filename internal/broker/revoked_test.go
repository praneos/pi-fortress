package broker

import (
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/preamble"
)

// The broker blanks the value of a disabled or expired slot, so that it
// never injects that value. Before, the value also dropped out of the
// strip set: the fence stopped knowing the one credential that the
// operator had just revoked. The broker strips it everywhere, its own core
// host included, and still never injects it.
func TestRevokedSlotValueStillStripped(t *testing.T) {
	const slot = "b0b1b2b3b4b5b6b7"
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	for _, tc := range []struct {
		name   string
		revoke func(t *testing.T, b *Broker)
	}{
		{"disabled", func(t *testing.T, b *Broker) {
			if err := b.Store.Disable(slot); err != nil {
				t.Fatal(err)
			}
		}},
		{"expired", func(t *testing.T, b *Broker) {
			if err := b.Store.SetExpiry(slot, time.Now().Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			tc.revoke(t, b)
			var seen atomic.Value
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				seen.Store(r.Header.Get("X-Note") + "|" + string(body))
				_, _ = w.Write([]byte("ok"))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			body := `{"note":"` + live + `"}`
			raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nX-Note: " + live +
				"\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			if got := roundtrip(t, b, p, raw); got != "ok" {
				t.Fatalf("body %q", got)
			}
			got, _ := seen.Load().(string)
			if got == "" || strings.Contains(got, live) || strings.Count(got, "pf_stripped") != 2 {
				t.Fatalf("origin saw %q", got)
			}

			// The fence still refuses the placeholder. It does not substitute it.
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("origin saw Authorization %q", r.Header.Get("Authorization"))
			})
			raw = "GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_" + slot + "_CLAUDE_OAT\r\n\r\n"
			if got := roundtrip(t, b, p, raw); got != RefusedBody {
				t.Fatalf("placeholder of a revoked slot: %q", got)
			}
		})
	}
}
