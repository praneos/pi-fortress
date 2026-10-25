package fence

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

// placeholderVariants are the GITHUB_TOKEN placeholder of slot
// a1b2c3d4e5f67890 with the letter case changed, or with a letter added.
// The origin can undo each change. None of them is the exact placeholder.
var placeholderVariants = []string{
	"pf_a1b2c3d4e5f67890_github_token",
	"pf_a1b2c3d4e5f67890_Github_Token",
	"pf_a1b2c3d4e5f67890_GITHUB_TOKENx",
	"pf_a1b2c3d4e5f67890_GITHUB_TOKEN_x",
	"PF_a1b2c3d4e5f67890_GITHUB_TOKEN",
	"Pf_A1B2C3D4E5F67890_GITHUB_TOKEN",
	"pF_a1b2c3d4e5f67890_github_token",
}

// The fence refuses a placeholder variant in each place where it refuses
// a placeholder. In the credential header of the kind it also refuses: it
// does not substitute the variant, and it does not forward it.
func TestPlaceholderVariantRefusedInEachPlace(t *testing.T) {
	places := map[string]func(v string) string{
		"auth":   func(v string) string { return "GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer " + v + "\r\n\r\n" },
		"header": func(v string) string { return "GET / HTTP/1.1\r\nHost: %s\r\nX-Note: " + v + "\r\n\r\n" },
		"url":    func(v string) string { return "GET /q?t=" + v + " HTTP/1.1\r\nHost: %s\r\n\r\n" },
		"body": func(v string) string {
			b := `{"t":"` + v + `"}`
			return "POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b
		},
		"name":   func(v string) string { return "GET / HTTP/1.1\r\nHost: %s\r\n" + v + ": 1\r\n\r\n" },
		"method": func(v string) string { return v + " / HTTP/1.1\r\nHost: %s\r\n\r\n" },
	}
	for _, sni := range []string{"api.github.com", "example.com"} {
		for place, mk := range places {
			for _, v := range placeholderVariants {
				t.Run(sni+"/"+place+"/"+v, func(t *testing.T) {
					raw := strings.ReplaceAll(mk(v), "%s", sni)
					req := parseReq(t, raw)
					_, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
					if err == nil {
						t.Fatalf("variant forwarded: auth=%q", req.Get("Authorization"))
					}
					var ref *RefusedError
					if !errors.As(err, &ref) {
						t.Fatalf("want a refusal, got %v", err)
					}
				})
			}
		}
	}
}

// Only the exact placeholder gets the live value.
func TestExactPlaceholderStillInjects(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer " + phGH + "\r\n\r\n"
	req := parseReq(t, raw)
	if _, err := Decide(Ctx{SNI: "api.github.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
		t.Fatal(err)
	}
	if got := req.Get("Authorization"); got != "Bearer "+liveGH {
		t.Fatalf("auth %q", got)
	}
}

// The stream guard stops a body with a variant at every read boundary,
// and emits no byte of the variant.
func TestPlaceholderGuardStopsVariant(t *testing.T) {
	for _, v := range placeholderVariants {
		body := strings.Repeat("x", 40) + " " + v + " " + strings.Repeat("y", 40)
		for cut := 1; cut < len(body); cut++ {
			g := newPlaceholderGuard(&chunkReader{src: []byte(body), sizes: []int{cut}})
			out, err := io.ReadAll(g)
			if !errors.Is(err, ErrPlaceholderInStream) {
				t.Fatalf("%s cut %d: err %v", v, cut, err)
			}
			if len(out) > 41 || !bytes.HasPrefix([]byte(body), out) {
				t.Fatalf("%s cut %d: emitted %q", v, cut, out)
			}
		}
	}
}
