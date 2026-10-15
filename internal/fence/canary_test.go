package fence

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

const (
	canarySlot = "d0d1d2d3d4d5d6d7"
	canaryLive = "canary-live-7f3a9c2e51"
)

// canarySlots is labSlots with a CANARY slot added.
func canarySlots() map[string]secrets.Slot {
	m := labSlots()
	m[secrets.EnvKey(canarySlot, corepolicy.KindCanary)] = secrets.Slot{
		ID: canarySlot, Kind: corepolicy.KindCanary,
		Dummy: secrets.Placeholder(canarySlot, corepolicy.KindCanary), Live: canaryLive,
	}
	return m
}

// The shipped policy binds CANARY to no host, also not to the * of the lab
// echo. Thus the fence refuses its placeholder toward all hosts.
func TestCanaryRefusedWhereUnbound(t *testing.T) {
	re, pol := testPolicy(t)
	ph := secrets.Placeholder(canarySlot, corepolicy.KindCanary)
	want := Refusal{Cause: CauseKindNotAllowed, Slot: canarySlot, Kind: corepolicy.KindCanary, Where: "header"}
	for _, sni := range []string{"pf-core-echo.test", "api.anthropic.com", "github.com", "evil.example"} {
		req := parseReq(t, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nAuthorization: Bearer "+ph+"\r\n\r\n")
		_, err := Decide(Ctx{SNI: sni, TokenRE: re}, req, pol, canarySlots())
		var ref *RefusedError
		if !errors.As(err, &ref) || len(ref.Refusals) != 1 || ref.Refusals[0] != want {
			t.Fatalf("%s: %v %+v", sni, err, ref)
		}
	}
}

// The live value strips wherever it occurs, as does each value of a kind
// that the host cannot carry.
func TestCanaryLiveStripped(t *testing.T) {
	re, pol := testPolicy(t)
	rule := "secret:" + secrets.EnvKey(canarySlot, corepolicy.KindCanary)
	for _, sni := range []string{"pf-core-echo.test", "api.anthropic.com", "evil.example"} {
		body := `{"k":"` + canaryLive + `"}`
		raw := "POST /x?k=" + canaryLive + " HTTP/1.1\r\nHost: " + sni + "\r\nX-K: " + canaryLive + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		req := parseReq(t, raw)
		strips, err := Decide(Ctx{SNI: sni, TokenRE: re}, req, pol, canarySlots())
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		if o := decodedWire(t, req, raw); bytes.Contains(o, []byte(canaryLive)) {
			t.Fatalf("%s: canary on the wire: %q", sni, o)
		}
		where := map[string]bool{}
		for _, ev := range strips {
			if ev.Rule == rule {
				where[ev.Where] = true
			}
		}
		if !where["header"] || !where["url"] || !where["body"] {
			t.Fatalf("%s: strips %+v", sni, strips)
		}
	}
}

// A line that names CANARY makes the substitution path attackable.
func TestCanaryInjectsWhereBound(t *testing.T) {
	re, _ := testPolicy(t)
	path := filepath.Join(t.TempDir(), "core.hosts")
	if err := os.WriteFile(path, []byte("api.openai.com OPENAI_API_KEY CANARY\npf-core-echo.test *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pol, err := corepolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ph := secrets.Placeholder(canarySlot, corepolicy.KindCanary)
	req := parseReq(t, "GET / HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer "+ph+"\r\n\r\n")
	if _, err := Decide(Ctx{SNI: "api.openai.com", TokenRE: re}, req, pol, canarySlots()); err != nil || req.Get("Authorization") != "Bearer "+canaryLive {
		t.Fatalf("%v %q", err, req.Get("Authorization"))
	}
	req = parseReq(t, "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer "+ph+"\r\n\r\n")
	var ref *RefusedError
	if _, err := Decide(Ctx{SNI: "pf-core-echo.test", TokenRE: re}, req, pol, canarySlots()); !errors.As(err, &ref) {
		t.Fatalf("echo: %v", err)
	}
}

// A placeholder that ends a streamed body names its slot and kind.
func TestStreamRefusalNamesCanary(t *testing.T) {
	re, pol := testPolicy(t)
	ph := secrets.Placeholder(canarySlot, corepolicy.KindCanary)
	body := strings.Repeat("z", 1<<20+16) + " " + ph + " tail"
	for _, chunkedBody := range []bool{true, false} {
		raw := fuzzPost("/v1/messages", "api.anthropic.com", "X-A", "b", body, chunkedBody)
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecideStream(Ctx{SNI: "api.anthropic.com", TokenRE: re}, req, pol, canarySlots()); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		_, werr := req.WriteTo(&out)
		var sp *StreamPlaceholderError
		if !errors.Is(werr, ErrPlaceholderInStream) || !errors.As(werr, &sp) || sp.Slot != canarySlot || sp.Kind != corepolicy.KindCanary {
			t.Fatalf("chunked=%v: %v %+v", chunkedBody, werr, sp)
		}
		if bytes.Contains(out.Bytes(), []byte(canaryLive)) || bytes.Contains(out.Bytes(), []byte(ph)) {
			t.Fatalf("chunked=%v: placeholder or live value written", chunkedBody)
		}
	}
}
