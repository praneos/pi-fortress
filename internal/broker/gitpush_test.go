package broker

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

func gitPushList(t *testing.T, body string) *corepolicy.GitPush {
	t.Helper()
	g, err := corepolicy.ParseGitPush(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// gitPushBroker is a broker with the strip log in a temp dir. Its origin
// server records each request line and answers 200.
func gitPushBroker(t *testing.T, list *corepolicy.GitPush) (*Broker, chan string) {
	t.Helper()
	b, _ := testBroker(t)
	b.GitPush = list
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
	seen := make(chan string, 4)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI()
		_, _ = w.Write([]byte("ok"))
	})
	return b, seen
}

var githubPreamble = preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}

// pushRoundtrip answers "<status>\n<body>".
func pushRoundtrip(t *testing.T, b *Broker, p preamble.Preamble, raw string) string {
	t.Helper()
	resp, body := roundtripStream(t, b, p, raw)
	return resp.Status + "\n" + string(body)
}

func gitReq(method, target, body string) string {
	raw := method + " " + target + " HTTP/1.1\r\nHost: github.com\r\nUser-Agent: git/2.43.0\r\n" +
		"Authorization: " + basicHeader("x-access-token", basicGH) + "\r\n"
	if method == "POST" {
		raw += "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	return raw + "\r\n" + body
}

func assertRefusedPush(t *testing.T, b *Broker, seen chan string, resp, where, repo string) {
	t.Helper()
	if !strings.HasPrefix(resp, "503 ") || !strings.HasSuffix(resp, RefusedBody) {
		t.Fatalf("not the uniform refusal: %q", resp)
	}
	select {
	case got := <-seen:
		t.Fatalf("origin saw %q", got)
	default:
	}
	row, _ := os.ReadFile(b.Logs.StripPath)
	for _, want := range []string{`"cause":"git_push_not_allowed"`, `"where":"` + where + `"`, `"repo":"` + repo + `"`, `"host":"github.com"`} {
		if !strings.Contains(string(row), want) {
			t.Fatalf("strip row %q lacks %s", row, want)
		}
	}
	if strings.Contains(string(row), `"alert":true`) {
		t.Fatalf("git push refusal alerted: %q", row)
	}
}

func TestGitPushDeniedPack(t *testing.T) {
	b, seen := gitPushBroker(t, gitPushList(t, "github.com acme/widget\n"))
	resp := pushRoundtrip(t, b, githubPreamble, gitReq("POST", "/acme/Other.git/git-receive-pack", "0000PACK"))
	assertRefusedPush(t, b, seen, resp, "target", "acme/other")
}

func TestGitPushDeniedAdvertisement(t *testing.T) {
	b, seen := gitPushBroker(t, gitPushList(t, "github.com acme/widget\n"))
	resp := pushRoundtrip(t, b, githubPreamble, gitReq("GET", "/acme/other.git/info/refs?service=git-receive-pack", ""))
	assertRefusedPush(t, b, seen, resp, "target", "acme/other")
}

func TestGitPushAmbiguousRefused(t *testing.T) {
	b, seen := gitPushBroker(t, gitPushList(t, "github.com acme/widget\n"))
	resp := pushRoundtrip(t, b, githubPreamble, gitReq("POST", "/acme/widget/../other/git-receive-pack", "0000"))
	assertRefusedPush(t, b, seen, resp, "target_ambiguous", "/acme/widget/../other/git-receive-pack")
}

// No git_push.allow at all: every push is refused.
func TestGitPushMissingFileDenies(t *testing.T) {
	list, err := corepolicy.LoadGitPush(filepath.Join(t.TempDir(), "git_push.allow"))
	if err != nil {
		t.Fatal(err)
	}
	b, seen := gitPushBroker(t, list)
	resp := pushRoundtrip(t, b, githubPreamble, gitReq("GET", "/acme/widget.git/info/refs?service=git-receive-pack", ""))
	assertRefusedPush(t, b, seen, resp, "target", "acme/widget")
}

func TestGitPushAllowedForwards(t *testing.T) {
	b, seen := gitPushBroker(t, gitPushList(t, "github.com acme/*\n"))
	for _, target := range []string{"/acme/widget.git/info/refs?service=git-receive-pack", "/acme/widget.git/git-receive-pack"} {
		method := "GET"
		if strings.HasSuffix(target, "git-receive-pack") {
			method = "POST"
		}
		resp := pushRoundtrip(t, b, githubPreamble, gitReq(method, target, "0000"))
		if !strings.HasPrefix(resp, "200") {
			t.Fatalf("%s: %q", target, resp)
		}
		select {
		case got := <-seen:
			if got != method+" "+target {
				t.Fatalf("origin saw %q", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: origin saw nothing", target)
		}
	}
}

// Clone and fetch of a repo that may not be pushed to still work.
func TestGitPushCloneOfDeniedRepo(t *testing.T) {
	b, seen := gitPushBroker(t, nil)
	for _, c := range []struct{ method, target string }{
		{"GET", "/acme/other.git/info/refs?service=git-upload-pack"},
		{"POST", "/acme/other.git/git-upload-pack"},
	} {
		resp := pushRoundtrip(t, b, githubPreamble, gitReq(c.method, c.target, "0000"))
		if !strings.HasPrefix(resp, "200") {
			t.Fatalf("%s: %q", c.target, resp)
		}
		select {
		case <-seen:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: origin saw nothing", c.target)
		}
	}
	if row, _ := os.ReadFile(b.Logs.StripPath); strings.Contains(string(row), "git_push") {
		t.Fatalf("clone logged a push refusal: %q", row)
	}
}
