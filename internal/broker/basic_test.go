package broker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

const basicGH = "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// The git credential helper sends the placeholder as a Basic password.
// The origin decodes it and finds the live token. The broker writes the
// use row of the slot as for a bearer.
func TestBasicUpstreamSeesInjected(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
	seen := make(chan string, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		u, pw, ok := r.BasicAuth()
		seen <- fmt.Sprint(ok, " ", u, ":", pw)
	})
	p := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "GET /o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\nAuthorization: " + basicHeader("x-access-token", basicGH) + "\r\n\r\n"
	_ = roundtrip(t, b, p, raw)
	select {
	case got := <-seen:
		if got != "true x-access-token:lab_fence_github" {
			t.Fatal(got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream got no request")
	}
	use, _ := os.ReadFile(b.Logs.UsePath)
	if !strings.Contains(string(use), "a1b2c3d4e5f67890") {
		t.Fatalf("no use row: %q", use)
	}
}

// The shape of git push over HTTPS: a chunked receive-pack POST of more
// than 1 MiB behind Expect: 100-continue, with the placeholder in Basic
// auth. The origin gets the live credential and every body byte.
func TestGitPushShapeWithBasic(t *testing.T) {
	b, _ := testBroker(t)
	b.GitPush = gitPushList(t, "github.com o/r\n")
	type got struct{ auth, sum string }
	seen := make(chan got, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		u, pw, _ := r.BasicAuth()
		seen <- got{u + ":" + pw, strconv.FormatInt(n, 10) + " " + hex.EncodeToString(h.Sum(nil))}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_, _ = w.Write([]byte("ok"))
	})
	body := make([]byte, 1<<20+300_000)
	for i := range body {
		body[i] = byte(i*7 + i/4099)
	}
	sum := sha256.Sum256(body)
	want := strconv.Itoa(len(body)) + " " + hex.EncodeToString(sum[:])

	p := preamble.Preamble{SNI: "github.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	hdr := "POST /o/r.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\nUser-Agent: git/2.43.0\r\n" +
		"Authorization: " + basicHeader("x-access-token", basicGH) + "\r\n" +
		"Content-Type: application/x-git-receive-pack-request\r\nAccept: application/x-git-receive-pack-result\r\n" +
		"Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n"
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, hdr); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "100 Continue") {
		t.Fatalf("continue=%q err=%v", line, err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	werr := make(chan error, 1)
	go func() {
		cw := httpwire.NewChunkedWriter(c1)
		for i := 0; i < len(body); i += 65520 {
			if _, err := cw.Write(body[i:min(i+65520, len(body))]); err != nil {
				werr <- err
				return
			}
		}
		werr <- cw.Close()
	}()
	resp, err := httpwire.ReadResponse(br, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-werr; err != nil {
		t.Fatal(err)
	}
	c1.Close()
	<-errc
	if !strings.HasPrefix(resp.Status, "200") || string(resp.Body) != "ok" {
		t.Fatalf("%s %q", resp.Status, resp.Body)
	}
	g := <-seen
	if g.auth != "x-access-token:lab_fence_github" || g.sum != want {
		t.Fatalf("auth %q body %q want %q", g.auth, g.sum, want)
	}
}
