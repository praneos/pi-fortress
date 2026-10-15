package broker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

func TestMemBudgetAcquireRelease(t *testing.T) {
	var m memBudget
	if !m.tryAcquire(60, 100) || !m.tryAcquire(40, 100) {
		t.Fatal("room refused")
	}
	if m.tryAcquire(1, 100) {
		t.Fatal("over the limit granted")
	}
	m.release(40)
	if !m.tryAcquire(0, 0) || !m.tryAcquire(-5, 0) {
		t.Fatal("an empty take refused")
	}
	m.release(60)
	if m.inUse.Load() != 0 || m.peak.Load() != 100 {
		t.Fatalf("inUse=%d peak=%d", m.inUse.Load(), m.peak.Load())
	}

	var wg sync.WaitGroup
	var over atomic.Bool
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if m.tryAcquire(7, 50) {
					if m.inUse.Load() > 50 {
						over.Store(true)
					}
					m.release(7)
				}
			}
		}()
	}
	wg.Wait()
	if over.Load() || m.inUse.Load() != 0 || m.peak.Load() > 100 {
		t.Fatalf("over=%v inUse=%d peak=%d", over.Load(), m.inUse.Load(), m.peak.Load())
	}
}

// TestMemBudgetRowRateLimited: one row per where per second. The next row
// counts what the log skipped.
func TestMemBudgetRowRateLimited(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	now := time.Unix(1_800_000_000, 0)
	b.Now = func() time.Time { return now }
	for range 5 {
		b.logMemBudget("10.0.0.2", "h", "body")
	}
	b.logMemBudget("10.0.0.2", "h", "ws")
	now = now.Add(memLogEvery)
	b.logMemBudget("10.0.0.2", "h", "body")
	rows := memRows(t, b)
	if n := strings.Count(rows, ruleMemBudget); n != 3 || !strings.Contains(rows, `"count":5`) {
		t.Fatalf("%d rows: %s", n, rows)
	}
}

var budgetPre = preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}

// exchange runs one connection and returns the response head and body. It
// is safe to call from any goroutine. It returns after Handle returns.
func exchange(b *Broker, raw string) (*httpwire.Response, []byte, error) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	go func() {
		p := budgetPre
		if err := preamble.Encode(c1, &p); err != nil {
			return
		}
		_, _ = io.WriteString(c1, raw)
	}()
	_ = c1.SetReadDeadline(time.Now().Add(20 * time.Second))
	resp, err := httpwire.ReadResponseHead(bufio.NewReader(c1), false)
	var body []byte
	if err == nil && resp.Stream != nil {
		body, err = io.ReadAll(resp.Stream)
	}
	c1.Close()
	<-errc
	return resp, body, err
}

func post(path string, body []byte) string {
	return "POST " + path + " HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
}

func memRows(t *testing.T, b *Broker) string {
	t.Helper()
	raw, _ := os.ReadFile(b.Logs.StripPath)
	return string(raw)
}

// lengthUpstream answers each request with the number of body bytes that
// it got, as a framed response of respLen bytes.
func lengthUpstream(t *testing.T, b *Broker, respLen int) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		got, _ := io.ReadAll(r.Body)
		out := []byte(strconv.Itoa(len(got)) + " ")
		out = append(out, bytes.Repeat([]byte("r"), max(respLen-len(out), 0))...)
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		_, _ = w.Write(out)
	})
	return &hits
}

// TestNormalRequestUnaffectedByBudget: under the budget, the broker buffers
// a body and a response as before (the response keeps its
// Content-Length). The budget saw them, and nothing is logged.
func TestNormalRequestUnaffectedByBudget(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	lengthUpstream(t, b, 2000)
	body := bytes.Repeat([]byte("b"), 1000)
	resp, got, err := exchange(b, post("/v1/x", body))
	if err != nil || resp.Code != 200 || resp.Chunked || resp.ContentLength != 2000 || !strings.HasPrefix(string(got), "1000 ") {
		t.Fatalf("err=%v resp=%+v body=%.20q", err, resp, got)
	}
	if b.MemPeak() < bufCopies*1000 || b.MemInUse() != 0 {
		t.Fatalf("peak=%d inUse=%d", b.MemPeak(), b.MemInUse())
	}
	if rows := memRows(t, b); strings.Contains(rows, ruleMemBudget) {
		t.Fatal(rows)
	}
}

// TestOverBudgetStreams: with no room, the body and the response both take
// the streamed path that each larger one takes. The agent gets the same
// bytes (now chunked), and a row gives the reason.
func TestOverBudgetStreams(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	b.MemBudget = 1
	lengthUpstream(t, b, 2000)
	body := bytes.Repeat([]byte("b"), 1000)
	resp, got, err := exchange(b, post("/v1/x", body))
	if err != nil || resp.Code != 200 || !resp.Chunked || len(got) != 2000 || !strings.HasPrefix(string(got), "1000 ") {
		t.Fatalf("err=%v resp=%+v len=%d body=%.20q", err, resp, len(got), got)
	}
	rows := memRows(t, b)
	for _, want := range []string{`"where":"body"`, `"where":"response"`, `"rule":"mem_budget"`, `"limit":1`} {
		if !strings.Contains(rows, want) {
			t.Fatalf("strip.jsonl lacks %s: %s", want, rows)
		}
	}
	if b.MemInUse() != 0 {
		t.Fatalf("inUse=%d", b.MemInUse())
	}
}

// TestOverBudgetRecompressFallsBackToIdentity: a gzip writer is 0.8 MiB.
// Thus without room for one, the agent gets the inflated, scrubbed body
// uncompressed.
func TestOverBudgetRecompressFallsBackToIdentity(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	b.Recompress = true
	b.MemBudget = gzipWriterCost - 1
	payload := bytes.Repeat([]byte("event: x\n"), 4000)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz(t, payload))
	})
	resp, got, err := exchange(b, "GET /s HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept-Encoding: gzip\r\n\r\n")
	if err != nil || resp.Code != 200 || resp.Get("Content-Encoding") != "" || !bytes.Equal(got, payload) {
		t.Fatalf("err=%v code=%d ce=%q len=%d", err, resp.Code, resp.Get("Content-Encoding"), len(got))
	}
	if rows := memRows(t, b); !strings.Contains(rows, `"where":"gzip"`) {
		t.Fatal(rows)
	}
	if b.MemInUse() != 0 {
		t.Fatalf("inUse=%d", b.MemInUse())
	}
}

// TestOverBudgetRefreshRefused503: a token refresh cannot stream, on
// either side. If there is no room for its body, or for the reply that the
// harvest must hold, the broker answers 503 with a short Retry-After
// before the origin sees it. Thus no refresh token is spent on a reply
// that the broker could not keep.
func TestOverBudgetRefreshRefused503(t *testing.T) {
	reqBody := []byte(`{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`)
	for _, tc := range []struct {
		name   string
		budget int64
	}{
		{"body", 1},
		{"response", bufCopies * int64(len(reqBody))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, path := testBroker(t)
			stripLog(t, b)
			b.MemBudget = tc.budget
			before, _ := os.ReadFile(path)
			hits := lengthUpstream(t, b, 10)
			resp, got, err := exchange(b, post("/v1/oauth/token", reqBody))
			if err != nil || resp.Code != 503 || resp.Get("Retry-After") != "5" || string(got) != busyBody {
				t.Fatalf("err=%v resp=%+v body=%q", err, resp, got)
			}
			if hits.Load() != 0 {
				t.Fatal("the origin saw a refresh the broker could not hold")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("secrets changed")
			}
			if rows := memRows(t, b); !strings.Contains(rows, ruleMemBudget) || !strings.Contains(rows, `"where":"`+tc.name+`"`) {
				t.Fatal(rows)
			}
			if b.MemInUse() != 0 {
				t.Fatalf("inUse=%d", b.MemInUse())
			}
		})
	}
}

// TestWSOverBudgetCloses1013: a message within its own bound but past the
// byte budget ends the session with 1013. The origin gets a going-away
// close and none of the message, and the budget is whole.
func TestWSOverBudgetCloses1013(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	b.MemBudget = 1024
	seen := wsOriginSees(t, b)
	s, resp := openWS(t, b, wsHandshake+"\r\n")
	if resp.Code != 101 {
		t.Fatalf("code %d", resp.Code)
	}
	s.send(string(maskedFrame(true, opText, bytes.Repeat([]byte("x"), 3000))))
	if code := wsCloseCode(t, s.br); code != closeTryAgain {
		t.Fatalf("close code %d, want %d", code, closeTryAgain)
	}
	if err := waitErr(s); !errors.Is(err, ErrWSBusy) {
		t.Fatalf("err=%v want ErrWSBusy", err)
	}
	h, ok := <-seen
	if !ok || h.opcode != opClose || h.length != closeGoingAway {
		t.Fatalf("origin saw %+v (ok=%v), want only a %d close", h, ok, closeGoingAway)
	}
	if rows := memRows(t, b); !strings.Contains(rows, `"where":"ws"`) || !strings.Contains(rows, ruleMemBudget) {
		t.Fatal(rows)
	}
	if b.MemInUse() != 0 {
		t.Fatalf("inUse=%d", b.MemInUse())
	}
}

// TestWSMessageBudgetGivenBack: messages under the budget relay, and the
// broker gives back the bytes of each message. Thus a session can send
// many messages that together are far over the budget.
func TestWSMessageBudgetGivenBack(t *testing.T) {
	b, _ := testBroker(t)
	b.MemBudget = 256 << 10
	msg := bytes.Repeat([]byte("y"), 100<<10)
	var wire []byte
	for range 20 {
		wire = append(wire, maskedFrame(true, opBinary, msg)...)
	}
	sc := fence.NewScanner(fence.Ctx{SNI: "api.anthropic.com"}, &httpwire.Request{Method: "GET", Target: "/"}, b.Policy, nil)
	n, err := b.wsToOrigin(bufio.NewReader(bytes.NewReader(wire)), io.Discard, sc, "h", "ip", &stripCap{}, func() {})
	if !errors.Is(err, io.EOF) || n != int64(20*len(msg)) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b.MemInUse() != 0 || b.MemPeak() > b.MemBudget {
		t.Fatalf("inUse=%d peak=%d", b.MemInUse(), b.MemPeak())
	}
}

// TestMemBudgetZeroAfterLoad runs many concurrent requests against a
// budget far below what they would buffer together. Some of them fail half
// way. The test checks that each request got an answer, that the budget
// never went over, and that the budget is back to 0 after.
func TestMemBudgetZeroAfterLoad(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	b.MemBudget = 2 << 20
	const size = 200 << 10
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if r.URL.Path == "/die" {
			_, _ = w.Write(got[:size/2])
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write(bytes.Repeat([]byte("r"), size))
	})
	body := bytes.Repeat([]byte("b"), size)
	const n = 48
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := "/ok"
			if i%4 == 0 {
				path = "/die"
			}
			if i%6 == 1 {
				path = "/v1/oauth/token"
			}
			resp, got, err := exchange(b, post(path, body))
			switch {
			case path == "/die":
				return
			case path == "/v1/oauth/token":
				// It has no ORT: an ordinary request on a path that always buffers. The
				// origin answers it, or the broker refuses it with 503.
				if err != nil || (resp.Code != 200 && resp.Code != 503) {
					errs <- fmt.Errorf("oauth path: err=%v resp=%+v", err, resp)
				}
			case err != nil || resp.Code != 200 || len(got) != size:
				errs <- fmt.Errorf("%s: err=%v resp=%+v len=%d", path, err, resp, len(got))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if b.MemInUse() != 0 {
		t.Fatalf("inUse=%d after load", b.MemInUse())
	}
	if b.MemPeak() > b.MemBudget || b.MemPeak() == 0 {
		t.Fatalf("peak=%d budget=%d", b.MemPeak(), b.MemBudget)
	}
	if rows := memRows(t, b); !strings.Contains(rows, ruleMemBudget) {
		t.Fatal("a load over budget logged nothing")
	}
}
