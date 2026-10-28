package broker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

// A streamed body that makes the token scan do more work than its budget
// stops there. The body has a prefix every few bytes, and it comes in
// chunks of one byte, each in its own write, after a first chunk that
// fills the head. The agent gets the busy 503, not the refusal of a
// body, and the row names the scan budget. The origin never gets the
// full body.
func TestStreamedBodyOverScanBudgetIsBusy(t *testing.T) {
	b, _ := testBroker(t)
	stripLog(t, b)
	var completed atomic.Bool
	done := make(chan struct{}, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err == nil {
			completed.Store(true)
		}
		done <- struct{}{}
	})
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	go func() {
		p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
		if err := preamble.Encode(c1, &p); err != nil {
			return
		}
		head := strings.Repeat("x", 64<<10)
		if _, err := fmt.Fprintf(c1, "POST /v1/x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", len(head), head); err != nil {
			return
		}
		// The writes end when the broker closes the connection.
		for i := 0; i < 64<<10; i++ {
			if _, err := fmt.Fprintf(c1, "1\r\n%c\r\n", "ghp_"[i%4]); err != nil {
				return
			}
		}
		_, _ = io.WriteString(c1, "0\r\n\r\n")
	}()
	_ = c1.SetReadDeadline(time.Now().Add(60 * time.Second))
	resp, err := httpwire.ReadResponseHead(bufio.NewReader(c1), false)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	if resp.Stream != nil {
		got, _ = io.ReadAll(resp.Stream)
	}
	c1.Close()
	<-errc
	if resp.Code != 503 || string(got) != busyBody {
		t.Fatalf("%d %q", resp.Code, got)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	if completed.Load() {
		t.Fatal("the origin got the full body")
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(rows), `"rule":"`+ruleScanBudget+`"`) || !strings.Contains(string(rows), `"where":"body"`) {
		t.Fatalf("log %q", rows)
	}
	if strings.Contains(string(rows), "encoded") || strings.Contains(string(rows), `"cause"`) {
		t.Fatalf("a busy stop logged as a refusal: %q", rows)
	}
}
