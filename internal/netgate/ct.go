package netgate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// ctEvery is the shortest time between two CT requests. observe asks
	// one time in each poll (10 s).
	ctEvery = 2 * time.Second
	// ctTimeout limits one conntrack run, as observe did before.
	ctTimeout = 5 * time.Second
	// ctMax limits the output of one run. A line of -o extended is about
	// 250 bytes, and the table holds at most 131072 entries (apply.sh,
	// nf_conntrack_max). Thus a full table is about 33 MiB.
	ctMax = 48 << 20
)

// ctArgv is the one command of CT. No part of it comes from a client.
var ctArgv = []string{"conntrack", "-L", "-o", "extended"}

// ctVerb is CT: the conntrack table for pf observe. netgate runs the
// fixed command and streams its output back. It does not read the
// output.
type ctVerb struct {
	cfg  *Config
	argv []string

	mu      sync.Mutex
	running bool
	last    time.Time
	log     logLimit
}

func newCTVerb(cfg *Config) *ctVerb {
	argv := cfg.CTArgv
	if len(argv) == 0 {
		argv = ctArgv
	}
	return &ctVerb{cfg: cfg, argv: argv}
}

// serve answers the one CT request of c.
func (v *ctVerb) serve(c *net.UnixConn, first []byte) {
	if err := decodeCTRequest(first); err != nil {
		v.log.say(v.cfg.Now(), v.cfg.Logf, "ct.sock: %v", err)
		return
	}
	status, why := v.run(c)
	c.SetWriteDeadline(time.Now().Add(replyWait))
	c.Write(encodeReply(status, why))
}

// start reports if a run may start now: one at a time, at most one each
// ctEvery.
func (v *ctVerb) start(now time.Time) (bool, string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case v.running:
		return false, "a CT request is in progress"
	case !v.last.IsZero() && now.Sub(v.last) < ctEvery:
		return false, fmt.Sprintf("more than one CT request in %v", ctEvery)
	}
	v.running, v.last = true, now
	return true, ""
}

func (v *ctVerb) done() {
	v.mu.Lock()
	v.running = false
	v.mu.Unlock()
}

func (v *ctVerb) run(c *net.UnixConn) (byte, string) {
	now := v.cfg.Now()
	if ok, why := v.start(now); !ok {
		v.log.say(now, v.cfg.Logf, "CT refused: %s", why)
		return statusRefused, why
	}
	defer v.done()
	ctx, cancel := context.WithTimeout(context.Background(), v.cfg.ctTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.argv[0], v.argv[1:]...)
	var stderr tailBuffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return v.failed(now, err.Error())
	}
	if err := cmd.Start(); err != nil {
		return v.failed(now, err.Error())
	}
	werr := v.stream(c, out)
	if werr != nil {
		// The client is gone or the output is too large. Stop the run.
		cancel()
	}
	err = cmd.Wait()
	switch {
	case werr != nil:
		return v.failed(now, werr.Error())
	case ctx.Err() != nil:
		return v.failed(now, fmt.Sprintf("conntrack ran longer than %v", v.cfg.ctTimeout))
	case err != nil:
		return v.failed(now, fmt.Sprintf("conntrack: %v: %s", err, stderr.String()))
	}
	return statusOK, ""
}

// stream copies the output of conntrack to c, ctChunk bytes a message.
func (v *ctVerb) stream(c *net.UnixConn, r io.Reader) error {
	buf := make([]byte, maxData)
	buf[0] = verbData
	total := 0
	for {
		n, err := io.ReadFull(r, buf[1:])
		if n > 0 {
			total += n
			if total > v.cfg.ctMax {
				return fmt.Errorf("the conntrack table is more than %d bytes", v.cfg.ctMax)
			}
			c.SetWriteDeadline(time.Now().Add(replyWait))
			if _, werr := c.Write(buf[:1+n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
	}
}

func (v *ctVerb) failed(now time.Time, why string) (byte, string) {
	v.log.say(now, v.cfg.Logf, "CT: %s", why)
	return statusFailed, why
}

// tailBuffer keeps the last 256 bytes written to it: the end of the
// stderr of conntrack, for the reason of a failure.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 256 {
		t.b = t.b[len(t.b)-256:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(bytes.ToValidUTF8(t.b, nil))) }
