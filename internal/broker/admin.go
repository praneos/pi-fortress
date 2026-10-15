package broker

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"pi-fortress/internal/secrets"
)

// The unlock channel is a second socket, and it must be a second socket.
// The engine dials the socket that exists,
// /run/pi-fortress/broker/broker.sock. The engine is the process that
// terminates untrusted agent TLS. A verb that gives the broker its
// decryption key must not be reachable from there, whatever the engine
// does at that time. Thus admin.sock has mode 0600 and pf-broker owns it.
// The fence cannot reach it at all. Root can still connect, because root
// bypasses DAC.
//
// The protocol has three lines because it does three things. The
// passphrase is base64 on the wire only so that a line reader can ignore
// its content. This encoding is not for secrecy. The socket is the
// confidentiality boundary.
type Admin struct {
	Store *secrets.Store
	// Budget answers the BUDGET verb from the in-memory hour of the broker
	// (budget.go). It is a function and not the broker itself, so the
	// listener that gives out the decryption key keeps its one dependency.
	// A nil Budget answers an empty line.
	Budget func() string
	// Now and Sleep are hooks, so a test of the backoff below does not
	// use wall-clock time.
	Now   func() time.Time
	Sleep func(time.Duration)

	mu     sync.Mutex
	misses int
}

const (
	adminBackoffStep = time.Second
	adminBackoffMax  = 30 * time.Second
)

func (a *Admin) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Admin) sleep(d time.Duration) {
	if a.Sleep != nil {
		a.Sleep(d)
		return
	}
	time.Sleep(d)
}

// penalty grows with each consecutive failure and resets after a
// success. The socket is root-only, so this penalty is small by design.
// It is here because it is cheap. Also, a root-only channel is still a
// channel, and a person can sit in front of it.
func (a *Admin) penalty() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := time.Duration(a.misses) * adminBackoffStep
	return min(d, adminBackoffMax)
}

func (a *Admin) missed(ok bool) {
	a.mu.Lock()
	if ok {
		a.misses = 0
	} else {
		a.misses++
	}
	a.mu.Unlock()
}

// Serve handles one admin connection. A malformed line gets an error,
// not a close. The caller is an operator tool, and an error that tells
// it the problem costs nothing here.
func (a *Admin) Serve(ctx context.Context, c net.Conn) error {
	defer c.Close()
	_ = c.SetDeadline(a.now().Add(2 * time.Minute))
	br := bufio.NewReader(&limitReader{r: c, n: 8 << 10})
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	verb, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
	out, err := a.do(strings.ToUpper(verb), arg)
	if err != nil {
		_, werr := c.Write([]byte("err " + oneLine(err.Error()) + "\n"))
		return werr
	}
	_, werr := c.Write([]byte(out + "\n"))
	return werr
}

var errAdminVerb = errors.New("broker: unknown admin verb")

func (a *Admin) do(verb, arg string) (string, error) {
	switch verb {
	case secrets.AdminState:
		return a.state()
	case secrets.AdminLock:
		a.Store.Lock()
		return "ok", nil
	case secrets.AdminUnlock:
		return a.unlock(arg)
	case secrets.AdminBudget:
		if a.Budget == nil {
			return "", nil
		}
		return a.Budget(), nil
	}
	return "", errAdminVerb
}

func (a *Admin) state() (string, error) {
	st, err := a.Store.State()
	if err != nil {
		return "", err
	}
	switch {
	case st.Fault != "":
		return "fault " + oneLine(st.Fault), nil
	case !st.Sealed:
		return "plaintext", nil
	case st.Unlocked:
		return "sealed unlocked", nil
	}
	return "sealed locked", nil
}

func (a *Admin) unlock(arg string) (string, error) {
	pass, err := base64.StdEncoding.DecodeString(strings.TrimSpace(arg))
	if err != nil {
		return "", errors.New("broker: passphrase is not base64")
	}
	if d := a.penalty(); d > 0 {
		a.sleep(d)
	}
	err = a.Store.Unlock(pass)
	// Set it to zero. The derived key stays. The passphrase does not need to.
	for i := range pass {
		pass[i] = 0
	}
	a.missed(err == nil)
	if err != nil {
		return "", err
	}
	return "ok", nil
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

type limitReader struct {
	r net.Conn
	n int
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("broker: admin request too long")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}
