package admin

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/secrets"
)

// The key is in the memory of the broker, not in this process. The broker
// does the substitution, so a Store unlocked here would open nothing that
// matters. Thus these verbs are a client of the root-only admin socket of
// the broker. That socket is intentionally not the one that the engine
// dials. Refer to internal/broker/admin.go.
func (c *Config) adminSock() string {
	if c.BrokerAdmin != "" {
		return c.BrokerAdmin
	}
	return secrets.AdminSock
}

var ErrBrokerAdmin = errors.New("broker admin socket unreachable; is pf-broker running?")

func (c *Config) brokerAsk(ctx context.Context, line string) (string, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.adminSock())
	if err != nil {
		return "", ErrBrokerAdmin
	}
	defer conn.Close()
	// Generous: scrypt on a Pi takes a moment, and the broker answers only
	// after it derives and checks the key. A caller that only wants a status
	// can set a shorter context deadline. A wait of a minute for a status is a
	// frozen operator screen.
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && reply == "" {
		return "", err
	}
	reply = strings.TrimSpace(reply)
	if rest, ok := strings.CutPrefix(reply, "err "); ok {
		return "", errors.New(rest)
	}
	return reply, nil
}

// SecretsState is what the operator surfaces show: sealed or not, open
// or not, and any fault. Never a value.
func (c *Config) SecretsState(ctx context.Context) (string, error) {
	return c.brokerAsk(ctx, secrets.AdminState)
}

// UnlockSecrets sends the passphrase and nothing else. The code never logs
// it and never writes it down. The caller must first read it with the echo
// off.
func (c *Config) UnlockSecrets(ctx context.Context, passphrase string) error {
	if passphrase == "" {
		return errors.New("no passphrase")
	}
	_, err := c.brokerAsk(ctx, secrets.AdminUnlock+" "+base64.StdEncoding.EncodeToString([]byte(passphrase)))
	return err
}

func (c *Config) LockSecrets(ctx context.Context) error {
	_, err := c.brokerAsk(ctx, secrets.AdminLock)
	return err
}

// SlotHour is the last hour of one slot as the broker counted it: the
// requests that it substituted, and the request-body bytes that went out
// with them.
type SlotHour struct {
	Requests int64 `json:"requests"`
	Bytes    int64 `json:"bytes"`
}

// SlotHours asks the broker for the hour of each slot. The window is in the
// memory of that process and nowhere on disk. Thus this is the only way to
// read it. A broker that does not run has no answer, not a zero. The caller
// gets to know which it got. If an idle slot and a dead fence look the
// same, an operator no longer watches.
func (c *Config) SlotHours(ctx context.Context) (map[string]SlotHour, error) {
	line, err := c.brokerAsk(ctx, secrets.AdminBudget)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(line)
	out := make(map[string]SlotHour, len(f)/3)
	for i := 0; i+2 < len(f); i += 3 {
		reqs, err1 := strconv.ParseInt(f[i+1], 10, 64)
		bytes, err2 := strconv.ParseInt(f[i+2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, errors.New("broker: malformed budget line")
		}
		out[f[i]] = SlotHour{Requests: reqs, Bytes: bytes}
	}
	return out, nil
}

// SecretsWarning is the standing condition that an operator must see from
// all screens, in the same slot that the stale-feed warning uses. Only the
// two states that make credentials fail give a warning. An unreachable
// socket is a dead broker, and the units screen already reports it. A
// repeat here would make the warning permanent on a box that does not run
// the fence at all.
func (c *Config) SecretsWarning(ctx context.Context) string {
	st, err := c.SecretsState(ctx)
	if err != nil {
		return ""
	}
	switch {
	case strings.HasPrefix(st, "fault "):
		return "credentials: " + strings.TrimPrefix(st, "fault ") + "; every substitution is refused"
	case st == "sealed locked":
		return "credentials: store sealed since boot; nothing is substituted until pf unlock"
	}
	return ""
}
