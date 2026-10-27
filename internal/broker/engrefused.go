package broker

import (
	"errors"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

// errEngineRefused is the result of Handle for a preamble that only
// reports a refusal of the engine. The connection carries no request.
var errEngineRefused = errors.New("broker: engine refusal")

// engineRefused writes the strip.jsonl row for a connection that the engine
// refused before the TLS handshake. The engine cannot write the log: its
// sandbox has no write access to /var/log/pi-fortress. Thus it sends the
// cause here, in a preamble, and the broker writes the row as it writes
// each other row of the fence.
//
// The row does not alert. A blocked name is expected traffic, and the
// fence stopped the connection. The jsonl writer limits the rows of each
// client and writes a summary row for the rows that it drops. The engine
// also sends at most one refusal for each name and client in a minute.
//
// The broker writes the row only for a cause that it knows, for a source
// that it serves, and for a name that its own blocklist has. Thus the
// engine cannot put a different name or cause in the log of the operator.
//
// Each refusal that the broker does not write is an error of Handle, and
// each error is a line in the journal. The engine limits its rows for each
// name and client, but an agent can rotate names. So Handle reports each
// kind of such a refusal at most one time in engineErrEvery.
func (b *Broker) engineRefused(p *preamble.Preamble) error {
	if p.Refused != preamble.RefusedSNIBlocked {
		return b.engineErr("cause", errEngineRefused)
	}
	if b.AgentNet.IsValid() && !b.serves(p.Src) {
		return b.engineErr("src", ErrSrc)
	}
	if !b.Blocked.Has(p.SNI) {
		return b.engineErr("name", errEngineRefused)
	}
	name := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	_ = b.Logs.Refused(jsonl.Refused{
		Host:     name,
		SNI:      p.SNI,
		Where:    "sni",
		Cause:    preamble.RefusedSNIBlocked,
		ClientIP: clientIP(p),
		Threat:   preamble.RefusedSNIBlocked,
	})
	return nil
}

// engineErrEvery is the shortest time between two reports of one kind of
// engine refusal that the broker does not write.
const engineErrEvery = time.Minute

// engineErr gives err when Handle did not report this kind in the last
// engineErrEvery, and nil when it did. The set of kinds is fixed, so the
// table stays small.
func (b *Broker) engineErr(kind string, err error) error {
	now := b.now()
	b.useMu.Lock()
	defer b.useMu.Unlock()
	if t, ok := b.engineSaid[kind]; ok && now.Sub(t) < engineErrEvery {
		return nil
	}
	if b.engineSaid == nil {
		b.engineSaid = map[string]time.Time{}
	}
	b.engineSaid[kind] = now
	return err
}
