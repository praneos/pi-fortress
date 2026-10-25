// Package preamble is the framed header that the engine writes before a
// relayed connection: connection id, addresses, SNI and ALPN. For a
// connection that the engine refused, it also carries the cause.
// internal/engine encodes it. internal/broker decodes it.
package preamble

import (
	"pi-fortress/internal/hello"

	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
)

const Magic = "PFB1"
const maxJSON = 8192

type Preamble struct {
	ConnID  string         `json:"conn_id"`
	Src     netip.AddrPort `json:"src"`
	OrigDst netip.AddrPort `json:"orig_dst"`
	SNI     string         `json:"sni"`
	ALPN    string         `json:"alpn"`
	// Refused, when set, is the cause for which the engine refused this
	// connection before the TLS handshake. No request follows. The broker
	// only writes the row for it (internal/broker engrefused.go).
	Refused string `json:"refused,omitempty"`
}

// RefusedSNIBlocked is the cause for a name that the blocklist has.
const RefusedSNIBlocked = "sni_blocked"

// ValidSNI rejects all names that hello.ValidHostName rejects, and the empty
// name. Thus a broker never judges a name that the client did not send. It
// also never dials an origin server that it cannot verify.
func ValidSNI(s string) bool { return s != "" && hello.ValidHostName(s) }

func Encode(w io.Writer, p *Preamble) error {
	if !ValidSNI(p.SNI) {
		return errors.New("preamble: sni is not a hostname")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(b) > maxJSON {
		return errors.New("preamble: json too large")
	}
	hdr := make([]byte, 4+2)
	copy(hdr, Magic)
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(b)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func Decode(r *bufio.Reader) (*Preamble, error) {
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != Magic {
		return nil, errors.New("preamble: bad magic")
	}
	n := int(binary.BigEndian.Uint16(hdr[4:]))
	if n < 2 || n > maxJSON {
		return nil, errors.New("preamble: bad length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var p Preamble
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	if !ValidSNI(p.SNI) {
		return nil, errors.New("preamble: sni is not a hostname")
	}
	return &p, nil
}
