// Package tlssni reads only the client->server bytes of a TCP connection to
// port 443. It gets the server_name from the TLS ClientHello. Thus a gateway
// can route on SNI before bytes get to the backend. Parse is incremental.
// The caller gives it all the bytes that arrived until now (from byte zero
// of the stream). Parse then tells how many more bytes it needs. Thus this
// package has no buffering policy.
//
// internal/hello is the ClientHello parser of the agent fence (SNI and
// ALPN). The two stay separate intentionally. This package is
// incremental and returns only what routing needs, normalized. hello
// checks the full extension block and keeps the raw name. FuzzSNIAgree makes
// sure that the two give the same server name for each hello that both
// accept.
package tlssni

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	// ErrNotTLS means that the bytes until now cannot be the start of a TLS
	// handshake record with a ClientHello (wrong content type, wrong record
	// version, or a handshake type other than ClientHello).
	ErrNotTLS = errors.New("tlssni: not a TLS ClientHello")
	// ErrMalformed means that the input has a TLS shape, but its lengths
	// or structure are not correct. An extension type that occurs two times
	// is also this error.
	ErrMalformed = errors.New("tlssni: malformed ClientHello")
)

// Hello is what a gateway needs from a ClientHello to route the connection.
type Hello struct {
	// ServerName is the SNI host_name, in lowercase, with no trailing dot.
	// It is empty if the extension was absent or had no name.
	ServerName string
	// ECH is true when the encrypted_client_hello extension (0xfe0d) is
	// present. In that case, ServerName is the outer (public) name, not
	// the real origin server.
	ECH bool
}

// maxRecordLen is the largest legal TLS record payload: 2^14 plaintext plus
// the 256 bytes that some stacks also allow for TLS 1.3 record padding.
const maxRecordLen = 16384 + 256

// maxHandshake is the maximum handshake data (across all fragmenting
// records) that Parse collects when it looks for a ClientHello. No real
// browser ClientHello is near this size. A larger hello is an attack or
// noise. In both cases, the code does not buffer it.
const maxHandshake = 64 << 10

// Parse examines buf, the stream of the client from its first byte, for a
// complete ClientHello. It never panics. Each input gives a parsed Hello, a
// request for more bytes, or one of ErrNotTLS/ErrMalformed.
func Parse(buf []byte) (Hello, int, error) {
	if len(buf) == 0 {
		return Hello{}, 5, nil
	}
	if buf[0] != 0x16 {
		return Hello{}, 0, ErrNotTLS
	}

	var hs []byte // handshake bytes, reassembled across fragmenting records
	off := 0
	for {
		if len(buf)-off < 5 {
			return Hello{}, 5 - (len(buf) - off), nil
		}
		if buf[off] != 0x16 {
			// The first record decides if the stream is TLS. A problem
			// after that (for example, an alert) means that the handshake
			// in assembly is broken. It does not mean that it was never TLS.
			if off == 0 {
				return Hello{}, 0, ErrNotTLS
			}
			return Hello{}, 0, ErrMalformed
		}
		major, minor := buf[off+1], buf[off+2]
		if major != 0x03 {
			if off == 0 {
				return Hello{}, 0, ErrNotTLS
			}
			return Hello{}, 0, ErrMalformed
		}
		if minor < 0x01 || minor > 0x04 {
			return Hello{}, 0, ErrMalformed
		}
		recLen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
		if recLen == 0 || recLen > maxRecordLen {
			return Hello{}, 0, ErrMalformed
		}
		avail := len(buf) - off - 5
		if avail < recLen {
			return Hello{}, recLen - avail, nil
		}
		hs = append(hs, buf[off+5:off+5+recLen]...)
		off += 5 + recLen
		if len(hs) > maxHandshake {
			return Hello{}, 0, ErrMalformed
		}
		if len(hs) < 4 {
			continue
		}
		if hs[0] != 1 {
			return Hello{}, 0, ErrNotTLS
		}
		bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		total := 4 + bodyLen
		if total > maxHandshake {
			return Hello{}, 0, ErrMalformed
		}
		if len(hs) < total {
			if off == len(buf) {
				return Hello{}, total - len(hs), nil
			}
			continue
		}
		return parseClientHello(hs[4:total])
	}
}

// parseClientHello reads a complete ClientHello body as RFC 8446 §4.1.2 gives:
// legacy_version(2) random(32) session_id cipher_suites compression_methods
// extensions(optional).
func parseClientHello(body []byte) (Hello, int, error) {
	off := 2 + 32 // legacy_version, random
	if off >= len(body) {
		return Hello{}, 0, ErrMalformed
	}
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return Hello{}, 0, ErrMalformed
	}
	off += sidLen

	if off+2 > len(body) {
		return Hello{}, 0, ErrMalformed
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if csLen == 0 || off+csLen > len(body) {
		return Hello{}, 0, ErrMalformed
	}
	off += csLen

	if off >= len(body) {
		return Hello{}, 0, ErrMalformed
	}
	cmLen := int(body[off])
	off++
	if cmLen == 0 || off+cmLen > len(body) {
		return Hello{}, 0, ErrMalformed
	}
	off += cmLen

	if off == len(body) {
		return Hello{}, 0, nil // no extensions block: no SNI, no ECH
	}
	if off+2 > len(body) {
		return Hello{}, 0, ErrMalformed
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extLen != len(body) {
		return Hello{}, 0, ErrMalformed
	}

	// No extension type may repeat (RFC 8446 4.2), as crypto/tls and
	// internal/hello require. A second server_name could give a name here
	// that is not the name that the TLS stack of the origin reads.
	var h Hello
	seen := map[uint16]bool{}
	end := off + extLen
	for off < end {
		if off+4 > end {
			return Hello{}, 0, ErrMalformed
		}
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extDataLen > end || seen[extType] {
			return Hello{}, 0, ErrMalformed
		}
		seen[extType] = true
		data := body[off : off+extDataLen]
		off += extDataLen

		switch extType {
		case 0x0000: // server_name
			name, err := parseServerName(data)
			if err != nil {
				return Hello{}, 0, err
			}
			h.ServerName = name
		case 0xfe0d: // encrypted_client_hello
			h.ECH = true
		}
	}
	return h, 0, nil
}

// parseServerName gets the host_name from the data of a server_name
// extension (RFC 6066 §3): ServerNameList = 2-byte length, then entries of
// type(1) len(2) name. The list must not hold more than one name of the
// same type (RFC 6066 §3). A list with two entries of one type is
// malformed, so no name in it is used.
func parseServerName(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrMalformed
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	off := 2
	end := off + listLen
	if end > len(data) {
		return "", ErrMalformed
	}
	var seen [256]bool
	host := ""
	for off < end {
		if off+3 > end {
			return "", ErrMalformed
		}
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+nameLen > end {
			return "", ErrMalformed
		}
		name := data[off : off+nameLen]
		off += nameLen
		if seen[nameType] {
			return "", ErrMalformed
		}
		seen[nameType] = true
		if nameType == 0 {
			s, err := normalizeHostName(name)
			if err != nil {
				return "", err
			}
			host = s
		}
	}
	return host, nil
}

// normalizeHostName changes the name to lowercase and removes a trailing dot.
// It rejects all values that are not a possible DNS name. It rejects an SNI
// value of only digits and dots (an IP literal, or garbage). A router that
// decides on SNI must never use an IP as a routable hostname.
func normalizeHostName(raw []byte) (string, error) {
	s := strings.ToLower(string(raw))
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return "", ErrMalformed
	}
	digitsAndDotsOnly := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c == '-', c == '_':
			digitsAndDotsOnly = false
		case c >= '0' && c <= '9', c == '.':
			// the all-digits-and-dots rejection still applies
		default:
			return "", ErrMalformed
		}
	}
	if digitsAndDotsOnly {
		return "", ErrMalformed
	}
	// Each label has 1 to 63 bytes. This also refuses a second trailing dot.
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", ErrMalformed
		}
	}
	return s, nil
}
