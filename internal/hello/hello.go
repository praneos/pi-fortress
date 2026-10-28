// Package hello parses a TLS ClientHello into its SNI and ALPN list.
// internal/peekconn and internal/engine call it.
//
// internal/tlssni also parses ClientHellos, for the house SNI check. It
// stays separate intentionally:
//   - It reads packets when they are queued. Thus it tells how many more
//     bytes to wait for across fragmenting records.
//   - It needs only the name and the ECH flag.
//   - It changes the name to lowercase and refuses a name of digits and dots.
//
// This package keeps the raw name and checks the full extension block.
// FuzzSNIAgree in tlssni makes sure that the two give the same server name
// for each hello that both accept.
package hello

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrIncomplete = errors.New("hello: incomplete")
	ErrMalformed  = errors.New("hello: malformed")
)

type Hello struct {
	SNI    string
	ALPNs  []string
	H2Only bool
}

func Parse(b []byte) (*Hello, error) {
	raw, err := extractBody(b)
	if err != nil {
		return nil, err
	}
	return parseBody(raw)
}

func extractBody(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, ErrIncomplete
	}
	if b[0] == 0x16 {
		var hs []byte
		off := 0
		for off < len(b) {
			if len(b)-off < 5 {
				return nil, ErrIncomplete
			}
			if b[off] != 0x16 {
				break
			}
			n := int(binary.BigEndian.Uint16(b[off+3 : off+5]))
			if n < 1 {
				return nil, ErrMalformed
			}
			if 5+n > len(b)-off {
				return nil, ErrIncomplete
			}
			hs = append(hs, b[off+5:off+5+n]...)
			off += 5 + n
			if len(hs) >= 4 {
				if hs[0] != 1 {
					return nil, ErrMalformed
				}
				hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
				if hsLen < 1 {
					return nil, ErrMalformed
				}
				if len(hs) >= 4+hsLen {
					return hs[4 : 4+hsLen], nil
				}
			}
		}
		return nil, ErrIncomplete
	}
	if b[0] == 1 {
		if len(b) < 4 {
			return nil, ErrIncomplete
		}
		hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if len(b) < 4+hsLen {
			return nil, ErrIncomplete
		}
		return b[4 : 4+hsLen], nil
	}
	return nil, ErrMalformed
}

func parseBody(raw []byte) (*Hello, error) {
	if len(raw) < 35 {
		return nil, ErrIncomplete
	}
	off := 2 + 32
	sidLen := int(raw[off])
	off++
	if off+sidLen > len(raw) {
		return nil, ErrIncomplete
	}
	off += sidLen
	if off+2 > len(raw) {
		return nil, ErrIncomplete
	}
	csLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
	off += 2
	if csLen < 2 || csLen%2 != 0 || off+csLen > len(raw) {
		return nil, ErrMalformed
	}
	off += csLen
	if off >= len(raw) {
		return nil, ErrIncomplete
	}
	compLen := int(raw[off])
	off++
	if off+compLen > len(raw) {
		return nil, ErrIncomplete
	}
	off += compLen
	var sni string
	var alpns []string
	alpnPresent := false
	if off < len(raw) {
		// raw is the full handshake body. Thus a short length is malformed,
		// not incomplete. The block fills it exactly and no type repeats,
		// as crypto/tls requires. Thus the SNI and ALPN that this code reads
		// are the same as the ones that the handshake reads.
		if off+2 > len(raw) {
			return nil, ErrMalformed
		}
		extLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
		off += 2
		end := off + extLen
		if end != len(raw) {
			return nil, ErrMalformed
		}
		seen := map[int]bool{}
		for off < end {
			if off+4 > end {
				return nil, ErrMalformed
			}
			typ := int(binary.BigEndian.Uint16(raw[off : off+2]))
			n := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
			off += 4
			if off+n > end || seen[typ] {
				return nil, ErrMalformed
			}
			seen[typ] = true
			body := raw[off : off+n]
			off += n
			switch typ {
			case 0:
				name, err := parseSNI(body)
				if err != nil {
					return nil, err
				}
				sni = name
			case 16:
				alpnPresent = true
				alpns = parseALPN(body)
			}
		}
	}
	return &Hello{
		SNI:    sni,
		ALPNs:  alpns,
		H2Only: h2Only(alpnPresent, alpns),
	}, nil
}

func h2Only(present bool, alpns []string) bool {
	if !present {
		return false
	}
	for _, a := range alpns {
		if a == "http/1.1" || a == "http/1.0" {
			return false
		}
	}
	return true
}

// parseSNI reads the full ServerNameList of a server_name extension
// (RFC 6066 §3) and gives its host_name. The list must not hold more than
// one name of the same type. A list with two entries of one type is
// ErrMalformed, so no name in it is used. A list that is cut short, or a
// host_name that is not a valid name, gives an empty SNI.
func parseSNI(body []byte) (string, error) {
	if len(body) < 2 {
		return "", nil
	}
	n := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	end := 2 + n
	if end > len(body) {
		end = len(body)
	}
	var seen [256]bool
	host := ""
	for off+3 <= end {
		nameType := body[off]
		ln := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if off+ln > end {
			return "", nil
		}
		if seen[nameType] {
			return "", ErrMalformed
		}
		seen[nameType] = true
		if nameType == 0 {
			if name := strings.ToLower(string(body[off : off+ln])); ValidHostName(name) {
				host = name
			}
		}
		off += ln
	}
	return host, nil
}

func parseALPN(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	end := 2 + n
	if end > len(body) {
		end = len(body)
	}
	var out []string
	for off < end {
		ln := int(body[off])
		off++
		if off+ln > end {
			break
		}
		out = append(out, string(body[off:off+ln]))
		off += ln
	}
	return out
}

// ValidHostName is the RFC 6066 host_name shape: ASCII letters, digits,
// hyphen, dot and underscore, a maximum of 253 bytes, and no empty label (a
// leading dot or ".."). A label walk reads an empty label as its parent. All
// other names are not names that a policy can match or a certificate can
// hold. JSON would change them to U+FFFD on the path to the broker.
//
// The length check is on the name without one trailing dot, as for DNS
// names. internal/tlssni does the same check in the same sequence.
func ValidHostName(s string) bool {
	if len(strings.TrimSuffix(s, ".")) > 253 || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}
