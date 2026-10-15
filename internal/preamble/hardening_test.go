package preamble

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func frame(body string) []byte {
	hdr := make([]byte, 6)
	copy(hdr, Magic)
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(body)))
	return append(hdr, body...)
}

func TestEmptySNIRefusedBothWays(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, &Preamble{SNI: ""}); err == nil {
		t.Fatal("encode accepted an empty sni")
	}
	for _, body := range []string{`{}`, `{"sni":""}`, `{"sni":"a b"}`, `{"sni":"x\n"}`} {
		_, err := Decode(bufio.NewReader(bytes.NewReader(frame(body))))
		if err == nil || !strings.Contains(err.Error(), "sni") {
			t.Fatalf("%s: err=%v", body, err)
		}
	}
	p, err := Decode(bufio.NewReader(bytes.NewReader(frame(`{"sni":"api.anthropic.com"}`))))
	if err != nil || p.SNI != "api.anthropic.com" {
		t.Fatalf("%v %+v", err, p)
	}
}
