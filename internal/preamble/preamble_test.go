package preamble

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestBadMagic(t *testing.T) {
	raw := []byte("XXXX\x00\x02{}")
	_, err := Decode(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("err=%v", err)
	}
}

func TestTruncation(t *testing.T) {
	in := &Preamble{SNI: "api.anthropic.com"}
	var buf bytes.Buffer
	if err := Encode(&buf, in); err != nil {
		t.Fatal(err)
	}
	cut := buf.Bytes()[:6]
	_, err := Decode(bufio.NewReader(bytes.NewReader(cut)))
	if err == nil {
		t.Fatal("expected truncation error")
	}
}
