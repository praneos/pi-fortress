package httpwire

import (
	"bufio"
	"strings"
	"testing"
)

func benchFields() Fields {
	var fs Fields
	for _, kv := range [][2]string{
		{"Host", "api.anthropic.com"},
		{"User-Agent", "claude-cli/2.1.0 (external, cli)"},
		{"Accept", "application/json"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Authorization", "Bearer pf_0123456789abcdef_CLAUDE_OAT"},
		{"Anthropic-Version", "2023-06-01"},
		{"Anthropic-Beta", "oauth-2025-04-20"},
		{"Content-Type", "application/json"},
		{"Content-Length", "1234"},
		{"X-Stainless-Lang", "js"},
		{"X-Stainless-Package-Version", "0.60.0"},
		{"Connection", "keep-alive"},
	} {
		fs.Append(kv[0], kv[1])
	}
	return fs
}

var sinkString string

func BenchmarkFieldsGet(b *testing.B) {
	fs := benchFields()
	b.Run("hit-first", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkString = fs.Get("Host")
		}
	})
	b.Run("hit-last", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkString = fs.Get("Connection")
		}
	})
	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkString = fs.Get("Sec-WebSocket-Key")
		}
	})
}

const benchRequest = "POST /v1/messages?beta=true HTTP/1.1\r\n" +
	"Host: api.anthropic.com\r\n" +
	"User-Agent: claude-cli/2.1.0 (external, cli)\r\n" +
	"Accept: application/json\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Authorization: Bearer pf_0123456789abcdef_CLAUDE_OAT\r\n" +
	"Anthropic-Version: 2023-06-01\r\n" +
	"Anthropic-Beta: oauth-2025-04-20\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 2\r\n" +
	"X-Stainless-Lang: js\r\n" +
	"X-Stainless-Package-Version: 0.60.0\r\n" +
	"Connection: keep-alive\r\n\r\n{}"

// BenchmarkRequestLookups parses one request and then does the field
// lookups that the fence and the broker do for one request.
func BenchmarkRequestLookups(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		req, err := ReadRequest(bufio.NewReaderSize(strings.NewReader(benchRequest), 4096))
		if err != nil {
			b.Fatal(err)
		}
		for _, n := range []string{"Host", "Content-Length", "Connection", "Upgrade", "Authorization", "User-Agent", "Content-Type", "Cookie", "Host", "Connection"} {
			sinkString = req.Get(n)
		}
	}
}
