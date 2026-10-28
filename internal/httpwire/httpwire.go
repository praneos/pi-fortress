// Package httpwire is the strict HTTP/1.1 wire codec used in place of
// net/http: bounded header parsing, chunked framing and in-stream replacement.
// internal/broker and internal/fence call it.
package httpwire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	maxHeaderBytes = 64 * 1024
	maxLineBytes   = 8 * 1024
	maxChunkLine   = 4 * 1024
	maxHeaders     = 40
	maxRespHeaders = 100
	maxInterim     = 8
)

var (
	ErrSmuggle     = errors.New("httpwire: content-length and chunked both present")
	ErrBadRequest  = errors.New("httpwire: malformed request")
	ErrTooManyHdr  = errors.New("httpwire: too many headers")
	ErrHeaderLimit = errors.New("httpwire: header block too large")
	ErrBodyLimit   = errors.New("httpwire: body larger than buffer limit")
	ErrDupHeader   = errors.New("httpwire: repeated host, authorization or cookie")
	ErrTransferEnc = errors.New("httpwire: transfer-encoding is not chunked")
	ErrUpgrade     = errors.New("httpwire: 101 switching protocols")
)

// singleton reports the fields that must not repeat. The fence rewrites
// them by name, and the origin must see exactly what the fence saw. The
// fence refuses a repeat of the other credential headers, because only the
// fence knows which headers a host declares.
func singleton(name string) bool {
	switch strings.ToLower(name) {
	case "host", "authorization", "cookie":
		return true
	}
	return false
}

// chunkedTE accepts exactly one chunked coding. The fence reframes the
// body, but it would forward any other coding, or a chain, verbatim.
func chunkedTE(v string) error {
	if strings.Trim(strings.ToLower(v), " \t") != "chunked" {
		return ErrTransferEnc
	}
	return nil
}

// trailerField refuses a Trailer field that names Content-Length,
// Transfer-Encoding or Trailer. A trailer must not change the framing of
// the message that it ends. net/http refuses such a field in a chunked
// message (fixTrailer in transfer.go). This code refuses it in each
// message, because the fence and the broker can change the framing of a
// message (SetBody, WriteHead). The broker drops the Trailer field and
// the trailers. Thus this is a refusal of a message that a Go peer
// refuses, not a change to what goes out.
func trailerField(v string) error {
	for _, name := range strings.Split(v, ",") {
		name = strings.Trim(name, " \t")
		if asciiEqualFold(name, "Content-Length") || asciiEqualFold(name, "Transfer-Encoding") || asciiEqualFold(name, "Trailer") {
			return ErrBadRequest
		}
	}
	return nil
}

// contentLength reads the value as the 1*DIGIT that the grammar
// specifies. It returns the digits that it read and also their value.
// ParseInt takes a sign, and TrimSpace takes any Unicode space. Thus,
// before, "+5", "-0" and "5 " all passed here and the next hop
// refused them. A smuggled request is built on that disagreement. The
// text comes back so that a repeat can be compared as bytes: "5" and "05"
// are the same number and not the same field.
func contentLength(v string) (int64, string, error) {
	v = strings.Trim(v, " \t")
	if v == "" {
		return 0, "", ErrBadRequest
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, "", ErrBadRequest
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, "", ErrBadRequest
	}
	return n, v, nil
}

type Field struct {
	Name  string
	Value string
	line  string
}

type Fields []Field

func (fs Fields) Get(name string) string {
	for _, f := range fs {
		if asciiEqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// asciiEqualFold compares two field names without case, in ASCII only. A
// field name from the wire is a token, thus ASCII. strings.EqualFold also
// folds Unicode ("ſ" matches "s"), which a field name must not do.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x == y {
			continue
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// Values returns every field of that name in order.
func (fs Fields) Values(name string) []string {
	var out []string
	for _, f := range fs {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// SetIndex rewrites field i by position. Thus a rewrite lands on the
// classified field and never on the first field of its name. Repeated
// names such as Set-Cookie each get one update.
func (fs Fields) SetIndex(i int, value string) {
	fs[i].Value = value
	fs[i].line = fs[i].Name + ": " + value
}

func (fs *Fields) SetInPlace(name, value string) {
	for i, f := range *fs {
		if asciiEqualFold(f.Name, name) {
			fs.SetIndex(i, value)
			return
		}
	}
	fs.Append(name, value)
}

func (fs *Fields) Append(name, value string) {
	*fs = append(*fs, Field{
		Name:  name,
		Value: value,
		line:  name + ": " + value,
	})
}

// Del removes every field with that name.
func (fs *Fields) Del(name string) {
	out := (*fs)[:0]
	for _, f := range *fs {
		if strings.EqualFold(f.Name, name) {
			continue
		}
		out = append(out, f)
	}
	*fs = out
}

type Request struct {
	Method, Target, Proto string
	Fields
	Body          io.Reader
	ContentLength int64
	Chunked       bool
	reqLine       string
}

// ReadRequest parses the head and leaves Body unread and uncapped. A body
// can stream past any buffer size. Thus the reader that buffers it also
// caps it (internal/fence).
func ReadRequest(br *bufio.Reader) (*Request, error) {
	line, err := readCRLF(br)
	if err != nil {
		return nil, err
	}
	if line == "" || hasCTL(line) {
		return nil, ErrBadRequest
	}
	method, rest, ok := strings.Cut(line, " ")
	if !ok {
		return nil, ErrBadRequest
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok || method == "" || target == "" || proto == "" {
		return nil, ErrBadRequest
	}
	// The fence evaluates policy on Method and Target and forwards both
	// verbatim. Thus a request line that the origin parses differently is a
	// policy divergence, not only a framing divergence. net/http refuses each
	// of these. Refuse them here too, and do not forward a line that the
	// origin re-reads. A third space puts its tail in proto. Thus the strict
	// version check also catches "GET / HTTP/1.1 extra" and "GE T / HTTP/1.1".
	if !isToken(method) || !validProto(proto) || !validRequestTarget(method, target) {
		return nil, ErrBadRequest
	}
	req := &Request{
		Method:        method,
		Target:        target,
		Proto:         proto,
		reqLine:       line,
		ContentLength: 0,
	}
	n := len(line) + 2
	for {
		h, err := readCRLF(br)
		if err != nil {
			return nil, err
		}
		n += len(h) + 2
		if n > maxHeaderBytes {
			return nil, ErrHeaderLimit
		}
		if h == "" {
			break
		}
		if len(req.Fields) >= maxHeaders {
			return nil, ErrTooManyHdr
		}
		if h[0] == ' ' || h[0] == '\t' || hasCTL(h) {
			return nil, ErrBadRequest
		}
		name, value, ok := strings.Cut(h, ":")
		if !ok || !isToken(name) {
			return nil, ErrBadRequest
		}
		req.Fields = append(req.Fields, Field{
			Name:  name,
			Value: strings.TrimLeft(value, " \t"),
			line:  h,
		})
	}
	cl := false
	te := false
	var clVal int64
	seen := map[string]bool{}
	for _, f := range req.Fields {
		name := strings.ToLower(f.Name)
		if singleton(name) {
			if seen[name] {
				return nil, ErrDupHeader
			}
			seen[name] = true
		}
		switch name {
		case "content-length":
			v, _, err := contentLength(f.Value)
			if err != nil {
				return nil, err
			}
			// The parser refuses any repeat, not only a disagreeing one. RFC 9112
			// lets a recipient collapse identical values instead, and the response
			// parser does accept them. But here a request is the attacker-controlled
			// direction. If both fields stay, the rewrite is unsafe. SetBody updates
			// the first Content-Length in place and leaves the second. Thus a
			// request that arrives with two 1s leaves as "Content-Length: 0" plus
			// "Content-Length: 1", and the next hop can frame it differently from
			// us. No real client sends a repeat.
			if cl {
				return nil, ErrBadRequest
			}
			cl, clVal = true, v
		case "transfer-encoding":
			if te {
				return nil, ErrTransferEnc
			}
			if err := chunkedTE(f.Value); err != nil {
				return nil, err
			}
			te = true
		case "trailer":
			if err := trailerField(f.Value); err != nil {
				return nil, err
			}
		}
	}
	// RFC 9112 has no chunked coding below HTTP/1.1. net/http drops the field
	// there and does not frame on it. WriteTo forwards the request line and
	// the field verbatim. Thus, if we honour it here while the origin ignores
	// it, the origin gets our chunk data as its next request. A refusal is
	// the only reading that both hops can share.
	if te && req.Proto != "HTTP/1.1" {
		return nil, ErrTransferEnc
	}
	if cl && te {
		return nil, ErrSmuggle
	}
	if te {
		req.Chunked = true
		req.ContentLength = -1
		req.Body = newChunkedReader(br)
		return req, nil
	}
	if cl {
		req.ContentLength = clVal
		req.Body = &lengthReader{br, clVal}
		return req, nil
	}
	req.Body = bytes.NewReader(nil)
	return req, nil
}

func (r *Request) SetTarget(target string) {
	r.Target = target
	r.reqLine = r.Method + " " + target + " " + r.Proto
}

func (r *Request) SetBody(b []byte) {
	r.Body = bytes.NewReader(b)
	r.ContentLength = int64(len(b))
	r.Chunked = false
	r.Del("Transfer-Encoding")
	r.SetInPlace("Content-Length", strconv.FormatInt(r.ContentLength, 10))
}

// PrependBody puts already-consumed body bytes back in front of the
// stream, and does not change framing. The fence uses it after it reads
// the head of a streamed body.
func (r *Request) PrependBody(b []byte) {
	if len(b) == 0 {
		return
	}
	if r.Body == nil {
		r.Body = bytes.NewReader(b)
		return
	}
	r.Body = io.MultiReader(bytes.NewReader(b), r.Body)
}

func (r *Request) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	buf.WriteString(r.reqLine)
	if r.reqLine == "" {
		buf.WriteString(r.Method)
		buf.WriteByte(' ')
		buf.WriteString(r.Target)
		buf.WriteByte(' ')
		buf.WriteString(r.Proto)
	}
	buf.WriteString("\r\n")
	for _, f := range r.Fields {
		if f.line != "" {
			buf.WriteString(f.line)
		} else {
			buf.WriteString(f.Name)
			buf.WriteString(": ")
			buf.WriteString(f.Value)
		}
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	n, err := w.Write(buf.Bytes())
	if err != nil {
		return int64(n), err
	}
	if r.Body == nil {
		return int64(n), nil
	}
	if r.Chunked {
		cw := NewChunkedWriter(w)
		c, err := io.Copy(cw, r.Body)
		if err != nil {
			return int64(n) + c, err
		}
		return int64(n) + c, cw.Close()
	}
	c, err := io.Copy(w, r.Body)
	return int64(n) + c, err
}

type Response struct {
	Proto, Status string
	Code          int
	Fields
	Body   []byte
	NoBody bool
	// ReadResponseHead sets these. Stream is the decoded body that is not
	// read yet. ContentLength is -1 when unknown (chunked or read-to-EOF).
	Stream        io.Reader
	ContentLength int64
	Chunked       bool
	// CTLs is how many control bytes the origin's head carried in the reason
	// phrase and field values. Each is now a space (see blankCTL).
	CTLs       int
	statusLine string
}

// ReadResponseHead parses the status line and headers and leaves the body
// unread in resp.Stream (decoded if chunked). It skips interim 1xx
// responses, to a bounded number. 101 is an error because the fence
// never asked to switch protocols.
func ReadResponseHead(br *bufio.Reader, noBody bool) (*Response, error) {
	return readHead(br, noBody, false)
}

// ReadUpgradeResponseHead is ReadResponseHead for a request that did ask
// to switch protocols. Thus a 101 is the answer and not the desync that
// ErrUpgrade guards against. It still skips interim 1xx below 101. It
// consumes the status line and headers. All that the origin sent after
// them stays in br for the new protocol to read.
func ReadUpgradeResponseHead(br *bufio.Reader) (*Response, error) {
	return readHead(br, false, true)
}

// readHead is the interim-1xx skip loop that both entry points run.
// wantUpgrade decides whether a 101 is the answer or the desync that
// ErrUpgrade guards against.
func readHead(br *bufio.Reader, noBody, wantUpgrade bool) (*Response, error) {
	for i := 0; ; i++ {
		resp, err := readResponseHead(br, noBody)
		if err != nil {
			return nil, err
		}
		if resp.Code == 101 {
			if wantUpgrade {
				return resp, nil
			}
			return nil, ErrUpgrade
		}
		if resp.Code >= 100 && resp.Code < 200 {
			if i >= maxInterim {
				return nil, ErrBadRequest
			}
			continue
		}
		return resp, nil
	}
}

func readResponseHead(br *bufio.Reader, noBody bool) (*Response, error) {
	line, err := readCRLF(br)
	if err != nil {
		return nil, err
	}
	proto, rest, ok := strings.Cut(line, " ")
	if !ok || (proto != "HTTP/1.0" && proto != "HTTP/1.1") {
		return nil, ErrBadRequest
	}
	codeStr, _, _ := strings.Cut(rest, " ")
	code, ok := threeDigitCode(codeStr)
	if !ok {
		return nil, ErrBadRequest
	}
	ctls := 0
	if hasCTL(rest) {
		rest, ctls = blankCTL(rest)
		line = proto + " " + rest
	}
	resp := &Response{Proto: proto, Status: rest, Code: code, statusLine: line, NoBody: noBody, ContentLength: -1, CTLs: ctls}
	var cl int64 = -1
	clText := ""
	chunked := false
	n := len(line) + 2
	for {
		h, err := readCRLF(br)
		if err != nil {
			return nil, err
		}
		n += len(h) + 2
		if n > maxHeaderBytes {
			return nil, ErrHeaderLimit
		}
		if h == "" {
			break
		}
		if len(resp.Fields) >= maxRespHeaders {
			return nil, ErrTooManyHdr
		}
		if h[0] == ' ' || h[0] == '\t' {
			return nil, ErrBadRequest
		}
		name, value, ok := strings.Cut(h, ":")
		if !ok || !responseFieldName(name) {
			return nil, ErrBadRequest
		}
		if hasCTL(value) {
			var n int
			value, n = blankCTL(value)
			h = name + ":" + value
			resp.CTLs += n
		}
		val := strings.TrimLeft(value, " \t")
		resp.Fields = append(resp.Fields, Field{Name: name, Value: val, line: h})
		switch strings.ToLower(name) {
		case "content-length":
			v, text, err := contentLength(val)
			if err != nil {
				return nil, err
			}
			if cl >= 0 && clText != text {
				return nil, ErrBadRequest
			}
			cl, clText = v, text
		case "transfer-encoding":
			if chunked {
				return nil, ErrTransferEnc
			}
			if err := chunkedTE(val); err != nil {
				return nil, err
			}
			chunked = true
		case "trailer":
			if err := trailerField(val); err != nil {
				return nil, err
			}
		}
	}
	if cl >= 0 && chunked {
		return nil, ErrSmuggle
	}
	if code == 204 || code == 304 || (code >= 100 && code < 200) {
		resp.NoBody = true
	}
	if resp.NoBody {
		return resp, nil
	}
	switch {
	case chunked:
		resp.Chunked = true
		resp.Stream = newChunkedReader(br)
	case cl >= 0:
		resp.ContentLength = cl
		resp.Stream = &lengthReader{br, cl}
	default:
		resp.Stream = br
	}
	return resp, nil
}

// Buffer reads the whole Stream into Body. A body above max is an error,
// never a truncation.
func (r *Response) Buffer(max int64) error {
	if r.NoBody || r.Stream == nil {
		r.Stream = nil
		return nil
	}
	if max <= 0 {
		max = 1 << 20
	}
	if r.ContentLength > max {
		return ErrBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(r.Stream, max+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > max {
		return ErrBodyLimit
	}
	r.Body = body
	r.Stream = nil
	r.dropTE()
	return nil
}

func ReadResponse(br *bufio.Reader, maxBody int64, noBody bool) (*Response, error) {
	resp, err := ReadResponseHead(br, noBody)
	if err != nil {
		return nil, err
	}
	if err := resp.Buffer(maxBody); err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *Response) dropTE() {
	r.Del("Transfer-Encoding")
}

// SetStatus replaces the code and reason ("200 OK"). The status line that
// WriteTo and WriteHead write is then Proto and this text.
func (r *Response) SetStatus(status string) {
	r.Status = status
	r.statusLine = r.Proto + " " + status
}

// WriteHead writes the status line and headers for a streamed body. It
// replaces Content-Length and Transfer-Encoding with chunked framing (or
// omits them when chunked is false: the body runs to close).
func (r *Response) WriteHead(w io.Writer, chunked bool) error {
	var buf bytes.Buffer
	if chunked && r.Proto != "HTTP/1.1" {
		// Chunked framing does not exist below HTTP/1.1. Thus, if the status
		// line of an HTTP/1.0 origin carried over, it would tell the reader that
		// the body ends at the close of the connection, while the bytes are
		// chunks. This code reframes the body in all cases. Thus the announced
		// version is the one that this head is written in, not the one that the
		// origin answered in.
		buf.WriteString("HTTP/1.1 ")
		buf.WriteString(r.Status)
	} else if r.statusLine != "" {
		buf.WriteString(r.statusLine)
	} else {
		buf.WriteString(r.Proto)
		buf.WriteByte(' ')
		buf.WriteString(r.Status)
	}
	buf.WriteString("\r\n")
	for _, f := range r.Fields {
		if strings.EqualFold(f.Name, "Content-Length") || strings.EqualFold(f.Name, "Transfer-Encoding") {
			continue
		}
		if f.line != "" {
			buf.WriteString(f.line)
		} else {
			buf.WriteString(f.Name + ": " + f.Value)
		}
		buf.WriteString("\r\n")
	}
	if chunked {
		buf.WriteString("Transfer-Encoding: chunked\r\n")
	} else {
		buf.WriteString("Connection: close\r\n")
	}
	buf.WriteString("\r\n")
	_, err := w.Write(buf.Bytes())
	return err
}

func (r *Response) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	if r.statusLine != "" {
		buf.WriteString(r.statusLine)
	} else {
		buf.WriteString(r.Proto)
		buf.WriteByte(' ')
		buf.WriteString(r.Status)
	}
	buf.WriteString("\r\n")
	clSet := false
	for _, f := range r.Fields {
		if !r.NoBody && strings.EqualFold(f.Name, "Content-Length") {
			f.line = f.Name + ": " + strconv.Itoa(len(r.Body))
			clSet = true
		}
		if strings.EqualFold(f.Name, "Transfer-Encoding") {
			continue
		}
		if f.line != "" {
			buf.WriteString(f.line)
		} else {
			buf.WriteString(f.Name + ": " + f.Value)
		}
		buf.WriteString("\r\n")
	}
	if !r.NoBody && !clSet {
		buf.WriteString("Content-Length: " + strconv.Itoa(len(r.Body)) + "\r\n")
	}
	buf.WriteString("\r\n")
	if !r.NoBody {
		buf.Write(r.Body)
	}
	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// tchar and isToken are the RFC 9110 §5.6.2 token grammar. A method and a
// header name are tokens. net/http refuses a request whose method or a
// header name is not a token, and the origin parses both again. Thus a
// non-token read here would go forward to a peer that would reject it.
func tchar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tchar(s[i]) {
			return false
		}
	}
	return true
}

// validProto is the request-line version. HTTP/2 and HTTP/0.9 never reach
// this parser, and the code refuses a chunked body below HTTP/1.1
// downstream. A version that is neither means an unparsed tail after a
// second space.
func validProto(p string) bool {
	return p == "HTTP/1.1" || p == "HTTP/1.0"
}

// validRequestTarget accepts the four RFC 9112 §3.2 request-target forms:
// origin-form (/path, what a TLS-terminating proxy sees), asterisk-form
// (*), authority-form (host:port, CONNECT only) and absolute-form
// (scheme://...). A bare word like "foo" is none of them. net/http
// refuses it, and the fence classifies policy on the target.
func validRequestTarget(method, target string) bool {
	switch {
	case target == "*":
		return true
	case target[0] == '/':
		return true
	case method == "CONNECT":
		return validAuthority(target)
	default:
		scheme, _, ok := strings.Cut(target, "://")
		return ok && isScheme(scheme)
	}
}

// validAuthority is the host:port of CONNECT. The host is a DNS name or
// IPv4 literal, and the port is 1-5 digits. An IPv6 literal is refused,
// as at all other locations here.
func validAuthority(s string) bool {
	host, port, ok := strings.Cut(s, ":")
	if !ok || host == "" || port == "" || len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func isScheme(s string) bool {
	if s == "" || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// hasCTL reports a control byte other than HTAB. A request with one is
// refused. If forwarded verbatim, a bare CR is a line break to an origin
// that splits on it. Thus "X-A: b\rTransfer-Encoding: chunked" is framed
// by Content-Length here and by chunked there. Only the agent would send
// one; no client library does. A 400 is visible, but a silent repair
// would forward a request that the agent did not write.
//
// A response takes blankCTL instead.
func hasCTL(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\t' && (c < ' ' || c == 0x7f) {
			return true
		}
	}
	return false
}

// blankCTL replaces each control byte except HTAB with a space and counts
// them. It is the response side of hasCTL. It is also the other answer
// that RFC 9110 §5.5 allows to CR, LF and NUL in a field value. This
// parser reads the origin's head one time, and the agent's client reads
// it again. A bare CR is a line break to some of those clients and not
// to this parser. Python 3.13's http.client, under urllib3 and requests,
// splits header lines on it. Node's llhttp and net/http refuse the head
// fully. "X-A: b\rContent-Encoding: gzip" would then be a header that
// the scrub never saw, because the scrub decides gzip from
// Content-Encoding. The agent would then inflate a gzip body with a live
// value inside that the scrub could not read. A space is a line break to
// no reader. A refusal of the response would break a page because of a
// stray byte that no parser acts on after the blank. net/http's own
// client refuses these heads, so an agent on Go loses nothing that it had.
func blankCTL(s string) (string, int) {
	b := []byte(s)
	n := 0
	for i, c := range b {
		if c != '\t' && (c < ' ' || c == 0x7f) {
			b[i] = ' '
			n++
		}
	}
	return string(b), n
}

// responseFieldName is a response header name: a token. An inner space
// is tolerated, as the net/http client tolerates it (go.dev/issue/34540).
// A name has no repair as a value does. "X\rContent-Encoding" blanked is
// still one name here and two lines to a client that split it before the
// colon. Thus anything else refuses the response, as net/http already
// does.
func responseFieldName(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tchar(s[i]) && s[i] != ' ' {
			return false
		}
	}
	return true
}

// threeDigitCode is the status-code grammar (RFC 9112 §4): exactly three
// digits. strconv.Atoi alone also takes a sign, leading zeros or any
// other digit count ("-10", "0200", "20", "99999"). Code decides whether
// a body follows (204, 304, 1xx), so it is a framing input, not free text.
func threeDigitCode(s string) (int, bool) {
	if len(s) != 3 {
		return 0, false
	}
	n := 0
	for i := 0; i < 3; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// readCRLF reads one line. It refuses the line before allocation when it
// passes maxLineBytes. Thus a peer cannot pin memory with a line that
// never ends.
func readCRLF(br *bufio.Reader) (string, error) {
	return readLineMax(br, maxLineBytes)
}

// readLineMax is readCRLF with a different limit. The limit includes the
// CRLF.
func readLineMax(br *bufio.Reader, max int) (string, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > max {
			return "", ErrHeaderLimit
		}
		line = append(line, frag...)
		if err == nil {
			break
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", ErrBadRequest
	}
	return string(line[:len(line)-2]), nil
}
