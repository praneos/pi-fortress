// Package fence scans and rewrites credentials in agent requests. For each
// header and each body, it decides whether to keep, inject or strip. The
// broker HTTP path and the broker websocket relay call it.
package fence

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

type Disposition int

const (
	DispKeep Disposition = iota
	DispInject
	DispStrip
)

type BodyMode int

const (
	BodyStream BodyMode = iota
	BodyBuffer
)

const (
	StripRepl  = secrets.StripRepl
	maxBodyBuf = 1 << 20
	// streamHead: the fence reads this much of a streamed body before
	// the head goes out. A framing error in these bytes fails the request
	// before the origin sees it.
	streamHead = 64 << 10
)

var stripRepl = []byte(StripRepl)

type Ctx struct {
	SNI     string
	TokenRE *regexp.Regexp
	// Rules, with StripCore set, makes a core host strip each token kind
	// that it does not inject. With StripCore off, core hosts run no prefix rules.
	Rules     *TokenRules
	StripCore bool
	// OnInject, when set, receives the slot id each time the fence writes a
	// live value into the request: into a header, or into the buffered body
	// of the refresh token.
	OnInject func(slot string)
	// NoInject says that this request does not go to the origin that the
	// SNI names. A responder on the box answers it. Thus the substitution
	// authority of that SNI does not apply to the request. An injection
	// gains nothing, because no credential is spent. It costs everything,
	// because the fence must then remove the live value from all that the
	// responder reflects. The open echo showed that this removal is not
	// reliable: it scrubs literal bytes, but a Basic Authorization value
	// comes back base64-encoded, with no substring in common with the
	// credential in it. The fence still strips and refuses. Thus a fixture
	// that exists only to show the fence in operation still shows it.
	NoInject bool
	// Reserve, when set, receives a request for n bytes before the fence
	// buffers a body of up to n bytes. It says whether the process-wide
	// byte budget of the caller had them. If Reserve refuses, a body that
	// can stream does stream, the same as a body over maxBodyBuf. The body
	// of the refresh token must be buffered for the substitution. If
	// Reserve refuses, that body fails with ErrBufferBudget before the
	// fence reads a byte of it. The caller owns the reservation and
	// releases it. A nil Reserve reserves nothing, and the fence always buffers.
	Reserve func(n int64) bool
}

// ErrBufferBudget means that a body that must be buffered found the byte
// budget of the caller spent (Ctx.Reserve). The fence read nothing and sent
// nothing. A retry of the same request without a change is possible.
var ErrBufferBudget = errors.New("fence: byte budget spent, body not buffered")

type FieldPlan struct {
	Index     int
	Disp      Disposition
	StripOnly bool
}

type StripEvent struct {
	Where string
	Rule  string
}

type PlanResult struct {
	Fields   []FieldPlan
	Target   Disposition
	Body     Disposition
	BodyMode BodyMode
	Inject   bool
	Kinds    []string
}

// StreamStrips reports what a streamed body lost, after the copy to the
// origin is complete: live values from the scrubber, and token-prefix
// matches from the token stream below it. It is nil when the body was
// buffered.
type StreamStrips struct {
	sc    *httpwire.Scrubber
	rules []string
	tok   *tokenStream
}

func (s *StreamStrips) Events() []StripEvent {
	if s == nil {
		return nil
	}
	var ev []StripEvent
	if s.sc != nil {
		for i, c := range s.sc.Counts {
			if c > 0 && s.rules[i] != "" {
				ev = append(ev, StripEvent{Where: "body", Rule: s.rules[i]})
			}
		}
	}
	return append(ev, s.tok.events()...)
}

// IsOAuthPath is the exact set of refresh endpoints that the fence
// harvests from. A substring match would let any path that mentions oauth
// rotate the slot. The broker forwards the target as the agent wrote it.
// Thus the path bytes must be exactly "/v1/oauth/token" or "/oauth/token".
// A query after '?' is permitted. A fragment, a percent escape, a dot
// segment, a run of slashes or a case variant in the path is not a refresh
// path: an origin can route such a target to a different handler. The
// broker refuses all forms except origin-form before the fence runs. This
// function strips the scheme and authority of an absolute-form target
// anyway, so the answer does not depend on that broker check.
//
// The fence substitutes the refresh token only on a refresh path
// (scanner.at), and the harvest uses this same test. Thus on any other
// target, the fence refuses a CLAUDE_ORT placeholder and never arms the
// harvest: nothing ever asks for what the origin could mint.
func IsOAuthPath(target string) bool {
	p := target
	if scheme, rest, ok := strings.Cut(p, "://"); ok && isScheme(scheme) {
		p = rest
		if i := strings.IndexAny(p, "/?#"); i >= 0 {
			p = p[i:]
		} else {
			p = "/"
		}
	}
	if strings.Contains(p, "#") {
		return false
	}
	p, _, _ = strings.Cut(p, "?")
	return p == "/v1/oauth/token" || p == "/oauth/token"
}

// isScheme is the RFC 3986 scheme grammar: a letter, then letters,
// digits, '+', '-' and '.'.
func isScheme(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// refreshKind is the only kind that the fence writes outside a header. It
// goes only into the refresh_token value of a refresh body.
const refreshKind = "CLAUDE_ORT"

// RefreshTokenField is the refresh_token member of a refresh body. It reads
// the body strictly: one top-level JSON object, the key spelled exactly
// once and in no other case, and its value a string with no escape in it.
// For all other input, ok == false. Without this rule, an origin that reads
// the first of two keys, or folds case as encoding/json does, would spend
// the token of one slot while the broker bound the harvest to a different slot.
func RefreshTokenField(body []byte) (string, bool) {
	sp, ok := refreshTokenSpan(body)
	if !ok {
		return "", false
	}
	return string(body[sp[0]:sp[1]]), true
}

// StrictFields reads the named members of body with the RefreshTokenField
// rule, for each key: one top-level JSON object, each key spelled exactly
// once and in no other case, each value a string with no escape in it. A key
// that is absent has no entry. A key with the value null also has no entry,
// but it still counts for the once-only rule. For all other input, ok ==
// false. The broker reads a refresh response with it. A loose read there
// stores one value and lets a different one through to the agent.
func StrictFields(body []byte, keys ...string) (map[string]string, bool) {
	spans, ok := fieldSpans(body, keys, true)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(spans))
	for k, sp := range spans {
		out[k] = string(body[sp[0]:sp[1]])
	}
	return out, true
}

// refreshTokenSpan is the location of the RefreshTokenField value in body,
// without the quotes.
func refreshTokenSpan(body []byte) ([2]int, bool) {
	spans, ok := fieldSpans(body, []string{"refresh_token"}, false)
	sp, found := spans["refresh_token"]
	return sp, ok && found
}

// fieldSpans is the location of each StrictFields value in body, without
// the quotes. When nullAbsent is true, a null value gives no span. The
// fence never reads a request body this way. There, a null refresh_token
// fails the read, and the body binds nothing.
func fieldSpans(body []byte, keys []string, nullAbsent bool) (map[string][2]int, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	spans := map[string][2]int{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := t.(string)
		want := ""
		for _, k := range keys {
			if strings.EqualFold(key, k) {
				want = k
			}
		}
		if want == "" {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil, false
			}
			continue
		}
		if key != want || seen[want] {
			return nil, false
		}
		seen[want] = true
		from := int(dec.InputOffset())
		if t, err = dec.Token(); err != nil {
			return nil, false
		}
		if t == nil && nullAbsent {
			continue
		}
		if _, ok := t.(string); !ok {
			return nil, false
		}
		end := int(dec.InputOffset())
		q := bytes.IndexByte(body[from:end], '"')
		if q < 0 {
			return nil, false
		}
		span := [2]int{from + q + 1, end - 1}
		if span[0] > span[1] || bytes.IndexByte(body[span[0]:span[1]], '\\') >= 0 {
			return nil, false
		}
		spans[want] = span
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return spans, true
}

// framingHeader names the fields that the parser owns. Their values are
// numbers and codings. The fence never scans them.
func framingHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding":
		return true
	}
	return false
}

// stripOnlyHeader names fields that no credential belongs in. The fence
// scans and strips them like all other fields, and never injects into them.
// A placeholder in one refuses the request, as in all other non-credential
// headers. Host is not here: the fence never strips it (noteHost).
func stripOnlyHeader(name string) bool {
	return strings.EqualFold(name, "connection")
}

// maxFieldLine is the httpwire limit on one request header line. The fence
// does not forward a Basic value that grows past it when encoded again.
const maxFieldLine = 8 << 10

// basicToken returns the offset of the token68 in an Authorization value
// with the Basic scheme (RFC 7617, any case, spaces or tabs before the
// token), or -1. All other fields exit after two length compares.
func basicToken(name, value string) int {
	const scheme = "basic"
	if len(name) != len("authorization") || len(value) <= len(scheme) || !strings.EqualFold(name, "authorization") || !strings.EqualFold(value[:len(scheme)], scheme) {
		return -1
	}
	i := len(scheme)
	for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	if i == len(scheme) || i == len(value) {
		return -1
	}
	return i
}

// BasicCredentials decodes the user:password of a Basic Authorization
// value, with or without padding, and returns the token offset. ok is false
// for all other fields and for a token that is not base64. Such a value
// gets only the raw scan that all headers get.
func BasicCredentials(name, value string) (dec []byte, at int, ok bool) {
	at = basicToken(name, value)
	if at < 0 {
		return nil, 0, false
	}
	tok := strings.TrimRight(value[at:], " \t")
	enc := base64.StdEncoding
	if len(tok)%4 != 0 {
		enc = base64.RawStdEncoding
	}
	dec, err := enc.DecodeString(tok)
	if err != nil {
		return nil, 0, false
	}
	return dec, at, true
}

type scanner struct {
	inject bool
	// quiet stops refusal records. The no-inject scanner sets it: a
	// strip-only header and a WebSocket frame have no field that the fence
	// injects into. Thus a placeholder there was never a substitution that
	// the fence could refuse.
	quiet  bool
	kinds  []string
	idx    *secrets.Index
	tokens *tokenSet
	all    *tokenSet
	ref    *[]Refusal
	// seen prevents duplicate entries in ref with one lookup. The no-inject
	// copy of this scanner shares it, and records into the same list.
	seen map[Refusal]struct{}
	used func(slot string)
	// placed marks a scanner for a location other than a header. There,
	// only the kinds in place substitute. refresh says that the target is
	// the refresh endpoint. Its body is the one place outside a header
	// where a credential must go.
	placed  bool
	place   []string
	refresh bool
	// refreshBody marks the body scanner of the refresh path. This is the one
	// place where the fence can write a refresh token, and there only as the
	// refresh_token value. ort holds the location of that value in the bytes
	// of the most recent query.
	refreshBody bool
	ort         *ortMemo
	// extra maps each header that the entry of this host declares, in
	// addition to corepolicy.DefaultHeaders, to the kinds it carries. field
	// names the header that a field scanner reads, for the refusal row.
	extra map[string][]string
	field string
}

// ortMemo is refreshTokenSpan for the one buffer of a scan pass. Thus the
// fence parses a body with many placeholders one time, not one time per
// span. It holds the buffer, so a match on its address and length is a
// match on its bytes.
type ortMemo struct {
	b    []byte
	span [2]int
	ok   bool
}

// at is the scanner for one place in the request. Headers carry all kinds
// that the SNI can carry, as before. A buffered body carries only the
// refresh token, and only on the refresh path. The URL carries nothing.
// Reason: an origin can send a body back, publish it, or give it to a model
// that prints it reversed. A URL goes into access logs, and the fence can
// scrub none of it. The fence strips the same way in all three places.
// This limits only what the fence writes in.
func (s *scanner) at(where string) *scanner {
	if where == "header" || !s.inject {
		return s
	}
	c := *s
	c.placed, c.place, c.field = true, nil, ""
	if where == "body" && s.refresh {
		c.place, c.refreshBody = []string{refreshKind}, true
	}
	return &c
}

// placeAllows says that the placeholder at span in b can be substituted
// where this scanner reads. The refresh token goes only into the exact
// refresh_token value of the refresh body. It does not go into a header,
// where it would travel to any path. It does not go into a different
// field, which the origin can send back.
// header is the scanner for one request field. The default credential
// headers carry all kinds that the host binds. Each other header carries
// only the kinds that its entry declared it for. The fence refuses a
// placeholder of a different kind there, and never writes it in: a
// User-Agent, a Referer or an X-anything goes into access logs and comes
// back in audit APIs, past the literal response scrub.
func (s *scanner) header(name string) *scanner {
	if !s.inject || corepolicy.DefaultHeader(name) {
		return s
	}
	c := *s
	c.placed, c.place, c.field = true, s.extra[strings.ToLower(name)], name
	return &c
}

func (s *scanner) placeAllows(b []byte, span [2]int, kind string) bool {
	if kind == refreshKind {
		return s.refreshBody && s.refreshTokenAt(b, span)
	}
	return !s.placed || corepolicy.KindAllowed(kind, s.place)
}

func (s *scanner) refreshTokenAt(b []byte, span [2]int) bool {
	if len(b) == 0 || s.ort == nil {
		return false
	}
	m := s.ort
	if len(m.b) != len(b) || &m.b[0] != &b[0] {
		m.b = b
		m.span, m.ok = refreshTokenSpan(b)
	}
	return m.ok && m.span == span
}

func (s *scanner) allowed(kind string) bool {
	return s.inject && corepolicy.KindAllowed(kind, s.kinds)
}

// keeps says that a value from Index.Lives can stay in its place: a live
// value of a kind that this host carries. The fence strips the value of a
// revoked slot (disabled or expired) everywhere, also on its own host.
func (s *scanner) keeps(sl secrets.Slot) bool {
	return s.allowed(sl.Kind) && !sl.Disabled && !sl.Expired
}

// noInject is the same scanner with no allowed kind. Thus each live value
// strips and no placeholder injects.
func (s *scanner) noInject() *scanner {
	c := *s
	c.inject, c.kinds, c.tokens, c.quiet = false, nil, c.all, true
	return &c
}

// injectable returns the live value for the placeholder at span, or nil
// when it is not exact, unknown, empty, or not a kind this SNI may carry.
func (s *scanner) injectable(b []byte, span [2]int) []byte {
	if !secrets.PlaceholderExact(b, span) {
		return nil
	}
	sl, ok := s.idx.ByDummy[secrets.PlaceholderKey(b, span)]
	if !ok || sl.Live == "" || !s.allowed(sl.Kind) || !s.placeAllows(b, span, sl.Kind) {
		return nil
	}
	return []byte(sl.Live)
}

// injected is injectable for a span that the fence writes out. It reports
// the slot to Ctx.OnInject. classify calls injectable, because a query is
// not a use.
func (s *scanner) injected(b []byte, span [2]int) []byte {
	live := s.injectable(b, span)
	if live != nil && s.used != nil {
		s.used(s.idx.ByDummy[secrets.PlaceholderKey(b, span)].ID)
	}
	return live
}

func (s *scanner) classify(b []byte) Disposition {
	for _, span := range secrets.FindPlaceholderSpans(b) {
		if s.injectable(b, span) != nil {
			return DispInject
		}
	}
	for _, sl := range s.idx.Lives {
		if s.keeps(sl) {
			continue
		}
		if httpwire.Contains(b, []byte(sl.Live)) {
			return DispStrip
		}
	}
	if s.tokens.match(b) {
		return DispStrip
	}
	return DispKeep
}

func (s *scanner) injectAll(b []byte) []byte {
	spans := secrets.FindPlaceholderSpans(b)
	if len(spans) == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+64*len(spans))
	pos := 0
	for _, span := range spans {
		live := s.injected(b, span)
		if live == nil {
			continue
		}
		out = append(out, b[pos:span[0]]...)
		out = append(out, live...)
		pos = span[1]
	}
	return append(out, b[pos:]...)
}

// stripPairs maps live values to the strip marker. On a foreign host, it
// maps all live values. On a core host, it maps only the kinds that this
// host cannot carry. Padded keeps the byte length, for bodies that stream
// under a fixed Content-Length.
func (s *scanner) stripPairs(padded bool) ([][2][]byte, []string) {
	pairs := make([][2][]byte, 0, len(s.idx.Lives))
	rules := make([]string, 0, len(s.idx.Lives))
	for _, sl := range s.idx.Lives {
		if s.keeps(sl) {
			continue
		}
		repl := stripRepl
		if padded {
			repl = padRepl(len(sl.Live))
		}
		pairs = append(pairs, [2][]byte{[]byte(sl.Live), repl})
		rules = append(rules, "secret:"+secrets.EnvKey(sl.ID, sl.Kind))
	}
	return pairs, rules
}

func padRepl(n int) []byte {
	if n <= len(stripRepl) {
		return stripRepl[:n]
	}
	out := make([]byte, n)
	copy(out, stripRepl)
	for i := len(stripRepl); i < n; i++ {
		out[i] = '*'
	}
	return out
}

func (s *scanner) strip(b []byte) []byte {
	pairs, _ := s.stripPairs(false)
	out := b
	if len(pairs) > 0 {
		out = httpwire.ReplaceAll(make([]byte, 0, len(b)), b, pairs, nil)
	}
	out = s.tokens.replace(out, stripRepl)
	return out
}

// rewrite strips first and injects second. Thus a field that carries both
// an allowed placeholder and a foreign live value gets the live token of
// its own kind and the marker for the other. Events cover the strip half.
func (s *scanner) rewrite(b []byte, where string) ([]byte, []StripEvent) {
	ev := s.strips(b, where)
	out := s.strip(b)
	if s.inject {
		out = s.injectAll(out)
	}
	return out, ev
}

// rewriteHeader is rewrite for one field. The decoded credentials of a
// Basic Authorization value go through it first, and the fence encodes
// them again with padding. If rewrite does not change the decoded
// credentials, the original bytes stay. The raw pass then runs over the
// value that results.
func (s *scanner) rewriteHeader(name, value string) (string, []StripEvent, error) {
	out := value
	var ev []StripEvent
	if dec, at, ok := BasicCredentials(name, value); ok && s.classify(dec) != DispKeep {
		nd, e := s.rewrite(dec, "header")
		ev = e
		if !bytes.Equal(nd, dec) {
			out = value[:at] + base64.StdEncoding.EncodeToString(nd)
		}
	}
	if s.classify([]byte(out)) != DispKeep {
		nv, e := s.rewrite([]byte(out), "header")
		ev = append(ev, e...)
		out = string(nv)
	}
	// The 1 MiB read limit applies to the input, not to the output: each
	// placeholder takes its own bytes, and a full live value replaces it.
	// Thus a field that the parser accepted can go out as a field that it
	// would not accept. Refusal is the only safe result for that case,
	// because the outgoing request carries live credentials and the
	// origin rejects it in any case.
	if len(name)+2+len(out) > maxFieldLine {
		return "", nil, httpwire.ErrHeaderLimit
	}
	return out, ev, nil
}

func (s *scanner) strips(b []byte, where string) []StripEvent {
	var ev []StripEvent
	for _, rule := range s.tokens.rules(b) {
		ev = append(ev, StripEvent{Where: where, Rule: rule})
	}
	for _, sl := range s.idx.Lives {
		if s.keeps(sl) {
			continue
		}
		if httpwire.Contains(b, []byte(sl.Live)) {
			ev = append(ev, StripEvent{Where: where, Rule: "secret:" + secrets.EnvKey(sl.ID, sl.Kind)})
		}
	}
	return ev
}

// allTokens is the set of every token rule: TokenRE, else all of Rules.
func allTokens(ctx Ctx) *tokenSet {
	allRE := ctx.TokenRE
	if allRE == nil && ctx.Rules != nil {
		allRE = ctx.Rules.All()
	}
	return tokensFor(allRE)
}

func newScanner(ctx Ctx, req *httpwire.Request, pol *corepolicy.Policy, idx *secrets.Index) *scanner {
	host := req.Get("Host")
	inject := !ctx.NoInject && pol != nil && pol.Authority(ctx.SNI, host)
	var kinds []string
	var extra map[string][]string
	if inject {
		kinds = pol.KindsFor(ctx.SNI)
		extra = pol.HeadersFor(ctx.SNI)
		if len(kinds) == 0 {
			inject = false
		}
	}
	all := allTokens(ctx)
	tokens := all
	if inject {
		tokens = nil
		if ctx.StripCore && ctx.Rules != nil {
			tokens = tokensFor(ctx.Rules.Except(kinds))
		}
	}
	return &scanner{inject: inject, kinds: kinds, idx: idx, tokens: tokens, all: all, ref: new([]Refusal), seen: map[Refusal]struct{}{}, used: ctx.OnInject, refresh: IsOAuthPath(req.Target), ort: &ortMemo{}, extra: extra}
}

func plan(s *scanner, req *httpwire.Request) PlanResult {
	out := PlanResult{BodyMode: BodyStream, Inject: s.inject, Kinds: s.kinds}
	if IsOAuthPath(req.Target) || (!req.Chunked && req.ContentLength >= 0 && req.ContentLength <= maxBodyBuf) {
		out.BodyMode = BodyBuffer
	}
	s.noteMethod(req.Method)
	s.noteNames(req.Fields)
	for i, f := range req.Fields {
		if framingHeader(f.Name) {
			continue
		}
		sc, stripOnly := s.header(f.Name), stripOnlyHeader(f.Name)
		if strings.EqualFold(f.Name, "host") {
			// The authority decision and the broker checks read this Host,
			// and the origin routes by it. Thus the fence never changes it.
			// A placeholder refuses as in all other non-credential headers.
			// A live value refuses also.
			sc.noteAll([]byte(f.Value), "header")
			s.noteHost(f.Value)
			continue
		}
		if stripOnly {
			// The fence refuses this as in all other non-credential headers.
			// It still strips each live value here, an allowed kind also.
			sc.noteAll([]byte(f.Value), "header")
			sc = s.noInject()
		}
		sc.noteAll([]byte(f.Value), "header")
		d := sc.classify([]byte(f.Value))
		if dec, _, ok := BasicCredentials(f.Name, f.Value); ok {
			sc.noteAll(dec, "header")
			if d == DispKeep {
				d = sc.classify(dec)
			}
		}
		if d != DispKeep {
			out.Fields = append(out.Fields, FieldPlan{Index: i, Disp: d, StripOnly: stripOnly})
		}
	}
	u := s.at("url")
	u.noteAll([]byte(req.Target), "url")
	u.noteTarget(req.Target)
	out.Target = u.classify([]byte(req.Target))
	return out
}

// overflows reports a body with bytes past the buffer limit. A buffer
// would truncate it and leave the remainder on the wire as the next
// request. A probe that fails found a body cut short at the limit, not a
// body that ended there.
func overflows(r io.Reader) error {
	var probe [1]byte
	n, err := r.Read(probe[:])
	if n > 0 {
		return httpwire.ErrBodyLimit
	}
	if err == io.EOF {
		return nil
	}
	return err
}

// bufferSize is the most a buffered body can occupy: its announced
// length, or the whole buffer limit when no length was announced.
func bufferSize(req *httpwire.Request) int64 {
	if !req.Chunked && req.ContentLength >= 0 && req.ContentLength <= maxBodyBuf {
		return req.ContentLength
	}
	return maxBodyBuf
}

// readBody reads up to lim bytes. For a body of announced length, it
// allocates one buffer at that length (plus the byte that the EOF read
// needs). Thus the cost is the amount that Ctx.Reserve got a request for.
// The doubling of io.ReadAll would take up to twice that, and hold both
// halves at the same time during the copy.
func readBody(r io.Reader, lim, length int64, chunked bool) ([]byte, error) {
	lr := io.LimitReader(r, lim)
	if chunked || length < 0 {
		return io.ReadAll(lr)
	}
	b := make([]byte, 0, min(length, lim)+1)
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
		n, err := lr.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			return b, nil
		}
		if err != nil {
			return b, err
		}
	}
}

// requestEncodings is the list of codings that the Content-Encoding
// field(s) of the agent name, with the most recently applied last (RFC 9110
// 8.4.1). It drops identity: identity names no transformation and is never
// a layer to undo. It reads multiple header lines and one comma-separated
// line the same way, because each is a legal way to write a stack.
func requestEncodings(req *httpwire.Request) []string {
	var out []string
	for _, v := range req.Values("Content-Encoding") {
		for tok := range strings.SplitSeq(v, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" && tok != "identity" {
				out = append(out, tok)
			}
		}
	}
	return out
}

const (
	// maxEncodingLayers is the maximum number of codings on one request
	// body before the fence stops the attempt to unwind it. Two covers
	// what a real client stacks (gzip, sometimes gzip+deflate). Past that,
	// the layers do more to hide the body from the scan than to compress
	// it for the wire.
	maxEncodingLayers = 2
	// maxDecodedBody is the limit on the fully decoded size of a request
	// body, at a modest multiple of the compressed limit. It gives headroom
	// for the decode ratio of ordinary JSON and git objects. It is tight
	// enough that a compression bomb still ends in memory, not on the wire.
	maxDecodedBody = 8 * maxBodyBuf
)

// decodeLayer undoes one coding. These are the same two codings that the
// response side undoes (docs/fence.md 5.3b): gzip and its x-gzip alias
// with compress/gzip, and deflate with compress/zlib. This is the
// zlib-wrapped form that all libraries that send deflate write. It is not
// raw RFC 1951, which the response path also never had to read. ok is
// false for all other codings, for bytes that do not decode, and for a
// decoded size past maxDecodedBody. For gzip, fields are the optional
// fields of the member headers (gunzipMembers).
func decodeLayer(coding string, b []byte) (decoded []byte, fields [][]byte, ok bool) {
	switch coding {
	case "gzip", "x-gzip":
		return gunzipMembers(b)
	case "deflate":
		return inflate(b)
	}
	return nil, nil, false
}

// inflate undoes the deflate coding: the zlib-wrapped form.
func inflate(b []byte) (decoded []byte, fields [][]byte, ok bool) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, nil, false
	}
	defer r.Close()
	out, err := readBody(r, maxDecodedBody+1, -1, true)
	if err != nil || int64(len(out)) > maxDecodedBody {
		return nil, nil, false
	}
	return out, nil, true
}

// gunzipMembers inflates a gzip body one member at a time. It also returns
// the FEXTRA, FNAME and FCOMMENT fields of each member header. The fence
// forwards the compressed bytes, so these fields reach the origin with the
// body. The stdlib reader keeps only the header of the first member when
// it reads all members in one pass. Thus this reads each member alone.
func gunzipMembers(b []byte) (decoded []byte, fields [][]byte, ok bool) {
	br := bytes.NewReader(b)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, nil, false
	}
	defer zr.Close()
	for {
		zr.Multistream(false)
		for _, f := range [][]byte{zr.Extra, []byte(zr.Name), []byte(zr.Comment)} {
			if len(f) > 0 {
				fields = append(fields, f)
			}
		}
		out, err := readBody(zr, maxDecodedBody+1-int64(len(decoded)), -1, true)
		decoded = append(decoded, out...)
		if err != nil || int64(len(decoded)) > maxDecodedBody {
			return nil, nil, false
		}
		if err = zr.Reset(br); err == io.EOF {
			return decoded, fields, true
		} else if err != nil {
			return nil, nil, false
		}
	}
}

// decodeRequestBody undoes each coding in encs, the last-listed first,
// because that coding was applied last (requestEncodings). Thus the scan
// sees what the origin will decode the body to. ok is false for more
// layers than maxEncodingLayers, for an unsupported coding anywhere in the
// stack, and for bytes that do not decode. This includes a decompression
// bomb, because decodeLayer refuses it the same way. fields are the gzip
// header fields of all layers.
func decodeRequestBody(encs []string, body []byte) (decoded []byte, fields [][]byte, ok bool) {
	if len(encs) > maxEncodingLayers {
		return nil, nil, false
	}
	decoded = body
	for i := len(encs) - 1; i >= 0; i-- {
		var fs [][]byte
		if decoded, fs, ok = decodeLayer(encs[i], decoded); !ok {
			return nil, nil, false
		}
		fields = append(fields, fs...)
	}
	return decoded, fields, true
}

// noteEncodedBody scans a request body after the decode, for what the
// fence scans a buffered plaintext body for: a placeholder outside a
// header, and a live value or token-prefix match that a buffered body
// would strip and forward. The fence cannot repair either of them here,
// because it never rewrites the compressed bytes that reach the origin
// (docs/fence.md 5.3b). Thus a hit refuses the full request, not only the
// one field that a header hit would cost. No placement is allowed, not
// even the body of the refresh token: the fence never substitutes back in
// what this scan finds. Thus no place stays where a placeholder is safe.
func (s *scanner) noteEncodedBody(decoded []byte) {
	bs := *s
	bs.placed, bs.place = true, nil
	bs.noteAll(decoded, "body")
	for _, sl := range bs.idx.Lives {
		if bs.keeps(sl) {
			continue
		}
		if httpwire.Contains(decoded, []byte(sl.Live)) {
			s.refuse(CauseEncodedBodyToken, sl.ID, sl.Kind, "body")
		}
	}
	if bs.tokens.match(decoded) {
		s.refuse(CauseEncodedBodyToken, "", "", "body")
	}
}

func Decide(ctx Ctx, req *httpwire.Request, pol *corepolicy.Policy, slots map[string]secrets.Slot) ([]StripEvent, error) {
	strips, _, err := DecideStream(ctx, req, pol, slots)
	return strips, err
}

// DecideStream is Decide plus the handle for strips that occur while the
// fence copies a streamed body. When Ctx.Reserve grants the bytes, the
// fence buffers bodies up to maxBodyBuf and rewrites them in full. Larger
// bodies, and bodies for which Ctx.Reserve refuses, stream through a
// length-preserving scrub of each live value. Chunked bodies do the same.
// The fence never substitutes into these bodies. Thus a placeholder in one
// stops the copy (ErrPlaceholderInStream). Token-prefix rules do apply to
// streamed bodies: newTokenStream below wraps the copy. A streamed body
// loses refusal before the head goes out. It does not lose the scan.
func DecideStream(ctx Ctx, req *httpwire.Request, pol *corepolicy.Policy, slots map[string]secrets.Slot) ([]StripEvent, *StreamStrips, error) {
	s := newScanner(ctx, req, pol, secrets.NewIndex(slots))
	plan := plan(s, req)
	var strips []StripEvent
	var stream *StreamStrips

	var body []byte
	if req.Body != nil {
		var err error
		if body, err = s.intakeBody(ctx.Reserve, req, &plan); err != nil {
			return nil, nil, err
		}
	}
	// This runs before any rewrite and before the head reaches the origin.
	// Thus the origin never sees a refused request. The fence does not
	// read the bytes of a streamed body here. For a placeholder past the
	// buffer limit, placeholderGuard in the copy finds it instead and
	// stops the request at that byte.
	if len(*s.ref) > 0 {
		return nil, nil, &RefusedError{Refusals: *s.ref}
	}

	for _, fp := range plan.Fields {
		f := req.Fields[fp.Index]
		sc := s.header(f.Name)
		if fp.StripOnly {
			sc = s.noInject()
		}
		nv, ev, err := sc.rewriteHeader(f.Name, f.Value)
		if err != nil {
			return nil, nil, err
		}
		strips = append(strips, ev...)
		req.SetIndex(fp.Index, nv)
	}
	if plan.Target != DispKeep {
		nt, ev := s.at("url").rewrite([]byte(req.Target), "url")
		// A parser with the same line limit as the input parser reads back
		// the request line that the fence writes. A target that the
		// substitution made longer than that limit is a request that no origin completes.
		if len(req.Method)+len(req.Proto)+len(nt)+2 > maxFieldLine {
			return nil, nil, httpwire.ErrHeaderLimit
		}
		strips = append(strips, ev...)
		req.SetTarget(string(nt))
	}
	if plan.BodyMode == BodyBuffer && plan.Body != DispKeep {
		var ev []StripEvent
		body, ev = s.at("body").rewrite(body, "body")
		if len(body) > maxBodyBuf {
			return nil, nil, httpwire.ErrBodyLimit
		}
		strips = append(strips, ev...)
	}

	if plan.BodyMode == BodyBuffer {
		// A request that arrived with no body and no framing goes out
		// without one. SetBody would add Content-Length: 0 to each GET.
		// Clients do not send that (RFC 9110 8.6), and an origin can see it.
		if len(body) > 0 || req.Chunked || req.Get("Content-Length") != "" {
			req.SetBody(body)
		}
	} else {
		req.PrependBody(body)
		stream = s.wrapStream(req)
	}
	return strips, stream, nil
}

// intakeBody reads the body before the rewrite: all of it when the plan
// buffers it, else the first streamHead bytes. When reserve refuses the bytes, it
// moves the body to the stream path, or refuses an OAuth request. It
// scans a buffered body and sets plan.Body.
func (s *scanner) intakeBody(reserve func(n int64) bool, req *httpwire.Request, plan *PlanResult) ([]byte, error) {
	if plan.BodyMode == BodyBuffer && reserve != nil {
		n := bufferSize(req)
		if n > 0 && !reserve(n) {
			if IsOAuthPath(req.Target) {
				return nil, ErrBufferBudget
			}
			plan.BodyMode = BodyStream
		}
	}
	// The scan cannot read a body under Content-Encoding before a
	// decode, and only a buffered body can be decoded. The fence
	// refuses a body that will stream, because it is too large to
	// buffer or because the reservation above moved it to the stream
	// path. It does not forward it unscanned (docs/fence.md 5.3).
	encs := requestEncodings(req)
	if len(encs) > 0 && plan.BodyMode != BodyBuffer {
		s.refuse(CauseEncodedBody, "", "", "body")
	}
	lim := int64(streamHead)
	if plan.BodyMode == BodyBuffer {
		lim = maxBodyBuf
	}
	body, err := readBody(req.Body, lim, req.ContentLength, req.Chunked)
	if err != nil {
		return nil, err
	}
	if plan.BodyMode != BodyBuffer {
		return body, nil
	}
	if int64(len(body)) == lim {
		if err := overflows(req.Body); err != nil {
			return nil, err
		}
	}
	if len(encs) > 0 {
		// The fence never rewrites it in either case (5.3b): a clean
		// decode only proves that the compressed bytes can go out as they are.
		// Each gzip header field gets the scan of the body, one field at a
		// time. A hit there refuses the request in the same way.
		if decoded, fields, ok := decodeRequestBody(encs, body); ok {
			s.noteEncodedBody(decoded)
			s.noteJSONBody(req, decoded)
			for _, f := range fields {
				s.noteEncodedBody(f)
			}
		} else {
			s.refuse(CauseEncodedBody, "", "", "body")
		}
	} else {
		s.at("body").noteAll(body, "body")
		s.noteJSONBody(req, body)
		plan.Body = s.at("body").classify(body)
	}
	return body, nil
}

// wrapStream puts the copy-time scans over a streamed body, from the
// bottom up: the scrubber, the placeholder guard, then the token stream.
// It returns nil when no scan reports strips.
func (s *scanner) wrapStream(req *httpwire.Request) *StreamStrips {
	pairs, rules := s.stripPairs(!req.Chunked)
	var sc *httpwire.Scrubber
	if len(pairs) > 0 && req.Body != nil {
		sc = httpwire.NewScrubber(req.Body, pairs)
		req.Body = sc
	}
	// Above the scrubber: placeholders. The fence never writes into a
	// streamed body. The one body that a credential goes in, the body
	// of the refresh token, is always buffered. Thus a placeholder here
	// is one that the buffered path would refuse. The head already went
	// out, so the copy stops at the placeholder.
	if req.Body != nil {
		req.Body = newPlaceholderGuard(req.Body)
	}
	// Above the guard, so a stored value goes into the log as its own
	// slot name, not as the rule that its shape matches. The buffered
	// path uses the same order. This is also safe over the injected
	// side: for a host that injects a kind, newScanner gives a token set
	// without the rules of that kind. Thus the pass cannot strip the
	// credential that the guard just wrote.
	var tok *tokenStream
	if s.tokens != nil && req.Body != nil {
		tok = newTokenStream(req.Body, s.tokens, !req.Chunked)
		req.Body = tok
	}
	if sc == nil && tok == nil {
		return nil
	}
	return &StreamStrips{sc: sc, rules: rules, tok: tok}
}

// Scanner exposes the credential scan of request headers and bodies to
// callers that hold bytes that the HTTP path never sees. Today these are
// the WebSocket frames of the broker. It is the no-inject scanner on
// purpose: a frame is opaque application data, with no field that the
// fence owns. A placeholder rewritten into a live token there would give
// the agent a credential that it did not have. The fence could not scrub
// that credential out of the reply. Inside frames, the fence only strips.
// The broker refuses a placeholder in a frame before this scan
// (CausePlaceholderInWS).
type Scanner struct{ s *scanner }

func NewScanner(ctx Ctx, req *httpwire.Request, pol *corepolicy.Policy, slots map[string]secrets.Slot) *Scanner {
	return &Scanner{s: newScanner(ctx, req, pol, secrets.NewIndex(slots)).noInject()}
}

// Scrub replaces every stored live value and every token-prefix match in
// b, and reports one event per match under where.
func (s *Scanner) Scrub(b []byte, where string) ([]byte, []StripEvent) {
	return s.s.rewrite(b, where)
}
