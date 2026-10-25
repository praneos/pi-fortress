package broker

import (
	"strings"
	"sync"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// logRefusals writes the full taxonomy to the channel of the operator.
// This half of the design makes the single response to the agent
// affordable: nothing is lost, it only goes to a different location. The
// destination deny is marked for the alerter. Reason: it is not an
// operational fault to fix. It is the fence that catches a credential
// aimed at a location where it is not permitted.
//
// A refusal that names a CANARY slot alerts every time, whatever the
// cause. It does not use the once-per-cause alert of the other refusals.
func (b *Broker) logRefusals(c *call, rs []fence.Refusal) {
	// A Host that holds a live value must not go to the log, because the
	// alerter posts the host of a row to the webhook. The rows of this
	// request name the SNI instead.
	host := c.host
	for _, r := range rs {
		if r.Cause == fence.CauseLiveInHost {
			host = strings.ToLower(strings.TrimSuffix(c.p.SNI, "."))
		}
	}
	for _, r := range rs {
		canary := r.Kind == corepolicy.KindCanary
		// Before alertRefusal: a row that the cap drops must not use the
		// once-per-cause alert. If it did, the operator would never get the alert.
		if !c.strips.take(canary) {
			continue
		}
		row := jsonl.Refused{
			Host:     host,
			SNI:      c.p.SNI,
			Where:    r.Where,
			Cause:    string(r.Cause),
			Slot:     r.Slot,
			Kind:     r.Kind,
			Alert:    canary || b.alertRefusal(r.Cause),
			ClientIP: clientIP(c.p),
		}
		if canary {
			row.Threat = threatCanary
		}
		_ = b.Logs.Refused(row)
	}
}

const threatCanary = "canary"

// canaryRule reports whether a strip rule names a stored CANARY value.
func canaryRule(rule string) bool {
	key, ok := strings.CutPrefix(rule, "secret:")
	if !ok {
		return false
	}
	_, kind, ok := secrets.ParseEnvKey(key)
	return ok && kind == corepolicy.KindCanary
}

// alertRefusal decides which refusals are important enough to wake a
// person for.
//
// The destination deny is always important enough. It is not an
// operational fault to fix. It is the fence that catches a credential
// aimed at a location where it is not permitted. A flood of these is the
// signal, not the noise.
//
// The other three are conditions, not events. If a 03:00 power cut seals
// the store, the store refuses each request that an agent retries. A post
// for each refusal would change one fact into a webhook every few seconds.
// Thus these three alert on the first refusal of their kind since this
// process started. The operator must know one time that credentials
// stopped working. The log still records each occurrence.
func (b *Broker) alertRefusal(cause fence.RefusalCause) bool {
	// A live value in a decoded body, a decoded target, the Host, a
	// Connection or an Upgrade has the same signature as the other two:
	// a credential aimed where the plain scan would not see it. A body that
	// the fence could not decode is different. An ordinary client that
	// compresses its uploads with zstd gets a refusal on each request. A post
	// for each would use all of the hourly cap of the webhook before a real
	// strip arrives. It alerts one time, like the conditions below. A
	// repeated credential header or a repeated Content-Type on a refresh is
	// an attempt to make the origin read a value that the fence did not
	// decide on. No ordinary client sends it.
	switch cause {
	case fence.CauseKindNotAllowed, fence.CauseOutsideHeader, fence.CausePlaceholderInWS,
		fence.CauseEncodedBodyToken, fence.CauseKeyInHeaderName, fence.CauseKeyInMethod,
		fence.CauseEncodedURLToken, fence.CauseLiveInHost, fence.CauseLiveInConnection,
		fence.CauseRepeatedCredHeader, fence.CauseRepeatedContentType:
		return true
	}
	b.useMu.Lock()
	defer b.useMu.Unlock()
	if b.saidCause == nil {
		b.saidCause = map[fence.RefusalCause]bool{}
	}
	if b.saidCause[cause] {
		return false
	}
	b.saidCause[cause] = true
	return true
}

// used is one credential that the fence put on the wire for this call. The
// use log of the operator and the hourly budget of the slot see exactly
// the same events. Both see them only after the request is past the point
// where the fence could still refuse it unsubstituted.
func (b *Broker) used(c *call, slot string) {
	c.spend(slot)
	b.logUse(slot, c.host, clientIP(c.p))
}

func (b *Broker) logUse(slot, host, ip string) {
	if b.Logs == nil || b.Logs.UsePath == "" {
		return
	}
	// use.jsonl was examined for the growth problem of the unknown and strip
	// logs. It has one row per slot per minute. Slots belong to the operator,
	// and an agent cannot mint them, so the store bounds this log. The code
	// makes the decision one time, under the lock. Before, it made the decision
	// two times, and two requests in the same instant could both see the
	// minute as over.
	b.useMu.Lock()
	last, seen := b.lastUse[slot]
	now := time.Now()
	write := !seen || now.Sub(last) >= time.Minute
	if write {
		if b.lastUse == nil {
			b.lastUse = map[string]time.Time{}
		}
		b.lastUse[slot] = now
	}
	b.useMu.Unlock()
	if write {
		_ = b.Logs.Use(jsonl.Use{Slot: slot, Host: host, ClientIP: ip})
	}
}

// clientIP is the agent-side address of the connection, from the preamble,
// without the port. It is empty when the engine sent no address.
func clientIP(p *preamble.Preamble) string {
	if p == nil || !p.Src.IsValid() {
		return ""
	}
	return p.Src.Addr().String()
}

// maxStripRows is the number of rows that one request may write to
// strip.jsonl before the broker counts the remaining rows instead. A
// websocket session counts as the request that opened it. The fence logs a
// row per rule per place where it found a token. Thus a body full of each
// prefix in each field was about 900 rows and 130 KB for one request, and
// pf alert posts a strip row to the webhook. Sixteen is more than a real
// request trips: one credential in a header and possibly its echo in a
// body is two or three rows. pf alert fires on the first rows. The one
// summary row that flushStrips writes still counts the dropped rows.
const maxStripRows = 16

// stripSummaryRule is the rule of that summary row. It is an ordinary
// strip row with Count and Limit set, which every reader of the file
// already decodes, and it reads in pf alert as "STRIP suppressed in
// request -> host".
const stripSummaryRule = "suppressed"

// ruleRespCTL is the strip row for an origin head with control bytes that
// the broker blanked to spaces (httpwire blankCTL). Like "encoded:", it is
// not a credential. It is a byte that the client of the agent would read
// differently.
const ruleRespCTL = "response_ctl"

// stripCap counts the strip.jsonl rows of one request against
// maxStripRows. nil counts nothing: the rows that the broker writes outside
// a request (the fake-IP admission, the slot budget) are already one per
// connection or per crossing. The mutex is for the websocket relay,
// because its two directions run on their own goroutines.
type stripCap struct {
	mu         sync.Mutex
	n          int
	canary     bool
	suppressed int64
}

// take reports whether one more row may be written. One time per request,
// take lets a canary row go past a full cap. The canary row shows the
// challenge credential, and it is the row that the operator needs most. An
// agent that sent sixteen junk tokens first must not be able to hide it
// behind them.
func (s *stripCap) take(canary bool) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n < maxStripRows {
		s.n++
		s.canary = s.canary || canary
		return true
	}
	if canary && !s.canary {
		s.canary = true
		return true
	}
	s.suppressed++
	return false
}

func (s *stripCap) drain() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.suppressed
	s.suppressed = 0
	return n
}

func (b *Broker) logStrip(cp *stripCap, ip, host, where, rule string) error {
	if b.Logs == nil {
		return nil
	}
	ev := jsonl.Strip{Host: host, Where: where, Rule: rule, ClientIP: ip}
	if canaryRule(rule) {
		ev.Threat = threatCanary
	}
	if !cp.take(ev.Threat == threatCanary) {
		return nil
	}
	return b.Logs.Strip(ev)
}

// flushStrips writes what the cap dropped for this request as one row.
func (b *Broker) flushStrips(c *call) {
	n := c.strips.drain()
	if n == 0 || b.Logs == nil {
		return
	}
	_ = b.Logs.Strip(jsonl.Strip{
		Host:     c.host,
		Where:    "request",
		Rule:     stripSummaryRule,
		ClientIP: clientIP(c.p),
		Count:    n,
		Limit:    maxStripRows,
	})
}

// whereParanoid is the unknown row of the paranoid destination deny.
const whereParanoid = "paranoid_deny"

// host is the host of the row (rowHost). where names the path that
// logged the row. Empty is the ordinary unknown-host sample, and jsonl
// fills in "http".
func (b *Broker) logUnknown(p *preamble.Preamble, req *httpwire.Request, host string, stripped bool, where string) error {
	if b.Logs == nil {
		return nil
	}
	// The row has the shape of the request only: no hash of a header or a
	// body, because a body hash after substitution comes from the credential.
	bodyLen := 0
	if req.ContentLength > 0 {
		bodyLen = int(req.ContentLength)
	}
	names := make([]string, 0, len(req.Fields))
	for _, f := range req.Fields {
		names = append(names, f.Name)
	}
	if len(names) > 40 {
		names = names[:40]
	}
	destIP := ""
	destPort := 0
	if p.OrigDst.IsValid() {
		destIP = p.OrigDst.Addr().String()
		destPort = int(p.OrigDst.Port())
	}
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	if sni == "" {
		sni = host
	}
	path, ua, ct, cookies := pathOnly(req.Target), clip(req.Get("User-Agent"), 256), clip(req.Get("Content-Type"), 128), cookieNames(req.Get("Cookie"))
	if where == whereParanoid {
		// The paranoid deny runs before the fence. Thus these are the bytes of the
		// agent before any strip, and a token can be in any of them, also in
		// a field name.
		path, ua, ct, cookies, names = "", "", "", nil, nil
		bodyLen = 0
	}
	return b.Logs.Unknown(jsonl.Unknown{
		ClientIP:    clientIP(p),
		Host:        host,
		SNI:         sni,
		DestIP:      destIP,
		DestPort:    destPort,
		Method:      req.Method,
		Path:        path,
		HTTPVersion: req.Proto,
		HeaderNames: names,
		UA:          ua,
		ContentType: ct,
		BodyLen:     bodyLen,
		AuthScheme:  authScheme(req.Get("Authorization")),
		CookieNames: cookies,
		Stripped:    stripped,
		Where:       where,
	})
}

// rowHost is the host that the rows of a request name. Usually it is host,
// the prettyHost of the request. A Host that holds a live value or a
// token-prefix match makes the fence refuse the request (live_in_host).
// But the broker writes some rows before the fence runs: the target
// rules, the blocklist, the paranoid deny and a refused git push. The
// alerter posts the host of a strip row to the webhook. So for such a
// Host, each row names the SNI. The test reads the Host as sent and as
// the row writes it (lowercase), because a live value can be in either
// form. A sealed store gives no live values; then only the token rules
// apply.
func (b *Broker) rowHost(p *preamble.Preamble, req *httpwire.Request, host string) string {
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	if host == sni {
		return host
	}
	var slots map[string]secrets.Slot
	if b.Store != nil {
		slots, _ = b.Store.Snapshot()
	}
	ctx := fence.Ctx{TokenRE: b.TokenRE, Rules: b.Rules}
	if fence.SecretInHost(ctx, req.Get("Host"), slots) || fence.SecretInHost(ctx, host, slots) {
		return sni
	}
	return host
}

// logLiveConn writes the live_in_connection rows of the fence for a
// protocol switch that the broker refuses before the fence runs. The
// agent gets the same 501 in all cases.
func (b *Broker) logLiveConn(c *call) {
	var slots map[string]secrets.Slot
	if b.Store != nil {
		slots, _ = b.Store.Snapshot()
	}
	ctx := fence.Ctx{TokenRE: b.TokenRE, Rules: b.Rules}
	var rs []fence.Refusal
	for _, name := range []string{"Connection", "Upgrade"} {
		for _, v := range c.req.Values(name) {
			rs = append(rs, fence.LiveIn(ctx, v, slots, fence.CauseLiveInConnection, "header:"+name)...)
		}
	}
	b.logRefusals(c, rs)
}

func prettyHost(req *httpwire.Request, sni string) string {
	h := req.Get("Host")
	if i := strings.Index(h, ":"); i >= 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h != "" {
		return h
	}
	return strings.ToLower(strings.TrimSuffix(sni, "."))
}

func pathOnly(target string) string {
	p := target
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 128 {
		p = p[:128]
	}
	return p
}

func authScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "none"
	}
	scheme, _, _ := strings.Cut(raw, " ")
	if len(scheme) > 16 {
		scheme = scheme[:16]
	}
	return scheme
}

func cookieNames(raw string) []string {
	var names []string
	for _, part := range strings.Split(raw, ";") {
		bit := strings.TrimSpace(part)
		if bit == "" {
			continue
		}
		name, _, _ := strings.Cut(bit, "=")
		name = strings.TrimSpace(name)
		if len(name) > 64 {
			name = name[:64]
		}
		if name != "" {
			names = append(names, name)
		}
		if len(names) >= 32 {
			break
		}
	}
	return names
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
