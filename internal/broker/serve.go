package broker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/doh"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/hello"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// errCloseDelimited: the response body had no framing, so the body ends
// at the end of the connection. Handle must close the connection. It must
// not wait for a next request and answer the idle timeout with a 400: the
// client would read that 400 as body bytes.
var errCloseDelimited = errors.New("broker: close-delimited response")

// errRefusedUnread: the broker refused the request when the client had
// not sent its body yet (Expect pending). The broker drains nothing. The
// connection closes.
var errRefusedUnread = errors.New("broker: refused before the body was read")

// errRefused: the broker refused the request and wrote all of the
// refusal. The refusal announces Connection: close. Handle ends the
// connection. It does not wait for a next request, because the header
// said that no next request will come.
var errRefused = errors.New("broker: refused, connection closes")

func drain(req *httpwire.Request) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
	}
}

// refuse answers a request that the fence will not forward. refuse never
// waits for a body that the client has not sent yet. Otherwise it drains
// the body, so that it writes the refusal after the request, never in the
// middle of it. The connection closes in both cases: see errRefused.
func (b *Broker) refuse(client net.Conn, req *httpwire.Request, expect bool, code int, status, msg string) error {
	return b.answer(client, req, expect, func() error { return writeErr(client, code, status, msg) })
}

// refuseSubstitution answers a request that the fence had to substitute
// into and could not. Like every other refusal, it goes through answer,
// so the connection stays in the same state. It takes no cause: see
// writeRefused.
func (b *Broker) refuseSubstitution(c *call) error {
	return b.answer(c.client, c.req, c.expect, func() error { return writeRefused(c.client) })
}

func (b *Broker) answer(client net.Conn, req *httpwire.Request, expect bool, write func() error) error {
	if expect {
		_ = write()
		return errRefusedUnread
	}
	drain(req)
	if err := write(); err != nil {
		return err
	}
	return errRefused
}

// call is one request on one client connection: what serve decided
// about it and what the stages after the decision share.
type call struct {
	client net.Conn
	br     *bufio.Reader
	p      *preamble.Preamble
	req    *httpwire.Request
	up     *upstream
	expect bool
	// authority is the Host as the decisions read it (prettyHost). host is
	// the name that the rows of the request carry (rowHost). They differ
	// only for a Host that holds a credential.
	authority string
	host      string
	echo      bool
	// echoRole is set with echo and names the fixture that answers. The two
	// fixtures differ in what they may receive. The core fixture is lab-gated
	// and reflects a substituted request on purpose. The open fixture is
	// reachable from a shipped box. It must never get a credential to reflect.
	echoRole string
	ws       bool
	slots    map[string]secrets.Slot
	// refresh is harvestAllowed for this request. jsonBody says that its
	// Content-Type is application/json, and is set only with refresh.
	// prepare sets both.
	refresh, jsonBody bool
	harvestSlot       string
	clientGzip        bool
	ubr               *bufio.Reader
	// spent are the slots that this request substituted, in the order that
	// the fence reached them. Each slot is in spent one time, however many
	// times the fence injected it. charged is the number of these slots for
	// which the hourly budget has counted a request. Because the code only
	// appends to spent, the second charge can take spent[charged:] and know
	// that it charges nothing twice.
	spent   []string
	charged int
	// stopsSeen is budget.stopsLanded from before the slot snapshot. It
	// tells a restored slot from one that this request saw before its stop.
	stopsSeen uint64
	// body counts a streamed request body while the copy occurs. body does
	// not wrap a buffered body, on purpose. roundTrip replays those bytes on a
	// redial. It uses a type switch to decide that it can replay, and a
	// wrapper would hide the type. Also, the length of a buffered body is
	// already exact in the request.
	body          *countReader
	uploadCharged bool
	// strips holds the strip.jsonl rows of this request, to a maximum of
	// maxStripRows.
	strips stripCap
	// memReq is the part of the broker byte budget that the buffered request
	// body holds. The broker releases it when the origin has the request.
	// memResp is the share of the response side: a buffer or a gzip writer.
	// When serve returns, it releases all that remains of both, on every
	// path. bodyDenied records that the budget refused the body.
	memReq, memResp int64
	bodyDenied      bool
}

// The budget charge for a request body or a response is two times its
// length. A buffered body is live together with its rewritten copy in the
// fence. It is also live together with the serialized replay copy while
// roundTrip writes it. A buffered response is live together with the
// grown buffer of io.ReadAll, and then with its rewritten copy.
const bufCopies = 2

// spend records that this call substituted slot, once.
func (c *call) spend(slot string) {
	if slices.Contains(c.spent, slot) {
		return
	}
	c.spent = append(c.spent, slot)
}

// uploadBytes is what this request put on the origin leg as a body.
func (c *call) uploadBytes() int64 {
	if c.body != nil {
		return c.body.n
	}
	if c.req.ContentLength > 0 {
		return c.req.ContentLength
	}
	return 0
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// serve runs the stages of one request in order: admit it, prepare it
// for the origin, bind a harvest slot, send it, then decode and write
// the response through the buffered or the streamed path.
func (b *Broker) serve(ctx context.Context, client net.Conn, br *bufio.Reader, p *preamble.Preamble, req *httpwire.Request, up *upstream, expect bool) error {
	c := &call{client: client, br: br, p: p, req: req, up: up, expect: expect}
	defer b.flushStrips(c)
	defer func() {
		b.memGive(&c.memReq)
		b.memGive(&c.memResp)
	}()
	if done, err := b.admit(c); done {
		return err
	}
	if done, err := b.paranoidRefuse(c); done {
		return err
	}
	if done, err := b.gitPushRefuse(c); done {
		return err
	}
	strips, stream, done, err := b.prepare(c)
	if done {
		return err
	}
	b.chargeBudget(c)
	if done, err := b.bindHarvest(c); done {
		return err
	}
	if c.harvestSlot != "" {
		if !b.Store.Acquire(c.harvestSlot) {
			_ = b.refuse(client, req, false, 429, "429 Too Many Requests", "refresh_busy\n")
			return ErrBusy
		}
		defer b.Store.Release(c.harvestSlot)
		if done, err := b.spentRefuse(c); done {
			return err
		}
		// The broker always buffers the token response, to harvest it. So the
		// broker takes its bytes now, while a refusal costs nothing. When the
		// origin has the refresh token, it rotates the pair. After that, if the
		// broker could not hold the reply, a slot would lose its credential.
		if !b.memTake(&c.memResp, bufCopies*maxRespBuf) {
			b.logMemBudget(clientIP(p), c.host, "response")
			return b.refuseBusy(c)
		}
	}
	if c.echo {
		if !c.ws {
			if done, err := b.echoBody(c, stream); done {
				return err
			}
			return b.echo(client, p, req, c.slots, c.harvestSlot)
		}
		// The handshake meets a net.Pipe instead of the uplink. Every
		// stage below is the one a real wss connection runs.
		b.echoWSOrigin(c)
	}
	if !b.hostAllowed(c.authority) {
		_ = b.logUnknown(p, req, c.host, len(strips) > 0, "")
	}
	// A chunked body announces no length. So the only honest count of its
	// upload occurs while the body goes past. This is after bindHarvest,
	// because bindHarvest reads the body with a type switch that this
	// wrapper would hide.
	if req.Body != nil && req.ContentLength < 0 {
		c.body = &countReader{r: req.Body}
		req.Body = c.body
	}
	resp, err := b.roundTrip(ctx, c)
	// The charge occurs whatever roundTrip returned. A streamed body
	// substitutes during the copy, so slots that prepare never saw can appear
	// here. Also, bytes that an aborted copy put on the wire went out all the
	// same.
	b.chargeBudget(c)
	b.chargeUpload(c)
	// The origin has the request, so the broker no longer needs a buffered
	// body. Drop it and release its bytes now. Do not hold them for as long
	// as a streamed response runs: for an event stream, that is minutes.
	if c.memReq > 0 {
		if _, ok := req.Body.(*bytes.Reader); ok {
			req.Body = nil
		}
		b.memGive(&c.memReq)
	}
	// The broker scrubs a streamed body during the copy to the origin. So
	// when roundTrip reports an error, the strips from that copy are already
	// on the wire. The broker logged them only on the path that reached a
	// response. So a copy that ended at a placeholder, a dropped origin or a
	// write failure left no record that the broker had replaced a credential
	// in bytes that the origin received. The broker reads the events one
	// time, before it answers the error, so neither path logs them twice.
	// Events is nil-safe for a body that the broker never streamed and for a
	// stream that was only half built.
	for _, ev := range stream.Events() {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, ev.Where, ev.Rule)
	}
	if err != nil {
		return err
	}
	// The parser (httpwire blankCTL) changed control bytes in the origin head
	// to spaces. So the client of the agent reads the head as the scrub did.
	// No real origin sends a control byte. The row is for an origin that
	// does: that origin probably reflects something that the agent sent.
	if resp.CTLs > 0 {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "response", ruleRespCTL)
	}
	// The origin agreed to switch: from here the connection carries frames,
	// not responses. Any other answer from the origin is an ordinary response
	// and takes the path below.
	if c.ws && resp.Code == 101 {
		return b.serveWS(client, br, up, c.ubr, p, req, resp, c.slots, c.host, &c.strips, len(c.spent) > 0)
	}
	dropHopByHop(&resp.Fields)
	originCloseDelimited, reencode, zr, err := b.decodeBody(c, resp)
	if err != nil {
		return err
	}
	if zr != nil {
		defer zr.Close()
	}
	buffered := c.harvestSlot != "" || resp.NoBody || (!resp.Chunked && resp.ContentLength >= 0 && resp.ContentLength <= maxRespBuf)
	// A harvest took its bytes before the request went out. Any other
	// buffered body takes its bytes here. If the bytes are not available, the
	// body streams through the same scrub that every response over
	// maxRespBuf goes through.
	if buffered && c.harvestSlot == "" && !resp.NoBody && !b.memTake(&c.memResp, bufCopies*resp.ContentLength) {
		b.logMemBudget(clientIP(p), c.host, "response")
		buffered = false
	}
	if reencode {
		// A buffered re-encode also holds the compressed copy.
		cost := int64(gzipWriterCost)
		if buffered {
			cost += maxRespBuf
		}
		if !b.memTake(&c.memResp, cost) {
			// Identity is always acceptable to a client that asked for
			// gzip. The only cost is more bytes on the LAN hop.
			b.logMemBudget(clientIP(p), c.host, "gzip")
			reencode = false
		}
	}
	if buffered {
		return b.writeBuffered(c, resp, reencode)
	}
	return b.writeStreamed(c, resp, reencode, originCloseDelimited)
}

// admit refuses each request that the fence will not forward at all: a
// listed name, a core echo outside the lab, a protocol switch that is not
// wss, and a DoH request. It sets host, echo and ws for the later stages.
// done says that admit answered the request. A refusal that wrote without
// error returns done with errRefused, so the caller tests done, not err.
func (b *Broker) admit(c *call) (done bool, err error) {
	c.authority = prettyHost(c.req, c.p.SNI)
	c.host = b.rowHost(c.p, c.req, c.authority)
	if rule := targetRefusal(c.req, c.p.OrigDst.Port()); rule != "" {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "target", rule)
		return true, b.refuse(c.client, c.req, c.expect, 400, "400 Bad Request", "request\n")
	}
	if b.Blocked.Has(c.authority) || b.Blocked.Has(c.p.SNI) {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "host", "blocklist")
		return true, b.refuse(c.client, c.req, c.expect, 403, "403 Forbidden", "blocked\n")
	}
	c.echo = isEcho(c.p.OrigDst) || echoHost(c.p.SNI, c.authority)
	if c.echo {
		c.echoRole = echoRole(c.p, c.req)
	}
	if c.echo && !b.LabEcho && c.echoRole == "core" {
		_ = b.refuse(c.client, c.req, c.expect, 403, "403 Forbidden", "lab_only\n")
		return true, ErrLabOnly
	}
	// The broker forwards a complete wss handshake. Each other Upgrade is a
	// protocol with frames that the fence cannot read. The echo fixtures
	// answer locally and have no origin to switch protocols with. The
	// exception is the fixture that echoUpgrade names: the core fixture holds
	// its own peer on a pipe (echows.go). This gives the frame path a test
	// that runs end to end.
	c.ws = isWebSocketUpgrade(c.req) && (!c.echo || b.echoUpgrade(c))
	if isUpgrade(c.req) && !c.ws {
		b.logLiveConn(c)
		return true, b.refuse(c.client, c.req, c.expect, 501, "501 Not Implemented", "upgrade\n")
	}
	if c.ws {
		// permessage-deflate would make each frame opaque to the scan. So
		// the offer never reaches the origin, and the origin cannot accept it.
		c.req.Del("Sec-WebSocket-Extensions")
	}
	if doh.HTTPFields(c.req.Target, c.req.Values("Content-Type"), c.req.Values("Accept")) {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "doh", "dns_pin")
		return true, b.refuse(c.client, c.req, c.expect, 403, "403 Forbidden", "dns_pin\n")
	}
	return false, nil
}

// targetRefusal gives the reason that the broker does not forward a
// request line, or "" for a request line that it forwards. Each decision
// here uses the SNI and the Host as the authority. The broker forwards
// the target verbatim. An origin that follows RFC 9112 §3.2.2 routes an
// absolute-form target by its own authority and ignores the Host. So only
// origin-form and OPTIONS * ever leave. Any other form would let the agent
// name a vhost that the fence never judged, with the credential injected
// for the vhost that the fence judged. CONNECT is a tunnel that the fence
// cannot read into. An HTTP/1.1 request without a Host field, or with an
// empty one, makes the routing of the origin a guess. Each origin can send
// it to a different vhost than the one the SNI names. HTTP/1.0 has no
// Host requirement, so there the decisions use the SNI. A Host that is
// there must be a host and port (validHost). Its port must be the port
// that the broker dialled (hostPortMismatch). dialled is 0 when no
// original destination is known.
func targetRefusal(req *httpwire.Request, dialled uint16) string {
	switch {
	case req.Method == "CONNECT":
		return "connect"
	case req.Target == "*":
		if req.Method != "OPTIONS" {
			return "request_target"
		}
	case !strings.HasPrefix(req.Target, "/"):
		return "request_target"
	}
	host := strings.Trim(req.Get("Host"), " \t")
	if req.Proto != "HTTP/1.0" && host == "" {
		return "no_host"
	}
	if host != "" && !validHost(host) {
		return "bad_host"
	}
	if host != "" && hostPortMismatch(host, dialled) {
		return "host_port_mismatch"
	}
	return ""
}

// hostPortMismatch reports a Host port that is not the dialled port. The
// fence, the blocklist and paranoid mode decide on the name and ignore
// the port. An origin can route by the port in the Host, so a different
// port can name a vhost that nobody judged. A Host with no port names no
// other port, so it goes out. host is valid
// (validHost). A bracketed IPv6 literal has colons of its own, so only a
// colon after the ']' starts a port.
func hostPortMismatch(host string, dialled uint16) bool {
	if dialled == 0 || strings.HasSuffix(host, "]") {
		return false
	}
	i := strings.LastIndexByte(host, ':')
	if i < 0 {
		return false
	}
	n, err := strconv.Atoi(host[i+1:])
	return err != nil || n != int(dialled)
}

// validHost reports whether h is host[:port] (RFC 9110 §7.2): a DNS name,
// an IPv4 literal or a bracketed IPv6 literal, then an optional port.
// Blocked.Has walks labels. A Host such as "x@blocked.example" or
// "[blocked.example]" has no label that the list holds, but an origin that
// reads it loosely still routes it to the listed name.
func validHost(h string) bool {
	host := h
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.HasSuffix(h, "]") {
		n, err := strconv.Atoi(h[i+1:])
		if err != nil || n < 1 || n > 65535 || strings.TrimLeft(h[i+1:], "0123456789") != "" {
			return false
		}
		host = h[:i]
	}
	if ip, ok := strings.CutPrefix(host, "["); ok {
		ip, ok = strings.CutSuffix(ip, "]")
		a, err := netip.ParseAddr(ip)
		return ok && err == nil && a.Is6() && a.Zone() == ""
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" || !hello.ValidHostName(host) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

// paranoidRefuse is the destination deny of docs/paranoid_mode.md. When
// the mode is armed, the broker forwards a request only when the forward
// oracle accepts both the SNI and the Host. It runs before the
// 100-continue, the slot snapshot and the websocket handshake. So an
// unlisted name never reaches the origin and never spends a slot. The
// blocklist above still wins. When the mode is off, nothing here fires.
func (b *Broker) paranoidRefuse(c *call) (done bool, err error) {
	if !b.paranoidFor(c.p) || c.echo {
		return false, nil
	}
	if b.forwardAllowed(c.authority) && b.forwardAllowed(c.p.SNI) {
		return false, nil
	}
	_ = b.logUnknown(c.p, c.req, c.host, false, whereParanoid)
	return true, b.refuse(c.client, c.req, c.expect, 403, "403 Forbidden", "paranoid\n")
}

// gitPushRefuse applies docs/git_push.md. A git smart-HTTP push (the
// info/refs advertisement or the pack POST) reaches the origin only for a
// repo in git_push.allow. It runs before the 100-continue, so a refused
// push never sends its pack. It answers with the one substitution
// refusal, so the agent cannot tell a list miss from a sealed store.
func (b *Broker) gitPushRefuse(c *call) (done bool, err error) {
	refused, repo, clean := fence.GitPushRefused(b.GitPush, c.authority, c.p.SNI, c.req.Method, c.req.Target)
	if !refused {
		return false, nil
	}
	where := "target"
	if !clean {
		where, repo = "target_ambiguous", clip(pathOnly(c.req.Target), 256)
	}
	_ = b.Logs.Refused(jsonl.Refused{
		Host:     c.host,
		SNI:      c.p.SNI,
		Where:    where,
		Cause:    string(fence.CauseGitPushNotAllowed),
		ClientIP: clientIP(c.p),
		Repo:     repo,
	})
	return true, b.refuseSubstitution(c)
}

// prepare snapshots the slots, releases a held-back body with 100
// Continue, and runs the fence over the request. done says that prepare
// answered the request (an echo answered locally, or a refusal). Then the
// caller returns err as it is, nil or not.
func (b *Broker) prepare(c *call) (strips []fence.StripEvent, stream *fence.StreamStrips, done bool, err error) {
	if b.Store != nil {
		c.stopsSeen = b.budget.stopsLanded()
		c.slots, err = b.Store.Snapshot()
		if err != nil {
			if c.echo {
				return nil, nil, true, b.echo(c.client, c.p, c.req, map[string]secrets.Slot{}, "")
			}
			_ = b.refuse(c.client, c.req, c.expect, 500, "500 Internal Server Error", "secrets\n")
			return nil, nil, true, err
		}
	}
	if c.slots == nil {
		c.slots = map[string]secrets.Slot{}
	}
	// The fence accepts the request for the origin. Only now may the client
	// send the body that it held back.
	if c.expect {
		if _, err := io.WriteString(c.client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return nil, nil, true, err
		}
	}
	// The broker holds the slots that the fence injects during the decision
	// until DecideStream returns without error. Thus a refused request never
	// leaves a use row that claims a credential went out. A streamed body
	// injects later, in the copy, and logs during the copy.
	var pending []string
	decided := false
	onInject := func(slot string) {
		if decided {
			b.used(c, slot)
			return
		}
		pending = append(pending, slot)
	}
	// The open fixture answers here on the box. So the substitution authority
	// of the SNI is about an origin that this request will never reach. The
	// decision occurs before the credentials go in, so a local responder
	// never holds one. This is stronger than a response scrub that must know
	// every encoding in which a reflected credential can return.
	reserve := func(n int64) bool {
		if b.memTake(&c.memReq, bufCopies*n) {
			return true
		}
		c.bodyDenied = true
		return false
	}
	strips, stream, err = fence.DecideStream(fence.Ctx{SNI: c.p.SNI, TokenRE: b.TokenRE, Rules: b.Rules, StripCore: b.StripCore, OnInject: onInject, NoInject: c.echo && c.echoRole != "core", Reserve: reserve}, c.req, b.Policy, c.slots)
	if c.bodyDenied {
		// The body streams instead. If the body must be buffered, the
		// code below refuses it.
		b.logMemBudget(clientIP(c.p), c.host, "body")
	}
	if err != nil {
		var refused *fence.RefusedError
		if errors.As(err, &refused) {
			b.logRefusals(c, refused.Refusals)
			return nil, nil, true, b.refuseSubstitution(c)
		}
		if errors.Is(err, fence.ErrBufferBudget) {
			return nil, nil, true, b.refuseBusy(c)
		}
		if c.echo {
			return nil, nil, true, b.echo(c.client, c.p, c.req, c.slots, "")
		}
		_ = writeErr(c.client, 502, "502 Bad Gateway", "fence\n")
		return nil, nil, true, err
	}
	// The harvest cannot read a refresh body that is not JSON. If the fence
	// wrote a refresh token into such a body, the broker refuses here, before
	// the use rows. Thus the agent gets the one refusal, and the slot logs no
	// use and spends no budget.
	if c.refresh = b.harvestAllowed(c.p.SNI, c.req); c.refresh {
		c.jsonBody = jsonContentType(c.req.Get("Content-Type"))
	}
	// The bind reads the first Content-Type. A refresh with a second media
	// type gets the one refusal, because the origin can read the other one.
	if name := repeatedContentType(c.req.Fields); c.refresh && name != "" {
		b.logRefusals(c, []fence.Refusal{{Cause: fence.CauseRepeatedContentType, Where: "header:" + name}})
		return nil, nil, true, b.refuseSubstitution(c)
	}
	if c.refresh && !c.jsonBody && len(pending) > 0 {
		if slot := injectedORT(bufferedBody(c.req), pending, c.slots); slot != "" {
			b.logRefusals(c, []fence.Refusal{{Cause: fence.CauseOutsideHeader, Slot: slot, Kind: "CLAUDE_ORT", Where: "body"}})
			return nil, nil, true, b.refuseSubstitution(c)
		}
	}
	decided = true
	for _, slot := range pending {
		b.used(c, slot)
	}
	for _, ev := range strips {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, ev.Where, ev.Rule)
	}
	if c.ws {
		// The buffered-body path gave a bodyless handshake a
		// Content-Length: 0 the origin never expects to see on a GET.
		c.req.Del("Content-Length")
	}
	return strips, stream, false, nil
}

// bindHarvest binds the slot that a refresh spends, from the credential
// itself. It refuses a request that carries an ORT in any other shape,
// because the reply would carry a live pair that the harvest cannot read.
// The caller holds the slot from before the origin write until the
// rewrite lands, so two refreshes of one slot never race. bindHarvest sets
// done when it refused the request, whatever the write returned.
func (b *Broker) bindHarvest(c *call) (done bool, err error) {
	if !c.refresh {
		return false, nil
	}
	auth, body := bearer(c.req.Get("Authorization")), bufferedBody(c.req)
	if !carriesORT(auth+" "+string(body), c.slots) {
		return false, nil
	}
	c.harvestSlot = bindRefreshSlot(auth, body, c.slots)
	if c.harvestSlot == "" || !c.jsonBody {
		return true, b.refuse(c.client, c.req, false, 403, "403 Forbidden", "harvest\n")
	}
	return false, nil
}

// spentRefuse reads the refresh token again on the near side of the hold.
// Nothing guards the slot while prepare snapshots it and while the fence
// substitutes from that snapshot. The broker cannot hold the slot earlier
// than this: the credential in the body names the slot, and only the
// buffering of the fence makes the body readable. So a refresh can be
// delayed in that window while another handler completes a rotation. That
// refresh then carries the token that the other handler already spent.
// Sending it would fail at the origin and would leave the slot of the
// agent with a dead credential. Under the hold, no second handler can
// rotate. So the value in the store here is the value that the request
// had to carry. The agent gets the same refresh_busy that it would have
// got a moment earlier, while the other handler held the slot. Its retry
// substitutes the live pair.
func (b *Broker) spentRefuse(c *call) (done bool, err error) {
	fresh, err := b.Store.Snapshot()
	if err != nil {
		_ = b.refuse(c.client, c.req, false, 500, "500 Internal Server Error", "secrets\n")
		return true, err
	}
	key := secrets.EnvKey(c.harvestSlot, "CLAUDE_ORT")
	if fresh[key].Live == c.slots[key].Live {
		return false, nil
	}
	_ = b.refuse(c.client, c.req, false, 429, "429 Too Many Requests", "refresh_busy\n")
	return true, ErrBusy
}

// roundTrip writes the request to the origin and reads the response head.
// It redials one time if a reused keep-alive connection was dead and the
// body can be replayed. The origin leg stays compressed and the scrub sees
// plaintext. The broker offers only gzip (stdlib). decodeBody inflates it,
// and the broker re-gzips it for the client if the client asked.
func (b *Broker) roundTrip(ctx context.Context, c *call) (*httpwire.Response, error) {
	c.clientGzip = acceptsGzip(strings.Join(c.req.Values("Accept-Encoding"), ","))
	c.req.Del("Accept-Encoding")
	c.req.Append("Accept-Encoding", "gzip")
	dropHopByHop(&c.req.Fields)
	replay, replayable := replayBytes(c.req)
	for attempt := 0; ; attempt++ {
		conn, br, reused, derr := c.up.acquire(ctx)
		if derr != nil {
			_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
			return nil, derr
		}
		c.ubr = br
		var resp *httpwire.Response
		var err error
		var wrote int64
		if replayable {
			var n int
			n, err = conn.Write(replay)
			wrote = int64(n)
		} else {
			wrote, err = c.req.WriteTo(conn)
		}
		if err == nil {
			release := c.up.headBy(time.Now().Add(originHeadIdles * b.idle()))
			if c.ws {
				resp, err = httpwire.ReadUpgradeResponseHead(c.ubr)
			} else {
				resp, err = httpwire.ReadResponseHead(c.ubr, c.req.Method == "HEAD")
			}
			release()
		}
		if err == nil {
			return resp, nil
		}
		// The origin may have closed a reused keep-alive connection between
		// requests. Redial one time, but only for a replayable body. Replayable
		// says that the bytes can be sent again, not that they may be sent
		// again. The origin cannot have seen a write that moved no byte. If the
		// write moved bytes, only a method that the origin may run twice with one
		// effect may be sent again. The broker answers a POST with an ambiguous
		// completion as a failure, because it is a failure. It does not silently
		// mutate the origin twice.
		c.up.discard()
		if errors.Is(err, fence.ErrPlaceholderInStream) {
			// The origin connection is gone with the head, so the request
			// cannot complete.
			return nil, b.refuseStreamPlaceholder(c, err)
		}
		if reused && replayable && attempt == 0 && (wrote == 0 || idempotent(c.req.Method)) {
			continue
		}
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return nil, err
	}
}

// refuseStreamPlaceholder answers a request whose streamed body stopped
// at a placeholder (fence.ErrPlaceholderInStream). The agent gets the one
// refusal. The operator gets the cause.
func (b *Broker) refuseStreamPlaceholder(c *call, err error) error {
	r := fence.Refusal{Cause: fence.CausePlaceholderInStream, Where: "body"}
	var sp *fence.StreamPlaceholderError
	if errors.As(err, &sp) {
		r.Slot, r.Kind = sp.Slot, sp.Kind
	}
	b.logRefusals(c, []fence.Refusal{r})
	if werr := writeRefused(c.client); werr != nil {
		return werr
	}
	return errRefused
}

// echoBody reads a streamed body that goes to an echo fixture. The
// fixture has no origin, so no copy reads the body. The read goes
// through the same guard as the copy to an origin. Thus a placeholder in
// the body gets the same refusal as at a real host. The scrub writes its
// strip events while the read occurs. echoBody logs them on each exit, as
// serve does after roundTrip. Thus the rows are the rows of a real host,
// also for the strips before a placeholder. done says that echoBody
// answered the request.
func (b *Broker) echoBody(c *call, stream *fence.StreamStrips) (done bool, err error) {
	if c.req.Body == nil {
		return false, nil
	}
	defer func() {
		for _, ev := range stream.Events() {
			_ = b.logStrip(&c.strips, clientIP(c.p), c.host, ev.Where, ev.Rule)
		}
	}()
	if _, err := io.Copy(io.Discard, c.req.Body); err != nil {
		if errors.Is(err, fence.ErrPlaceholderInStream) {
			return true, b.refuseStreamPlaceholder(c, err)
		}
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return true, err
	}
	return false, nil
}

// decodeBody inflates a gzip body so that the scrub sees plaintext. It
// also reports whether the origin framed its body. An unframed
// (close-delimited) body ends only when the origin closes, so its
// connection can never be reused. decodeBody captures this before gzip
// rewrites ContentLength. If the returned reader is not nil, the caller
// must close it after the body is written.
func (b *Broker) decodeBody(c *call, resp *httpwire.Response) (originCloseDelimited, reencode bool, zr *gzip.Reader, err error) {
	originCloseDelimited = !resp.NoBody && !resp.Chunked && resp.ContentLength < 0
	switch enc := responseCoding(resp); enc {
	case "identity":
	case "gzip", "x-gzip":
		if !resp.NoBody && resp.Stream != nil {
			zr, err = gzip.NewReader(resp.Stream)
			if err != nil {
				_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
				return false, false, nil, err
			}
			resp.Stream = &capReader{r: zr, left: b.maxDecoded()}
			resp.ContentLength = -1
			resp.Chunked = false
			resp.Del("Content-Encoding")
			resp.Del("Content-Length")
			reencode = c.clientGzip && b.Recompress
		}
	default:
		// The body is not gzip, and gzip is all that the broker asked for. The
		// scrub cannot see inside. A live value can only be in the reply to a
		// request that spent one, so the broker refuses that reply. Any other
		// reply passes as opaque.
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "response", "encoded:"+clip(enc, 64))
		if len(c.spent) > 0 || c.harvestSlot != "" {
			_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
			return false, false, nil, ErrOpaque
		}
	}
	return originCloseDelimited, reencode, zr, nil
}

// responseCoding is the one coding that the Content-Encoding fields of the
// response name. It reads all fields and all commas. It gives "identity"
// for none. For anything but exactly one of identity, gzip and x-gzip, it
// gives the stack, lowercased and joined. A read of only the first field
// let "identity" in front of a "gzip" field send a gzip body past the
// scrub as plain. Two gzips make a body that is still gzip after one
// inflation.
func responseCoding(resp *httpwire.Response) string {
	var encs []string
	for _, v := range resp.Values("Content-Encoding") {
		for tok := range strings.SplitSeq(v, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" {
				encs = append(encs, tok)
			}
		}
	}
	switch {
	case len(encs) == 0:
		return "identity"
	case len(encs) == 1 && (encs[0] == "identity" || encs[0] == "gzip" || encs[0] == "x-gzip"):
		return encs[0]
	}
	return strings.Join(encs, ",")
}

// writeBuffered reads the whole response, harvests a refreshed pair if
// this request spent one, rewrites live values, and writes it out.
func (b *Broker) writeBuffered(c *call, resp *httpwire.Response, reencode bool) error {
	if err := resp.Buffer(maxRespBuf); err != nil {
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return err
	}
	// Bytes after a framed response are never ours: they are a stray interim
	// response or an origin desync. None of these bytes reach the client.
	if c.ubr.Buffered() > 0 {
		c.up.discard()
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return ErrLeftover
	}
	if c.harvestSlot != "" {
		minted, err := b.harvest(c.harvestSlot, resp)
		if err != nil {
			if errors.Is(err, ErrHarvest) {
				b.logHarvestRefused(c)
			}
			c.up.discard()
			_ = writeErr(c.client, 502, "502 Bad Gateway", "harvest\n")
			return err
		}
		c.slots = withMinted(c.slots, minted)
	}
	hit, err := rewriteResponse(resp, c.slots)
	for _, key := range hit {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "response", "secret:"+key)
	}
	if err != nil {
		c.up.discard()
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return err
	}
	// The scrub replaces only the values that the broker holds. A token
	// response that still has a token shape after it holds a value that the
	// broker did not store: a shape that the harvest did not know, or a
	// status that it does not harvest. The agent must not get it.
	if c.harvestSlot != "" && b.residue(resp) {
		b.logHarvestRefused(c)
		c.up.discard()
		_ = writeErr(c.client, 502, "502 Bad Gateway", "harvest\n")
		return ErrResidue
	}
	if reencode {
		resp.Body = gzipBytes(resp.Body)
		resp.SetInPlace("Content-Encoding", "gzip")
	}
	_, err = resp.WriteTo(c.client)
	// The broker read the body to its framed end. So the upstream may be
	// reused, unless one of the two sides asked to close.
	if err != nil || !reusableResp(c.req, resp) {
		c.up.discard()
	}
	return err
}

// writeStreamed scrubs the body while it passes. It writes the body
// chunked for HTTP/1.1. For HTTP/1.0, which cannot read chunked, it writes
// the body raw with a close.
func (b *Broker) writeStreamed(c *call, resp *httpwire.Response, reencode, originCloseDelimited bool) error {
	hit, err := rewriteHeaders(resp, c.slots)
	for _, key := range hit {
		_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "response", "secret:"+key)
	}
	if err != nil {
		c.up.discard()
		_ = writeErr(c.client, 502, "502 Bad Gateway", "origin\n")
		return err
	}
	pairs, keys := scrubPairs(c.slots)
	sc := httpwire.NewScrubber(resp.Stream, pairs)
	chunked := c.req.Proto != "HTTP/1.0"
	if reencode {
		resp.SetInPlace("Content-Encoding", "gzip")
	}
	if err := resp.WriteHead(c.client, chunked); err != nil {
		return err
	}
	var copyErr error
	var cw *httpwire.ChunkedWriter
	var dst io.Writer = c.client
	if chunked {
		cw = httpwire.NewChunkedWriter(c.client)
		dst = cw
	}
	if reencode {
		gz := newFlushingGzip(dst)
		_, copyErr = io.Copy(gz, sc)
		if cerr := gz.Close(); copyErr == nil {
			copyErr = cerr
		}
	} else {
		_, copyErr = io.Copy(dst, sc)
	}
	for i, n := range sc.Counts {
		if n > 0 {
			_ = b.logStrip(&c.strips, clientIP(c.p), c.host, "response", "secret:"+keys[i])
		}
	}
	if copyErr != nil {
		c.up.discard()
		return copyErr
	}
	if cw != nil {
		if cerr := cw.Close(); cerr != nil {
			c.up.discard()
			return cerr
		}
		// Reuse only when: the chunked reader reached its terminating chunk, the
		// scrubber reached EOF (copyErr nil), the origin framed the body, neither
		// side asked to close, and nothing trails the body.
		if originCloseDelimited || !reusableResp(c.req, resp) || c.ubr.Buffered() > 0 {
			c.up.discard()
		}
		return nil
	}
	c.up.discard()
	return errCloseDelimited
}

// dropHopByHop removes the RFC 9110 hop-by-hop fields that the broker
// does not already reframe or act on. TE: trailers would promise the
// origin that trailers reach the client, but the broker drops trailers.
// Trailer announces trailer fields that the broker drops (httpwire reads
// them and does not forward them), and the fence does not scan them.
// Keep-Alive states the connection limits of the origin, not the limits
// of the broker to the client.
func dropHopByHop(fs *httpwire.Fields) {
	fs.Del("TE")
	fs.Del("Trailer")
	fs.Del("Keep-Alive")
}

// acceptsGzip reads Accept-Encoding as RFC 9110 12.5.3 defines it. Each
// entry has an optional qvalue. q=0 is a prohibition, not a preference:
// the coding is not acceptable at all. A parser that cut each entry at the
// semicolon and answered true on the first gzip, x-gzip or * read
// "gzip;q=0" (the one form that names gzip to exclude it) as the form that
// asks for it. So "*, gzip;q=0" got a gzip body that the client had said
// it could not take. The most specific entry present decides. So a named
// coding outranks the wildcard, whatever order they arrive in.
func acceptsGzip(accept string) bool {
	// -1 is "no such entry"; otherwise the entry's qvalue in thousandths.
	gzipQ, xgzipQ, starQ := -1, -1, -1
	for tok := range strings.SplitSeq(strings.ToLower(accept), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(tok), ";")
		switch strings.TrimSpace(name) {
		case "gzip":
			gzipQ = max(gzipQ, qvalue(params))
		case "x-gzip":
			xgzipQ = max(xgzipQ, qvalue(params))
		case "*":
			starQ = max(starQ, qvalue(params))
		}
	}
	for _, q := range [...]int{gzipQ, xgzipQ, starQ} {
		if q >= 0 {
			return q > 0
		}
	}
	return false
}

// qvalue is the q parameter of one Accept-Encoding entry, in thousandths.
// An absent q is 1 (RFC 9110 12.4.2). A q that does not parse is also 1:
// qvalue ignores an unreadable parameter, as it ignores any unknown one.
// The entry keeps its default, and qvalue does not invent a preference.
func qvalue(params string) int {
	for p := range strings.SplitSeq(params, ";") {
		k, v, ok := strings.Cut(p, "=")
		if !ok || strings.TrimSpace(k) != "q" {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f < 0 || f > 1 {
			return 1000
		}
		return int(f * 1000)
	}
	return 1000
}

// capReader stops an inflating body at a byte budget so a compression
// bomb ends the response, not the process.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, httpwire.ErrBodyLimit
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left <= 0 && err == nil {
		// One more read tells whether the body really ended here.
		var probe [1]byte
		if m, perr := c.r.Read(probe[:]); m > 0 || (perr != nil && perr != io.EOF) {
			return n, httpwire.ErrBodyLimit
		}
		return n, io.EOF
	}
	return n, err
}

// flushingGzip flushes after every write, so that a streamed event leaves
// the Pi immediately after the scrub. BestSpeed: the LAN hop is cheap, but
// the CPU of the Pi is not.
type flushingGzip struct{ gz *gzip.Writer }

func newFlushingGzip(w io.Writer) *flushingGzip {
	gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	return &flushingGzip{gz: gz}
}

func (f *flushingGzip) Write(p []byte) (int, error) {
	n, err := f.gz.Write(p)
	if err != nil {
		return n, err
	}
	return n, f.gz.Flush()
}

func (f *flushingGzip) Close() error { return f.gz.Close() }

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	_, _ = gz.Write(b)
	_ = gz.Close()
	return buf.Bytes()
}

// isUpgrade reports a request for a WebSocket or other protocol switch.
// The fence uses HTTP/1.1 only. A refusal at the start is better than a
// 101 followed by a dead socket.
func isUpgrade(req *httpwire.Request) bool {
	if req.Get("Upgrade") != "" {
		return true
	}
	for tok := range strings.SplitSeq(strings.ToLower(req.Get("Connection")), ",") {
		if strings.TrimSpace(tok) == "upgrade" {
			return true
		}
	}
	return false
}
