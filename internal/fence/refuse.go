package fence

import (
	"strings"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

// A refusal is the message that the operator gets when the fence cannot
// do a substitution. The agent gets one message for all refusals, byte for
// byte, because the agent is the adversary. The full fence rests on that
// premise. A differentiated error taxonomy gives the adversary an oracle.
// Distinct codes, leaked in order of severity, would give up the
// operational state of the box, which slots exist and which are
// quarantined, the slot inventory, and finally the full SNI-to-kind
// policy. An agent could probe that policy host by host and then aim at
// the weakest approved destination.
//
// A dev-mode detail flag is also not the answer. Two response paths mean
// that the production path is the untested one, and it leaks as soon as
// the flag is wrong. Thus the fence does not delete the detail. It routes
// it: the detail goes in these records to the log of the operator, never to the wire.
type RefusalCause string

const (
	// CauseKindNotAllowed is the destination that refuses the credential
	// kind. Either the SNI has no authority for substitution, or it has
	// authority and this kind is not on its list. This is the fence in
	// operation as designed, and the signature of attempted credential
	// egress. Thus it is the one cause that alerts.
	CauseKindNotAllowed RefusalCause = "kind_not_allowed_for_sni"
	// CauseOutsideHeader is a placeholder of a kind that the SNI does carry,
	// in a location where the fence does not substitute: the URL, or a body
	// other than the body of the refresh token. The fence substitutes the
	// refresh token itself only as the refresh_token value of the refresh
	// body. Thus a refresh token in a header, in a different field, or off
	// the refresh path is also this cause. A credential put into a prompt
	// comes back from the model transformed, past all literal scrubs. A
	// credential put into a gist is published. Thus this is attempted
	// egress, and it alerts like the cause above.
	CauseOutsideHeader RefusalCause = "placeholder_outside_header"
	// CauseSlotUnknown is a placeholder for a slot that is not in the
	// store, usually a stale agent environment after a delete.
	CauseSlotUnknown RefusalCause = "slot_unknown"
	// CauseSlotDisabled is a slot the operator quarantined.
	CauseSlotDisabled RefusalCause = "slot_disabled"
	// CauseSlotExpired is a slot past the deadline that it was minted or
	// renewed with. The row and its placeholder still exist. The fence
	// treats the slot exactly like a disabled slot, not like a slot that was
	// never minted. Thus `enroll list` still shows it, and `enroll renew`
	// still works on it.
	CauseSlotExpired RefusalCause = "slot_expired"
	// CauseStoreSealed is a slot whose value is encrypted at rest with a
	// key that nobody entered since boot. The inventory is readable, so
	// the operator knows exactly which slots wait. The agent gets the same
	// answer as for all other causes.
	CauseStoreSealed RefusalCause = "store_sealed"
	// CauseSlotEmpty is a slot that exists and holds no value.
	CauseSlotEmpty RefusalCause = "slot_empty"
	// CausePlaceholderInStream is a placeholder in a body that was already
	// in a stream to the origin when the fence saw it. For any slot, a
	// stream under a fixed Content-Length cannot substitute, and the head
	// already went out. Thus the copy stops there, and the request never
	// completes. The fence logs it, and does not send a distinct response.
	CausePlaceholderInStream RefusalCause = "placeholder_in_streamed_body"
	// CausePlaceholderInWS is a placeholder in a websocket message, ping,
	// pong or close reason from the agent. A frame is opaque application
	// data, so the fence substitutes into no frame (NewScanner). Thus the
	// broker does not forward the frame and closes the session. It is
	// attempted egress, and it alerts like CauseOutsideHeader.
	CausePlaceholderInWS RefusalCause = "placeholder_in_ws"
	// CauseGitPushNotAllowed is a git smart-HTTP push to a repo that is
	// not in git_push.allow, or a push-shaped target with no single repo to
	// examine (docs/git_push.md). It is not an alert: the operator writes
	// the push policy, and a refused push is a list to edit.
	CauseGitPushNotAllowed RefusalCause = "git_push_not_allowed"
	// CauseEncodedBody is a request body under a Content-Encoding that the
	// scan cannot read through: a coding that stdlib does not undo, more
	// layers than the fence unwinds, bytes that do not decode, a decoded
	// size past the bomb limit, or a body that Content-Encoding forces to
	// stream, not buffer. The fence cannot tell a clean body from a body
	// that hides a token behind an encoding that the fence cannot read.
	// Thus the fence treats the case where it cannot look the same as an
	// adversary that selects such an encoding (docs/fence.md 5.3).
	CauseEncodedBody RefusalCause = "encoded_body_unscannable"
	// CauseEncodedBodyToken is a live value or a token-prefix match inside
	// a request body that did decode: what a buffered plaintext body strips
	// and forwards. The fence never rewrites a compressed body (docs/fence.md
	// 5.3b). Thus the fence refuses all of this body instead. A match that
	// shows only after the unescape of a JSON string in a buffered body is
	// also this cause: the raw bytes are different, so the fence cannot
	// strip it in place.
	CauseEncodedBodyToken RefusalCause = "encoded_body_token"
	// CauseKeyInHeaderName is a field name that holds a live value, a
	// token-prefix match or a placeholder. A field name is a token, and
	// most key formats are tokens too. The fence cannot rewrite a name,
	// because the name gives the field its meaning. Thus it refuses the
	// request.
	CauseKeyInHeaderName RefusalCause = "key_in_header_name"
	// CauseKeyInMethod is a request method that holds a live value, a
	// token-prefix match or a placeholder. A method is a token, as a field
	// name is. The fence cannot rewrite a method, because the method gives
	// the request its meaning. Thus it refuses the request.
	CauseKeyInMethod RefusalCause = "key_in_method"
	// CauseEncodedURLToken is a live value or a token-prefix match in the
	// percent-decoded target that the raw target does not show: what a
	// literal target strips. The raw bytes are different, so the fence
	// cannot strip it in place. A target that does not decode to a stable
	// form in a few rounds is also this cause, because the fence cannot see
	// what the origin decodes. Thus the fence refuses the request.
	CauseEncodedURLToken RefusalCause = "encoded_url_token"
	// CauseLiveInHost is a Host that holds a live value or a token-prefix
	// match. The origin routes the request by its Host. A strip there
	// sends the request to a name that the fence did not judge, and the
	// credential of the judged name goes with it. Thus the fence cannot
	// strip the value in place, and it refuses the request.
	CauseLiveInHost RefusalCause = "live_in_host"
	// CauseLiveInConnection is a Connection or an Upgrade field that holds
	// a live value or a token-prefix match. The broker reads these fields
	// to decide on a WebSocket before the fence runs, and the origin reads
	// them to switch the protocol. A strip there changes what the origin
	// does after that decision. Thus the fence cannot strip the value in
	// place, and it refuses the request. Where names the field.
	CauseLiveInConnection RefusalCause = "live_in_connection"
	// CauseRepeatedCredHeader is a credential header that occurs more than
	// one time: X-Api-Key, or a header that the core.hosts line of the host
	// declares. The fence writes a credential by name, and the origin can
	// read either field. Thus the origin can read a value that is different
	// from the value that the fence decided on. httpwire refuses a repeated
	// Authorization before the fence runs. Where names the second field.
	CauseRepeatedCredHeader RefusalCause = "repeated_credential_header"
)

type Refusal struct {
	Cause RefusalCause
	Slot  string
	Kind  string
	Where string
}

// RefusedError ends the request before the fence rewrites anything and
// before anything reaches the origin. Refusal, not forwarding, keeps the
// single response valid. If the fence forwarded a placeholder instead, the
// 401 of the origin would leak the distinction that the uniform answer
// hides. It would also give the slot ID and the credential kind to a
// destination that the agent chose.
type RefusedError struct{ Refusals []Refusal }

func (e *RefusedError) Error() string { return "fence: substitution refused" }

// note records why the fence cannot substitute the placeholder at span,
// or records nothing when it can. note reads the kind from the placeholder,
// not from the slot. Thus a placeholder that names a kind that this SNI
// cannot carry gets a decision on that alone. It never needs a store lookup first.
// A placeholder that is not exact (secrets.PlaceholderExact) has no slot:
// the fence never substitutes it, and refuses it as slot_unknown.
func (s *scanner) note(b []byte, span [2]int, where string) {
	if s.quiet {
		return
	}
	slot, kind := secrets.PlaceholderParts(b, span)
	sl, ok := s.idx.ByDummy[secrets.Placeholder(slot, kind)]
	ok = ok && secrets.PlaceholderExact(b, span)
	switch {
	case !s.inject || !corepolicy.KindAllowed(kind, s.kinds):
		s.refuse(CauseKindNotAllowed, slot, kind, where)
	case !s.placeAllows(b, span, kind):
		if s.field != "" {
			where += ":" + s.field
		}
		s.refuse(CauseOutsideHeader, slot, kind, where)
	case !ok:
		s.refuse(CauseSlotUnknown, slot, kind, where)
	case sl.Disabled:
		s.refuse(CauseSlotDisabled, slot, kind, where)
	case sl.Expired:
		s.refuse(CauseSlotExpired, slot, kind, where)
	case sl.Sealed:
		s.refuse(CauseStoreSealed, slot, kind, where)
	case sl.Live == "":
		s.refuse(CauseSlotEmpty, slot, kind, where)
	}
}

// noteAll runs note over each placeholder in b. It is a separate pass
// from injectable, which stays a pure lookup: classify and injectAll
// both call injectable over the same bytes. A cause recorded inside
// injectable would be recorded twice.
func (s *scanner) noteAll(b []byte, where string) {
	for _, span := range secrets.FindPlaceholderSpans(b) {
		s.note(b, span, where)
	}
}

// noteNames refuses the request when a field name holds a placeholder, a
// live value or a token-prefix match. It checks every live value, also
// one of a kind that this host injects, and every token rule. The placeholder
// and token scans join the names with a newline and scan once. A newline
// is not a token byte, so no match can join two names.
func (s *scanner) noteNames(fields httpwire.Fields) {
	n := 0
	for _, f := range fields {
		n += len(f.Name) + 1
	}
	b := make([]byte, 0, n)
	for _, f := range fields {
		b = append(append(b, f.Name...), '\n')
	}
	for _, span := range secrets.FindPlaceholderSpans(b) {
		slot, kind := secrets.PlaceholderParts(b, span)
		s.refuse(CauseKeyInHeaderName, slot, kind, "header_name")
	}
	for _, f := range fields {
		for _, sl := range s.idx.Lives {
			if strings.Contains(f.Name, sl.Live) {
				s.refuse(CauseKeyInHeaderName, sl.ID, sl.Kind, "header_name")
			}
		}
	}
	if s.all.match(b) {
		s.refuse(CauseKeyInHeaderName, "", "", "header_name")
	}
}

// noteRepeats refuses the request when a header that the fence writes a
// credential into for this host occurs more than one time. A host that
// gets no credential has no such header.
func (s *scanner) noteRepeats(fields httpwire.Fields) {
	if !s.inject {
		return
	}
	seen := map[string]bool{}
	for _, f := range fields {
		name := strings.ToLower(f.Name)
		if !corepolicy.DefaultHeader(name) && s.extra[name] == nil {
			continue
		}
		if seen[name] {
			s.refuse(CauseRepeatedCredHeader, "", "", "header:"+f.Name)
		}
		seen[name] = true
	}
}

// noteMethod refuses the request when the method holds a placeholder, a
// live value or a token-prefix match. It does the same checks as
// noteNames, on the method.
func (s *scanner) noteMethod(method string) {
	b := []byte(method)
	for _, span := range secrets.FindPlaceholderSpans(b) {
		slot, kind := secrets.PlaceholderParts(b, span)
		s.refuse(CauseKeyInMethod, slot, kind, "method")
	}
	for _, sl := range s.idx.Lives {
		if strings.Contains(method, sl.Live) {
			s.refuse(CauseKeyInMethod, sl.ID, sl.Kind, "method")
		}
	}
	if s.all.match(b) {
		s.refuse(CauseKeyInMethod, "", "", "method")
	}
}

// noteHost refuses the request when the Host holds a live value or a
// token-prefix match. It checks every live value, also one of a kind that
// this host injects, and every token rule, as noteNames does.
func (s *scanner) noteHost(host string) {
	s.noteLive(host, CauseLiveInHost, "header:Host")
}

// noteConn refuses the request when a Connection or an Upgrade field holds
// a live value or a token-prefix match, as noteHost does for the Host.
func (s *scanner) noteConn(name, v string) {
	where := "header:Connection"
	if strings.EqualFold(name, "upgrade") {
		where = "header:Upgrade"
	}
	s.noteLive(v, CauseLiveInConnection, where)
}

// noteLive refuses the request with cause when v holds a live value or a
// token-prefix match.
func (s *scanner) noteLive(v string, cause RefusalCause, where string) {
	for _, sl := range livesIn(s.idx.Lives, v) {
		s.refuse(cause, sl.ID, sl.Kind, where)
	}
	if s.all.match([]byte(v)) {
		s.refuse(cause, "", "", where)
	}
}

// livesIn gives the live values that v holds.
func livesIn(lives []secrets.Slot, v string) []secrets.Slot {
	var in []secrets.Slot
	for _, sl := range lives {
		if httpwire.Contains([]byte(v), []byte(sl.Live)) {
			in = append(in, sl)
		}
	}
	return in
}

// SecretInHost reports whether host holds a live value of slots or a
// token-prefix match. It is the test of noteHost (CauseLiveInHost). The
// broker uses it for the rows that it writes before the fence runs. Only
// TokenRE and Rules of ctx apply.
func SecretInHost(ctx Ctx, host string, slots map[string]secrets.Slot) bool {
	return len(livesIn(secrets.NewIndex(slots).Lives, host)) > 0 || allTokens(ctx).match([]byte(host))
}

// noteTarget scans the percent-decoded target, because the origin decodes
// it. A placeholder there refuses the request as in the raw target. The
// live value and token scans read the decoded form of the target after
// the raw strip. Thus a literal match strips as before, and only an
// encoded match refuses (CauseEncodedURLToken). A '+' stays a '+', as in
// GitPushTarget.
func (s *scanner) noteTarget(target string) {
	if !strings.Contains(target, "%") {
		return
	}
	dec, stable := unescapeAll(target)
	if !stable {
		s.refuse(CauseEncodedURLToken, "", "", "url")
		return
	}
	s.noteAll([]byte(dec), "url")
	b, _ := unescapeAll(string(s.strip([]byte(target))))
	for _, sl := range s.idx.Lives {
		if !s.keeps(sl) && strings.Contains(b, sl.Live) {
			s.refuse(CauseEncodedURLToken, sl.ID, sl.Kind, "url")
		}
	}
	if s.tokens.match([]byte(b)) {
		s.refuse(CauseEncodedURLToken, "", "", "url")
	}
}

// maxRefusals is the limit on what one request can put in the log of the
// operator. Refusals are the feedback channel of the agent. Thus the agent
// can mint distinct refusals as fast as it can write placeholders. Each
// refusal that the fence keeps costs the broker a synchronous write on the
// credential path. The first few say what the request tried to reach. The
// thousandth says nothing that the first did not say, and the fence refuses
// the request in all cases.
const maxRefusals = 32

func (s *scanner) refuse(cause RefusalCause, slot, kind, where string) {
	if len(*s.ref) >= maxRefusals {
		return
	}
	r := Refusal{Cause: cause, Slot: slot, Kind: kind, Where: where}
	if _, dup := s.seen[r]; dup {
		return
	}
	s.seen[r] = struct{}{}
	*s.ref = append(*s.ref, r)
}
