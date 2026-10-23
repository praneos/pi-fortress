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
	// 5.3b). Thus the fence refuses all of this body instead.
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
func (s *scanner) note(b []byte, span [2]int, where string) {
	if s.quiet {
		return
	}
	slot, kind := secrets.PlaceholderParts(b, span)
	sl, ok := s.idx.ByDummy[secrets.Placeholder(slot, kind)]
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
