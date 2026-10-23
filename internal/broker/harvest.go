package broker

import (
	"bytes"
	"io"
	"strings"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/secrets"
)

func jsonContentType(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// harvestAllowed: only where the fence would inject the Claude refresh
// token, on an exact refresh path. SNI and Host agree on a core host that
// carries that kind. Any other origin that returns access_token is
// untrusted input.
func (b *Broker) harvestAllowed(sni string, req *httpwire.Request) bool {
	if b.Policy == nil || b.Store == nil || !fence.IsOAuthPath(req.Target) {
		return false
	}
	if !b.Policy.Authority(sni, req.Get("Host")) {
		return false
	}
	return corepolicy.KindAllowed("CLAUDE_ORT", b.Policy.KindsFor(sni))
}

// harvest reads the new token pair from a refresh response, for a slot
// that the caller holds busy. The fence refuses a 200 that is not JSON and
// does not forward it: a token that the fence could not read would get to
// the agent live. harvest returns the values that it read. Reason: the
// caller must scrub those exact values from this exact response. A second
// read from the store is a second chance to fail, on the one path that must
// not fail.
func (b *Broker) harvest(slotID string, resp *httpwire.Response) ([]secrets.Slot, error) {
	if slotID == "" {
		return nil, nil
	}
	if !jsonContentType(resp.Get("Content-Type")) {
		if resp.Code == 200 {
			return nil, ErrHarvest
		}
		return nil, nil
	}
	// A 200 is the new pair. The broker must store each token in it, or
	// refuse it. A value that it did not store is a value that it does not
	// scrub. Thus a 200 with no access_token that it can read, or with a
	// refresh_token that it cannot read, never reaches the agent. A 200
	// without a refresh_token is valid: some servers do not rotate it.
	f, ok := fence.StrictFields(resp.Body, "access_token", "refresh_token")
	if resp.Code == 200 {
		ort, hasORT := f["refresh_token"]
		if !ok || !secrets.ValidLive(f["access_token"]) || hasORT && !secrets.ValidLive(ort) {
			return nil, ErrHarvest
		}
	}
	oat, ort := f["access_token"], f["refresh_token"]
	if !secrets.ValidLive(oat) {
		oat = ""
	}
	if !secrets.ValidLive(ort) {
		ort = ""
	}
	if oat == "" && ort == "" {
		return nil, nil
	}
	var minted []secrets.Slot
	if oat != "" {
		minted = append(minted, secrets.Slot{ID: slotID, Kind: "CLAUDE_OAT", Live: oat})
	}
	if ort != "" {
		minted = append(minted, secrets.Slot{ID: slotID, Kind: "CLAUDE_ORT", Live: ort})
	}
	err := b.Store.HarvestHeld(slotID, func(cur []secrets.Slot) ([]secrets.Slot, error) {
		out := cur
		if oat != "" {
			out = upsert(out, slotID, "CLAUDE_OAT", oat)
		}
		if ort != "" {
			out = upsert(out, slotID, "CLAUDE_ORT", ort)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return minted, nil
}

// residue reports a token shape (key_prefixes.rules) anywhere in a token
// response after the scrub: the status reason, a field name or value, or
// the body. The broker reads the body decoded, so the scan sees what the
// agent would decode.
func (b *Broker) residue(resp *httpwire.Response) bool {
	if b.TokenRE == nil {
		return false
	}
	if b.TokenRE.MatchString(resp.Status) || b.TokenRE.Match(resp.Body) {
		return true
	}
	for _, f := range resp.Fields {
		if b.TokenRE.MatchString(f.Name) || b.TokenRE.MatchString(f.Value) {
			return true
		}
	}
	return false
}

// CauseHarvestLeftover: the broker refused a refresh response. The harvest
// could not read the new pair, or a token shape stayed in the response
// after the scrub. The agent gets one 502. A provider format change looks
// the same, so the operator must see each one.
const CauseHarvestLeftover fence.RefusalCause = "harvest_leftover"

// logHarvestRefused writes the alert row for a refused refresh response.
// It names the slot that the refresh spent. It does not use the row cap of
// the request: a call writes this row one time at most.
func (b *Broker) logHarvestRefused(c *call) {
	_ = b.Logs.Refused(jsonl.Refused{
		Host:     c.host,
		SNI:      c.p.SNI,
		Where:    "response",
		Cause:    string(CauseHarvestLeftover),
		Slot:     c.harvestSlot,
		ClientIP: clientIP(c.p),
		Alert:    true,
	})
}

// withMinted puts the values that a harvest just read on top of the slots
// that the request was decided against. The rewrite of the response that
// contained those values uses the result. Before, a second Store.Snapshot
// supplied the values, and the code dropped its error. Thus the redaction
// path failed open in two ways. A read could return an error. A read could
// also succeed while the slot was disabled or re-sealed in the gap, and
// then return a blank Live. Both left scrubPairs with no pair for the new
// pair, and the agent got the new credential exactly as the origin wrote
// it. These values need no read. If the snapshot holds no row for a kind,
// the scrub changes the value to its own placeholder and does not skip it.
// Thus the agent does not see a value that the store did not keep.
func withMinted(slots map[string]secrets.Slot, minted []secrets.Slot) map[string]secrets.Slot {
	if len(minted) == 0 {
		return slots
	}
	out := make(map[string]secrets.Slot, len(slots)+len(minted))
	for k, v := range slots {
		out[k] = v
	}
	for _, m := range minted {
		key := secrets.EnvKey(m.ID, m.Kind)
		sl, ok := out[key]
		if !ok {
			sl = secrets.Slot{ID: m.ID, Kind: m.Kind, Dummy: secrets.Placeholder(m.ID, m.Kind)}
		}
		sl.Live = m.Live
		out[key] = sl
	}
	return out
}

// bufferedBody returns a body that the fence already buffered, and puts it
// back. For a streamed body, it returns nil.
func bufferedBody(req *httpwire.Request) []byte {
	br, ok := req.Body.(*bytes.Reader)
	if !ok {
		return nil
	}
	raw, _ := io.ReadAll(br)
	req.SetBody(raw)
	return raw
}

// carriesORT reports a refresh token of any slot anywhere in the blob,
// as placeholder or live value.
func carriesORT(blob string, slots map[string]secrets.Slot) bool {
	for _, ph := range secrets.FindPlaceholders(blob) {
		if ph[1] == "CLAUDE_ORT" {
			return true
		}
	}
	for _, sl := range slots {
		if sl.Kind == "CLAUDE_ORT" && sl.Live != "" && strings.Contains(blob, sl.Live) {
			return true
		}
	}
	return false
}

// injectedORT names the slot of injected whose live refresh token is the
// refresh_token value of body. The fence writes a refresh token only into
// that value, read strictly (fence.RefreshTokenField).
func injectedORT(body []byte, injected []string, slots map[string]secrets.Slot) string {
	rt, ok := fence.RefreshTokenField(body)
	if !ok || rt == "" {
		return ""
	}
	for _, id := range injected {
		if slots[secrets.EnvKey(id, "CLAUDE_ORT")].Live == rt {
			return id
		}
	}
	return ""
}

// bindRefreshSlot names the slot whose refresh token this request spends.
// This is the credential in Authorization or in the refresh_token field,
// as the placeholder of the slot or as its live value. No other part of
// the request counts, so a body that names a different slot cannot
// redirect the harvest. The read of the field is strict
// (fence.RefreshTokenField). Two parsers can disagree about a second
// refresh_token, or one in a different case. Thus such a body binds
// nothing, and the fence refuses the refresh.
func bindRefreshSlot(auth string, body []byte, slots map[string]secrets.Slot) string {
	creds := []string{auth}
	if rt, ok := fence.RefreshTokenField(body); ok {
		creds = append(creds, rt)
	}
	for _, c := range creds {
		if c == "" {
			continue
		}
		for _, sl := range slots {
			// The bind excludes an expired slot the same as a disabled slot. No
			// bind means no harvest. Thus a refresh cannot revive a slot after its
			// deadline. It also cannot move the deadline later: expiry is in its own
			// sidecar, and harvest never touches that sidecar.
			if sl.Kind != "CLAUDE_ORT" || sl.Disabled || sl.Expired {
				continue
			}
			if strings.EqualFold(c, sl.Dummy) || (sl.Live != "" && c == sl.Live) {
				return sl.ID
			}
		}
	}
	return ""
}

func bearer(auth string) string {
	auth = strings.TrimSpace(auth)
	if i := strings.LastIndexByte(auth, ' '); i >= 0 {
		return strings.TrimSpace(auth[i+1:])
	}
	return auth
}

// A harvest can refresh an existing slot row. It never creates a slot row.
// A slot that the Pi did not mint does not exist, whatever the request says.
func upsert(cur []secrets.Slot, _ string, kind, live string) []secrets.Slot {
	for i, s := range cur {
		if s.Kind == kind {
			cur[i].Live = live
			return cur
		}
	}
	return cur
}
