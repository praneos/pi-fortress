package broker

import (
	"net/netip"
	"strconv"
	"strings"

	"pi-fortress/internal/eyeball"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

// CauseEyeball: the address that the broker dials for the agent is in an
// eyeball network (internal/eyeball). dest.Allowed already refuses the
// private, reserved and LAN addresses. But a public name can resolve to
// the home line of an attacker: a dynamic DNS name, a residential proxy,
// or a server for exfil or control. A dial from the agent to such an
// address is rare, and it is the shape of those channels.
//
// In audit mode the broker dials, and the row has where "audit". In refuse
// mode the broker does not dial. The row then has where "resolve" (a fake
// destination) or "preamble" (a real address that the agent dialed).
const CauseEyeball fence.RefusalCause = "eyeball_network"

// whereAudit is the where of an eyeball row when the broker dialed.
const whereAudit = "audit"

// eyeballAlertKeys limits the memory of the alert debounce. When the set
// is full, it starts again empty. Thus a flood of names costs alerts, and
// the webhook caps limit those, but it never costs memory.
const eyeballAlertKeys = 1024

// logEyeball writes the row of one eyeball hit. Kind has the ASN, because
// the alerter posts kind and host.
func (b *Broker) logEyeball(name, sni, ip, where string, dst netip.Addr, asn uint32) {
	_ = b.Logs.Refused(jsonl.Refused{
		Host:     name,
		SNI:      sni,
		Where:    where,
		Cause:    string(CauseEyeball),
		Kind:     "AS" + strconv.FormatUint(uint64(asn), 10),
		ClientIP: ip,
		DestIP:   dst.String(),
		Alert:    b.eyeballAlert(name, asn),
	})
}

// eyeballAlert alerts one time for each name and ASN since the start of
// the process. A name in an eyeball network is a fact about that name, and
// the agent repeats it on each connection. A new name is a new fact. The
// once-per-cause rule of alertRefusal would hide the second home server
// behind the first one.
func (b *Broker) eyeballAlert(name string, asn uint32) bool {
	key := name + " " + strconv.FormatUint(uint64(asn), 10)
	b.useMu.Lock()
	defer b.useMu.Unlock()
	if b.eyeSaid == nil || len(b.eyeSaid) >= eyeballAlertKeys {
		b.eyeSaid = map[string]bool{}
	}
	if b.eyeSaid[key] {
		return false
	}
	b.eyeSaid[key] = true
	return true
}

// eyeballRefused runs the check for a connection to a real address (not a
// fake destination). Only the agent network gets the check: a segment with
// INSPECT=on holds devices that talk to home lines for good reasons. It
// reports true when the broker must refuse the connection.
func (b *Broker) eyeballRefused(p *preamble.Preamble) bool {
	if b.Eyeball == nil || isEcho(p.OrigDst) || echoHost(p.SNI, "") {
		return false
	}
	if b.AgentNet.IsValid() && !b.AgentNet.Contains(p.Src.Addr()) {
		return false
	}
	sni := strings.ToLower(strings.TrimSuffix(p.SNI, "."))
	asn, hit := b.Eyeball.Match(sni, p.OrigDst.Addr())
	if !hit {
		return false
	}
	refuse := b.Eyeball.Mode == eyeball.Refuse
	where := whereAudit
	if refuse {
		where = "preamble"
	}
	b.logEyeball(sni, sni, clientIP(p), where, p.OrigDst.Addr(), asn)
	return refuse
}
