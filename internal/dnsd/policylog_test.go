package dnsd

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
)

// replies is every row that the harness logged. One row is one
// transaction, so no filter is necessary now. The name stays because
// these tests examine how the log wrote the answer.
func replies(t *testing.T, h *harness) []dnslog.Event {
	t.Helper()
	return h.logLines(t)
}

// The resolver uses an empty answer to suppress two different
// things. One is a type that it always filters (AAAA, HTTPS, SVCB). The
// other is a name on the sinkhole list, asked for a type that the
// sinkhole has no record of. The log wrote both as "config <name> is
// NODATA", the same as an empty upstream answer. Thus the consumer could
// not tell them apart, or count either one as policy action.
func TestPolicySuppressionIsSpeltApartFromOrdinaryNODATA(t *testing.T) {
	h := newHarness(t, []string{"blocked.test"}, map[string][4]byte{"tracker.test": {1, 2, 3, 4}}, 300)
	h.ask(t, "tracker.test", dnsmessage.TypeAAAA)
	h.ask(t, "blocked.test", dnsmessage.TypeMX)
	h.ask(t, "blocked.test", dnsmessage.TypeA)

	got := replies(t, h)
	if len(got) != 3 {
		t.Fatalf("%d reply lines, want one per query: %+v", len(got), got)
	}
	filtered, listed, sunk := got[0], got[1], got[2]
	if sunk.Answer != "0.0.0.0" || sunk.Act != dnslog.ActBlocked {
		t.Fatalf("sinkholed A %+v, want the blocked 0.0.0.0 row", sunk)
	}
	if filtered.Act != dnslog.ActFiltered {
		t.Fatalf("a type-filtered query logs %+v, which the reader counts as ordinary unresolved traffic", filtered)
	}
	if listed.Act != dnslog.ActFiltered {
		t.Fatalf("a listed name's non-A query logs %+v, which the reader counts as ordinary unresolved traffic", listed)
	}
}

// An answer from upstream is not policy, even if it is empty. It keeps
// the reply verb and the spelling of the upstream. Thus a larger policy
// vocabulary must not absorb it.
func TestAnUpstreamAnswerIsNotPolicy(t *testing.T) {
	h := newHarness(t, nil, nil, 300)
	h.ask(t, "nothing.test", dnsmessage.TypeMX)
	got := replies(t, h)
	if len(got) != 1 {
		t.Fatalf("%d reply lines: %+v", len(got), got)
	}
	if got[0].Act == dnslog.ActBlocked || got[0].Act == dnslog.ActFiltered {
		t.Fatalf("an upstream answer logged as policy: %+v", got[0])
	}
}

// Before, the log showed an upstream that failed as one that answered.
// The rcode came through as "RCODESERVERFAILURE". Nothing read that as a
// verdict, so the row said resolved. Now each failure rcode has its own word.
func TestAnUpstreamFailureIsNotResolved(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"ok.test": {192, 0, 2, 10}}, 300)
	for name, rc := range map[string]dnsmessage.RCode{
		"fail.test":    dnsmessage.RCodeServerFailure,
		"refused.test": dnsmessage.RCodeRefused,
		"formerr.test": dnsmessage.RCodeFormatError,
		"notimp.test":  dnsmessage.RCodeNotImplemented,
		"yx.test":      dnsmessage.RCode(6),
	} {
		h.up.rcodes.Store(name, rc)
	}
	want := map[string][2]string{
		"fail.test":    {dnslog.ActServfail, "SERVFAIL"},
		"refused.test": {dnslog.ActRefused, "REFUSED"},
		"formerr.test": {dnslog.ActServfail, "FORMERR"},
		"notimp.test":  {dnslog.ActServfail, "NOTIMP"},
		"yx.test":      {dnslog.ActServfail, "RCODE6"},
		"ok.test":      {dnslog.ActResolved, "192.0.2.10"},
	}
	for name := range want {
		h.ask(t, name, dnsmessage.TypeA)
	}
	got := map[string][2]string{}
	for _, r := range replies(t, h) {
		got[r.Name] = [2]string{r.Act, r.Answer}
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: logged %v, want %v", name, got[name], w)
		}
	}
}
