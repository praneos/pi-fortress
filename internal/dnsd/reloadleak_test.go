package dnsd

import (
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// heapInUse is the live heap after a full collection.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// Each SIGHUP loads the key rules again, and logrotate sends one to pf dns
// each hour. A reload must not keep the rule set that it replaced. Before,
// keyshape kept the forms of each rule set that a name was checked against
// in a cache with no limit. One reload and one name with a key head then
// kept approximately 170 KiB for each segment with key rules. The unit has
// MemoryMax=256M, so pf dns grew until the kernel stopped it, and each
// segment lost DNS while it started again.
func TestReloadKeepsNoOldKeyRules(t *testing.T) {
	h := newHarness(t, nil, nil, 300)
	h.srv.segs[0].KeyRulesPath = shippedRules
	key := "sk-ant-oat01-" + strings.Repeat("A", 40) + ".evil.example"
	cycle := func() {
		t.Helper()
		if err := h.srv.Reload(); err != nil {
			t.Fatal(err)
		}
		if hdr, _ := h.ask(t, key, dnsmessage.TypeA); hdr.RCode != dnsmessage.RCodeRefused {
			t.Fatalf("rcode %v, want REFUSED", hdr.RCode)
		}
	}
	cycle()
	before := heapInUse()
	const reloads = 200
	for range reloads {
		cycle()
	}
	grew := int64(heapInUse()) - int64(before)
	t.Logf("%d reloads kept %d KiB of heap", reloads, grew>>10)
	// Without a limit, 200 reloads keep approximately 34 MiB.
	if grew > 16<<20 {
		t.Fatalf("%d reloads kept %d KiB of heap (%d KiB each)", reloads, grew>>10, grew/reloads>>10)
	}
}
