package nftsets

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// listing is what `nft list set inet fortress <name>` prints, with the tabs.
// The elements block wraps across lines when it is longer than a terminal.
// The parser must read that shape.
func listing(name, body string) string {
	return "table inet fortress {\n\tset " + name + " {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout 2h\n" + body + "\t}\n}\n"
}

func elements(items ...string) string {
	return "\t\telements = { " + strings.Join(items, ",\n\t\t\t     ") + " }\n"
}

func TestParseSetReadsTheRemainingLifeNFTPrintsForEachElement(t *testing.T) {
	s, err := ParseSet(listing("resolved_v4", elements(
		"1.2.3.4 timeout 2h expires 1h58m12s",
		"5.6.7.8 expires 1h2m",
		"9.9.9.9 timeout 2h expires 45s",
	)))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if s.Name != "resolved_v4" {
		t.Fatalf("name = %q, want resolved_v4", s.Name)
	}
	want := []Element{
		{"1.2.3.4", time.Hour + 58*time.Minute + 12*time.Second},
		{"5.6.7.8", time.Hour + 2*time.Minute},
		{"9.9.9.9", 45 * time.Second},
	}
	if len(s.Elements) != len(want) {
		t.Fatalf("got %d elements, want %d: %v", len(s.Elements), len(want), s.Elements)
	}
	for i, e := range s.Elements {
		if e != want[i] {
			t.Fatalf("element %d = %v, want %v", i, e, want[i])
		}
	}
}

// nft prints `expires` for each live element. Thus an element without one
// is a listing that this box did not see. It must still have a limit: the
// timeout of the element, never the full 2h of the set by default.
func TestAnElementWithNoExpiresFallsBackToItsOwnTimeoutAndOneWithNeitherIsDropped(t *testing.T) {
	s, err := ParseSet(listing("resolved_v4", elements(
		"1.2.3.4 timeout 30m",
		"5.6.7.8",
	)))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if len(s.Elements) != 1 || s.Elements[0] != (Element{"1.2.3.4", 30 * time.Minute}) {
		t.Fatalf("got %v, want only 1.2.3.4 with 30m", s.Elements)
	}
}

// The code would add a bare element again with the full timeout of the set.
// That is the "resolved once, allowed forever" that the gate must stop. The
// same applies to an expires longer than the timeout of the set, from any source.
func TestNoCarriedElementOutlivesTheSetsOwnTimeout(t *testing.T) {
	s, err := ParseSet(listing("resolved_v4", elements("1.2.3.4 timeout 9h expires 8h59m")))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if len(s.Elements) != 1 || s.Elements[0].Remaining != 2*time.Hour {
		t.Fatalf("got %v, want 1.2.3.4 clamped to 2h", s.Elements)
	}
}

func TestAnEmptySetParsesToNoElementsRatherThanAnError(t *testing.T) {
	s, err := ParseSet(listing("resolved_desk_v4", ""))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if len(s.Elements) != 0 {
		t.Fatalf("got %v, want nothing", s.Elements)
	}
}

// One unreadable element must not make a segment lose the rest of its set.
// The alternative is an empty set and a desk that cannot reach anything.
func TestGarbageInTheListingCostsOnlyTheElementItIsIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want int
	}{
		{"not a listing at all", "Error: syntax error, unexpected string\n", 0},
		{"a truncated elements block", listing("resolved_v4", "\t\telements = { 1.2.3.4 expires 5m,\n"), 1},
		{"an element that is not an address", listing("resolved_v4", elements("not-an-ip expires 5m", "1.2.3.4 expires 5m")), 1},
		{"an element with an unreadable duration", listing("resolved_v4", elements("1.2.3.4 expires 5 minutes", "5.6.7.8 expires 5m")), 1},
		{"an IPv6 element in a v4 set", listing("resolved_v4", elements("2001:db8::1 expires 5m", "1.2.3.4 expires 5m")), 1},
		{"a comment holding a brace", listing("resolved_v4", elements(`1.2.3.4 comment "a } brace" expires 5m`, "5.6.7.8 expires 5m")), 2},
	} {
		s, err := ParseSet(tc.out)
		if err != nil {
			t.Fatalf("%s: ParseSet: %v", tc.name, err)
		}
		if len(s.Elements) != tc.want {
			t.Fatalf("%s: got %d elements, want %d: %v", tc.name, len(s.Elements), tc.want, s.Elements)
		}
	}
}

func TestParseDurationReadsEveryUnitNFTPrints(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"2h", 2 * time.Hour},
		{"1h58m12s", time.Hour + 58*time.Minute + 12*time.Second},
		{"1d2h3m4s", 24*time.Hour + 2*time.Hour + 3*time.Minute + 4*time.Second},
		{"1w", 7 * 24 * time.Hour},
		{"500ms", 500 * time.Millisecond},
		{"0s", 0},
		{"45s", 45 * time.Second},
	} {
		got, err := ParseDuration(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q = %v, want %v", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "5 minutes", "h", "12", "1x", "-5s"} {
		if d, err := ParseDuration(bad); err == nil {
			t.Fatalf("%q parsed as %v, want a refusal", bad, d)
		}
	}
}

// Sub-second is not a rounding question: `timeout 0s` means no timeout in
// nft. Thus an element with 500ms left would come back with no expiry.
func TestAnElementWithLessThanASecondLeftIsDroppedRatherThanMadePermanent(t *testing.T) {
	s, err := ParseSet(listing("resolved_v4", elements(
		"1.2.3.4 expires 500ms",
		"5.6.7.8 expires 0s",
		"9.9.9.9 expires 1s",
	)))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if len(s.Elements) != 1 || s.Elements[0].Addr != "9.9.9.9" {
		t.Fatalf("got %v, want only 9.9.9.9", s.Elements)
	}
}

func TestACarryFileRoundTripsWithTheReloadsOwnTimeTakenOffEveryElement(t *testing.T) {
	saved := time.Unix(1_758_513_600, 0)
	var b bytes.Buffer
	if err := Format(&b, saved, []Set{
		{Name: "resolved_v4", Elements: []Element{{"1.2.3.4", 2 * time.Hour}, {"5.6.7.8", 40 * time.Second}}},
		{Name: "resolved_desk_v4", Elements: []Element{{"203.0.113.5", time.Hour}}},
	}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	sets, err := Parse(bytes.NewReader(b.Bytes()), saved.Add(45*time.Second))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2: %v", len(sets), sets)
	}
	// The reload took 45 s from the element with 2h. The element with 40 s
	// left expired while the ruleset loaded.
	if sets[0].Name != "resolved_v4" || len(sets[0].Elements) != 1 {
		t.Fatalf("agent set = %v, want only 1.2.3.4", sets[0])
	}
	if want := 2*time.Hour - 45*time.Second; sets[0].Elements[0].Remaining != want {
		t.Fatalf("1.2.3.4 has %v left, want %v", sets[0].Elements[0].Remaining, want)
	}
	if sets[1].Name != "resolved_desk_v4" || sets[1].Elements[0].Remaining != time.Hour-45*time.Second {
		t.Fatalf("desk set = %v", sets[1])
	}
}

// The clock is the one input that this box does not control. If it goes
// backwards, the worst result is that an element keeps the life it had.
func TestAClockThatWentBackwardsNeverLengthensACarriedElement(t *testing.T) {
	saved := time.Unix(1_758_513_600, 0)
	var b bytes.Buffer
	if err := Format(&b, saved, []Set{{Name: "resolved_v4", Elements: []Element{{"1.2.3.4", time.Hour}}}}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	sets, err := Parse(bytes.NewReader(b.Bytes()), saved.Add(-72*time.Hour))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sets[0].Elements[0].Remaining != time.Hour {
		t.Fatalf("1.2.3.4 has %v left, want no more than the 1h it was saved with", sets[0].Elements[0].Remaining)
	}
}

// Nothing else can get to `nft add element` through this file. A set name
// is a command word. A carried compiled set would put back the addresses
// that the operator just removed from the compile.
func TestACarryFileNamingASetTheResolverDoesNotFillIsRefused(t *testing.T) {
	for _, bad := range []string{
		"resolved_v4 1.2.3.4 60\nblacklist_v4 203.0.113.9 60\n",
		"resolved_v4 1.2.3.4 60\ndirect_ip_v4 203.0.113.9 60\n",
		"resolved_v4 1.2.3.4 60\nresolved_v4 } ; drop 60\n",
		"resolved_v4 1.2.3.4\n",
		"resolved_v4 1.2.3.4 sixty\n",
	} {
		if _, err := Parse(strings.NewReader(bad), time.Now()); err == nil {
			t.Fatalf("Parse accepted %q", bad)
		}
	}
}

// fakeNFT answers the two listings that Save makes and records what Restore
// put on stdin. Thus the full path can run without root or a kernel.
type fakeNFT struct {
	sets    string            // `nft list sets table ...`
	listing map[string]string // set name -> `nft list set ...`
	script  string
	failOn  string
}

func (f *fakeNFT) run(stdin string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return "", fmt.Errorf("nft %s: Error: No such file or directory", joined)
	}
	switch {
	case strings.HasPrefix(joined, "list sets table"):
		return f.sets, nil
	case strings.HasPrefix(joined, "list set "):
		return f.listing[args[len(args)-1]], nil
	case joined == "-f -":
		f.script = stdin
		return "", nil
	}
	return "", fmt.Errorf("unexpected nft %s", joined)
}

func twoSegmentBox() *fakeNFT {
	return &fakeNFT{
		sets: "table inet fortress {\n\tset blacklist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n" +
			"\tset resolved_v4 {\n\t\ttype ipv4_addr\n\t}\n\tset resolved_desk_v4 {\n\t\ttype ipv4_addr\n\t}\n}\n",
		listing: map[string]string{
			"resolved_v4":      listing("resolved_v4", elements("1.2.3.4 expires 1h58m12s")),
			"resolved_desk_v4": listing("resolved_desk_v4", elements("203.0.113.5 expires 30m")),
		},
	}
}

func TestSaveTakesTheResolvedSetsAndLeavesTheCompiledOnesAlone(t *testing.T) {
	f := twoSegmentBox()
	sets, err := Save(f.run, "inet fortress")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(sets) != 2 || sets[0].Name != "resolved_v4" || sets[1].Name != "resolved_desk_v4" {
		t.Fatalf("saved %v, want the two resolved sets only", sets)
	}
}

// There is one set for each segment, because a name resolved on one segment
// must not open an address on a different one. The carry must not merge them.
func TestRestoreReturnsEachSegmentsAddressesToItsOwnSetOnly(t *testing.T) {
	f := twoSegmentBox()
	sets, err := Save(f.run, "inet fortress")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Restore(f.run, "inet fortress", sets); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, want := range []string{
		"add element inet fortress resolved_v4 { 1.2.3.4 timeout 7092s }",
		"add element inet fortress resolved_desk_v4 { 203.0.113.5 timeout 1800s }",
	} {
		if !strings.Contains(f.script, want) {
			t.Fatalf("the restore script has no %q:\n%s", want, f.script)
		}
	}
	if strings.Contains(f.script, "resolved_v4 { 203.0.113.5") || strings.Contains(f.script, "resolved_desk_v4 { 1.2.3.4") {
		t.Fatalf("a segment's address landed in another segment's set:\n%s", f.script)
	}
}

// If a segment is deleted between the two rulesets, its addresses are lost.
// Its set is gone. An add to a set that is not there would fail the full
// transaction. Then all other segments would also lose their elements.
func TestElementsForASetTheNewRulesetDoesNotHaveAreDropped(t *testing.T) {
	f := twoSegmentBox()
	sets, err := Save(f.run, "inet fortress")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	f.sets = "table inet fortress {\n\tset resolved_v4 {\n\t\ttype ipv4_addr\n\t}\n}\n"
	n, err := Restore(f.run, "inet fortress", sets)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 1 || strings.Contains(f.script, "resolved_desk_v4") {
		t.Fatalf("restored %d elements into:\n%s", n, f.script)
	}
}

// Thousands of addresses are normal on a busy segment. They go in one nft
// transaction. A fork for each address would cost more than the reload that
// this repairs. The split into statements is only so that a failure names a
// readable statement.
func TestThousandsOfAddressesGoBackInOneTransaction(t *testing.T) {
	items := make([]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		items = append(items, fmt.Sprintf("10.%d.%d.%d expires 1h", i/65536, (i/256)%256, i%256))
	}
	f := &fakeNFT{
		sets:    "table inet fortress {\n\tset resolved_v4 {\n\t\ttype ipv4_addr\n\t}\n}\n",
		listing: map[string]string{"resolved_v4": listing("resolved_v4", elements(items...))},
	}
	sets, err := Save(f.run, "inet fortress")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(sets[0].Elements) != 5000 {
		t.Fatalf("parsed %d of 5000 elements", len(sets[0].Elements))
	}
	n, err := Restore(f.run, "inet fortress", sets)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 5000 {
		t.Fatalf("restored %d of 5000", n)
	}
	if got := strings.Count(f.script, "add element"); got != 5000/batch+1 {
		t.Fatalf("%d add statements, want %d", got, 5000/batch+1)
	}
	if strings.Count(f.script, "10.0.0.1 timeout 3600s") != 1 {
		t.Fatalf("an address was not carried exactly once:\n%s", f.script[:200])
	}
}

// The apply must continue if the two halves fail. An empty set is what the
// box did before this code. The fence is the same in the two cases.
func TestASaveOrRestoreThatCannotReachNFTReportsItRatherThanGuessing(t *testing.T) {
	f := twoSegmentBox()
	f.failOn = "list sets table"
	if _, err := Save(f.run, "inet fortress"); err == nil {
		t.Fatal("Save said nothing when nft could not list the table")
	}
	f = twoSegmentBox()
	sets, err := Save(f.run, "inet fortress")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	f.failOn = "-f -"
	if _, err := Restore(f.run, "inet fortress", sets); err == nil {
		t.Fatal("Restore said nothing when the transaction was refused")
	}
}
