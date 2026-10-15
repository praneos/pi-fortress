package doctor

import (
	"errors"
	"strings"
	"testing"
)

// The fence is two units, and the ladder looked at neither. The one rung
// that would have noticed (the credential store) answers "not
// applicable" for exactly the case where the broker is down. So a
// stopped broker printed an all-green ladder and exited 0.
func TestStoppedBrokerFailsTheLadder(t *testing.T) {
	stub(t)
	unitActive = func(u string) bool { return u != "pi-fortress-broker.service" }
	r, ok := UnitsRung(FenceUnits...)
	if !ok {
		t.Fatal("no units rung at all")
	}
	if r.Status != Fail {
		t.Fatalf("broker down reported as %v: %+v", r.Status, r)
	}
	if !strings.Contains(r.Detail, "pi-fortress-broker.service") {
		t.Fatalf("the dead unit is not named: %q", r.Detail)
	}
	var b strings.Builder
	if code := Report(&b, []Result{r}); code != 1 {
		t.Fatalf("exit %d with the broker stopped", code)
	}
}

func TestUnitsRungGreenWhenTheFenceIsUp(t *testing.T) {
	stub(t)
	r, ok := UnitsRung(FenceUnits...)
	if !ok || r.Status != OK {
		t.Fatalf("every unit active: %+v ok=%v", r, ok)
	}
	for _, u := range FenceUnits {
		if !strings.Contains(r.Detail, u) {
			t.Fatalf("%s is not named in %q", u, r.Detail)
		}
	}
}

func TestUnitsRungWithoutUnitsIsNoRung(t *testing.T) {
	stub(t)
	if _, ok := UnitsRung(); ok {
		t.Fatal("rung for an empty unit list")
	}
}

// An admin socket that could not be reached was silently discarded:
// the rung was appended only when SecretsState returned no error, so the
// operator saw nothing at all about the store.
func TestSecretsRungFailsWhenTheStoreCannotBeAsked(t *testing.T) {
	r, ok := SecretsRung("", errors.New("dial unix /run/pi-fortress/admin.sock: connect: connection refused"))
	if !ok {
		t.Fatal("an unreachable store produced no rung")
	}
	if r.Status != Fail {
		t.Fatalf("status %v, want FAIL: %+v", r.Status, r)
	}
	if !strings.Contains(r.Detail, "connection refused") {
		t.Fatalf("the reason was dropped: %q", r.Detail)
	}
}

func TestSecretsRungStillReadsTheState(t *testing.T) {
	r, ok := SecretsRung("sealed locked", nil)
	if !ok || r.Status != Warn || !strings.Contains(r.Detail, "pf unlock") {
		t.Fatalf("%+v ok=%v", r, ok)
	}
	if r, ok := SecretsRung("fault hsm gone", nil); !ok || r.Status != Fail {
		t.Fatalf("%+v ok=%v", r, ok)
	}
	if _, ok := SecretsRung("", nil); ok {
		t.Fatal("rung for a box with no store and no error")
	}
}
