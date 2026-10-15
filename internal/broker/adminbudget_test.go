package broker

import (
	"testing"

	"pi-fortress/internal/secrets"
)

// The hour is in the memory of this process. Thus the only place to read
// it is the socket that the operator tools already dial.
func TestAdminBudgetVerb(t *testing.T) {
	b, _, _ := budgetBroker(t, SlotBudget{WarnRequests: 1000})
	a := &Admin{Store: b.Store, Budget: b.BudgetHour}
	if got := ask(t, a, secrets.AdminBudget); got != "" {
		t.Fatalf("an untouched broker answered %q", got)
	}
	spendBody(t, b, budgetSlot, 64)
	spend(t, b, budgetSlot)
	if got, want := ask(t, a, secrets.AdminBudget), budgetSlot+" 2 64"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

// A broker without the hook still answers the verb and does not return
// an error. An empty line means "no slot has spent anything". A broker
// with no armed budget must say that.
func TestAdminBudgetWithoutTheHook(t *testing.T) {
	st, _ := adminStore(t)
	if got := ask(t, &Admin{Store: st}, secrets.AdminBudget); got != "" {
		t.Fatalf("%q", got)
	}
}
