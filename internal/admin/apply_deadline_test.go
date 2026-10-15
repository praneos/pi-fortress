package admin

import (
	"context"
	"io"
	"testing"
)

// Before, a deadline on apply sent a SIGTERM to apply.sh part way through.
// That leaves a half-applied box. The verb streams under the context of the
// caller and adds no deadline of its own.
func TestApplyVerbHasNoDeadline(t *testing.T) {
	var deadlined, called bool
	c := &Config{Stream: func(ctx context.Context, _ []string, _ io.Writer) error {
		called = true
		_, deadlined = ctx.Deadline()
		return nil
	}, PfCmd: []string{"pf"}}
	for _, local := range []bool{false, true} {
		if _, err := c.Call(RoleAdmin, "apply", Args{Out: io.Discard, Local: local}); err != nil {
			t.Fatal(err)
		}
		if !called || deadlined {
			t.Fatalf("local=%v: called %v, deadline %v", local, called, deadlined)
		}
	}
}
