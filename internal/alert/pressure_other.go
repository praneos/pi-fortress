//go:build !linux

package alert

import "context"

func (p *Pressure) waiterFor(ctx context.Context, _ *procReader) waiter {
	return &sleepWaiter{ctx: ctx, why: "no PSI on this OS; files read each 2 s"}
}
