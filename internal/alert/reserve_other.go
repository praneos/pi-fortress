//go:build !linux

package alert

// LockMemory does nothing outside Linux.
func LockMemory(int64) string { return "memory not locked: not Linux" }
