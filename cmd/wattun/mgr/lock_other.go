//go:build !linux

package mgr

func lockFile(string) bool { return true }

// WriteLock is a no-op off Linux (no other writer can run there).
func WriteLock() (func(), error) { return func() {}, nil }
