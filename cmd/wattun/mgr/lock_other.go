//go:build !linux

package mgr

func lockFile(string) bool { return true }
