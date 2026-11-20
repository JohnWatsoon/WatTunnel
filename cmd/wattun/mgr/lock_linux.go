//go:build linux

package mgr

import (
	"os"

	"golang.org/x/sys/unix"
)

var lockHeld *os.File

// lockFile takes an exclusive non-blocking flock held until the process exits.
func lockFile(p string) bool {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return true
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return false
	}
	lockHeld = f
	return true
}
