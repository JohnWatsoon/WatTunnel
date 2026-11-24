//go:build linux

package mgr

import (
	"os"
	"path/filepath"
	"time"

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

// WriteLock is the one-writer lock (panel plan D3): a blocking flock on $RUN/write.lock, held only around one
// config write or unit enable/disable. The console, the web panel, Kharej's remote ops and the bash manager all
// take it, so two of them never interleave a rewrite. Waits up to 10 s, then gives up with a plain error.
func WriteLock() (func(), error) {
	dir := lockDir()
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "write.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil // no run dir (a test, a read-only box): nothing else can write here either
	}
	for end := time.Now().Add(10 * time.Second); unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil; {
		if time.Now().After(end) {
			f.Close()
			return nil, errWriteBusy
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
