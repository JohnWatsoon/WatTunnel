package mgr

import "errors"

var errWriteBusy = errors.New("another change is being saved, try again")

// lockDir is $RUN without needing InitPaths (the engine's Kharej ops take the write lock too).
func lockDir() string {
	if P.Run != "" {
		return P.Run
	}
	return envOr("WAT_RUN", "/run/"+envOr("WAT_PREFIX", "wattun"))
}

// withWriteLock runs fn under WriteLock.
func withWriteLock(fn func() error) error {
	unlock, err := WriteLock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
