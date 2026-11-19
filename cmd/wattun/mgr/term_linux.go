//go:build linux

package mgr

import (
	"os"

	"golang.org/x/sys/unix"
)

// isTTY via stat mode.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// termWidth via TIOCGWINSZ (what tput cols reads).
func termWidth() int {
	if ws, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
		return int(ws.Col)
	}
	return 0
}

// rawMode puts stdin in cbreak/no-echo; returns a restore func.
func rawMode() (restore func(), err error) {
	old, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return func() {}, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(0, unix.TCSETS, &raw); err != nil {
		return func() {}, err
	}
	return func() { _ = unix.IoctlSetTermios(0, unix.TCSETS, old) }, nil
}
