//go:build !linux

package mgr

import (
	"os"
)

// Windows/dev fallback: the manager runs on Linux; on a dev box line input via
// the console reader is enough (no raw mode, kernel echoes).
// shortcut: no Windows console-mode raw input; add golang.org/x/sys/windows
// SetConsoleMode if arrow-key screens must be driven on a dev box.

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func termWidth() int { return 0 }

func rawMode() (restore func(), err error) { return func() {}, nil }
