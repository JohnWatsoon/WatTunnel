//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/mgr"
)

// runManager makes `wattun` the one command users need: with no arguments, or a first argument that is not a flag
// (`wattun heal`, `wattun auto-test NAME`), it opens the Go manager (the Iran-main dashboard, owner decision
// 2026-11-23 — the UI pass is the reviewed default). WAT_BASH_MGR=1 keeps the classic bash console as the
// default hand-off (`wattun-manager` stays installed and directly runnable either way). Every engine invocation
// (systemd units, scripts) passes flags, so it is unaffected. Returns only if there is nothing to hand over to.
func runManager() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-") {
		return
	}
	if os.Getenv("WAT_BASH_MGR") == "1" { // the bash console opt-out; the Go manager is the default
		if p, err := exec.LookPath("wattun-manager"); err == nil {
			syscall.Exec(p, append([]string{"wattun-manager"}, os.Args[1:]...), os.Environ())
		}
		if len(os.Args) == 1 {
			return // no manager installed: keep the old usage error
		}
		os.Stderr.WriteString("wattun: wattun-manager is not installed; engine options start with '-' (wattun -h)\n")
		os.Exit(2)
	}
	os.Exit(mgr.Run(os.Args[1:]))
}
