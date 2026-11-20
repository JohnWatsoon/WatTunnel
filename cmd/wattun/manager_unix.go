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
// (`wattun heal`, `wattun auto-test NAME`), it replaces itself with wattun-manager. Every engine invocation (systemd
// units, scripts) passes flags, so it is unaffected. Returns only if there is nothing to hand over to.
func runManager() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-") {
		return
	}
	if os.Getenv("WAT_GO_MGR") == "1" { // opt-in preview of the Go manager; bash stays the default until sign-off
		os.Exit(mgr.Run(os.Args[1:]))
	}
	p, err := exec.LookPath("wattun-manager")
	if err != nil {
		if len(os.Args) == 1 {
			return // no manager installed: keep the old usage error
		}
		os.Stderr.WriteString("wattun: wattun-manager is not installed; engine options start with '-' (wattun -h)\n")
		os.Exit(2)
	}
	syscall.Exec(p, append([]string{"wattun-manager"}, os.Args[1:]...), os.Environ())
}
