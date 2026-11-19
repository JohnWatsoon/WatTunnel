//go:build !linux

package main

import (
	"fmt"
	"os"
)

// fieldprobe needs Linux raw sockets; like wat's desync_other.go it refuses everywhere else.
func main() {
	fmt.Fprintln(os.Stderr, "fieldprobe: Linux only (raw sockets); this build cannot run")
	os.Exit(1)
}
