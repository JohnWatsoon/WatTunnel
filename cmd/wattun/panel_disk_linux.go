//go:build linux

package main

import "golang.org/x/sys/unix"

func diskUsedPct(path string) float64 {
	var s unix.Statfs_t
	if unix.Statfs(path, &s) != nil || s.Blocks == 0 {
		return 0
	}
	return float64(s.Blocks-s.Bavail) * 100 / float64(s.Blocks)
}
