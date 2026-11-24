//go:build !linux

package main

func diskUsedPct(string) float64 { return 0 }
