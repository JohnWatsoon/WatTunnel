package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// A server session's packet numbers start at the wall clock in microseconds and advance by one per packet. A clock
// stepped back across a restart could start a new run below the old one and reuse nonces under the same key, so the
// server keeps a high-water mark in <config>.pn (next to the other state files) and never starts below it.
const (
	pnSaveEvery = time.Minute
	// pnFloorMargin: at 1 packet/µs (far above any real rate) a session cannot pass the mark before the next save.
	pnFloorMargin = 10 * time.Minute
)

// keepPNFloor loads the mark of the previous run, raises wat's floor above it, saves a new mark now and every minute.
// A missing or unreadable file only means no floor: the wall clock base still applies.
func keepPNFloor(path string) {
	margin := uint64(pnFloorMargin.Microseconds())
	var floor uint64
	if b, err := os.ReadFile(path); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			floor = v + margin
		}
	}
	save := func() {
		floor = max(floor, uint64(time.Now().UnixMicro()))
		wat.SetPNFloor(floor)
		tmp := path + ".tmp"
		err := os.WriteFile(tmp, []byte(strconv.FormatUint(floor+margin, 10)+"\n"), 0o600)
		if err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			log.Printf("packet-number mark %s: %v", path, err)
		}
	}
	save()
	go func() {
		last := time.Now()
		for range time.Tick(pnSaveEvery) {
			floor += uint64(time.Since(last).Microseconds()) // the floor never falls behind real elapsed time
			last = time.Now()
			save()
		}
	}()
}
