package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// A mark from a run whose clock was ahead (here: one day) is never undercut by the next run's mark.
func TestKeepPNFloor(t *testing.T) {
	t.Cleanup(func() { wat.SetPNFloor(0) })
	path := filepath.Join(t.TempDir(), "t.yml.pn")
	prev := uint64(time.Now().Add(24 * time.Hour).UnixMicro())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(prev, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keepPNFloor(path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got <= prev {
		t.Fatalf("new mark %d not above the previous run's %d", got, prev)
	}
}
