package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The diagnose job's speed bars redraw in place; the page shows the last frame as plain text.
func TestTailLogTerminalRedraw(t *testing.T) {
	f := filepath.Join(t.TempDir(), "log")
	os.WriteFile(f, []byte("start\n"+
		"\x1b[K↓ Download 3.0 MB/s ▕███▏\n\x1b[K↑ Upload 2.0 MB/s ▕██▏\n"+
		"\x1b[2A\x1b[K↓ Download 12.0 MB/s ▕█████████▏\n\x1b[K↑ Upload 9.5 MB/s ▕████████▏\n"+
		"done\n"), 0o600)
	lines, _ := tailLog(f, 400)
	got := strings.Join(lines, "|")
	if want := "start|↓ Download 12.0 MB/s|↑ Upload 9.5 MB/s|done"; got != want {
		t.Errorf("lines = %q\nwant %q", got, want)
	}
}
