package mgr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Handoff 4 R7: user-facing menu text names things in the user's words. Item labels, descriptions and hints
// never carry a remote command name (tunnel.create, state.get …) or the protocol words PSK, twin, journal,
// cursor, chunked.
func TestNoProtocolWordsInUI(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	ui := regexp.MustCompile(`(Desc:|Label:|Hint\(|hintLine\(|Title\(|Page\(|Confirm\()\s*"([^"]*)"`)
	bad := regexp.MustCompile(`\b(tunnel|state|scepter|events|doctor|auto|update|backup|carrier|preset|limits|audit)\.[a-z]+\b|\bPSK\b|\b[Tt]win\b|journal|\bcursor\b|chunked`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range ui.FindAllStringSubmatch(line, -1) {
				if w := bad.FindString(m[2]); w != "" {
					t.Errorf("%s:%d: %q in user text %q", f, i+1, w, m[2])
				}
			}
		}
	}
}

// Handoff 4 R7: on a paired Iran, New tunnel offers "On Kharej and here" first; a Kharej never sees it.
func TestNewTunnelOffersBothSides(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := homeTestHost(t)
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\npairing: true\n"), 0o600)
	_ = ConfSet("side", "iran")
	defer feed("0")()
	if out := capture(t, newTunnelScreen); !strings.Contains(out, "On Kharej and here") {
		t.Errorf("a paired Iran must offer both sides:\n%s", out)
	}
	_ = ConfSet("side", "kharej")
	defer feed("0")()
	if out := capture(t, newTunnelScreen); strings.Contains(out, "On Kharej and here") {
		t.Errorf("Kharej must not offer it:\n%s", out)
	}
}
