package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A switch to a reverse pool carrier writes listen as ":PORT"; a bare "PORT" made the engine exit
// ("missing port in address") and every switch rolled back (4.0.5 and before).
func TestAutoApplyReverseListenHasColon(t *testing.T) {
	oldP, oldQ, oldV, oldE := P, atQuiet, atVerify, engineVer
	P.Conf, P.Run = t.TempDir(), t.TempDir()
	atQuiet, atVerify, engineVer = true, false, func() string { return "9.9.9" }
	defer func() { P, atQuiet, atVerify, engineVer = oldP, oldQ, oldV, oldE }()
	f := filepath.Join(P.Conf, "r.yml")
	os.WriteFile(f, []byte("mode: client\ncarrier: h2\npeer: 1.2.3.4:26668\nreverse: true\nlisten: \":26668\"\n"), 0o600)
	if err := autoApply("r", atChoice{Carrier: "wss", Peer: "1.2.3.4:17344", Rev: "1", Label: "wss reverse"}, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "listen: \":17344\"") {
		t.Errorf("config after switch:\n%s", b)
	}
}
