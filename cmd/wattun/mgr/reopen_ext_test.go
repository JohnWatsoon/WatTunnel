package mgr

import (
	"os"
	"path/filepath"
	"testing"
)

// A main bond that carries ptcp or spray (written by the 4.0.2-4.0.4 bash manager) needs a reopen, which leaves
// them to their NAME-e-* helpers; a correct main bond does not.
func TestAutoNeedsReopenRepairsExtInBond(t *testing.T) {
	oldP := P
	P.Conf, P.Run = t.TempDir(), t.TempDir()
	defer func() { P = oldP }()
	plan := "d=udp:1001,tcp:1002,ptcp:1003,spray:1004;r=tcp:2001"
	tok := MakeToken("auto", "1.2.3.4", "k", "/p", "", "", "", "", plan)
	os.WriteFile(filepath.Join(P.Conf, "g.token"), []byte(tok+"\n"), 0o600)
	w := func(car string) {
		os.WriteFile(filepath.Join(P.Conf, "g.yml"), []byte("mode: server\ncarrier: "+car+"\n"), 0o600)
	}
	w("icmp+udp+tcp")
	if autoNeedsReopen("g") {
		t.Error("a correct main bond asked for a reopen")
	}
	w("icmp+udp+tcp+ptcp+spray")
	if !autoNeedsReopen("g") {
		t.Error("ptcp/spray in the main bond was not repaired")
	}
	if apD, _ := autoPlanLists(plan); len(apD) != 3 {
		t.Errorf("plan lists = %v, want icmp udp tcp", apD)
	}
}
