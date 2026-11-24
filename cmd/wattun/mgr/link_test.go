package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pairing link is hidden from the tunnel lists but kept running; its key file holds the whole token.
func TestPairingLinkHidden(t *testing.T) {
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	w := func(n, s string) { os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600) }
	w("t1.yml", "mode: client\n")
	w("pair.yml", "mode: client\n")
	w("pair.link", "iran\n")

	if got := strings.Join(Tunnels(), ","); got != "t1" {
		t.Errorf("Tunnels() = %q, want t1 (the link hidden)", got)
	}
	if got := strings.Join(ManagedTunnels(), ","); got != "pair,t1" {
		t.Errorf("ManagedTunnels() = %q, want pair,t1", got)
	}
	if n := freeLinkName(); n != "pair-2" {
		t.Errorf("freeLinkName() = %q, want pair-2", n)
	}

	tok := MakeToken("auto", "203.0.113.7", "secretkey", "", "", "", "", "", "", "pair=full")
	if k := pskOf(tok + "\n"); k != "secretkey" {
		t.Errorf("pskOf(token) = %q, want the key field", k)
	}
	if k := pskOf("plainkey\n"); k != "plainkey" {
		t.Errorf("pskOf(plain) = %q", k)
	}
}
