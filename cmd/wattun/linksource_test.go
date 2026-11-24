package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A pairing link's process answers for the visible tunnels of its config dir; a plain unit only for itself.
func TestLinkSourceSiblings(t *testing.T) {
	dir := t.TempDir()
	w := func(n, s string) { os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600) }
	w("pair.yml", "mode: server\n")
	w("pair.link", "kharej\n")
	w("pair-r.yml", "mode: server\n")
	w("t1.yml", "mode: server\ncarrier: tls\nmetrics: 127.0.0.1:1\nports:\n  - \"443\"\n  - 80\n")
	w("t1-e-sit.yml", "mode: server\n")
	w("t1-e-sit.autoext", "")

	for _, unit := range []string{"pair", "pair-r"} {
		u := &unitSource{name: unit, dir: dir}
		got := u.Tunnels()
		if len(got) != 1 || got[0].Name != "t1" || got[0].Carrier != "tls" || got[0].Ports != "443,80" {
			t.Fatalf("%s lists %+v, want only t1 (tls, 443,80)", unit, got)
		}
		if _, ok := u.TunnelStats("t1"); !ok {
			t.Errorf("%s: stats of t1 not found", unit)
		}
		if _, ok := u.TunnelStats("t1-e-sit"); ok {
			t.Errorf("%s: a hidden helper must not answer", unit)
		}
	}
	plain := &unitSource{name: "t1", dir: dir, alivef: func() bool { return true }}
	if got := plain.Tunnels(); len(got) != 1 || got[0].Name != "t1" {
		t.Errorf("a plain unit lists %+v, want itself", got)
	}
}
