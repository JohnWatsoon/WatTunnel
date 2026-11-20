package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 5 (PLAN-go-manager): applyMatrixVariant writes the desync keys through
// the config writer (SetValue/UnsetValue) and restarts the unit — the
// ac_matrix_apply tail (bash matrix.go apply branch).
func TestApplyMatrixVariant(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldP, oldSys := P, p1Systemctl
	P.Conf = dir
	P.Prefix = "wattun"
	var restarts []string
	p1Systemctl = func(action, unit string) error {
		restarts = append(restarts, action+" "+unit)
		return nil
	}
	defer func() { P, p1Systemctl = oldP, oldSys }()
	conf := "# WatTunnel - Iran (client). Created by wattun-manager.\nmode: client\ncarrier: tcp+tls\n" +
		"fake-sni: old.example\nfake-mode: seq\nfake-ttl: 7\nech: ladder\nmetrics: 127.0.0.1:19750\n"
	if err := os.WriteFile(filepath.Join(dir, "t1.yml"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	// the best variant replaces the desync keys; fake-ttl goes (the probes always
	// run ttl auto-calibration); the unit restarts
	applyMatrixVariant("t1", variant{FS: "mci.ir", FM: "rst", ECH: ""})
	b, err := os.ReadFile(filepath.Join(dir, "t1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(b)
	for _, w := range []string{"fake-sni: mci.ir\n", "fake-mode: rst\n", "ech: ladder\n", "metrics: 127.0.0.1:19750\n"} {
		if !strings.Contains(yml, w) {
			t.Errorf("yml missing %q after apply:\n%s", w, yml)
		}
	}
	if strings.Contains(yml, "fake-ttl") || strings.Contains(yml, "old.example") {
		t.Errorf("stale keys survived:\n%s", yml)
	}
	if len(restarts) != 1 || !strings.Contains(restarts[0], "restart wattun@t1") {
		t.Errorf("restarts = %v", restarts)
	}

	// an empty variant (baseline won) clears the disguise and keeps ech
	restarts = nil
	applyMatrixVariant("t1", variant{})
	if b, _ := os.ReadFile(filepath.Join(dir, "t1.yml")); strings.Contains(string(b), "fake-sni") ||
		strings.Contains(string(b), "fake-mode") || strings.Contains(string(b), "fake-ttl") {
		t.Errorf("disguise keys not cleared:\n%s", string(b))
	} else if !strings.Contains(string(b), "ech: ladder") {
		t.Errorf("ech lost:\n%s", string(b))
	}
	if len(restarts) != 1 {
		t.Errorf("restarts = %v", restarts)
	}

	// ech is only written when the variant carries one
	applyMatrixVariant("t1", variant{FS: "irancell.ir", FM: "seq"})
	if b, _ := os.ReadFile(filepath.Join(dir, "t1.yml")); !strings.Contains(string(b), "ech: ladder\n") {
		t.Errorf("ech clobbered by an ech-less variant:\n%s", string(b))
	}
}
