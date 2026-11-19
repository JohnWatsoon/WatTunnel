package mgr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresetCanonicalAndBuiltin(t *testing.T) {
	cases := map[string]string{
		"cf": "cloudflare", "Cloudflare-Tested": "cloudflare", "fast": "rst-fast",
		"hamrah-aval": "mci", "Mokhaberat": "irancell", "emergency": "blackout",
		"mild": "conservative", "Iran whitelist - MCI": "mci", "none": "off",
		"totally-custom": "totally-custom",
	}
	for in, want := range cases {
		if got := PresetCanonical(in); got != want {
			t.Errorf("PresetCanonical(%q) = %q, want %q", in, got, want)
		}
	}
	for _, p := range []string{"cloudflare", "rst-fast", "mci", "irancell", "blackout", "conservative"} {
		if !IsBuiltinPreset(p) {
			t.Errorf("%s should be builtin", p)
		}
	}
	if IsBuiltinPreset("custom-thing") {
		t.Error("custom-thing must not be builtin")
	}
}

func TestApplyPresetKeys(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	// stub the binary gate and the restart: this host has no systemd
	oldVer, oldRestart := binVerOKFn, restartFn
	binVerOKFn = func(string) bool { return true }
	restartFn = func(unit string) error { return nil }
	defer func() { binVerOKFn, restartFn = oldVer, oldRestart }()

	apply := func(t *testing.T, body, preset string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if !ApplyPreset("p", preset) {
			t.Fatalf("ApplyPreset(%s) failed", preset)
		}
		return readFile(t, filepath.Join(dir, "p.yml"))
	}

	// mci: the full key set, in apply_preset's order. The governor is an
	// icmp-only key (apply_preset's icmp branch); pool carriers never get it.
	out := apply(t, "mode: client\ncarrier: wss\nmetrics: 127.0.0.1:19701\n", "mci")
	wantOrder := []string{"fake-sni: mci.ir", "fake-mode: rst", "pool-rotate: 30m", "pool-rotate-bytes: 500MB", "ech: ladder"}
	pos := -1
	for _, w := range wantOrder {
		i := strings.Index(out, w)
		if i < 0 {
			t.Errorf("preset mci missing %q:\n%s", w, out)
			continue
		}
		if i < pos {
			t.Errorf("preset mci order wrong: %q after the previous key\n%s", w, out)
		}
		pos = i
	}
	if strings.Contains(out, "fake-ttl:") || strings.Contains(out, "sessions:") || strings.Contains(out, "conns:") {
		t.Errorf("preset mci must not write fake-ttl/sessions/conns:\n%s", out)
	}
	if strings.Contains(out, "governor:") {
		t.Errorf("a pool carrier must not get the governor key:\n%s", out)
	}

	// rst-fast: sessions+conns only when not reverse, on a pool carrier
	out = apply(t, "mode: client\ncarrier: wss\n", "rst-fast")
	for _, w := range []string{"fake-sni: www.cloudflare.com", "fake-mode: rst", "pool-rotate: 30m", "sessions: 4", "conns: 4"} {
		if !strings.Contains(out, w) {
			t.Errorf("rst-fast missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "ech:") {
		t.Errorf("rst-fast must unset ech, not write it:\n%s", out)
	}

	// rst-fast on a reverse Kharej pool config: sessions skipped (the server dials one pool)
	body := "mode: server\ncarrier: wss\nreverse: true\n"
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ApplyPreset("p", "rst-fast") {
		t.Fatal("reverse rst-fast failed")
	}
	out = readFile(t, filepath.Join(dir, "p.yml"))
	if strings.Contains(out, "sessions:") {
		t.Errorf("reverse rst-fast must skip sessions:\n%s", out)
	}

	// irancell / blackout / conservative: their exact fake-sni/mode/rotate trios
	out = apply(t, "mode: client\ncarrier: wss\n", "irancell")
	if !strings.Contains(out, "fake-sni: irancell.ir") || !strings.Contains(out, "fake-mode: seq") ||
		!strings.Contains(out, "pool-rotate: 20m") || !strings.Contains(out, "pool-rotate-bytes: 300MB") {
		t.Errorf("irancell keys wrong:\n%s", out)
	}
	out = apply(t, "mode: client\ncarrier: wss\n", "blackout")
	if !strings.Contains(out, "fake-sni: mci.ir") || !strings.Contains(out, "fake-mode: rst") ||
		!strings.Contains(out, "pool-rotate: 90s") || !strings.Contains(out, "pool-rotate-bytes: 100MB") {
		t.Errorf("blackout keys wrong:\n%s", out)
	}
	out = apply(t, "mode: client\ncarrier: wss\n", "conservative")
	if !strings.Contains(out, "fake-sni: mci.ir") || !strings.Contains(out, "fake-mode: seq") ||
		!strings.Contains(out, "pool-rotate: 4h") || !strings.Contains(out, "pool-rotate-bytes: 4GB") ||
		!strings.Contains(out, "ech: auto") {
		t.Errorf("conservative keys wrong:\n%s", out)
	}

	// off clears everything that is set
	out = apply(t, "mode: client\ncarrier: wss\nfake-sni: mci.ir\nfake-mode: rst\nfake-ttl: 4\npool-rotate: 90s\npool-rotate-bytes: 100MB\nech: ladder\n", "off")
	for _, w := range []string{"fake-sni:", "fake-mode:", "fake-ttl:", "pool-rotate:", "pool-rotate-bytes:", "ech:"} {
		if strings.Contains(out, w) {
			t.Errorf("off left %q behind:\n%s", w, out)
		}
	}

	// icmp carrier: only the governor moves (the fake keys are left alone, like the bash)
	out = apply(t, "mode: client\ncarrier: icmp\nfake-sni: mci.ir\n", "mci")
	if !strings.Contains(out, "governor: true") || strings.Contains(out, "pool-rotate:") {
		t.Errorf("icmp preset must touch only the governor:\n%s", out)
	}
}

func TestApplyPresetRefusals(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	oldVer, oldRestart := binVerOKFn, restartFn
	binVerOKFn = func(string) bool { return true }
	restartFn = func(string) error { return nil }
	defer func() { binVerOKFn, restartFn = oldVer, oldRestart }()

	w := func(body string) {
		if err := os.WriteFile(filepath.Join(P.Conf, "p.yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a server (non-reverse) config: presets run on the dialer
	w("mode: server\ncarrier: wss\n")
	if ApplyPreset("p", "mci") {
		t.Error("Kharej pool config must be refused")
	}
	// a reverse Iran pool config: refused, the listener runs there
	w("mode: client\ncarrier: wss\nreverse: true\n")
	if ApplyPreset("p", "mci") {
		t.Error("reverse Iran config must be refused")
	}
	// raw carriers carry no anti-censorship layer
	w("mode: client\ncarrier: gre\n")
	if ApplyPreset("p", "mci") {
		t.Error("gre must be refused")
	}
	// an unknown preset name
	w("mode: client\ncarrier: wss\n")
	if ApplyPreset("p", "nope") {
		t.Error("unknown preset must fail")
	}
	// an old binary
	binVerOKFn = func(string) bool { return false }
	defer func() { binVerOKFn = func(string) bool { return true } }()
	w("mode: client\ncarrier: wss\n")
	if ApplyPreset("p", "mci") {
		t.Error("an old binary must be refused")
	}
}

func TestApplyPresetRestartFailure(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	oldVer, oldRestart := binVerOKFn, restartFn
	binVerOKFn = func(string) bool { return true }
	restartFn = func(string) error { return errors.New("systemctl down") }
	defer func() { binVerOKFn, restartFn = oldVer, oldRestart }()
	if err := os.WriteFile(filepath.Join(P.Conf, "p.yml"), []byte("mode: client\ncarrier: wss\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ApplyPreset("p", "mci") {
		t.Error("a failed restart must report failure")
	}
	// the keys are still written: the restart is the last step, like the bash
	out := readFile(t, filepath.Join(P.Conf, "p.yml"))
	if !strings.Contains(out, "fake-sni: mci.ir") {
		t.Errorf("keys must survive a failed restart:\n%s", out)
	}
}

func TestApplyPresetNoChange(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	oldVer, oldRestart := binVerOKFn, restartFn
	binVerOKFn = func(string) bool { return true }
	called := false
	restartFn = func(string) error { called = true; return nil }
	defer func() { binVerOKFn, restartFn = oldVer, oldRestart }()
	// the only true no-change case, exactly as in the bash: preset off on a
	// clean pool config (an explicit preset like mci always rewrites its keys
	// and restarts, even when they already match)
	if err := os.WriteFile(filepath.Join(P.Conf, "p.yml"), []byte("mode: client\ncarrier: wss\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ApplyPreset("p", "off") {
		t.Fatal("off on a clean config must succeed")
	}
	if called {
		t.Error("a no-change preset must not restart")
	}
	// and a matching explicit preset DOES restart (the bash sets every key again)
	called = false
	if !ApplyPreset("p", "mci") {
		t.Fatal("mci must succeed")
	}
	if !called {
		t.Error("an explicit preset must restart even when the keys already match")
	}
}

func TestDetectPreset(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	cases := []struct {
		body, want string
	}{
		{"mode: client\ncarrier: icmp\ngovernor: true\n", "Governor Active (ICMP Pacer)"},
		{"mode: client\ncarrier: icmp\n", "none / disabled"},
		{"mode: client\ncarrier: wss\nfake-sni: www.cloudflare.com\nfake-mode: rst\n", "Cloudflare (field-tested)"},
		{"mode: client\ncarrier: wss\nfake-sni: www.cloudflare.com\nfake-mode: rst\npool-rotate: 30m\n", "rst-fast"},
		{"mode: client\ncarrier: wss\nfake-sni: mci.ir\nfake-mode: rst\npool-rotate: 30m\n", "Iran Whitelist - MCI"},
		{"mode: client\ncarrier: wss\nfake-sni: irancell.ir\nfake-mode: seq\npool-rotate: 20m\n", "Iran Whitelist - Irancell/Mokhaberat"},
		{"mode: client\ncarrier: wss\nfake-sni: mci.ir\nfake-mode: rst\npool-rotate: 90s\n", "Emergency Blackout Mode"},
		{"mode: client\ncarrier: wss\nfake-sni: mci.ir\nfake-mode: seq\npool-rotate: 4h\n", "Conservative / Low-Churn"},
		{"mode: client\ncarrier: wss\nfake-sni: something.else\n", "Custom"},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, "d.yml"), []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := StripANSI(DetectPreset("d")); got != c.want {
			t.Errorf("DetectPreset(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}
