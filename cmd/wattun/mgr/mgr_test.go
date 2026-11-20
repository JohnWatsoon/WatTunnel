package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScreenRegistryDispatch(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	saveRegistry(t)
	calls := []string{}
	Register("status_all", func(args ...string) int { calls = append(calls, "status_all"); return 0 })
	Register("restart_all", func(args ...string) int { calls = append(calls, "restart_all"); return 0 })
	Register("show_token", func(args ...string) int { calls = append(calls, "show_token:"+args[0]); return 0 })
	Register("preset_cmd", func(args ...string) int { calls = append(calls, "preset_cmd:"+args[0]+":"+args[1]); return 0 })
	Register("mgr_lock", func(args ...string) int { calls = append(calls, "mgr_lock"); return 0 })
	Register("heal", func(args ...string) int { calls = append(calls, "heal"); return 0 })

	if rc := runCommand("status", nil); rc != 0 {
		t.Errorf("status rc = %d", rc)
	}
	if rc := runCommand("status-all", nil); rc != 0 {
		t.Errorf("status-all rc = %d", rc)
	}
	if rc := runCommand("restart-all", nil); rc != 0 {
		t.Errorf("restart-all rc = %d", rc)
	}
	if rc := runCommand("heal", nil); rc != 0 {
		t.Errorf("heal rc = %d", rc)
	}
	// a held lock (non-zero mgr_lock, the bash `mgr_lock || return 0`) skips the flow
	Register("mgr_lock", func(args ...string) int { return 1 })
	Register("heal", func(args ...string) int { calls = append(calls, "heal-ran-anyway"); return 0 })
	if rc := runCommand("heal", nil); rc != 0 {
		t.Errorf("heal with a held lock rc = %d", rc)
	}
	if contains(calls, "heal-ran-anyway") {
		t.Error("heal ran while the lock was held")
	}
	Register("mgr_lock", func(args ...string) int { calls = append(calls, "mgr_lock"); return 0 })
	// a tunnel command gates on the config file first
	if rc := runCommand("token", []string{"token", "ghost"}); rc == 0 {
		t.Error("token ghost must fail without a config")
	}
	if err := os.WriteFile(filepath.Join(P.Conf, "real.yml"), []byte("mode: client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := runCommand("token", []string{"token", "real"}); rc != 0 {
		t.Errorf("token real rc = %d", rc)
	}
	// positional args skip flags, like NI_POS
	if rc := runCommand("preset", []string{"preset", "--extended", "real", "mci"}); rc != 0 {
		t.Errorf("preset rc = %d", rc)
	}
	if !contains(calls, "status_all") || !contains(calls, "show_token:real") ||
		!contains(calls, "mgr_lock") || !contains(calls, "heal") || !contains(calls, "preset_cmd:real:mci") {
		t.Errorf("dispatch trace wrong: %v", calls)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestUnregisteredScreen(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	saveRegistry(t)
	screenRegistry = map[string]func(args ...string) int{}
	out := capture(t, func() {
		if rc := runCommand("monitor", nil); rc != 1 {
			t.Errorf("monitor rc = %d", rc)
		}
	})
	if !strings.Contains(out, "not available in this build") {
		t.Errorf("stub message missing: %q", out)
	}
}

func TestNeedTunnel(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	if NeedTunnel("ghost") {
		t.Error("NeedTunnel(ghost) must fail")
	}
	if err := os.WriteFile(filepath.Join(P.Conf, "real.yml"), []byte("mode: client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !NeedTunnel("real") {
		t.Error("NeedTunnel(real) must pass")
	}
}

func TestPosSkipsFlags(t *testing.T) {
	args := []string{"preset", "--extended", "real", "mci"}
	if posNI(args, 0) != "real" || posNI(args, 1) != "mci" || posNI(args, 2) != "" {
		t.Errorf("posNI wrong: %q %q %q", posNI(args, 0), posNI(args, 1), posNI(args, 2))
	}
	args2 := []string{"boost", "--undo"}
	if posNI(args2, 0) != "" {
		t.Errorf("flag leaked as positional: %q", posNI(args2, 0))
	}
}

func TestInitPaths(t *testing.T) {
	t.Setenv("WAT_PREFIX", "wattest")
	t.Setenv("WAT_CONF", "")
	t.Setenv("WAT_BIN", "")
	t.Setenv("WAT_RUN", "")
	if err := InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	if P.Conf != "/etc/wattest" || P.Run != "/run/wattest" || P.Bin != "/opt/wattest/wattun" {
		t.Errorf("sandbox paths wrong: %+v", P)
	}
	if !P.Sandbox || P.MConf != "/etc/wattest/.manager.conf" || P.Heal != "wattest-heal" {
		t.Errorf("sandbox fields wrong: %+v", P)
	}
	if P.Self == "" || !strings.Contains(P.Self, "WAT_PREFIX=wattest") {
		t.Errorf("Self = %q", P.Self)
	}
	t.Setenv("WAT_PREFIX", "wattun")
	if err := InitPaths(); err != nil {
		t.Fatal(err)
	}
	if P.Conf != "/etc/wattun" || P.Bin != "/usr/local/bin/wattun" || P.Sandbox {
		t.Errorf("production paths wrong: %+v", P)
	}
	// WAT_CONF still overrides a single path
	t.Setenv("WAT_CONF", "/tmp/watconf")
	if err := InitPaths(); err != nil {
		t.Fatal(err)
	}
	if P.Conf != "/tmp/watconf" {
		t.Errorf("WAT_CONF override lost: %q", P.Conf)
	}
	t.Setenv("WAT_CONF", "")
	// a bad prefix is refused
	t.Setenv("WAT_PREFIX", "-bad")
	if err := InitPaths(); err == nil {
		t.Error("bad prefix accepted")
	}
	t.Setenv("WAT_PREFIX", "wattun")
}

func TestUsageTextVerbatimShape(t *testing.T) {
	// the usage block carries the owner's exact command list; spot-check the
	// lines that must never drift
	for _, want := range []string{
		"Usage: $SELF [command]",
		"  preset NAME [PRESET]  apply built-in anti-censorship preset",
		"  blackout NAME [SNI|PRESET] turn on resilience",
		"  matrix NAME",
		"  heal                  restart Iran tunnels whose link is down (used by the timer)",
		"Sandbox: WAT_PREFIX=wattest wattun-manager",
	} {
		if !strings.Contains(usageText, want) {
			t.Errorf("usage lost %q", want)
		}
	}
}

func TestUsagePrintsSelf(t *testing.T) {
	InitColor(false, 8)
	setTempConf(t)
	out := capture(t, func() { usage() })
	if !strings.Contains(out, "Usage: wattun [command]") {
		t.Errorf("$SELF not substituted: %q", out[:80])
	}
}

// saveRegistry restores the real route table after a test swaps entries.
func saveRegistry(t *testing.T) {
	t.Helper()
	saved := map[string]func(args ...string) int{}
	for k, v := range screenRegistry {
		saved[k] = v
	}
	t.Cleanup(func() { screenRegistry = saved })
}
