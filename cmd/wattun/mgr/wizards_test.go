package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeProc struct{}

func (fakeProc) Kill() error { return nil }

// Task 1 (PLAN-go-manager): an auto token runs the test front-end and the Iran
// wizard writes the config the bash one writes for the chosen carrier —
// .yml, .key and the .auto copy of the token (bash write_client + AUTO_TOKEN).
// Everything the probes touch is stubbed; only udp is let through so "best"
// picks it deterministically.
func TestWizardIranAutoToken(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldP, oldVer, oldNI, oldNon, oldSpawn, oldFetch, oldSpeed, oldSleep, oldWait := P, engineVer, NI, NonInteractive,
		envSpawnClient, p1FetchStats, p1Speedtest, timeSleep, p2WaitLink
	P.Conf, P.Run = dir, dir
	engineVer = func() string { return "9.9.9" }
	NonInteractive = true
	envSpawnClient = func(args []string, logFile string) (clientProc, error) {
		for i, a := range args {
			if a == "-carrier" && i+1 < len(args) && args[i+1] == "udp" {
				return fakeProc{}, nil
			}
		}
		return nil, //nolint:staticcheck // the probe reports the failure itself
			os.ErrPermission
	}
	p1FetchStats = func(addr string) string { return `{"alive":true,"rtt_ms":21.5}` }
	p1Speedtest = func(int, string) (bool, float64) { return true, 25 }
	timeSleep = func(int) {}
	p2WaitLink = func(string, int) bool { return true }
	tok := MakeToken("auto", "203.0.113.10", "kk", "/api/ab", "", "", "443,8443", "", "d=udp:4443,tcp:4443;r=tcp:24431")
	niReset()
	NI.Token, NI.Name, NI.Map, NI.Test, NI.Pick = tok, "iran-auto", "8443:8443/tcp", "normal", "best"
	defer func() {
		P, engineVer, NI, NonInteractive = oldP, oldVer, oldNI, oldNon
		envSpawnClient, p1FetchStats, p1Speedtest, timeSleep, p2WaitLink = oldSpawn, oldFetch, oldSpeed, oldSleep, oldWait
	}()

	var ok bool
	out := capture(t, func() { ok = wizardIran() })
	if !ok {
		t.Fatalf("wizardIran failed:\n%s", out)
	}
	if !strings.Contains(out, "LINK=up") || !strings.Contains(out, "TUNNEL=iran-auto") {
		t.Errorf("NI epilogue missing:\n%s", out)
	}
	ymlB, err := os.ReadFile(filepath.Join(dir, "iran-auto.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(ymlB)
	for _, w := range []string{
		"# WatTunnel - Iran (client). Created by wattun-manager.\n",
		"mode: client\n",
		"carrier: udp\n",
		"peer: 203.0.113.10:4443\n",
		"key-file: " + dir + "/iran-auto.key\n",
		"metrics: 127.0.0.1:",
		"ports:\n  - 8443\n", // --map replaced the token prefill (bash port_editor NI; 8443→8443 collapses to the port)
	} {
		if !strings.Contains(yml, w) {
			t.Errorf("iran auto yml missing %q;\ngot:\n%s", w, yml)
		}
	}
	for _, bad := range []string{"path:", "sni:", "reverse:", "listen:"} {
		if strings.Contains(yml, bad) {
			t.Errorf("plain udp auto yml must not contain %q:\n%s", bad, yml)
		}
	}
	key, _ := os.ReadFile(filepath.Join(dir, "iran-auto.key"))
	if strings.TrimSpace(string(key)) != "kk" {
		t.Errorf("key = %q", string(key))
	}
	autoB, err := os.ReadFile(filepath.Join(dir, "iran-auto.auto"))
	if err != nil || strings.TrimSpace(string(autoB)) != tok {
		t.Errorf(".auto = %q err=%v", string(autoB), err)
	}
}

// A reverse auto choice writes the listen line and keeps the carrier port off
// the published rows (bash wizard_iran 3431-3462). Only the reverse tcp leg is
// let through.
func TestWizardIranAutoTokenReverse(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldP, oldVer, oldNI_, oldSpawn, oldFetch, oldSpeed, oldSleep, oldWait := P, engineVer, NonInteractive,
		envSpawnClient, p1FetchStats, p1Speedtest, timeSleep, p2WaitLink
	P.Conf, P.Run = dir, dir
	engineVer = func() string { return "9.9.9" }
	NonInteractive = true
	envSpawnClient = func(args []string, logFile string) (clientProc, error) {
		for i, a := range args {
			if a == "-carrier" && i+1 < len(args) && args[i+1] == "tcp" {
				for j, b := range args {
					if b == "-reverse" || (b == "-carrier" && j > i) {
						return fakeProc{}, nil
					}
				}
			}
		}
		return nil, os.ErrPermission //nolint:staticcheck // the probe reports the failure itself
	}
	p1FetchStats = func(addr string) string { return `{"alive":true,"rtt_ms":21.5}` }
	p1Speedtest = func(int, string) (bool, float64) { return true, 25 }
	timeSleep = func(int) {}
	p2WaitLink = func(string, int) bool { return true }
	tok := MakeToken("auto", "203.0.113.10", "kk", "/api/ab", "", "", "443", "", "d=udp:4443;r=tcp:24431")
	niReset()
	NI.Token, NI.Name, NI.Map, NI.Pick = tok, "iran-rev", "443:443/tcp", "best"
	defer func() {
		P, engineVer, NonInteractive = oldP, oldVer, oldNI_
		envSpawnClient, p1FetchStats, p1Speedtest, timeSleep, p2WaitLink = oldSpawn, oldFetch, oldSpeed, oldSleep, oldWait
	}()

	var ok bool
	out := capture(t, func() { ok = wizardIran() })
	if !ok {
		t.Fatalf("wizardIran failed:\n%s", out)
	}
	ymlB, err := os.ReadFile(filepath.Join(dir, "iran-rev.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(ymlB)
	for _, w := range []string{
		"carrier: tcp\n",
		"peer: 203.0.113.10:24431\n",
		"reverse: true\n",
		"listen: \":24431\"\n",
	} {
		if !strings.Contains(yml, w) {
			t.Errorf("reverse auto yml missing %q;\ngot:\n%s", w, yml)
		}
	}
}
