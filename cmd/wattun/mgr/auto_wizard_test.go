package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 2 (PLAN-go-manager): wizardKharejAuto end to end against a temp conf —
// stubbed ports/IP/systemd/firewall; the yml, the key and a parseable auto
// token with a d= and an r= plan come out (bash wizard_kharej_auto 4056).
func TestWizardKharejAutoEndToEnd(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldP, oldSpawn, oldFW := P, envSystemdRun, envFWOpen
	P.Conf, P.Run = dir, dir
	oldVer := engineVer
	engineVer = func() string { return "9.9.9" }
	next := 30000
	envRandOpenPortSaved := envRandOpenPort
	envRandOpenPort = func(string, []string) (int, error) { next++; return next, nil }
	oldIP := envPublicIP
	envPublicIP = func() string { return "203.0.113.10" }
	envSystemdRun = func(unit string, maxSec int, args ...string) error { return nil }
	var fw []string
	envFWOpen = func(specs ...string) { fw = append(fw, specs...) }
	defer func() {
		P, envSystemdRun, envFWOpen, envPublicIP, envRandOpenPort, engineVer = oldP, oldSpawn, oldFW, oldIP, envRandOpenPortSaved, oldVer
	}()

	niReset()
	NI.Name, NI.Ports = "ci1", "18999"
	defer niReset()
	out := capture(t, func() {})
	r := wizardKharejAuto("ci1", autoWizardOpts{Name: NI.Name, Addr: "127.0.0.1", Ports: NI.Ports})
	if r.Error != nil {
		t.Fatalf("wizardKharejAuto: %v\n%s", r.Error, out)
	}
	if r.Name != "ci1" {
		t.Errorf("name = %q", r.Name)
	}
	if len(r.Units) == 0 || r.Units[0] != "ci1" {
		t.Errorf("units = %v", r.Units)
	}

	ymlB, err := os.ReadFile(filepath.Join(dir, "ci1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(ymlB)
	for _, w := range []string{
		"# WatTunnel - Kharej (server), auto: every carrier at once. Created by wattun-manager.\n",
		"mode: server\n",
		"carrier: icmp+",
		"listen-udp: \":",
		"listen-tcp: \":",
		"path: /api/",
		"metrics: 127.0.0.1:",
		"ports:\n  - \"18999\"\n",
	} {
		if !strings.Contains(yml, w) {
			t.Errorf("auto kharej yml missing %q;\ngot:\n%s", w, yml)
		}
	}

	key, err := os.ReadFile(filepath.Join(dir, "ci1.key"))
	if err != nil {
		t.Fatal(err)
	}
	k := strings.TrimSpace(string(key))
	if len(k) != 40 {
		t.Errorf("key length = %d (want the 40-char random form): %q", len(k), k)
	}
	if strings.Contains(k, "wattun-devkey") {
		t.Errorf("key fell back to the dev constant: %q", k)
	}

	tokB, err := os.ReadFile(filepath.Join(dir, "ci1.token"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ReadToken(strings.TrimSpace(string(tokB)))
	if err != nil {
		t.Fatalf("token does not parse: %v (%q)", err, strings.TrimSpace(string(tokB)))
	}
	if tok.Carrier != "auto" {
		t.Errorf("carrier = %q", tok.Carrier)
	}
	if !strings.Contains(tok.Auto, "d=") || !strings.Contains(tok.Auto, "r=") {
		t.Errorf("plan = %q (want d= and r=)", tok.Auto)
	}
	if !strings.Contains(tok.Auto, ";r=") {
		t.Errorf("plan = %q (want a separate r= part)", tok.Auto)
	}
	if tok.Peer != "127.0.0.1" {
		t.Errorf("peer = %q", tok.Peer)
	}
	if tok.Ports != "18999" {
		t.Errorf("allow = %q", tok.Ports)
	}
	if !strings.Contains(r.Token, "wat1:") {
		t.Errorf("result token = %q", r.Token)
	}
	if len(fw) == 0 {
		t.Errorf("no firewall rules opened: %v", fw)
	}
	// 4.0.2: ptcp and spray are planned as hidden helpers (the engine refuses to bond them), never main legs
	for _, c := range []string{"ptcp", "spray"} {
		if !strings.Contains(tok.Auto, ","+c+":") {
			t.Errorf("plan = %q, want a %s entry", tok.Auto, c)
		}
		if strings.Contains(yml, "+"+c) {
			t.Errorf("main yml bonds %s: %s", c, yml)
		}
		if _, err := os.Stat(filepath.Join(dir, "ci1-e-"+c+".yml")); err != nil {
			t.Errorf("no %s helper: %v", c, err)
		}
	}
	var tcp, rng bool
	for _, f := range fw {
		tcp = tcp || strings.HasSuffix(f, "/tcp")
		rng = rng || strings.ContainsAny(strings.TrimSuffix(f, "/udp"), ":-")
	}
	if !tcp || !rng {
		t.Errorf("firewall %v: want a TCP port for ptcp and a UDP range for spray", fw)
	}
}

// 4.0.2: the last test's rows and the carriers in use survive for a switch without a new test.
func TestAutoResultsRoundTrip(t *testing.T) {
	oldP := P
	P.Conf = t.TempDir()
	defer func() { P = oldP; atDone, atPicks = nil, nil }()
	if _, _, rows := AutoResults("x"); rows != nil {
		t.Fatalf("rows before a test = %v", rows)
	}
	atDone = []string{"ok|tls reverse|22.6|16.6|170", "ok|l2tpv3 (shape only)|16.3|6.8|97", "fail|grpc :8443|no link"}
	atPicks = []string{"tls reverse", "l2tpv3 (shape only)"}
	atSaveResults("x")
	atSaveUse("x")
	at, _, rows := AutoResults("x")
	if at == 0 || strings.Join(rows, "|") != strings.Join(atDone, "|") {
		t.Errorf("at %d rows %q", at, rows)
	}
	if u := AutoInUse("x"); strings.Join(u, ",") != "tls reverse,l2tpv3 (shape only)" {
		t.Errorf("in use = %q", u)
	}
}

func TestSprayBaseSkipsUsed(t *testing.T) {
	old := envRandOpenPort
	defer func() { envRandOpenPort = old }()
	tries := []int{40000, 64800, 42000}
	envRandOpenPort = func(string, []string) (int, error) { q := tries[0]; tries = tries[1:]; return q, nil }
	if q := sprayBase([]string{"40500"}); q != 42000 { // 40000 covers 40500, 64800 overflows
		t.Errorf("sprayBase = %d, want 42000", q)
	}
}
