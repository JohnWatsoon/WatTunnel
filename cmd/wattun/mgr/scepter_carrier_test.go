package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- arg builders + parsers (the wire shapes, pinned against the engine's
// strictly-typed arg readers) ----

func TestScepterTestOpenArgs(t *testing.T) {
	args := scepterTestOpenArgs("udp", 45, "mgr1")
	if args["carrier"] != "udp" || args["id"] != "mgr1" || args["ttl"] != 45 {
		t.Errorf("args = %v", args)
	}
	// ttl 0 stays absent: the engine defaults to 300 (probeTTLClamp)
	args = scepterTestOpenArgs("tcp", 0, "mgr2")
	if _, present := args["ttl"]; present {
		t.Errorf("ttl 0 must stay absent: %v", args)
	}
	if args["carrier"] != "tcp" || args["id"] != "mgr2" {
		t.Errorf("args = %v", args)
	}
}

func TestScepterParseProbe(t *testing.T) {
	pr, err := scepterParseProbe(map[string]any{
		"id": "probe-123", "carrier": "wss", "port": float64(20501), "key": "k1",
		"ttl": float64(120), "path": "/wat", "metrics": "127.0.0.1:19700",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pr.ID != "probe-123" || pr.Carrier != "wss" || pr.Port != 20501 || pr.Key != "k1" ||
		pr.TTL != 120 || pr.Path != "/wat" || pr.Metrics != "127.0.0.1:19700" {
		t.Errorf("probe = %+v", pr)
	}
	// path/metrics are shape-dependent and may be absent
	pr, err = scepterParseProbe(map[string]any{
		"id": "probe-1", "carrier": "udp", "port": float64(20500), "key": "k", "ttl": float64(300),
	})
	if err != nil || pr.Path != "" || pr.Metrics != "" {
		t.Errorf("bare probe = %+v err=%v", pr, err)
	}
	// a missing id, port or key must never look dialable
	for _, c := range []struct {
		name string
		p    map[string]any
	}{
		{"no id", map[string]any{"port": float64(1), "key": "k"}},
		{"no port", map[string]any{"id": "x", "key": "k"}},
		{"no key", map[string]any{"id": "x", "port": float64(1)}},
		{"nil", nil},
	} {
		if _, err := scepterParseProbe(c.p); err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}
}

func TestScepterCarrierChangeArgs(t *testing.T) {
	args := scepterCarrierChangeArgs("web", "tcp", map[string]string{"sni": "a.ir", "listen": ":8443"}, 41, "mgr1")
	if args["name"] != "web" || args["carrier"] != "tcp" || args["base_seq"] != uint64(41) ||
		args["ttl_s"] != scepterTTLDefault || args["id"] != "mgr1" {
		t.Errorf("args = %v", args)
	}
	p, ok := args["params"].(map[string]string)
	if !ok || p["sni"] != "a.ir" || p["listen"] != ":8443" {
		t.Errorf("params = %v", args["params"])
	}
	// the carrier never rides inside params — the engine refuses the duplicate
	for k := range p {
		if k == "carrier" {
			t.Error("carrier must not be inside params")
		}
	}
	// empty params stay absent (argStringMap treats absent as empty)
	args = scepterCarrierChangeArgs("web", "udp", nil, 0, "mgr2")
	if _, present := args["params"]; present {
		t.Errorf("empty params must stay absent: %v", args)
	}
}

func TestScepterAutoTestArgs(t *testing.T) {
	args := scepterAutoTestArgs("tls", "mgr1")
	if args["mode"] != "tls" || args["id"] != "mgr1" {
		t.Errorf("args = %v", args)
	}
	args = scepterAutoTestArgs("", "mgr2")
	if _, present := args["mode"]; present {
		t.Errorf("mode \"\" must stay absent (the engine's plain default): %v", args)
	}
}

func TestScepterAutoApplyArgs(t *testing.T) {
	args := scepterAutoApplyArgs("web", 2, 7, "mgr1")
	if args["name"] != "web" || args["row"] != 2 || args["base_seq"] != uint64(7) ||
		args["ttl_s"] != scepterTTLDefault || args["id"] != "mgr1" {
		t.Errorf("args = %v", args)
	}
}

func TestScepterParseAutoRows(t *testing.T) {
	tab, err := scepterParseAutoRows(map[string]any{
		"run": "at-9", "mode": "plain", "done": true, "ok": float64(2),
		"rows": []any{
			map[string]any{"rank": float64(1), "carrier": "udp", "port": float64(20501), "ok": true, "down_mbps": 8.4},
			map[string]any{"rank": float64(2), "carrier": "tcp", "port": float64(20502), "ok": true, "down_mbps": 3.1},
			map[string]any{"rank": float64(3), "carrier": "ws", "port": float64(20503), "ok": false, "why": "no link in 15 s"},
		},
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tab.Run != "at-9" || tab.Mode != "plain" || !tab.Done || tab.OK != 2 || len(tab.Rows) != 3 {
		t.Fatalf("table = %+v", tab)
	}
	if tab.Rows[0].Carrier != "udp" || tab.Rows[0].Port != 20501 || !tab.Rows[0].OK || tab.Rows[0].DownMbps != 8.4 {
		t.Errorf("row 1 = %+v", tab.Rows[0])
	}
	if tab.Rows[2].OK || tab.Rows[2].Why != "no link in 15 s" {
		t.Errorf("failure row = %+v", tab.Rows[2])
	}
	// an empty rows list is a valid "nothing measured yet"; a missing list is not
	tab, err = scepterParseAutoRows(map[string]any{"run": "at-1", "done": false, "rows": []any{}})
	if err != nil || len(tab.Rows) != 0 || tab.Done {
		t.Errorf("empty table = %+v err=%v", tab, err)
	}
	for _, c := range []struct {
		name string
		p    map[string]any
	}{
		{"nil", nil},
		{"no rows", map[string]any{"run": "at-1", "done": true}},
		{"rows not a list", map[string]any{"rows": "x"}},
	} {
		if _, err := scepterParseAutoRows(c.p); err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}
}

// ---- the local follow: yml rewrite, save/restore, restart + revert ----

func scepterCarrierTestConf(t *testing.T) string {
	t.Helper()
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	t.Cleanup(func() { P.Conf = old })
	return dir
}

func TestScepterApplyLocalCarrier(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	if err := scepterApplyLocalCarrier("ir", "wss", map[string]string{"sni": "a.ir", "path": "/x", "listen": ":8443"}, 8443); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg := mustRead(filepath.Join(dir, "ir.yml"))
	for _, want := range []string{"carrier: wss", "peer: 198.51.100.7:8443", "sni: a.ir", "path: /x"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("yml missing %q:\n%s", want, cfg)
		}
	}
	// listen is Kharej's bind — it must not become a local key
	if strings.Contains(cfg, "listen") {
		t.Errorf("listen leaked into the local yml:\n%s", cfg)
	}
	// a raw carrier answers no listen: the peer stays untouched
	if err := scepterApplyLocalCarrier("ir", "icmp", nil, 0); err != nil {
		t.Fatalf("apply icmp: %v", err)
	}
	cfg = mustRead(filepath.Join(dir, "ir.yml"))
	if !strings.Contains(cfg, "peer: 198.51.100.7:8443") || !strings.Contains(cfg, "carrier: icmp") {
		t.Errorf("icmp change moved the peer or lost the carrier:\n%s", cfg)
	}
}

func TestScepterSaveRestoreLocal(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	saved := scepterSaveLocal("ir", "carrier", "peer", "path", "sni")
	if err := scepterApplyLocalCarrier("ir", "tcp", map[string]string{"path": "/p"}, 8443); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := scepterRestoreLocal("ir", saved); err != nil {
		t.Fatalf("restore: %v", err)
	}
	cfg := mustRead(filepath.Join(dir, "ir.yml"))
	if !strings.Contains(cfg, "carrier: udp") || !strings.Contains(cfg, "peer: 198.51.100.7:4443") {
		t.Errorf("values not restored:\n%s", cfg)
	}
	// path was absent before the change: the restore unsets it, never empties it
	if strings.Contains(cfg, "path") {
		t.Errorf("formerly-absent key must be unset, not emptied:\n%s", cfg)
	}
}

// scepterStubLocalMachine stubs the restart/link seams and counts the restarts.
func scepterStubLocalMachine(t *testing.T, alive bool) *int {
	t.Helper()
	calls := 0
	oldRestart, oldWait := scepterRestartTunnel, scepterWaitAlive
	scepterRestartTunnel = func(string) error { calls++; return nil }
	scepterWaitAlive = func(string, int) bool { return alive }
	t.Cleanup(func() { scepterRestartTunnel, scepterWaitAlive = oldRestart, oldWait })
	return &calls
}

func TestScepterFollowLocalOK(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	calls := scepterStubLocalMachine(t, true)
	out := capture(t, func() {
		if !scepterFollowLocal("ir", "ir", "tcp", map[string]string{"path": "/p"}, 8443) {
			t.Error("follow-local reported failure")
		}
	})
	cfg := mustRead(filepath.Join(dir, "ir.yml"))
	for _, want := range []string{"carrier: tcp", "peer: 198.51.100.7:8443", "path: /p"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("yml missing %q:\n%s", want, cfg)
		}
	}
	if !strings.Contains(out, "Link is up") {
		t.Errorf("verdict missing:\n%s", out)
	}
	if *calls != 1 {
		t.Errorf("restarts = %d, want 1", *calls)
	}
}

func TestScepterFollowLocalRevert(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	calls := scepterStubLocalMachine(t, false)
	// interactive, so the verdict prints on Stdout (Err goes to stderr only in
	// unattended mode) and the revert question takes the fed y
	NonInteractive = false
	defer feed("y")() // the revert question: yes
	out := capture(t, func() {
		if scepterFollowLocal("ir", "ir", "tcp", map[string]string{"path": "/p"}, 8443) {
			t.Error("follow-local must report the dead link")
		}
	})
	// the revert restores the previous values and restarts once more
	cfg := mustRead(filepath.Join(dir, "ir.yml"))
	if !strings.Contains(cfg, "carrier: udp") || !strings.Contains(cfg, "peer: 198.51.100.7:4443") ||
		strings.Contains(cfg, "path") {
		t.Errorf("revert did not restore the previous yml:\n%s", cfg)
	}
	for _, want := range []string{"No link within 15 s", "Revert", "Reverted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "its carrier back") {
		t.Errorf("the remote revert contract must be surfaced:\n%s", out)
	}
	if *calls != 2 {
		t.Errorf("restarts = %d, want 2 (change + revert)", *calls)
	}
}

func TestScepterFollowLocalNoLocal(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	// only a Kharej config: no Iran tunnel here to follow with
	writeTestYml(t, dir, "kh", "mode: server\ncarrier: udp\n")
	old := NonInteractive
	NonInteractive = true
	defer func() { NonInteractive = old }()
	out := capture(t, func() {
		if !scepterFollowLocal("ir", "web", "tcp", nil, 8443) {
			t.Error("a skipped local follow is not a failure")
		}
	})
	if !strings.Contains(out, "No local tunnel changed") || !strings.Contains(out, "is on tcp") {
		t.Errorf("the skip must say what happened and what Kharej holds:\n%s", out)
	}
}

// TestScepterFollowLocalPeerMatch pins the round-2 finding: a same-named local
// tunnel that dials a DIFFERENT Kharej must not be rewritten by the follow —
// two paired Kharej can both have a remote "web", and rewriting the wrong one
// redirects it to the wrong host. The follow must fall to the pick screen with
// the pair's host stated, exclude the wrong-peer tunnel from the candidates,
// and rewrite only the tunnel that actually dials the pair's host.
func TestScepterFollowLocalPeerMatch(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "pair", "mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\npairing: true\n")
	writeTestYml(t, dir, "web", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4000\n")
	writeTestYml(t, dir, "good", "mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\n")
	calls := scepterStubLocalMachine(t, true)
	NonInteractive = false
	defer feed("1")() // the pick screen lists good+pair only (web dials another host): 1 picks good
	out := capture(t, func() {
		if !scepterFollowLocal("pair", "web", "tcp", map[string]string{"path": "/p"}, 8443) {
			t.Error("follow-local reported failure")
		}
	})
	good := mustRead(filepath.Join(dir, "good.yml"))
	if !strings.Contains(good, "carrier: tcp") || !strings.Contains(good, "peer: 198.51.100.9:8443") {
		t.Errorf("the tunnel that dials the pair's host did not follow:\n%s", good)
	}
	web := mustRead(filepath.Join(dir, "web.yml"))
	if !strings.Contains(web, "carrier: udp") || !strings.Contains(web, "peer: 198.51.100.7:4000") {
		t.Errorf("the wrong-peer same-name tunnel was rewritten:\n%s", web)
	}
	if !strings.Contains(out, "198.51.100.9") {
		t.Errorf("the pick screen must state the pair's host:\n%s", out)
	}
	if *calls != 1 {
		t.Errorf("restarts = %d, want 1", *calls)
	}
}

// ---- the probe screen ----

func TestScepterProbeScreenSmoke(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\npairing: true\n")
	open := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"id": "probe-77", "carrier": "udp", "port": float64(20501), "key": "pk", "ttl": float64(300),
	}}
	closing := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"id": "probe-77", "closed": true}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"test.open":  {{r: open}},
		"test.close": {{r: closing}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	oldMeasure := scepterProbeMeasure
	scepterProbeMeasure = func(string, scepterProbeInfo) (float64, bool, string) { return 12.5, true, "" }
	defer func() { scepterProbeMeasure = oldMeasure }()
	NonInteractive = false
	defer feed("1\n")() // pick udp (quick pick 1), ttl default (empty line)
	out := capture(t, func() { scepterProbeTest("ir", cl, CapTunnel|CapCreate|CapManage) })
	// restyle pins (lane U4): the probe details moved into the Probe panel (ttl
	// its own KV row), and the rate renders through Rate() — the manager's one
	// unit system (1024-based): 12.5 decimal MB/s = 11.9 MB/s there
	for _, want := range []string{"probe-77", "20501", "300s", "11.9 MB/s", "Link up", "Probe closed"} {
		if !strings.Contains(out, want) {
			t.Errorf("probe screen missing %q:\n%s", want, out)
		}
	}
	// the measured probe is closed, not left to its ttl
	if len(cl.cmds["test.open"]) != 1 || len(cl.cmds["test.close"]) != 1 {
		t.Errorf("call pattern: %v", cl.cmds)
	}
	// the probe rides "probe", not "id" — the one-shot CLI lifts a top-level "id" as the command id
	if id, _ := cl.cmds["test.close"][0]["probe"].(string); id != "probe-77" {
		t.Errorf("test.close probe = %v", cl.cmds["test.close"][0]["probe"])
	}
}

func TestScepterProbeRateLimited(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\npairing: true\n")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"test.open": {{r: ScepterResult{Code: scepterCodeRate, Params: map[string]any{"resource": "probe"}}}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	NonInteractive = false
	defer feed("1\n")() // udp, ttl default
	out := capture(t, func() { scepterProbeTest("ir", cl, CapTunnel|CapCreate|CapManage) })
	if !strings.Contains(out, "code 4") || !strings.Contains(out, "wait a moment") {
		t.Errorf("the rate limit must surface with its hint:\n%s", out)
	}
	if len(cl.cmds["test.close"]) != 0 {
		t.Errorf("a refused test.open must not be followed by test.close")
	}
}

func TestScepterProbeNoPeer(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npairing: true\n")
	cl := &scriptClient{byCmd: map[string][]scriptAns{}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	NonInteractive = false
	out := capture(t, func() { scepterProbeTest("ir", cl, CapTunnel|CapCreate|CapManage) })
	if !strings.Contains(out, "No peer address") {
		t.Errorf("the missing peer must be refused before spending the rate budget:\n%s", out)
	}
	if len(cl.cmds["test.open"]) != 0 {
		t.Error("no probe may be opened without a peer to dial it from")
	}
}

func TestScepterProbeNeedsManage(t *testing.T) {
	scepterCarrierTestConf(t)
	cl := &scriptClient{byCmd: map[string][]scriptAns{}}
	out := capture(t, func() { scepterProbeTest("ir", cl, CapTunnel) })
	if !strings.Contains(out, "manage") {
		t.Errorf("the capability gate is UX and must say so:\n%s", out)
	}
	if len(cl.cmds["test.open"]) != 0 {
		t.Error("a tunnel-only credential must not reach test.open")
	}
}

// ---- the carrier-change flow (tunnel page, item c) ----

func TestScepterCarrierChangeFlow(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "web", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	changed := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"name": "web", "carrier": "tcp", "listen": float64(8443), "link": "ok",
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"carrier.change": {{r: changed}},
	}}
	calls := scepterStubLocalMachine(t, true)
	NonInteractive = false
	defer feed("3\ny")() // pick tcp (quick pick 3), listen default (empty), confirm
	out := capture(t, func() {
		if !scepterRemoteCarrierChange("ir", cl, CapTunnel|CapCreate|CapManage, "web", 12) {
			t.Error("carrier change reported failure")
		}
	})
	if len(cl.cmds["carrier.change"]) != 1 {
		t.Fatalf("carrier.change calls = %d, want 1", len(cl.cmds["carrier.change"]))
	}
	sent := cl.cmds["carrier.change"][0]
	if sent["name"] != "web" || sent["carrier"] != "tcp" || sent["base_seq"] != uint64(12) {
		t.Errorf("intent = %v", sent)
	}
	cfg := mustRead(filepath.Join(dir, "web.yml"))
	if !strings.Contains(cfg, "carrier: tcp") || !strings.Contains(cfg, "peer: 198.51.100.7:8443") {
		t.Errorf("the local tunnel did not follow:\n%s", cfg)
	}
	for _, want := range []string{"Kharej switched", "Link is up"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if *calls != 1 {
		t.Errorf("restarts = %d, want 1", *calls)
	}
}

func TestScepterCarrierChangeRolledBack(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "web", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	// Kharej refused (rolled itself back): the local side must stay untouched
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"carrier.change": {{r: ScepterResult{Code: scepterCodeInternal,
			Params: map[string]any{"rolled_back": true, "detail": "unit did not come up"}}}},
	}}
	calls := scepterStubLocalMachine(t, true)
	NonInteractive = false
	defer feed("3\ny")()
	capture(t, func() {
		if scepterRemoteCarrierChange("ir", cl, CapTunnel|CapCreate|CapManage, "web", 12) {
			t.Error("a rolled-back change must report failure")
		}
	})
	cfg := mustRead(filepath.Join(dir, "web.yml"))
	if !strings.Contains(cfg, "carrier: udp") || !strings.Contains(cfg, "peer: 198.51.100.7:4443") {
		t.Errorf("a rolled-back change must not touch the local yml:\n%s", cfg)
	}
	if *calls != 0 {
		t.Errorf("restarts = %d, want 0", *calls)
	}
}

// ---- the fleet auto-test ----

func TestScepterFleetAutoSmoke(t *testing.T) {
	scepterCarrierTestConf(t)
	rows := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "at-9", "mode": "plain", "done": true, "ok": float64(2),
		"rows": []any{
			map[string]any{"rank": float64(1), "carrier": "udp", "port": float64(20501), "ok": true, "down_mbps": 8.4},
			map[string]any{"rank": float64(2), "carrier": "tcp", "port": float64(20502), "ok": true, "down_mbps": 3.1},
			map[string]any{"rank": float64(3), "carrier": "ws", "port": float64(20503), "ok": false, "why": "no link in 15 s"},
		},
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"auto.test": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"run": "at-9", "mode": "plain", "shapes": float64(3)}}}},
		"auto.rows": {{r: rows}, {r: rows}}, // the wait poll + the view's first fetch
	}}
	NonInteractive = false
	defer feed("p0")() // plain shapes, then leave the table
	out := capture(t, func() {
		scepterFleetAuto("ir", cl, CapTunnel|CapCreate|CapManage, scepterDoc{StateSeq: 4})
	})
	// restyle pins (lane U4): the ranked rows carry a relative GradBar and the
	// rate in the manager's unit system — 8.4 Mbps = 1.0 MB/s (bytes = Mbps*1e6/8)
	for _, want := range []string{"Run at-9 started", "1 · udp", "1.0 MB/s", "3 · ws", "failed: no link in 15 s"} {
		if !strings.Contains(out, want) {
			t.Errorf("auto-test screen missing %q:\n%s", want, out)
		}
	}
	if sent := cl.cmds["auto.test"][0]; sent["mode"] != nil || sent["id"] == nil {
		t.Errorf("plain mode rides absent, the id must ride: %v", sent)
	}
}

func TestScepterFleetAutoAlreadyRunning(t *testing.T) {
	scepterCarrierTestConf(t)
	rows := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "at-1", "mode": "plain", "done": false, "ok": float64(0), "rows": []any{},
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"auto.test": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"run": "at-1", "already_running": true}}}},
		"auto.rows": {{r: rows}},
	}}
	NonInteractive = false
	defer feed("p0")()
	out := capture(t, func() {
		scepterFleetAuto("ir", cl, CapTunnel|CapCreate|CapManage, scepterDoc{})
	})
	if !strings.Contains(out, "already going") {
		t.Errorf("already_running must be surfaced, not an error:\n%s", out)
	}
	if !strings.Contains(out, "in progress") {
		t.Errorf("the not-done table must say so:\n%s", out)
	}
}

func TestScepterAutoApplyFlow(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "web", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	rows := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "at-9", "mode": "plain", "done": true, "ok": float64(1),
		"rows": []any{
			map[string]any{"rank": float64(1), "carrier": "wss", "port": float64(20501), "ok": true, "down_mbps": 8.4},
		},
	}}
	applied := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"name": "web", "carrier": "wss", "listen": float64(20501), "link": "ok", "row": float64(1),
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"auto.apply": {{r: applied}},
		"auto.rows":  {{r: rows}, {r: rows}}, // the view's fetch + the post-apply refetch
	}}
	calls := scepterStubLocalMachine(t, true)
	NonInteractive = false
	defer feed("1\n0")() // pick row 1, tunnel name default (web), leave the table
	out := capture(t, func() {
		scepterAutoRowsView("ir", cl, CapTunnel|CapCreate|CapManage, scepterDoc{StateSeq: 4,
			Tunnels: []scepterTunRow{{Name: "web"}}})
	})
	if len(cl.cmds["auto.apply"]) != 1 {
		t.Fatalf("auto.apply calls = %d, want 1", len(cl.cmds["auto.apply"]))
	}
	sent := cl.cmds["auto.apply"][0]
	if sent["name"] != "web" || sent["row"] != 1 || sent["base_seq"] != uint64(4) {
		t.Errorf("intent = %v", sent)
	}
	cfg := mustRead(filepath.Join(dir, "web.yml"))
	if !strings.Contains(cfg, "carrier: wss") || !strings.Contains(cfg, "peer: 198.51.100.7:20501") {
		t.Errorf("the local tunnel did not follow the applied row:\n%s", cfg)
	}
	if !strings.Contains(out, "Row 1 applied on Kharej") || !strings.Contains(out, "Link is up") {
		t.Errorf("output missing the apply verdicts:\n%s", out)
	}
	if *calls != 1 {
		t.Errorf("restarts = %d, want 1", *calls)
	}
}

func TestScepterAutoApplyFailedRowNeedsYes(t *testing.T) {
	scepterCarrierTestConf(t)
	rows := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "at-9", "mode": "plain", "done": true, "ok": float64(0),
		"rows": []any{
			map[string]any{"rank": float64(1), "carrier": "ws", "port": float64(20503), "ok": false, "why": "no link in 15 s"},
		},
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"auto.rows": {{r: rows}},
	}}
	NonInteractive = false
	defer feed("1n0")() // pick the failed row, answer the confirm with no, leave
	out := capture(t, func() {
		scepterAutoRowsView("ir", cl, CapTunnel|CapCreate|CapManage, scepterDoc{})
	})
	if !strings.Contains(out, "failed (no link in 15 s)") {
		t.Errorf("the failed row must be named before applying:\n%s", out)
	}
	if len(cl.cmds["auto.apply"]) != 0 {
		t.Errorf("a failed row must not apply without an explicit yes")
	}
}

// ---- screen smoke: the new pair-screen and tunnel-page items render ----

func TestScepterPairScreenCarrierItems(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npairing: true\n")
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(6), "uptime_s": float64(60), "event_cursor": float64(3),
		"pair":    map[string]any{"uuid": "u1", "caps": "manage"},
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	hello := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "caps": "manage", "uuid": "u1", "state_seq": float64(6)}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"scepter.hello": {{r: hello}},
		"state.get":     {{r: doc}, {r: doc}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	NonInteractive = false
	defer feed("0")() // leave immediately
	out := capture(t, func() { scepterScreen("ir") })
	for _, want := range []string{"Test a carrier", "Find the best carrier", "measure it from here"} {
		if !strings.Contains(out, want) {
			t.Errorf("pair screen missing the phase-C items (%q):\n%s", want, out)
		}
	}
}

func TestScepterTunnelPageCarrierItem(t *testing.T) {
	scepterCarrierTestConf(t)
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(6), "event_cursor": float64(3),
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"state.get": {{r: doc}},
	}}
	NonInteractive = false
	defer feed("0")() // leave immediately
	out := capture(t, func() { scepterTunnelPage("ir", cl, CapTunnel|CapCreate|CapManage, "web") })
	if !strings.Contains(out, "Carrier") || !strings.Contains(out, "on both sides") {
		t.Errorf("tunnel page missing the carrier item:\n%s", out)
	}
}

func TestScepterProbeTTLValidator(t *testing.T) {
	InitColor(false, 8)
	errN0 := ErrN()
	if !vProbeTTL("") || !vProbeTTL("300") || !vProbeTTL("10") || !vProbeTTL("3600") {
		t.Error("valid ttls rejected")
	}
	if vProbeTTL("9") || vProbeTTL("3601") || vProbeTTL("abc") || vProbeTTL("-5") {
		t.Error("invalid ttls accepted")
	}
	if ErrN() != errN0+4 {
		t.Errorf("each refusal must print one error, got %d", ErrN()-errN0)
	}
}

func TestVPortOpt(t *testing.T) {
	InitColor(false, 8)
	if !vPortOpt("") || !vPortOpt("8443") {
		t.Error("empty = keep the bind, a port stays a port")
	}
	if vPortOpt("0") || vPortOpt("x") {
		t.Error("vPortOpt must refuse what vPort refuses")
	}
}

// writeTestYml writes a tunnel yml into the test conf dir (0600, like the manager).
func writeTestYml(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s.yml: %v", name, err)
	}
}

// TestChangeTypePairedRoutesRemote (owner live-test feedback 2026-11-23): on a
// PAIRED Iran tunnel the local [c] Carrier row runs the remote carrier change —
// the "Kharej fixed this type" dead-end appears only when the tunnel is unpaired.
func TestChangeTypePairedRoutesRemote(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: tcp\npeer: 198.51.100.7:4443\npairing: true\n")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"scepter.hello":  {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"ver": "3.5.0", "caps": "manage", "state_seq": float64(7)}}}},
		"state.get":      {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"ver": "3.5.0", "state_seq": float64(7), "tunnels": []any{}}}}},
		"carrier.change": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "ir", "carrier": "tls"}}}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	scepterStubLocalMachine(t, true)
	NonInteractive = false
	defer feed("4\n\ny")() // pick tls (quick pick 4), listen default, confirm
	out := capture(t, func() { changeType("ir") })
	if len(cl.cmds["carrier.change"]) != 1 {
		t.Fatalf("paired [c] must send carrier.change, got %v (%s)", cl.cmds, out)
	}
	if strings.Contains(out, "Kharej fixed this type") {
		t.Error("the dead-end message must not appear on a paired tunnel")
	}
	// unpaired twin: the honest dead-end stays
	writeTestYml(t, dir, "plain", "mode: client\ncarrier: tcp\npeer: 198.51.100.7:4443\n")
	out2 := capture(t, func() { changeType("plain") })
	if !strings.Contains(out2, "Kharej fixed this type") {
		t.Errorf("unpaired [c] keeps the honest dead-end:\n%s", out2)
	}
}

// Handoff 4 R4: a remote create builds the Iran token from the pair's Kharej host and the carrier port
// Kharej bound; it round-trips, and a reverse pair or a portless answer for a port carrier builds none.
func TestScepterCreatedToken(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "pair", "mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\npairing: true\n")
	ans := map[string]any{"carrier": "wss", "key": "k1", "listen_port": float64(8443), "allow": "443,80"}
	tok := scepterCreatedToken("pair", ans, map[string]string{"path": "/x", "sni": "a.ir"})
	got, err := ReadToken(tok)
	if err != nil || got.Carrier != "wss" || got.Peer != "198.51.100.9:8443" || got.Key != "k1" ||
		got.Path != "/x" || got.SNI != "a.ir" || got.Ports != "443,80" || got.Rev == "1" {
		t.Fatalf("built token %+v (%v)", got, err)
	}
	if tok := scepterCreatedToken("pair", map[string]any{"carrier": "icmp", "key": "k1"}, nil); tok == "" {
		t.Fatal("icmp has no carrier port: the token needs only the host")
	}
	if scepterCreatedToken("pair", map[string]any{"carrier": "udp", "key": "k1"}, nil) != "" {
		t.Fatal("a port carrier without listen_port must not guess the port")
	}
	writeTestYml(t, dir, "rev", "mode: client\ncarrier: tcp\npeer: 203.0.113.5:9000\nreverse: true\n")
	if scepterCreatedToken("rev", ans, nil) != "" {
		t.Fatal("a reverse pair's peer is this server, not Kharej")
	}
	if tok := scepterCreatedToken("rev", map[string]any{"token": "wat1:x"}, nil); tok != "wat1:x" {
		t.Fatal("Kharej's own token wins")
	}
}

// Handoff 4 R7: a tunnel made by "On Kharej and here" has no pairing of its own; its K row rides the paired
// direct tunnel that dials the same Kharej host. Other hosts, reverse tunnels and pairing: false get none.
func TestScepterChannelForSibling(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "pair", "mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\npairing: true\n")
	writeTestYml(t, dir, "made", "mode: client\ncarrier: wss\npeer: 198.51.100.9:8443\n")
	writeTestYml(t, dir, "other", "mode: client\ncarrier: udp\npeer: 203.0.113.1:4443\n")
	writeTestYml(t, dir, "off", "mode: client\ncarrier: udp\npeer: 198.51.100.9:5000\npairing: false\n")
	for n, want := range map[string]string{"pair": "pair", "made": "pair", "other": "", "off": ""} {
		if got := scepterChannelFor(n); got != want {
			t.Errorf("scepterChannelFor(%s) = %q, want %q", n, got, want)
		}
	}
	if !tunnelKharejKeyWanted("made") {
		t.Error("the sibling's tunnel page must offer On Kharej")
	}
}

// Handoff 4 R4 on the owner's route: a reverse pair creates a reverse tunnel — no Kharej listen question,
// reverse=true and a peer at this server's address, so Kharej's answer carries the token itself.
func TestScepterWizardCreateReversePair(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "rp", "mode: client\ncarrier: tcp\npeer: 203.0.113.5:27443\nreverse: true\nlisten: \":27443\"\npairing: true\n")
	done := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "tunnel", "carrier": "tcp"}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{"tunnel.create": {{r: done}}}}
	// name default, tcp (quick pick 3), dial port 28000, ports 443, send
	defer feed("\n328000\n443\ny")() // a quick pick takes no Enter
	out := capture(t, func() { scepterWizardCreate("rp", cl, scepterDoc{StateSeq: 7}) })
	sent := cl.cmds["tunnel.create"]
	if len(sent) != 1 {
		t.Fatalf("sends = %d:\n%s", len(sent), out)
	}
	p, _ := sent[0]["params"].(map[string]string)
	if p["reverse"] != "true" || p["peer"] != "203.0.113.5:28000" || p["listen"] != "" {
		t.Errorf("reverse create params = %v", p)
	}
	if strings.Contains(out, "Listen port on Kharej") {
		t.Errorf("a reverse tunnel binds nothing on Kharej; no listen question:\n%s", out)
	}
}

// A reverse sibling rides the reverse pair only while that pair is the one reverse pair (its peer names no Kharej).
func TestScepterChannelForReverseSibling(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "rp", "mode: client\ncarrier: tcp\npeer: 203.0.113.5:27443\nreverse: true\npairing: true\n")
	writeTestYml(t, dir, "made", "mode: client\ncarrier: tcp\npeer: 203.0.113.5:28000\nreverse: true\n")
	if got := scepterChannelFor("made"); got != "rp" {
		t.Fatalf("single reverse pair: %q", got)
	}
	writeTestYml(t, dir, "rp2", "mode: client\ncarrier: tcp\npeer: 203.0.113.5:27500\nreverse: true\npairing: true\n")
	if got := scepterChannelFor("made"); got != "" {
		t.Fatalf("two reverse pairs are ambiguous: %q", got)
	}
}
