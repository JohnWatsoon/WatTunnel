package mgr

// The home lane's tests: the menu contracts (order matters — Scepter is the
// promoted top-level entry), the pairing store round-trip (the credential is
// the only copy — the format must survive a write/read cycle byte-honestly),
// and the home head's pair line states (honest: not paired, checking,
// unreachable, seq). Colour is off everywhere so pins are plain text.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// homeTestHost isolates the paths the home screens read: config dir and manager
// conf. The restore is per-field so concurrent lanes' own fixtures are untouched.
func homeTestHost(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldMConf := P.Conf, P.MConf
	P.Conf, P.MConf = dir, filepath.Join(dir, ".manager.conf")
	t.Cleanup(func() { P.Conf, P.MConf = oldConf, oldMConf })
	return dir
}

func resetPairCache() {
	pairMu.Lock()
	pairDocs = map[string]*scepterDoc{}
	pairFail = map[string]string{}
	pairFlying = false
	pairAt = time.Time{}
	pairMu.Unlock()
}

func TestMainMenuItemsScepterPromoted(t *testing.T) {
	items := mainMenuItems(3)
	want := []string{"Tunnels", "New tunnel", "Scepter", "Find a carrier", "Blackout kit", "Tools", "Settings", "Exit"}
	if len(items) != len(want) {
		t.Fatalf("home menu has %d rows, want %d", len(items), len(want))
	}
	for i, w := range want {
		if items[i].Label != w {
			t.Errorf("row %d = %q, want %q", i, items[i].Label, w)
		}
	}
	if !items[len(items)-1].Off {
		t.Error("Exit must stay the dim last row")
	}
}

func TestSettingsItemsBoostAndScepterGate(t *testing.T) {
	InitColor(false, 8)
	dir := homeTestHost(t)
	labels := func() []string {
		var out []string
		for _, it := range settingsItems() {
			out = append(out, it.Label)
		}
		return out
	}
	// no tunnels, side unset: the bash gate (kharej || '' || pairing_active)
	// must keep the first pair reachable — the Scepter row shows.
	has := func(ls []string, w string) bool {
		for _, l := range ls {
			if l == w {
				return true
			}
		}
		return false
	}
	if !has(labels(), "Kernel boost") {
		t.Error("Settings lost the Kernel boost row again (bash parity)")
	}
	if !has(labels(), "Scepter") {
		t.Error("Settings must show the Scepter console row while the role is unset")
	}
	// explicit Iran and no store: the row hides — Iran pairs from the cockpit.
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	if has(labels(), "Scepter") {
		t.Error("Scepter console row must hide on an explicit Iran host with no store")
	}
	// Iran with an existing store: bash pairing_active bypasses the side gate.
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	os.WriteFile(pairStorePath(), []byte("watp1:1|1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4|"+key+"|full\n"), 0o600)
	if !has(labels(), "Scepter") {
		t.Error("an existing pairing store must surface the Scepter row on any side")
	}
	for _, it := range settingsItems() {
		if it.Label == "Scepter" && !strings.Contains(it.Desc, "paired") {
			t.Errorf("paired store renders %q, want a paired state", it.Desc)
		}
	}
}

func TestScepterScreensRegistered(t *testing.T) {
	if !registered("scepter_menu") {
		t.Error("scepter_menu must be registered: the Settings row dispatches it")
	}
	if !registered("scepter_fleet") {
		t.Error("scepter_fleet must be registered: the home menu dispatches it")
	}
}

func TestPairStoreRoundTrip(t *testing.T) {
	homeTestHost(t)
	if _, st := pairLoad(); st != 2 {
		t.Errorf("missing store = %d, want 2", st)
	}
	// engine format: a bare credential line, nothing else (cmd/wattun
	// writePairingFile's shape)
	line := MakePairingLine("1", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", make([]byte, 32), CapFull)
	os.WriteFile(pairStorePath(), []byte(line+"\n"), 0o600)
	c, st := pairLoad()
	if st != 0 {
		t.Fatalf("engine-format store unreadable (st %d)", st)
	}
	if c.line.UUID != "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4" || capTier(c.line.Caps) != "full" {
		t.Errorf("engine store parsed wrong: %+v", c.line)
	}
	if c.created != 0 {
		t.Errorf("engine store carries no bookkeeping, got created %d", c.created)
	}
	// a store this manager must refuse: garbage is not a credential
	os.WriteFile(pairStorePath(), []byte("uuid=x\nkey=y\n"), 0o600)
	if _, st := pairLoad(); st != 1 {
		t.Errorf("legacy key=value store = %d, want 1 (F1-B: refuse, never rewrite)", st)
	}
	// manager round-trip: write with bookkeeping, read it back (the tier comes
	// back as its expanded bit mask — compare the tier word, not the mask)
	p := PairingLine{Version: "1", UUID: "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", Key: make([]byte, 32), Caps: CapManage}
	if err := pairStoreWrite(p, "OLDKEY", 1700000000); err != nil {
		t.Fatalf("pairStoreWrite: %v", err)
	}
	c, st = pairLoad()
	if st != 0 {
		t.Fatalf("written store unreadable (st %d)", st)
	}
	if capTier(c.line.Caps) != "manage" || c.oldKey != "OLDKEY" || c.oldKeyExpires != 1700000000 || c.created == 0 {
		t.Errorf("round trip lost bookkeeping: %+v", c)
	}
	created := c.created
	time.Sleep(1100 * time.Millisecond)
	if err := pairStoreWrite(p, "", 0); err != nil {
		t.Fatalf("second pairStoreWrite: %v", err)
	}
	c, _ = pairLoad()
	if c.created != created {
		t.Errorf("a rewrite must keep the original creation time: %d -> %d", created, c.created)
	}
}

func TestPairStatusRows(t *testing.T) {
	InitColor(false, 8)
	homeTestHost(t)
	if rows := pairStatus(); len(rows) != 1 || !strings.Contains(rows[0], "off") {
		t.Errorf("no store: %v, want one off row", pairStatus())
	}
	os.WriteFile(pairStorePath(), []byte("not a store\n"), 0o600)
	if rows := pairStatus(); len(rows) != 1 || !strings.Contains(rows[0], "unreadable") {
		t.Errorf("garbage store: %v, want one unreadable row", pairStatus())
	}
	os.WriteFile(pairStorePath(), []byte(MakePairingLine("1", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", make([]byte, 32), CapFull)+"\n# created=1700000000\n"), 0o600)
	rows := pairStatus()
	joined := strings.Join(rows, "\n")
	for _, want := range []string{"on", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", "full", "created"} {
		if !strings.Contains(joined, want) {
			t.Errorf("paired status missing %q:\n%s", want, joined)
		}
	}
}

func TestPairAuditTail(t *testing.T) {
	homeTestHost(t)
	pairAuditTail(20) // must not crash without a file
	if !pairAudit("pair_created", "u1") {
		t.Fatal("first audit append failed")
	}
	pairAudit("pair_rotated", "u1")
	b, err := os.ReadFile(pairAuditPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "pair_created u1") || !strings.Contains(lines[1], "pair_rotated u1") {
		t.Errorf("audit trail wrong:\n%s", b)
	}
	var buf strings.Builder
	oldStd := Stdout
	Stdout = &buf
	pairAuditTail(1)
	Stdout = oldStd
	if out := buf.String(); strings.Contains(out, "pair_created") || !strings.Contains(out, "pair_rotated") {
		t.Errorf("tail 1 must show only the newest entry:\n%s", out)
	}
}

// stubScepterClient answers state.get with a fixed document (the same shape
// scepterParseDoc reads off the wire).
type stubScepterClient struct{ params map[string]any }

func (c stubScepterClient) Call(string, map[string]any) (ScepterResult, error) {
	return ScepterResult{Code: scepterCodeOK, Params: c.params}, nil
}

func TestPairKickFetchesFleetState(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	os.WriteFile(filepath.Join(P.Conf, "irp.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	resetPairCache()
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) {
		return stubScepterClient{params: map[string]any{
			"ver": "3.5.0", "state_seq": 42, "uptime_s": 3750,
			"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "up"}},
		}}, nil
	}
	t.Cleanup(func() { scepterDial = oldDial; resetPairCache() })
	pairKick()
	deadline := time.Now().Add(2 * time.Second)
	for {
		pairMu.Lock()
		doc, fail := pairDocs["irp"], pairFail["irp"]
		flying := pairFlying
		pairMu.Unlock()
		if fail != "" {
			t.Fatalf("stub dial failed: %s", fail)
		}
		if doc != nil && !flying {
			if doc.StateSeq != 42 || len(doc.Tunnels) != 1 {
				t.Errorf("fetched doc wrong: seq %d tunnels %d", doc.StateSeq, len(doc.Tunnels))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pairKick refresh never landed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPairLinesStates(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "80")
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	render := func() string {
		var b strings.Builder
		pairLines(&b)
		return b.String()
	}
	resetPairCache()
	defer resetPairCache()
	pairAt = time.Now() // not stale: the render must not dial (head redraws per tick)

	// unpaired first: only ir.yml exists at this point
	if out := render(); !strings.Contains(out, "not paired") {
		t.Errorf("unpaired host must say so honestly:\n%s", out)
	}

	// a paired tunnel changes the line's job: the last fleet state
	os.WriteFile(filepath.Join(P.Conf, "irp.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	resetPairCache()
	pairAt = time.Now()
	pairFail["irp"] = "no answer within 65s"
	if out := render(); !strings.Contains(out, "unreachable") || !strings.Contains(out, "no answer within 65s") {
		t.Errorf("a failed pair must name the error:\n%s", out)
	}

	resetPairCache()
	pairAt = time.Now()
	pairDocs["irp"] = &scepterDoc{Ver: "3.5.0", StateSeq: 42, UptimeS: 3750, Tunnels: []scepterTunRow{{Name: "web"}}}
	out := render()
	for _, want := range []string{"Scepter irp", "seq 42", "1 remote tunnel", "62m"} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet line missing %q:\n%s", want, out)
		}
	}

	resetPairCache()
	pairAt = time.Now()
	if out := render(); !strings.Contains(out, "checking the pair") {
		t.Errorf("no data and nothing fetched yet: the waiting state must show:\n%s", out)
	}
}

func TestHomeHeadEmptyState(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "80")
	var b strings.Builder
	homeHead(&b, nil, map[string]*tunnelInfo{}, nil, false)
	out := b.String()
	for _, want := range []string{"No tunnels yet.", "New tunnel"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty head missing %q:\n%s", want, out)
		}
	}
}

func TestHeadRateAndTweens(t *testing.T) {
	InitColor(false, 8)
	oldAnim := UseAnim
	UseAnim = false
	defer func() { UseAnim = oldAnim }()
	txt, meter := headRate(NewTween(0), NewFill(0), false, 15e6, nil)
	if StripANSI(txt) != "—" || strings.Contains(StripANSI(meter), "▰") {
		t.Errorf("a dead tunnel renders — with an empty meter: %q %q", txt, meter)
	}
	num, bar := NewTween(15e6), NewFill(0)
	txt, meter = headRate(num, bar, true, 15e6, nil)
	if StripANSI(txt) == "" || strings.Count(StripANSI(meter), "▰") != meterW {
		t.Errorf("full-scale rate: %q %q", txt, meter)
	}
	// a new sample snaps when anim is off (byte-stable refreshes)
	if got := num.Step(3e6); StripANSI(Rate(got)) != StripANSI(Rate(3e6)) {
		t.Errorf("anim off must snap to the target: %v", got)
	}
}

// The tunnel page's pair status line renders ONLY from the cockpit cache: with
// an expired cache and a dead pair it must still draw instantly (last known
// line), the fetch running on the kick goroutine — the round-3 HIGH (the old
// synchronous ScepterPairStatus froze the page's 1 s tick for minutes).
func TestTunnelHeadPairStatusFromCache(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "80")
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	entered := make(chan struct{})
	var once sync.Once
	rel := make(chan struct{})
	release := func() { once.Do(func() { close(rel) }) }
	oldFetch, oldBy := scepterStatusFetch, scepterStatusBy
	t.Cleanup(func() {
		release() // unblock a stuck fetch first, then give the kick goroutine its write-back moment
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			tunnelPairMu.Lock()
			flying := tunnelPairFlying["ir"]
			tunnelPairMu.Unlock()
			if !flying {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		scepterStatusFetch, scepterStatusBy = oldFetch, oldBy
	})
	scepterStatusFetch = func(string) string {
		close(entered)
		<-rel
		return "fresh fetch"
	}
	scepterStatusBy = map[string]scepterStatusEntry{
		"ir": {txt: "cached pair line", at: time.Now().Add(-time.Hour)}, // expired: stale but renderable
	}
	var buf strings.Builder
	tunnelHead(&buf, "ir", "Iran", "udp", &tunnelInfo{State: "stopped"})
	if out := buf.String(); !strings.Contains(out, "cached pair line") {
		t.Errorf("the head must render the cached line, got:\n%s", out)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the stale cache never kicked a background fetch")
	}
	if out := buf.String(); strings.Contains(out, "fresh fetch") {
		t.Error("the head must not wait for (or show) the kick's fetch result")
	}
	release()
	deadline := time.Now().Add(2 * time.Second)
	for {
		scepterStatusMu.Lock()
		txt, at := scepterStatusBy["ir"].txt, scepterStatusBy["ir"].at
		scepterStatusMu.Unlock()
		if txt == "fresh fetch" && time.Since(at) < time.Hour {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the kick goroutine never wrote the fetched status back to the cache")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The tunnel page's K row (and its ?-keys entry) is gated by exactly IsPaired:
// pairing:false beats the token's bootstrap credential — the off-switch must
// win, otherwise pressing K does nothing silently (round 3).
func TestTunnelKharejKeyGate(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	NonInteractive = false // the keys page ends on a key read; feed() must drive it
	defer func() { NonInteractive = false }()
	t.Setenv("COLUMNS", "80")
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: false\n"), 0o600)
	tok := MakeToken("udp", "198.51.100.7:4443", "k", "", "", "", "", "", "", "pair=full")
	os.WriteFile(filepath.Join(P.Conf, "ir.token"), []byte(tok+"\n"), 0o600)
	if tokenPairCaps("ir") == 0 {
		t.Fatal("the fixture token must carry a pair credential for this pin")
	}
	if tunnelKharejKeyWanted("ir") {
		t.Error("pairing:false must disable the K row even with a token-bootstrap pair")
	}
	keys := func() string {
		defer feed("x")() // the keys page ends on a key read
		return capture(t, func() { tunnelMenuKeys("ir", &deck{}) })
	}
	if out := keys(); strings.Contains(out, "Kharej view") {
		t.Errorf("the ?-keys page must hide the K row when the item is hidden:\n%s", out)
	}
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	if !tunnelKharejKeyWanted("ir") {
		t.Error("pairing:true must show the K row")
	}
	if out := keys(); !strings.Contains(out, "Kharej view") {
		t.Errorf("the ?-keys page must list the K row exactly when the menu shows it:\n%s", out)
	}
}

// Delete drops the name's home-side caches: rate history and the pair's last
// document/error must not survive as ghosts, and a recreated tunnel of the
// same name starts with an empty graph (round 3).
func TestDeletePrunesTunnelCaches(t *testing.T) {
	dir := homeTestHost(t)
	InitColor(false, 8)
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	resetPairCache()
	defer resetPairCache()
	pairDocs["a"] = &scepterDoc{Ver: "3.5.0", StateSeq: 7}
	pairFail["a"] = "no answer within 65s"
	samples["a"] = &sample{in: 1, out: 2}
	oldSys := p2Systemctl
	p2Systemctl = func(...string) error { return nil }
	defer func() { p2Systemctl = oldSys }()
	oldPrefix, oldRun, oldNon := P.Prefix, P.Run, NonInteractive
	P.Prefix, P.Run, NonInteractive = "wattun", t.TempDir(), true
	defer func() { P.Prefix, P.Run, NonInteractive = oldPrefix, oldRun, oldNon }()
	var ok bool
	capture(t, func() { ok = runDelete("a") }) // the prompts and the Ok line stay out of the log
	if !ok {
		t.Fatal("runDelete returned false")
	}
	pairMu.Lock()
	doc, fail := pairDocs["a"], pairFail["a"]
	pairMu.Unlock()
	if doc != nil || fail != "" {
		t.Errorf("a deleted tunnel's pair cache survived: doc %v fail %q", doc, fail)
	}
	if samples["a"] != nil {
		t.Error("a deleted tunnel's rate history survived")
	}
}

// An audit-append failure must not look like success: pair/rotate say the
// store change IS live and that the audit line was NOT recorded (the revoke
// path aborts instead — the same contract, adapted to an already-applied
// change, round 3).
func TestPairRotateAuditHonesty(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	NonInteractive = true // the asks take their defaults: generate a fresh pairing
	defer func() { NonInteractive = false }()
	auditDir := pairAuditPath()
	os.Mkdir(auditDir, 0o700) // a directory: every append fails

	out := capture(t, func() { scepterPair() })
	if !strings.Contains(out, "Pairing stored") || !strings.Contains(out, "The audit line was NOT recorded.") {
		t.Errorf("pair must state the store change and the missing audit line:\n%s", out)
	}
	if strings.Contains(out, "✓ Pairing stored") {
		t.Errorf("an unaudited pair must not print the success mark:\n%s", out)
	}

	out = capture(t, func() { scepterRotate() })
	if !strings.Contains(out, "Pairing key rotated") || !strings.Contains(out, "The audit line was NOT recorded.") {
		t.Errorf("rotate must state the key swap and the missing audit line:\n%s", out)
	}
	if strings.Contains(out, "✓ Pairing key rotated") {
		t.Errorf("an unaudited rotate must not print the success mark:\n%s", out)
	}

	os.Remove(auditDir) // writable again: the success branch keeps its Ok
	out = capture(t, func() { scepterRotate() })
	if !strings.Contains(out, "✓ Pairing key rotated") || strings.Contains(out, "NOT recorded") {
		t.Errorf("an audited rotate must keep the plain success line:\n%s", out)
	}
}
