package mgr

// The home lane's tests: the menu contracts (order matters — Scepter is the
// promoted top-level entry), the pairing store round-trip (the credential is
// the only copy — the format must survive a write/read cycle byte-honestly),
// and the home head's pair line states (honest: not paired, checking,
// unreachable, seq). Colour is off everywhere so pins are plain text.

import (
	"encoding/base64"
	"fmt"
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
	homeTestHost(t) // no tunnels, side unset: the union menu keeps all 8 slots
	items := mainMenuItems(3)
	want := []string{"Tunnels", "New tunnel", "Kharej server", "Find a carrier", "Blackout kit", "Tools", "Settings", "Exit"}
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

// Role-aware home (owner feedback 2026-11-23): the banner names the side, the
// Scepter slot swaps per role, and dispatch follows the role.
func TestRoleAwareHome(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "80")
	if got := scepterRoute(); got != "scepter_menu" {
		t.Errorf("unset role routes %q, want scepter_menu (the console's own gate sorts it out)", got)
	}

	// Iran: the cockpit
	_ = ConfSet("side", "iran")
	if got := scepterRoute(); got != "scepter_fleet" {
		t.Errorf("iran routes %q, want scepter_fleet", got)
	}
	items := mainMenuItems(1)
	if items[2].Label != "Kharej server" || !strings.Contains(items[2].Desc, "paired Kharej") {
		t.Errorf("iran scepter row = %q %q, want the cockpit", items[2].Label, items[2].Desc)
	}
	var b strings.Builder
	homeHead(&b, nil, map[string]*tunnelInfo{}, nil, false)
	if out := b.String(); !strings.Contains(out, "IRAN — the cockpit") {
		t.Errorf("iran head missing the role banner:\n%s", out)
	}

	// Kharej: the local console — no cockpit anywhere in the menu
	_ = ConfSet("side", "kharej")
	if got := scepterRoute(); got != "scepter_menu" {
		t.Errorf("kharej routes %q, want scepter_menu", got)
	}
	items = mainMenuItems(1)
	if items[2].Label != "Pairing" {
		t.Errorf("kharej scepter row = %q, want the local console label", items[2].Label)
	}
	for _, it := range items {
		if strings.Contains(it.Label+it.Desc, "cockpit") {
			t.Errorf("kharej menu must not offer the cockpit: %q %q", it.Label, it.Desc)
		}
	}
	b.Reset()
	homeHead(&b, nil, map[string]*tunnelInfo{}, nil, false)
	if out := b.String(); !strings.Contains(out, "KHAREJ — the server") {
		t.Errorf("kharej head missing the role banner:\n%s", out)
	}

	// Mixed: one host running both roles says so instead of guessing
	_ = confUnset("side")
	os.WriteFile(filepath.Join(P.Conf, "kh.yml"), []byte("mode: server\ncarrier: udp\n"), 0o600)
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	if serverSide() != "mixed" {
		t.Errorf("both roles present: serverSide() = %q, want mixed", serverSide())
	}
	b.Reset()
	homeHead(&b, nil, map[string]*tunnelInfo{}, nil, false)
	if out := b.String(); !strings.Contains(out, "Kharej + Iran — this host does both") {
		t.Errorf("mixed head missing the both-roles banner:\n%s", out)
	}
}

// The Kharej head's live glance is server-side: clients and ports, not the
// client's rate meters (owner feedback 2026-11-23).
func TestKharejHeadServerSideGlance(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100")
	_ = ConfSet("side", "kharej")
	os.WriteFile(filepath.Join(P.Conf, "kh.yml"), []byte("mode: server\ncarrier: udp\nports:\n  - 443\n"), 0o600)
	ti := &tunnelInfo{State: "up", Sess: 3, Out: 15e6}
	samples["kh"] = &sample{in: 0, out: 0, at: time.Now()}
	var b strings.Builder
	homeHead(&b, []string{"kh"}, map[string]*tunnelInfo{"kh": ti}, nil, false)
	out := b.String()
	for _, want := range []string{"3 clients", "443", Human(15e6)} {
		if !strings.Contains(out, want) {
			t.Errorf("kharej glance missing %q:\n%s", want, out)
		}
	}
	delete(samples, "kh")
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
	if !has(labels(), "Pairing") {
		t.Error("Settings must show the Scepter console row while the role is unset")
	}
	// explicit Iran and no store: the row hides — Iran pairs from the cockpit.
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	if has(labels(), "Pairing") {
		t.Error("Scepter console row must hide on an explicit Iran host with no store")
	}
	// Iran with an existing store: bash pairing_active bypasses the side gate.
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	os.WriteFile(pairStorePath(), []byte("watp1:1|1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4|"+key+"|full\n"), 0o600)
	if !has(labels(), "Pairing") {
		t.Error("an existing pairing store must surface the Scepter row on any side")
	}
	for _, it := range settingsItems() {
		if it.Label == "Pairing" && !strings.Contains(it.Desc, "paired") {
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
	if rows := pairStatus(); len(rows) != 1 || !strings.Contains(rows[0], "waiting") {
		t.Errorf("no store: %v, want one waiting row", pairStatus())
	}
	os.WriteFile(pairStorePath(), []byte("revoked u1 2026-11-24T00:00:00Z\n"), 0o600)
	if rows := pairStatus(); len(rows) != 1 || !strings.Contains(rows[0], "revoked") {
		t.Errorf("tombstone: %v, want one revoked row", pairStatus())
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
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: false\n"), 0o600)
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
	for _, want := range []string{"Kharej irp", "1 tunnel", "62m"} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet line missing %q:\n%s", want, out)
		}
	}

	resetPairCache()
	pairAt = time.Now()
	if out := render(); !strings.Contains(out, "checking") {
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
	if out := keys(); strings.Contains(out, "On Kharej") {
		t.Errorf("the ?-keys page must hide the K row when the item is hidden:\n%s", out)
	}
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	if !tunnelKharejKeyWanted("ir") {
		t.Error("pairing:true must show the K row")
	}
	if out := keys(); !strings.Contains(out, "On Kharej") {
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

// ---- boot intro + entry animations (Lane A animation pass, 2026-11-23) ----
// Owner directive: purposeful motion only — the cascade plays once per run,
// the flash is tied to a state change, the count-up carries the entry, and
// every anim-off / non-interactive render stays byte-identical to the static
// head.

// introFixture stands up two client tunnels the cascade can glance at.
func introFixture(t *testing.T) ([]string, map[string]*tunnelInfo) {
	t.Helper()
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100")
	for _, n := range []string{"alpha", "beta"} {
		os.WriteFile(filepath.Join(P.Conf, n+".yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	}
	return []string{"alpha", "beta"}, map[string]*tunnelInfo{
		"alpha": {State: "up", RTT: 24},
		"beta":  {State: "stopped"},
	}
}

func renderIntro(names []string, infos map[string]*tunnelInfo, e time.Duration) string {
	var b strings.Builder
	for _, l := range introBlockLines(names, infos, e) {
		fmt.Fprintln(&b, l)
	}
	return b.String()
}

// The cascade renders the rows in order, then settles: frame sequence stepped
// through the elapsed-time seam, and the settled frame is stable (a much later
// elapsed time draws the same block).
func TestIntroCascadeSequence(t *testing.T) {
	names, infos := introFixture(t)
	UseAnim = false // introBlockLines is a pure function of e; no flash, no count-up
	defer func() { UseAnim = false }()
	// frame 0: the mark just landed — no badge, no rows yet
	if out := renderIntro(names, infos, 0); strings.Contains(out, "alpha") || strings.Contains(out, Tagline) {
		t.Errorf("the first frame must be empty below the mark:\n%s", out)
	}
	// badge beat: the badge line is in, rows still rising
	out := renderIntro(names, infos, introBadgeMS)
	if !strings.Contains(out, Tagline) || strings.Contains(out, "alpha") {
		t.Errorf("badge beat must show the badge and no rows yet:\n%s", out)
	}
	// one row per beat: alpha risen, beta still waiting (half a beat later)
	out = renderIntro(names, infos, introBadgeMS+3*introRowMS/2)
	if !strings.Contains(out, "alpha") || strings.Contains(out, "beta") {
		t.Errorf("second beat must show only the first row:\n%s", out)
	}
	// settled: everything in, and a much later frame is identical
	total := introTotal(len(names))
	settled := renderIntro(names, infos, total)
	if !strings.Contains(settled, "alpha") || !strings.Contains(settled, "beta") {
		t.Errorf("settled frame must show every row:\n%s", settled)
	}
	if later := renderIntro(names, infos, 10*total); later != settled {
		t.Errorf("the cascade must settle (a later frame differs):\n%s\n---\n%s", settled, later)
	}
	if total > 1200*time.Millisecond {
		t.Errorf("intro total %v exceeds the 1.2 s ceiling", total)
	}
	// the settled glance region is exactly the static head's glance
	static := homeGlanceLines(names, infos, -1)
	block := introBlockLines(names, infos, total)
	tail := block[len(block)-glanceHeight(len(names)):]
	for i := range static {
		if tail[i] != static[i] {
			t.Errorf("settled glance row %d = %q, want the static %q", i, tail[i], static[i])
		}
	}
}

// Any pressed key during the cascade skips to the settled frame instantly (the
// key is spent on the skip), and the settled rows still land on screen.
func TestIntroCascadeKeySkips(t *testing.T) {
	names, infos := introFixture(t)
	UseAnim, IsTTY, EL = true, true, "\x1b[K"
	defer func() { UseAnim, IsTTY, EL = false, false, "" }()
	defer feed("\x1b")()
	t0 := time.Now()
	out := capture(t, func() { introCascade(names, infos) })
	if d := time.Since(t0); d > 800*time.Millisecond {
		t.Errorf("esc skip took %v, want the banner reveal plus one frame", d)
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("the skip must still paint the settled frame:\n%s", out)
	}
}

// The state-change flash: three alternating renders (amber, new colour,
// amber), then it expires and never returns without another change; anim off
// never flashes and never even tracks state (zero cost, byte-stable).
func TestStateFlashCountsDownAndExpires(t *testing.T) {
	InitColor(true, 8)
	NonInteractive = false
	UseAnim = true
	defer func() { UseAnim = false }()
	s := &sample{}
	if stateFlash(s, &tunnelInfo{State: "up"}) {
		t.Error("the first sight of a tunnel must not flash")
	}
	want := []bool{true, false, true}
	for i, w := range want {
		if got := stateFlash(s, &tunnelInfo{State: "down"}); got != w {
			t.Errorf("flash render %d = %v, want %v", i, got, w)
		}
	}
	for i := 0; i < 3; i++ {
		if stateFlash(s, &tunnelInfo{State: "down"}) {
			t.Error("the flash must expire after its three renders")
		}
	}
	UseAnim = false
	s2 := &sample{}
	stateFlash(s2, &tunnelInfo{State: "up"})
	if stateFlash(s2, &tunnelInfo{State: "down"}) {
		t.Error("anim off must never flash")
	}
	if s2.state != "" {
		t.Errorf("anim off must not even track state, got %q", s2.state)
	}
}

// The Kharej glance's served total counts up from zero on entry (anim on, the
// animNow seam drives the tween); the anim-off half is the existing Kharej
// glance pin, which must keep passing byte-identically.
func TestServedCountUpOnEntry(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100")
	_ = ConfSet("side", "kharej")
	os.WriteFile(filepath.Join(P.Conf, "kh.yml"), []byte("mode: server\ncarrier: udp\nports:\n  - 443\n"), 0o600)
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	ti := &tunnelInfo{State: "up", Sess: 3, Out: 15e6}
	samples["kh"] = &sample{in: 0, out: 0, at: time.Now()}
	defer delete(samples, "kh")
	render := func() string {
		var b strings.Builder
		homeHead(&b, []string{"kh"}, map[string]*tunnelInfo{"kh": ti}, nil, false)
		return b.String()
	}
	if first := render(); !strings.Contains(first, "served "+Human(0)) {
		t.Errorf("entry render must count up from zero:\n%s", first)
	}
	at = at.Add(600 * time.Millisecond)
	mid := render()
	if strings.Contains(mid, Human(15e6)) || !strings.Contains(mid, "served ") {
		t.Errorf("mid count-up must be between the ends:\n%s", mid)
	}
	at = at.Add(30 * time.Second)
	if fin := render(); !strings.Contains(fin, "served "+Human(15e6)) {
		t.Errorf("the count-up must land on the real total:\n%s", fin)
	}
}

// The pair status dot breathes (◆↔◇) only while a refresh is in flight; an
// idle pair holds the solid diamond.
func TestPairDotBreathesOnlyInFlight(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "80")
	os.WriteFile(filepath.Join(P.Conf, "irp.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	resetPairCache()
	defer resetPairCache()
	pairMu.Lock()
	pairDocs["irp"] = &scepterDoc{Ver: "3.5.0", StateSeq: 1}
	pairAt = time.Now()
	pairMu.Unlock()
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	render := func() string {
		var b strings.Builder
		pairLines(&b)
		return b.String()
	}
	setFlying := func(f bool) {
		pairMu.Lock()
		pairFlying = f
		pairMu.Unlock()
	}
	setFlying(false)
	if out := render(); strings.Contains(out, "◇") {
		t.Errorf("an idle pair must not breathe:\n%s", out)
	}
	setFlying(true)
	bright := render()
	at = at.Add(pairBreathMS + 100*time.Millisecond)
	dim := render()
	if n1, n2 := strings.Count(bright+dim, "◇"), strings.Count(bright+dim, "◆"); n1 != 1 || n2 != 1 {
		t.Errorf("in flight the dot must alternate exactly (◇=%d ◆=%d):\nbright:\n%s\ndim:\n%s", n1, n2, bright, dim)
	}
}

// The non-interactive head is byte-identical across renders: no cascade, no
// flash, no count-up may leak into it.
func TestHomeHeadStaticWhenNonInteractive(t *testing.T) {
	homeTestHost(t)
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100")
	NonInteractive = true
	defer func() { NonInteractive = false }()
	os.WriteFile(filepath.Join(P.Conf, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	ti := &tunnelInfo{State: "up", RTT: 20}
	render := func() string {
		var b strings.Builder
		homeHead(&b, []string{"ir"}, map[string]*tunnelInfo{"ir": ti}, nil, false)
		return b.String()
	}
	first, second := render(), render()
	if first != second {
		t.Errorf("non-interactive head must be byte-stable:\n%s\n---\n%s", first, second)
	}
	if strings.Contains(first, "\x1b") {
		t.Errorf("non-interactive head must carry no escapes:\n%q", first)
	}
}
