// Scepter local-wiring tests (3.5.0): the .pairing store format and its readers (F1), the -pair-to attach
// action (F2) and the file poller that makes revocation instant (F8-revoke, 2026-11-22).

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func testPairingLine(caps string) string {
	return "watp1:1|0a0b0c0d-0e0f-1011-1213-141516171819|" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|" + caps
}

// writePairingStore writes a raw store file the way the manager does (credential line + '# ' bookkeeping).
func writePairingStore(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReadPairingFileStoreFormat (F1, 2026-11-22): the store's line 1 is the watp1: credential, the rest is
// '# ' bookkeeping — only the credential line is parsed; a store without a watp1: first content line is
// rejected, and the legacy key=value shape names its format instead of failing with a generic parse error.
func TestReadPairingFileStoreFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")

	// credential + the manager's bookkeeping tail: loads
	writePairingStore(t, path, testPairingLine("manage")+"\n# attached to t1 2026-11-22\n# rotated from ...\n")
	p, err := readPairingFile(path)
	if err != nil {
		t.Fatalf("comment tail must be tolerated: %v", err)
	}
	if p.UUIDString() != "0a0b0c0d-0e0f-1011-1213-141516171819" || wat.CapName(p.Caps) != "manage" {
		t.Fatalf("wrong credential: %s %d", p.UUIDString(), p.Caps)
	}

	// blank lines and a leading comment (a rewritten store) also load
	writePairingStore(t, path, "\n# manager bookkeeping\n"+testPairingLine("full")+"\n")
	if p, err = readPairingFile(path); err != nil || wat.CapName(p.Caps) != "full" {
		t.Fatalf("leading comment/blank lines: %v %d", err, p.Caps)
	}

	// the credential line wins even with more content after it
	writePairingStore(t, path, testPairingLine("tunnel")+"\nwatp1:1|x|y|manage\n")
	if p, err = readPairingFile(path); err != nil || wat.CapName(p.Caps) != "tunnel" {
		t.Fatalf("first content line is the credential: %v %d", err, p.Caps)
	}

	// legacy pre-2026112211 manager store: rejected, error names the format (the manager converts these)
	writePairingStore(t, path, "version=1\nuuid=u\nkey=k\n")
	_, err = readPairingFile(path)
	if err == nil || !strings.Contains(err.Error(), "legacy key=value") {
		t.Fatalf("legacy store must name its format: %v", err)
	}

	// arbitrary garbage: the parse error, not the legacy one
	writePairingStore(t, path, "hello world\n")
	_, err = readPairingFile(path)
	if err == nil || strings.Contains(err.Error(), "legacy") {
		t.Fatalf("garbage store: %v", err)
	}

	// comments only: nothing to load
	writePairingStore(t, path, "# nothing here\n\n")
	if _, err = readPairingFile(path); err == nil || !strings.Contains(err.Error(), "no watp1:") {
		t.Fatalf("comment-only store: %v", err)
	}

	// missing file: os.ErrNotExist, so attachStoredPairing can keep the normal unpaired case silent
	if _, err = readPairingFile(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing store: %v", err)
	}
}

// TestAttachStoredPairing (F2b/F1): the default attach loads a good store, stays silent on a missing one and
// warns exactly once with the path when the store exists but cannot be used — an owner moving the file (or a
// legacy store from an old manager) must degrade the cockpit, never kill the tunnel. The missing-file error
// surfaces to the caller so a `pairing: true` run can warn about its own opt-in.
func TestAttachStoredPairing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	logs := []string{}
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }

	p, err := attachStoredPairing(path, logf)
	if err == nil || p != nil || len(logs) != 0 || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing store: silent unpaired attach, got %v %v %v", p, err, logs)
	}

	writePairingStore(t, path, testPairingLine("manage")+"\n# bookkeeping\n")
	p, err = attachStoredPairing(path, logf)
	if err != nil || p == nil || wat.CapName(p.Caps) != "manage" || len(logs) != 0 {
		t.Fatalf("good store: must attach, got %v %v %v", p, err, logs)
	}

	writePairingStore(t, path, "version=1\nuuid=u\n")
	p, err = attachStoredPairing(path, logf)
	if err == nil || p != nil || len(logs) != 1 || !strings.Contains(logs[0], path) || !strings.Contains(logs[0], "legacy") {
		t.Fatalf("unusable store: one warning naming the path, got %v %v %v", p, err, logs)
	}
}

// TestAttachPairingAction (F2a): the -pair-to body stores the credential, marks the yml `pairing: true` and
// is idempotent — the attach flow the Go manager drives (it execs wattun -pair-to and waits for exit 0).
func TestAttachPairingAction(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "t1.yml")
	yml := "mode: client\nkey: kk\npeer: 198.51.100.7\nports:\n  - 10001\n"
	if err := os.WriteFile(cfg, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := []string{}
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }

	if err := attachPairing(cfg, testPairingLine("manage"), logf); err != nil {
		t.Fatalf("attach: %v", err)
	}
	// the credential is stored and loads back
	p, err := readPairingFile(filepath.Join(dir, ".pairing"))
	if err != nil || wat.CapName(p.Caps) != "manage" {
		t.Fatalf("stored credential: %v %d", err, p.Caps)
	}
	// the yml gained the key, still parses with the ports list intact, and a later start would see it
	marked := mustReadExisting(t, cfg)
	if !strings.HasSuffix(strings.TrimSpace(marked), "pairing: true") {
		t.Fatalf("yml must gain `pairing: true`:\n%s", marked)
	}
	fc, err := parseConfig(marked, nil)
	if err != nil || len(fc.Ports) != 1 || fc.Ports[0].Port != 10001 {
		t.Fatalf("marked yml must still parse:\n%s (%v)", marked, err)
	}
	if _, ok := fc.get("pairing"); !ok {
		t.Fatal("parseConfig must see the pairing key")
	}
	// a second attach is a no-op on the yml (the key is already there)
	if err := attachPairing(cfg, testPairingLine("full"), logf); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if again := mustReadExisting(t, cfg); strings.Count(again, "pairing:") != 1 {
		t.Fatalf("re-attach must not duplicate the key:\n%s", again)
	}
	// an invalid line is the one fatal path (kept from the old behavior)
	if err := attachPairing(cfg, "watp1:1|x|y|manage", logf); err == nil {
		t.Fatal("an invalid watp1: line must fail")
	}
}

// TestPairingPollerTransitions (F8-revoke, 2026-11-22): the poller watches the store — a changed file
// reloads the credential (caps swap observable via PairingInfo), a removed or unparsable file disarms, a
// restored file re-arms, and no change re-logs or reloads. The interval is a var seam; the transitions here
// are driven by calling check() directly.
func TestPairingPollerTransitions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	writePairingStore(t, path, testPairingLine("manage")+"\n")

	p1, err := wat.ParsePairingLine(testPairingLine("manage"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := wat.NewScepterState(p1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logs := []string{}
	pl := &pairingPoller{path: path, scepter: st, logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }, interval: time.Hour}
	startPairingPoller(pl) // arms from the store's state; the run loop never ticks within the test (interval 1 h)
	if u, caps := st.PairingInfo(); u != p1.UUIDString() || wat.CapName(caps) != "manage" {
		t.Fatalf("initial arm: %s %d", u, caps)
	}

	bump := func(content string) { // rewrite + a fresh mtime: the mtime+size change is the poller's trigger
		writePairingStore(t, path, content)
		fut := time.Now().Add(2 * time.Second)
		os.Chtimes(path, fut, fut)
	}
	uuidOf := func(line string) string {
		p, err := wat.ParsePairingLine(line)
		if err != nil {
			t.Fatal(err)
		}
		return p.UUIDString()
	}

	// rotation: same UUID, different caps → reloaded, one "changed" log
	pl.check()
	if u, caps := st.PairingInfo(); u != uuidOf(testPairingLine("manage")) || wat.CapName(caps) != "manage" {
		t.Fatalf("unchanged poll must not reload: %s %d", u, caps)
	}
	if len(logs) != 0 {
		t.Fatalf("unchanged poll must not log: %v", logs)
	}
	bump(testPairingLine("full") + "\n# rotated\n")
	pl.check()
	if _, caps := st.PairingInfo(); wat.CapName(caps) != "full" {
		t.Fatalf("rotation must swap the caps: %d", caps)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "reloaded") {
		t.Fatalf("rotation log: %v", logs)
	}

	// revocation: the file is gone → disarmed, tunnel keeps running; logged once, not per tick
	os.Remove(path)
	pl.check()
	if u, caps := st.PairingInfo(); u != "" || caps != 0 {
		t.Fatalf("removed store must disarm: %s %d", u, caps)
	}
	before := len(logs)
	pl.check()
	if len(logs) != before {
		t.Fatalf("a stay-disarmed poll must not re-log: %v", logs)
	}

	// restore: the file is back → re-armed
	bump(testPairingLine("manage") + "\n")
	pl.check()
	if u, caps := st.PairingInfo(); u != uuidOf(testPairingLine("manage")) || wat.CapName(caps) != "manage" {
		t.Fatalf("restored store must re-arm: %s %d", u, caps)
	}

	// corrupted: an unparsable rewrite disarms (and later parses are not retried until it changes again)
	bump("version=1\nuuid=u\n")
	pl.check()
	if u, _ := st.PairingInfo(); u != "" {
		t.Fatalf("unparsable store must disarm: %s", u)
	}
}

// TestPairingPollerNotForConfigKeyPairing pins the scope note in the attach switch: only a FILE-backed
// credential is pollable. The poller starts only when pairingFromFile is set — a static pin on the wiring,
// because the condition is what keeps a config-key watp1: pairing from pretending to be revocable.
func TestPairingPollerNotForConfigKeyPairing(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "if pairingFromFile {") || !strings.Contains(src, "startPairingPoller(&pairingPoller{") {
		t.Fatal("the server path must start the poller only for file-backed pairings (pairingFromFile)")
	}
	if !strings.Contains(src, "static by definition") {
		t.Fatal("the config-key-pairing caveat must be documented where the attach happens")
	}
}

// TestPairingPollerLatchFollows: the latch follows the credential (2026-11-22 wave 2) — a rotation swaps
// the monitor's pairing (the next arm derives the latch PSK from the NEW key), a revocation revokes the
// monitor itself so a revoked pair's latch can never accept proofs again.
func TestPairingPollerLatchFollows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	writePairingStore(t, path, testPairingLine("manage")+"\n")

	p1, err := wat.ParsePairingLine(testPairingLine("manage"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := wat.NewScepterState(p1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	mon := &latchMonitor{pair: p1, scepter: st, alive: func() bool { return true }, port: 20999,
		logf: func(string, ...any) {}} // alive stays true: a rePair may spawn the run loop (round-2 F9),
	// and an inert loop (stand-down every tick, never arms) must not bind the test's port behind our back
	logs := []string{}
	pl := &pairingPoller{path: path, scepter: st, latch: mon,
		logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }, interval: time.Hour}
	startPairingPoller(pl)
	if mon.status()["revoked"].(bool) {
		t.Fatal("fresh monitor must not be revoked")
	}

	// rotation: the monitor's pairing is swapped (status stays enabled, not revoked)
	writePairingStore(t, path, testPairingLine("full")+"\n")
	fut := time.Now().Add(2 * time.Second)
	os.Chtimes(path, fut, fut)
	pl.check()
	if mon.status()["revoked"].(bool) {
		t.Fatal("a rotation must not revoke the monitor")
	}
	p2, err := wat.ParsePairingLine(testPairingLine("full"))
	if err != nil {
		t.Fatal(err)
	}
	mon.mu.Lock()
	swapped := mon.pair != nil && mon.pair.UUIDString() == p2.UUIDString()
	mon.mu.Unlock()
	if !swapped {
		t.Fatal("rotation must swap the monitor's pairing (the next arm derives the PSK from the new key)")
	}

	// revocation: the monitor is revoked and its listener stands down — the run loop exits on the next tick
	os.Remove(path)
	pl.check()
	if !mon.status()["revoked"].(bool) {
		t.Fatal("a removed store must revoke the monitor")
	}
}

// TestScepterAttachSwitch (round-2 F11, 2026-11-22): the attach switch is a function now, and `pairing:
// false` is an explicit opt-out — the stored file stays unattached (it used to fall to the default attach,
// so the key could not actually turn the channel off). Absent key and `true` attach the stored file; a
// watp1: value is never file-backed; an explicitly provided invalid one stays fatal for main. The token
// bootstrap is nil here: no field 10 = exactly the pre-bootstrap behavior.
func TestScepterAttachSwitch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	logs := []string{}
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }

	// explicit false: no attach, no arm, nothing logged
	p, origin, err := scepterAttach("false", path, nil, logf)
	if err != nil || p != nil || origin != scepterNone || len(logs) != 0 {
		t.Fatalf("pairing: false must opt out silently: %v %v %v %v", p, origin, err, logs)
	}
	// absent key + stored file: attach, file-backed
	writePairingStore(t, path, testPairingLine("manage")+"\n")
	p, origin, err = scepterAttach("", path, nil, logf)
	if err != nil || p == nil || origin != scepterFromFile || wat.CapName(p.Caps) != "manage" {
		t.Fatalf("absent key must attach the stored file: %v %v %v", p, origin, err)
	}
	// true + stored file: attach, file-backed
	p, origin, err = scepterAttach("true", path, nil, logf)
	if err != nil || p == nil || origin != scepterFromFile {
		t.Fatalf("true must attach the stored file: %v %v %v", p, origin, err)
	}
	// true + missing file + no token: unpaired with the one missing warning
	os.Remove(path)
	logs = nil
	p, origin, err = scepterAttach("true", path, nil, logf)
	if err != nil || p != nil || origin != scepterNone || len(logs) != 1 {
		t.Fatalf("true with a missing store: %v %v %v %v", p, origin, err, logs)
	}
	// a watp1: value: attached but NOT file-backed (the static, unpollable kind)
	p, origin, err = scepterAttach(testPairingLine("full"), path, nil, logf)
	if err != nil || p == nil || origin != scepterFromKey || wat.CapName(p.Caps) != "full" {
		t.Fatalf("watp1: value: %v %v %v", p, origin, err)
	}
	// an explicitly provided invalid watp1: line: the error main turns into log.Fatalf
	if _, _, err = scepterAttach("watp1:1|x|y|manage", path, nil, logf); err == nil {
		t.Fatal("an invalid watp1: line must fail")
	}
}

// testToken builds a classic wat1: token the way the manager's MakeToken does (7 pipe fields, fields 8/9
// riding along only when the optional field 10 is set, base64-wrapped).
func testToken(key, field10 string) string {
	f := "udp|198.51.100.7:20030|" + key + "|/wat|||20030"
	if field10 != "" {
		f += "|1||" + field10
	}
	return "wat1:" + base64.StdEncoding.EncodeToString([]byte(f))
}

// TestParseTokenKey: the tunnel key may BE the classic wat1: token (D5 bootstrap, owner directive
// 2026-11-22) — field 3 is the PSK the tunnel runs on, field 10 (written only when set) is the pairing
// bootstrap; a plain PSK and a field-10-less token are exactly today's behavior, and a wat1:-prefixed
// value that does not parse fails loud (a pasted token can never work as a literal PSK).
func TestParseTokenKey(t *testing.T) {
	k, tp, err := parseTokenKey([]byte("plain-psk-40-chars-alphanumeric-only"))
	if err != nil || string(k) != "plain-psk-40-chars-alphanumeric-only" || tp != nil {
		t.Fatalf("plain PSK must pass through untouched: %q %v %v", k, tp, err)
	}
	k, tp, err = parseTokenKey([]byte(testToken("kk", "")))
	if err != nil || string(k) != "kk" || tp != nil {
		t.Fatalf("field-10-less token: no bootstrap, PSK from field 3: %q %v %v", k, tp, err)
	}
	k, tp, err = parseTokenKey([]byte(testToken("kk", "pair=manage")))
	if err != nil || string(k) != "kk" || tp == nil || tp.field10 != "pair=manage" || tp.key != "kk" {
		t.Fatalf("token with field 10: %q %+v %v", k, tp, err)
	}
	// unpadded base64 tolerated (base64 -d parity with the manager's ReadToken)
	raw := "udp|h:1|kk2||||20030|1||pair"
	unpadded := "wat1:" + base64.RawStdEncoding.EncodeToString([]byte(raw))
	k, tp, err = parseTokenKey([]byte(unpadded))
	if err != nil || string(k) != "kk2" || tp == nil || tp.field10 != "pair" {
		t.Fatalf("unpadded token: %q %v %v", k, tp, err)
	}
	// quoted yml value shape: the unquote already stripped, whitespace tolerated
	k, _, err = parseTokenKey([]byte("  " + testToken("kk", "pair") + "\n"))
	if err != nil || string(k) != "kk" {
		t.Fatalf("whitespace around a token key: %q %v", k, err)
	}
	if _, _, err = parseTokenKey([]byte("wat1:!!!not-base64!!!")); err == nil {
		t.Fatal("a wat1:-prefixed key with bad base64 must fail loud")
	}
	if _, _, err = parseTokenKey([]byte("wat1:" + base64.StdEncoding.EncodeToString([]byte("udp|peer:1")))); err == nil {
		t.Fatal("a token without a key field must fail loud")
	}
}

// TestScepterAttachTokenDerived (D5 bootstrap, owner directive 2026-11-22): a token carrying field 10 arms
// BOTH roles with no `pairing:` key and no .pairing file — the pasted tunnel token is the only credential.
// Precedence: `pairing: false` beats everything; a readable stored file wins over the token (it is the
// rotate/revoke store); a present-but-unusable file stays unpaired rather than resurrecting a credential
// the file superseded; the token fills every remaining gap (`pairing: true` included); a malformed or
// lookalike field 10 degrades to unpaired with a warning, never fatal.
func TestScepterAttachTokenDerived(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	logs := []string{}
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	tok := func(field10 string) *tokenPair {
		_, tp, err := parseTokenKey([]byte(testToken("kk", field10)))
		if err != nil {
			t.Fatal(err)
		}
		return tp
	}

	// default attach, no file, token with pair=manage: derived, one exact log line
	p, origin, err := scepterAttach("", path, tok("pair=manage"), logf)
	if err != nil || p == nil || origin != scepterFromToken || wat.CapName(p.Caps) != "manage" {
		t.Fatalf("token-derived attach: %v %v %v", p, origin, err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "scepter: pairing derived from token field 10 (pairing ") ||
		!strings.Contains(logs[0], "capability manage)") {
		t.Fatalf("derivation log line: %v", logs)
	}
	// the derivation is deterministic per token key (both ends derive the same UUID)
	p2, _, _ := scepterAttach("", path, tok("pair=manage"), func(string, ...any) {})
	if p.UUIDString() != p2.UUIDString() {
		t.Fatal("the derived UUID must be stable per token key")
	}

	// a stored .pairing file WINS over the token bootstrap (file = rotate/revoke store)
	writePairingStore(t, path, testPairingLine("full")+"\n")
	logs = nil
	p, origin, err = scepterAttach("", path, tok("pair=manage"), logf)
	if err != nil || p == nil || origin != scepterFromFile || wat.CapName(p.Caps) != "full" {
		t.Fatalf("the stored file must win over the token: %v %v %v", p, origin, err)
	}
	if len(logs) != 0 {
		t.Fatalf("file-wins must not log a derivation: %v", logs)
	}

	// pairing: false beats the token bootstrap too
	p, origin, err = scepterAttach("false", path, tok("pair=full"), logf)
	if err != nil || p != nil || origin != scepterNone || len(logs) != 0 {
		t.Fatalf("pairing: false must beat the token bootstrap: %v %v %v %v", p, origin, err, logs)
	}

	// pairing: true + missing file + token: the bootstrap fills the gap, no missing-file warning
	os.Remove(path)
	logs = nil
	p, origin, err = scepterAttach("true", path, tok("pair=manage"), logf)
	if err != nil || p == nil || origin != scepterFromToken || wat.CapName(p.Caps) != "manage" || len(logs) != 1 {
		t.Fatalf("pairing: true with a missing store and a token: %v %v %v %v", p, origin, err, logs)
	}

	// a present-but-unusable file: unpaired, no token fallback (the store's presence is authoritative)
	writePairingStore(t, path, "version=1\nuuid=u\n")
	logs = nil
	p, origin, err = scepterAttach("", path, tok("pair=manage"), logf)
	if err != nil || p != nil || origin != scepterNone || len(logs) != 1 {
		t.Fatalf("unusable store beats the token: %v %v %v %v", p, origin, err, logs)
	}

	// malformed field 10: warn + unpaired, never fatal (the cockpit degrades, forwarding must not die)
	os.Remove(path)
	logs = nil
	if p, origin, err = scepterAttach("", path, tok("pair=bogus"), logf); err != nil || p != nil || origin != scepterNone {
		t.Fatalf("malformed field 10 must not be fatal: %v %v %v", p, origin, err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "token pairing bootstrap unusable") {
		t.Fatalf("malformed-field log: %v", logs)
	}

	// lookalike field ("pairxyz"): not a pairing credential (L5-strict), silently unpaired
	logs = nil
	if p, origin, err = scepterAttach("", path, tok("pairxyz"), logf); err != nil || p != nil || origin != scepterNone || len(logs) != 0 {
		t.Fatalf("lookalike field must be silently none: %v %v %v %v", p, origin, err, logs)
	}

	// regression: no token, no file = exactly today's behavior (nil, silent)
	if p, origin, err = scepterAttach("", path, nil, logf); err != nil || p != nil || origin != scepterNone || len(logs) != 0 {
		t.Fatalf("no token no file: %v %v %v %v", p, origin, err, logs)
	}
}

// TestPairingPollerDerivedMode: a token-derived run's poller watches the override store without requiring
// it — no file: the derived credential keeps serving; a file that appears overrides (the rotate/revoke
// store); its later removal disarms without falling back to the token (the file marked it superseded);
// a restored file re-arms.
func TestPairingPollerDerivedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	tok := "kk"
	dp, err := wat.ParsePairingTokenField("pair=manage", []byte(tok))
	if err != nil {
		t.Fatal(err)
	}
	st, err := wat.NewScepterState(dp, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logs := []string{}
	pl := &pairingPoller{path: path, scepter: st, derived: dp,
		logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }, interval: time.Hour}
	startPairingPoller(pl) // no store on disk: the derived credential is armed, fileSeen false

	// the store is absent: no disarm, no log — the token bootstrap is the running credential
	pl.check()
	if u, caps := st.PairingInfo(); u != dp.UUIDString() || wat.CapName(caps) != "manage" {
		t.Fatalf("derived credential must stay armed with no store: %s %d", u, caps)
	}
	if len(logs) != 0 {
		t.Fatalf("absent store on a derived run must stay silent: %v", logs)
	}

	// the store appears (the rotate/revoke store): it overrides
	writePairingStore(t, path, testPairingLine("full")+"\n")
	pl.check()
	if _, caps := st.PairingInfo(); wat.CapName(caps) != "full" {
		t.Fatalf("an appearing store must override the derived credential: caps %d", caps)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "changed — credential reloaded") {
		t.Fatalf("override log: %v", logs)
	}

	// the store is removed after having existed: disarmed, never a token fallback
	os.Remove(path)
	logs = nil
	pl.check()
	if u, _ := st.PairingInfo(); u != "" {
		t.Fatalf("removing a seen store must disarm (no token fallback): %s", u)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "removed") {
		t.Fatalf("removal log: %v", logs)
	}

	// the store is back: re-armed
	writePairingStore(t, path, testPairingLine("manage")+"\n")
	fut := time.Now().Add(2 * time.Second)
	os.Chtimes(path, fut, fut)
	pl.check()
	if u, caps := st.PairingInfo(); u == "" || wat.CapName(caps) != "manage" {
		t.Fatalf("a restored store must re-arm: %s %d", u, caps)
	}
}

// TestSetPairingKeyBOM (round-2 F12, 2026-11-22): a BOM'd first line must not defeat the existing-key scan
// — parseConfig trims the BOM, setPairingKey did not, so a BOM'd `pairing: true` went undetected and a
// second key was appended, which killed the boot.
func TestSetPairingKeyBOM(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "t1.yml")
	marked := "\xef\xbb\xbfpairing: true\nmode: client\nkey: kk\nports:\n  - 10001\n"
	if err := os.WriteFile(cfg, []byte(marked), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setPairingKey(cfg); err != nil {
		t.Fatalf("setPairingKey: %v", err)
	}
	if got := mustReadExisting(t, cfg); strings.Count(got, "pairing:") != 1 {
		t.Fatalf("a BOM'd pairing key must be detected (no duplicate key, no boot kill):\n%q", got)
	}
	// a BOM'd file without the key still gains it, and the result parses (the BOM stays — parseConfig
	// trims it the same way)
	if err := os.WriteFile(cfg, []byte("\xef\xbb\xbfmode: client\nkey: kk\nports:\n  - 10001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setPairingKey(cfg); err != nil {
		t.Fatalf("setPairingKey on a BOM'd file: %v", err)
	}
	got := mustReadExisting(t, cfg)
	if strings.Count(got, "pairing:") != 1 {
		t.Fatalf("the key must be appended exactly once:\n%q", got)
	}
	if fc, err := parseConfig(got, nil); err != nil || len(fc.Ports) != 1 {
		t.Fatalf("the BOM'd marked yml must still parse: %v", err)
	}
}

// TestPairingPollerSeed (round-2 F13, 2026-11-22): main stats the store right after the attach read and
// seeds the poller with that state, so a rotation in the startup gap between the read and the poller's own
// first stat is detected on the first check instead of being armed over.
func TestPairingPollerSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	writePairingStore(t, path, testPairingLine("manage")+"\n")
	p1, err := wat.ParsePairingLine(testPairingLine("manage"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := wat.NewScepterState(p1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// the attach read happened; the seed is main's post-read stat
	seed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// rotation during startup: the disk already holds the NEW credential when the poller starts
	writePairingStore(t, path, testPairingLine("full")+"\n")
	fut := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, fut, fut); err != nil {
		t.Fatal(err)
	}
	pl := &pairingPoller{path: path, scepter: st,
		logf: func(f string, a ...any) {}, interval: time.Hour,
		seedMt: seed.ModTime(), seedSz: seed.Size(), seeded: true}
	startPairingPoller(pl)
	pl.check() // the seeded state (old) vs disk (new): the rotation is a change on the very first check
	if _, caps := st.PairingInfo(); wat.CapName(caps) != "full" {
		t.Fatalf("the startup-gap rotation must be reloaded on the first check: caps %d", caps)
	}
}
