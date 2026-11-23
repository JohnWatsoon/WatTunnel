// Scepter local wiring (3.5.0, phase A): the pairing file, the unit source that feeds the read-only cockpit
// commands, the log ring behind tunnel.logs, and the client-side keepalive loop. Everything here is active only
// when a pairing credential exists; the default run never touches it.

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// writePairingFile stores a pairing credential atomically (tmp + rename, the manager-file discipline) with
// mode 0600: the credential is root-only local state, like the key files.
func writePairingFile(path string, p *wat.PairingConfig) error {
	if err := os.MkdirAll(dirOf(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(p.Line()+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readPairingFile loads the stored credential: the first content line must be the watp1: line, everything
// after it (and blank lines before it) is the manager's '# ' bookkeeping and is ignored (F1, 2026-11-22 — the
// whole file was once fed to ParsePairingLine, so any store with a comment tail failed to load). A first
// content line that is not a watp1: credential is rejected; the key=value shape of the pre-2026112211 manager
// stores gets its own error naming the format — the manager knows how to convert those, this parser must not
// guess at them.
func readPairingFile(path string) (*wat.PairingConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "revoked") { // the revoke tombstone (Handoff 4 R3): beats the token bootstrap
			return nil, fmt.Errorf("%s: %w", path, errPairingRevoked)
		}
		p, perr := wat.ParsePairingLine(t)
		if perr == nil {
			return p, nil
		}
		if !strings.HasPrefix(t, "watp1:") && strings.Contains(t, "=") {
			return nil, fmt.Errorf("%s: legacy key=value pairing store (pre-2026112211 manager format); re-pair to convert it to a watp1: store", path)
		}
		return nil, fmt.Errorf("%s: %v", path, perr)
	}
	return nil, fmt.Errorf("%s: no watp1: credential line in the pairing store", path)
}

// errPairingRevoked marks a revoke tombstone: a .pairing whose first line is "revoked <uuid> <time>". Its
// presence keeps the unit unpaired — unlike a deleted store, which a token-derived unit would re-derive.
var errPairingRevoked = errors.New("pairing revoked on this server")

// storePairingClaim writes the credential the first Iran claimed (Handoff 4 R2) as the server's .pairing
// store: from now on it, not the token, is the pairing, and every other unit's poller adopts it.
func storePairingClaim(path string, p *wat.PairingConfig) error {
	body := p.Line() + "\n# claimed by the first paired Iran over the token bootstrap, " + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"# revoke: replace this file with a 'revoked' line; allow a new Iran to pair: delete this file\n"
	return atomicWriteFile(path, []byte(body), 0o600)
}

// claimsPath is a client's store of the credentials it claimed (one watp1: line each). It is separate from
// .pairing, which on a box that also runs a server tunnel is that server's own credential.
func claimsPath(cfgPath string) string {
	if cfgPath == "" {
		return ""
	}
	return dirOf(cfgPath) + "/.pairing.claims"
}

// readClaims returns every credential in the claims store; unreadable lines are skipped.
func readClaims(path string) []*wat.PairingConfig {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []*wat.PairingConfig
	for _, line := range strings.Split(string(b), "\n") {
		if p, err := wat.ParsePairingLine(strings.TrimSpace(line)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// addClaim appends a claimed credential (deduplicated by uuid) to the claims store, atomically, 0600.
func addClaim(path, line string) error {
	np, err := wat.ParsePairingLine(line)
	if err != nil {
		return err
	}
	var lines []string
	for _, p := range readClaims(path) {
		if p.UUID != np.UUID {
			lines = append(lines, p.Line())
		}
	}
	lines = append(lines, np.Line())
	return atomicWriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	return "."
}

// attachStoredPairing is the run's default attach (F2, 2026-11-22): both roles pick up the stored credential
// when it exists (-pair wrote it on Kharej, -pair-to on Iran — both roles attach, which is what the
// pre-wave-2 code only did for the server). A missing file is the normal unpaired case and stays
// silent; a present but unusable one (a legacy key=value store from an old manager, a corrupted store) warns
// with the path and the reason and the tunnel runs unpaired — the cockpit degrades, forwarding must not die
// because the owner moved a file. The read error is returned so a caller that explicitly opted in
// (`pairing: true`) can warn on the missing file too; the caller marks an attached pairing file-backed
// (pollable, F8-revoke).
func attachStoredPairing(path string, logf func(string, ...any)) (*wat.PairingConfig, error) {
	p, err := readPairingFile(path)
	if err == nil {
		return p, nil
	}
	if errors.Is(err, errPairingRevoked) {
		logf("scepter: the pairing was revoked here (%s); running without the cockpit channel", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		logf("scepter: stored pairing %s unusable (%v); running without the cockpit channel", path, err)
	}
	return nil, err
}

// setPairingKey marks the tunnel yml with `pairing: true` (F2a, 2026-11-22): the -pair-to attach action
// writes this so every later start opens the cockpit channel without the line being passed again. tmp + rename
// (the manager-file discipline — the unit's cfgWatcher polls this file every 3 s, so a half-written yml must
// never land), and the original mode is kept. A pairing key already present (true, false or a full watp1:
// line) is left alone: whatever is there stays the owner's authority.
func setPairingKey(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	txt := strings.TrimPrefix(string(b), "\xef\xbb\xbf") // a BOM (Notepad, PowerShell) must not hide the first
	// line's key from this scan — parseConfig's own rule (round-2 F12, 2026-11-22): a BOM'd `pairing: true`
	// first line went undetected and a second key was appended, which killed the boot
	for _, line := range strings.Split(txt, "\n") {
		t := strings.TrimSpace(stripComment(line))
		if t == "" || strings.HasPrefix(t, "- ") {
			continue
		}
		if k, _, ok := strings.Cut(t, ":"); ok && strings.TrimSpace(k) == "pairing" {
			return nil
		}
	}
	// appended at the end: an unindented key line closes any ports:/limits: list context (config.go), so the
	// position is safe no matter how the file is laid out
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.TrimRight(string(b), "\n")+"\npairing: true\n"), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// attachPairing is the -pair-to action body (F2a, 2026-11-22): validate the watp1: line, store the
// credential, mark the tunnel yml. main() log.Fatal-wraps the error and exits 0 on success — the old
// -pair-to stored the file and then ran the tunnel forever, hanging the Go manager's attach flow
// (exec + CombinedOutput) and never re-reading the file at start.
func attachPairing(cfgPath, line string, logf func(string, ...any)) error {
	p, err := wat.ParsePairingLine(line)
	if err != nil {
		return err
	}
	ppath := pairingFilePath(cfgPath)
	if err := writePairingFile(ppath, p); err != nil {
		return err
	}
	if err := setPairingKey(cfgPath); err != nil {
		return fmt.Errorf("cannot mark %s: %v", cfgPath, err)
	}
	logf("pairing %s attached to %s (stored in %s, capability %s); restart the tunnel to open the cockpit channel",
		p.UUIDString(), cfgPath, ppath, wat.CapName(p.Caps))
	return nil
}

// tokenPair is the pairing bootstrap carried by a classic wat1: token used as the tunnel key (plan D5's
// classic-token bootstrap, wired per the owner directive of 2026-11-22: the setup is fully automated — the
// credential the user already pastes must set the pairing up with no extra steps). field10 is the token's
// optional 10th pipe field, "pair" or "pair=<tier>", strictly shaped (wat.ParsePairingTokenField); key is
// the token's key field, the secret the pairing credential (UUID included) is derived from. Both ends of
// the pair derive from the same token, so UUID, LatchKey and LatchPath agree without anything being
// distributed. A token without field 10 parses to nil: exactly today's behavior.
type tokenPair struct {
	field10, key string
}

// parseTokenKey splits the tunnel's key material when it is a classic wat1: token (the manager's layout:
// carrier|peer|key|path|sni|icmp|ports[|rev][|auto][|pair], base64-wrapped — the Go manager's ReadToken is
// the layout reference; unpadded base64 tolerated like base64 -d). It returns the PSK the tunnel runs on
// (field 3) and, when field 10 is present and non-empty, the pairing bootstrap. Anything that does not
// start with wat1: is returned untouched — a plain PSK is exactly today's behavior, and no legitimate PSK
// can collide (the manager mints alphanumerics only). A wat1:-prefixed value that does not parse is an
// error: a pasted token can never work as a literal PSK, so failing loud beats a tunnel that silently
// cannot connect. Only field 3 is read here — the carrier/peer/path fields are the manager's business, the
// yml's own keys rule the engine.
func parseTokenKey(raw []byte) ([]byte, *tokenPair, error) {
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, "wat1:") {
		return raw, nil, nil
	}
	b64 := strings.TrimPrefix(s, "wat1:")
	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if d, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "=")); err != nil {
			return nil, nil, fmt.Errorf("the key is a wat1: token but its base64 does not parse: %v", err)
		}
	}
	f := strings.Split(string(d), "|")
	if len(f) < 3 || f[2] == "" {
		return nil, nil, fmt.Errorf("the key is a wat1: token without a key field (want carrier|peer|key|...)")
	}
	var tp *tokenPair
	if len(f) >= 10 && f[9] != "" { // field 10 written only when set, like fields 8/9 — old tokens end at 7
		tp = &tokenPair{field10: f[9], key: f[2]}
	}
	return []byte(f[2]), tp, nil
}

// scepterOrigin marks where the attached credential came from — it decides the revocation surface.
type scepterOrigin int

const (
	scepterNone     scepterOrigin = iota // no credential: the pre-3.5 unpaired run
	scepterFromFile                      // the stored .pairing file: the pollable, revocation-live kind
	scepterFromKey                       // a config-key watp1: line: static by definition (no file to poll; revoking
	// it means restarting the unit without the key)
	scepterFromToken // derived from the tunnel token's field 10: armed at load; a .pairing that appears later
	// IS the rotate/revoke store and overrides it (the derived-mode poller), but the file is not required
)

// scepterAttach is main's Scepter attach switch, extracted as a function so the decision is testable
// (round-2 F11, 2026-11-22). pairingKey is the `pairing:` config value ("" when the key is absent); tok is
// the tunnel token's pairing bootstrap (nil when the key material was not a wat1: token carrying field 10).
// Precedence, highest first: an explicit `false` opts out entirely (no attach, no arm, nothing logged —
// the key must actually turn the channel off); a full watp1: value is that credential; a readable stored
// .pairing file WINS over the token bootstrap (the file is the rotate/revoke store — a corrupt one stays
// unpaired rather than silently resurrecting a credential the file superseded); the token bootstrap fills
// the gap (D5, owner directive 2026-11-22 — `pairing: true` is no longer needed for the channel to open).
// Returns the credential (nil = run unpaired), where it came from, and the error that stays fatal in main
// (an explicitly provided invalid watp1: line; a token-derived failure only warns — the cockpit degrades,
// forwarding must not die, the same posture as the stored-file branch).
func scepterAttach(pairingKey, pairPath string, tok *tokenPair, logf func(string, ...any)) (*wat.PairingConfig, scepterOrigin, error) {
	if pairingKey == "false" {
		return nil, scepterNone, nil // explicit opt-out beats everything, the token bootstrap included
	}
	if pairingKey != "" && strings.HasPrefix(pairingKey, "watp1:") {
		p, err := wat.ParsePairingLine(pairingKey)
		if err != nil {
			return nil, scepterNone, err
		}
		return p, scepterFromKey, nil
	}
	if p, aerr := attachStoredPairing(pairPath, logf); aerr == nil {
		return p, scepterFromFile, nil
	} else if !errors.Is(aerr, os.ErrNotExist) {
		return nil, scepterNone, nil // present but unusable: attachStoredPairing warned; the store's
		// presence is authoritative — falling back to the token could revive a credential it superseded
	}
	if tok == nil {
		if pairingKey != "" {
			// `pairing: true` (yml or flag) but neither a stored credential nor a token bootstrap: run
			// unpaired with one warning (F2, 2026-11-22 — an owner may move the file; the cockpit degrades,
			// the tunnel keeps working). An unusable file was already warned by attachStoredPairing.
			logf("scepter: pairing key set but the stored pairing %s is missing; running without the cockpit channel", pairPath)
		}
		return nil, scepterNone, nil
	}
	p, derr := wat.ParsePairingTokenField(tok.field10, []byte(tok.key))
	if derr != nil {
		logf("scepter: token pairing bootstrap unusable (%v); running without the cockpit channel", derr)
		return nil, scepterNone, nil
	}
	if p == nil { // a lookalike field ("pairxyz"): not a pairing credential (L5-strict), silently none
		return nil, scepterNone, nil
	}
	logf("scepter: pairing derived from token field 10 (pairing %s, capability %s)", p.UUIDString(), wat.CapName(p.Caps))
	return p, scepterFromToken, nil
}

// pairingPollInterval is the .pairing watch cadence (F8-revoke). Var, not const: the tests shrink it.
var pairingPollInterval = 5 * time.Second

// pairingPoller watches the stored pairing file — the ENGINE side wiring of the plan security requirement
// "revocation is instant and local" (F8-revoke, 2026-11-22; the .pairing store is Kharej's revocation
// surface): file gone or now unparsable → ScepterState.ReloadPairing(nil) disarms the management channel
// (live scepter streams reset mid-line, new ones refused; the tunnel and its sessions keep running), a
// changed file (mtime+size differ, the cfgWatcher's own test) → the new credential is loaded. Every
// transition logs once, not per tick.
//
// Two modes. File-backed (derived == nil, main starts it when the credential came off disk): the file is
// the credential, a missing file disarms. Derived-mode (derived set, started over a token-bootstrap
// credential, owner directive 2026-11-22): the file is the OVERRIDE store — it does not exist yet and that
// is normal (the token armed the channel); a file that appears or changes overrides the derived
// credential, and its later removal disarms the channel without falling back to the token (the file's
// existence marked the token superseded; a restart re-derives per the attach switch's precedence —
// revoking a token-derived pair means issuing a new token). A config-key watp1: pairing is static by
// definition: there is no file to poll, and revoking it means restarting the unit without the key.
type pairingPoller struct {
	path     string
	scepter  *wat.ScepterState
	latch    *latchMonitor // optional: the latch follows the credential (revoke = stand down permanently, rotate = re-arm from the new key)
	logf     func(string, ...any)
	interval time.Duration

	// Derived-mode base: the token-bootstrap credential the channel was armed with. nil = file-backed.
	derived *wat.PairingConfig
	// reclaim re-arms the token bootstrap claim (Handoff 4 R2) when a derived-mode store is deleted: deleting
	// the store is the console's "allow a new Iran to pair"; revoking writes a tombstone instead.
	reclaim func()

	// round-2 F13 (2026-11-22): the optional seed. main stats the store right after the attach read and
	// passes that state here, so a rotation in the startup gap between the read and the poller's own first
	// stat is seen as a change on the first check instead of being armed over.
	seedMt time.Time
	seedSz int64
	seeded bool

	mu       sync.Mutex
	mt       time.Time
	sz       int64
	armed    bool
	fileSeen bool // a store was present at least once: its later removal is a revocation, never a
	// fall back to the derived credential
}

func startPairingPoller(p *pairingPoller) {
	if p.seeded {
		p.mt, p.sz = p.seedMt, p.seedSz
		p.fileSeen = true
	} else if st, err := os.Stat(p.path); err == nil { // the credential was just loaded from this file: arm from its state
		p.mt, p.sz = st.ModTime(), st.Size()
		p.fileSeen = true
	}
	p.armed = true // the caller armed cfg.Pairing (from the file or the token bootstrap) before starting us
	go p.run()
}

func (p *pairingPoller) run() {
	for range time.Tick(p.interval) {
		p.check()
	}
}

// check is one poll step; split from run so the tests drive transitions without sleeping.
func (p *pairingPoller) check() {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, err := os.Stat(p.path)
	if err != nil {
		if p.fileSeen && p.derived != nil && p.reclaim != nil {
			p.scepter.ReloadPairing(p.derived)
			p.reclaim()
			if p.latch != nil {
				p.latch.rePair(p.derived)
			}
			p.armed, p.fileSeen = true, false
			p.logf("scepter: pairing file %s removed — the token bootstrap is claimable again (the next Iran to connect pairs)", p.path)
			p.mt, p.sz = time.Time{}, -1
			return
		}
		if p.armed && p.fileSeen {
			// Derived-mode runs with no store on disk keep the token-derived credential: the file is the
			// override store, not a requirement (owner directive 2026-11-22). Only a store that existed at
			// least once is a revocation when it disappears — falling back to the token would revive a
			// credential the file superseded.
			p.scepter.ReloadPairing(nil)
			if p.latch != nil {
				p.latch.revoke()
			}
			p.armed = false
			p.logf("scepter: pairing file %s removed — management channel disarmed, the tunnel keeps running", p.path)
		}
		p.mt, p.sz = time.Time{}, -1
		return
	}
	changed := !st.ModTime().Equal(p.mt) || st.Size() != p.sz
	if !changed {
		return
	}
	p.mt, p.sz = st.ModTime(), st.Size()
	pair, perr := readPairingFile(p.path)
	if perr != nil {
		if p.armed {
			p.scepter.ReloadPairing(nil)
			if p.latch != nil {
				p.latch.revoke()
			}
			p.armed = false
			p.fileSeen = true // a broken override store counts as seen: its removal revokes, never falls back
			p.logf("scepter: pairing file %s unusable (%v) — management channel disarmed, the tunnel keeps running", p.path, perr)
		}
		return
	}
	if p.armed && p.scepter.Holds(pair) {
		p.fileSeen = true // this process wrote it (the claim): nothing to reload, but the latch still keys from the token
		if p.latch != nil {
			p.latch.rePair(pair)
		}
		return
	}
	if p.armed {
		p.logf("scepter: pairing file %s changed — credential reloaded (pairing %s, capability %s)", p.path, pair.UUIDString(), wat.CapName(pair.Caps))
	} else {
		p.logf("scepter: pairing file %s restored — management channel armed (pairing %s, capability %s)", p.path, pair.UUIDString(), wat.CapName(pair.Caps))
	}
	p.scepter.ReloadPairing(pair)
	if p.latch != nil {
		p.latch.rePair(pair)
	}
	p.armed, p.fileSeen = true, true
}

// unitSource adapts THIS wattun process to the Scepter read commands. One process serves one unit (the systemd
// template runs wattun@NAME per tunnel config); multi-tunnel aggregation over the pair is a later phase. name is
// the config file's base name, so the cockpit sees the same names `wattun-manager` shows on Kharej.
type unitSource struct {
	name, carrier, metrics string
	statsf                 func() wat.Stats
	alivef                 func() bool
	hist                   *statsHistory
	logs                   *logRing
}

func (u *unitSource) Tunnels() []wat.ScepterTunnelInfo {
	state, health := "inactive", "down"
	if u.alivef() {
		state, health = "active", "ok"
	}
	return []wat.ScepterTunnelInfo{{
		Name: u.name, Carrier: u.carrier, State: state, Health: health, Metrics: u.metrics,
	}}
}

func (u *unitSource) TunnelStats(name string) (map[string]any, bool) {
	if name != u.name {
		return nil, false
	}
	st := u.statsf()
	return map[string]any{
		"name": u.name, "alive": u.alivef(), "streams": st.Streams, "rate_bps": st.RateBps,
		"srtt_ms": float64(st.SRTT) / 1e6, "min_rtt_ms": float64(st.MinRTT) / 1e6,
		"pkts_in": st.PktsIn, "pkts_out": st.PktsOut, "bytes_in": st.BytesIn, "bytes_out": st.BytesOut,
		"retrans": st.Retrans, "loss_pct": st.LossPct,
	}, true
}

func (u *unitSource) TunnelLogs(name string, tail int) ([]string, bool) {
	if name != u.name {
		return nil, false
	}
	return u.logs.tail(tail), true
}

func (u *unitSource) History(name string) ([]map[string]any, bool) {
	if name != u.name {
		return nil, false
	}
	out := []map[string]any{}
	for _, s := range u.hist.snapshot() {
		m := map[string]any{"t": s.T, "rate_bps": s.RateBps, "srtt_ms": s.SrttMs, "streams": s.Streams, "alive": s.Alive}
		if s.LossPct != nil {
			m["loss_pct"] = *s.LossPct
		}
		out = append(out, m)
	}
	return out, true
}

// logRing keeps the last logRingCap stderr log lines for Scepter's tunnel.logs — its one large phase A payload.
// Installed via log.SetOutput(io.MultiWriter(os.Stderr, ring)) only on a paired run, so nothing else changes.
type logRing struct {
	mu    sync.Mutex
	lines []string
}

const logRingCap = 1000

func (r *logRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		r.lines = append(r.lines, line)
		if len(r.lines) > logRingCap {
			r.lines = r.lines[len(r.lines)-logRingCap:]
		}
	}
	r.mu.Unlock()
	return len(p), nil
}

func (r *logRing) tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}
