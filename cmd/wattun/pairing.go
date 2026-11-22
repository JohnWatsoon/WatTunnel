// Scepter local wiring (3.5.0, phase A): the pairing file, the unit source that feeds the read-only cockpit
// commands, the log ring behind tunnel.logs, and the client-side keepalive loop. Everything here is active only
// when a pairing credential exists; the default run never touches it.

package main

import (
	"errors"
	"fmt"
	"log"
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

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	return "."
}

// attachStoredPairing is the run's default attach (F2, 2026-11-22): both roles pick up the stored credential
// when it exists (-pair wrote it on Kharej, -pair-to on Iran — the -pair help promises "server and client
// alike", which the old code only did for the server). A missing file is the normal unpaired case and stays
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
	if !errors.Is(err, os.ErrNotExist) {
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
	for _, line := range strings.Split(string(b), "\n") {
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

// pairingPollInterval is the .pairing watch cadence (F8-revoke). Var, not const: the tests shrink it.
var pairingPollInterval = 5 * time.Second

// pairingPoller watches the stored pairing file — the ENGINE side wiring of the plan security requirement
// "revocation is instant and local" (F8-revoke, 2026-11-22; the .pairing store is Kharej's revocation
// surface): file gone or now unparsable → ScepterState.ReloadPairing(nil) disarms the management channel
// (live scepter streams reset mid-line, new ones refused; the tunnel and its sessions keep running), a
// changed file (mtime+size differ, the cfgWatcher's own test) → the new credential is loaded. Every
// transition logs once, not per tick.
//
// File-backed pairings only. A pairing handed over as a config-key watp1: line is static by definition:
// there is no file to poll, and revoking it means restarting the unit without the key. Started in main's
// server path only, when cfg.Pairing came from readPairingFile.
type pairingPoller struct {
	path     string
	scepter  *wat.ScepterState
	latch    *latchMonitor // optional: the latch follows the credential (revoke = stand down permanently, rotate = re-arm from the new key)
	logf     func(string, ...any)
	interval time.Duration

	mu    sync.Mutex
	mt    time.Time
	sz    int64
	armed bool
}

func startPairingPoller(p *pairingPoller) {
	if st, err := os.Stat(p.path); err == nil { // the credential was just loaded from this file: arm from its state
		p.mt, p.sz = st.ModTime(), st.Size()
	}
	p.armed = true
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
		if p.armed {
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
			p.logf("scepter: pairing file %s unusable (%v) — management channel disarmed, the tunnel keeps running", p.path, perr)
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
	p.armed = true
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

// scepterClientLoop (client, 3.5.0): open the reserved stream on the tunnel's session, run the pairing hello and
// keep the channel warm with a 30 s ping (also the cockpit's scepter_up/down signal). A failed hello — an old
// peer without pairing material, or a reset stream — logs once and stops: no retry storm, and the tunnel itself
// is untouched (the mixed-version rule: at most one hello attempt of scepter traffic toward an old peer).
func scepterClientLoop(tun *tunnel, pair *wat.PairingConfig) {
	c, err := wat.DialScepter(tun.pick())
	if err != nil {
		log.Printf("scepter: %v (pairing needs %s on both ends; the tunnel runs without the cockpit)", err, wat.Version)
		return
	}
	defer c.Close()
	seq, _ := c.Hello["state_seq"].(float64)
	log.Printf("scepter: paired with %s (peer %s, caps %s, state_seq %.0f)", pair.UUIDString(), c.Hello["ver"], c.Hello["caps"], seq)
	for range time.Tick(30 * time.Second) {
		if _, code := c.Call("scepter.ping", nil); code != wat.CodeOK {
			log.Printf("scepter: channel down (code %d); the tunnel keeps running", code)
			return
		}
	}
}
