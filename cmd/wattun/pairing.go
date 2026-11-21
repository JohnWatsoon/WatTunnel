// Scepter local wiring (3.5.0, phase A): the pairing file, the unit source that feeds the read-only cockpit
// commands, the log ring behind tunnel.logs, and the client-side keepalive loop. Everything here is active only
// when a pairing credential exists; the default run never touches it.

package main

import (
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

// readPairingFile loads the stored credential.
func readPairingFile(path string) (*wat.PairingConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := wat.ParsePairingLine(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return p, nil
}

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	return "."
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
