// Scepter latch (3.5.0, phase A item 4): Kharej's fallback listener. When every unit of a paired tunnel group
// is inactive — the cockpit's normal in-band channel (sid 0 of a live tunnel) is gone — a shaped wss pool
// carrier is opened on -latch-port so Iran can reach the management plane and revive the pair. Opt-in twice
// over: it exists only with a stored pairing AND a non-zero -latch-port; the default run never listens here.
//
// One session at a time: the listener stands down on the FIRST contact (StopListen keeps that contact's
// connections alive; a full Close would cut the session it just accepted) and the monitor re-arms only after
// that session ends and the unit is still inactive. Because this port is the one Scepter surface a stranger
// can reach, the contact must prove knowledge of the 32-byte pairing key before any command is served
// (wat.ServeScepterLatch; the in-band channel needs no proof — it sits inside an authenticated session).
//
// Hidden infrastructure (plan D2): nothing here appears in /stats, any listing or dashboard. The only visible
// trace is the loopback /scepter endpoint on the metrics server (127.0.0.1, the same guard as /stats), which
// the doctor reads: pairing UUID, caps, latch state and the last commands (wat.ScepterState.Recent).

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// Var, not const (the pairingPollInterval precedent): the tests shrink the cadences to drive the run loop
// and the contact consumer without sleeping seconds.
var (
	latchPoll     = 5 * time.Second  // monitor cadence
	latchArmAfter = 30 * time.Second // quiet time before arming: must outlive the 10 s alive window flaps
)

// latchMonitor watches unit liveness and arms/disarms the latch listener. The "unit" of this process is what
// alive() reports (server: a client heard recently; the systemd template runs one wattun per tunnel config, so
// a multi-tunnel Kharej arms its latch in whichever paired unit lost its client — the shared pairing file and
// port mean exactly one listener wins the bind; the others log the collision and stand by, re-trying on the
// next cycle after the winner's contact ends).
type latchMonitor struct {
	pair    *wat.PairingConfig
	scepter *wat.ScepterState
	alive   func() bool
	port    int
	lo, hi  int
	al      *allow
	base    wat.Config // the server's own config; Key/Pairing are replaced per arm (the latch PSK is key-derived)
	logf    func(string, ...any)

	mu       sync.Mutex
	srv      *wat.Server
	lastBind time.Time // last bind failure, to rate-limit the log, not the retry
	loopUp   bool      // the run loop marks itself (round-2 F9): rePair reads it under mu to revive a loop a revocation ended

	contacts atomic.Int64
	rejected atomic.Int64
	revoked  atomic.Bool // the pairing was revoked under the running process (poller); the latch never arms again
}

// startLatch runs the monitor loop in the background and publishes it to /scepter.
func startLatch(m *latchMonitor) *latchMonitor {
	latchNow.Store(m)
	go m.run()
	return m
}

func (m *latchMonitor) run() {
	m.mu.Lock()
	if m.loopUp { // rePair revives the loop after a revocation; never two loops (round-2 F9)
		m.mu.Unlock()
		return
	}
	m.loopUp = true
	m.mu.Unlock()
	var inactiveSince time.Time
	for range time.Tick(latchPoll) {
		m.mu.Lock()
		if m.revoked.Load() { // the pairing poller disarmed the channel: no listener for a revoked pair
			m.loopUp = false // cleared under mu BEFORE the return so rePair's revival check is exact: if
			m.mu.Unlock()    // it runs first (clearing revoked), this tick never sees the old revocation
			return
		}
		m.mu.Unlock()
		if m.alive() {
			inactiveSince = time.Time{}
			m.standDown()
			continue
		}
		if inactiveSince.IsZero() {
			inactiveSince = time.Now()
			continue
		}
		m.mu.Lock()
		busy := m.srv != nil && m.srv.Sessions() > 0
		m.mu.Unlock()
		if busy || time.Since(inactiveSince) < latchArmAfter {
			continue
		}
		m.arm()
	}
}

// arm opens the latch listener. Losing the bind (another paired unit holds the port) is logged once per
// 10 minutes and retried on a later cycle, so the winner dying hands the latch over within latchPoll.
// Round-2 F8 (2026-11-22): the credential is snapshotted ONCE under mu at entry — arm used to read m.pair
// three times unsnapshot, so a concurrent rePair could mix the old path with the new key (or the reverse),
// and before installing the server it re-checks revoked so a revoke racing the bind cannot leave a
// listener accepting key proofs for a credential that no longer exists.
func (m *latchMonitor) arm() {
	m.mu.Lock()
	if m.srv != nil || m.revoked.Load() {
		m.mu.Unlock()
		return
	}
	pair := m.pair // one snapshot for the path, the PSK and the served key (see above)
	m.mu.Unlock()
	ps, err := wat.NewWSPoolServer(fmt.Sprintf(":%d", m.port), wat.HTTPServerOptions{Path: wat.LatchPath(pair), Secure: true})
	if err != nil {
		if time.Since(m.lastBind) > 10*time.Minute {
			m.lastBind = time.Now()
			m.logf("scepter latch: cannot listen on port %d: %v (another paired unit may hold it)", m.port, err)
		}
		return
	}
	m.lastBind = time.Time{}
	cfg := m.base
	cfg.Key = wat.LatchKey(pair) // the latch PSK: distinct from the tunnel PSK, derived from the pairing key
	cfg.Pairing = pair
	srv := wat.NewServer(cfg, ps)
	srv.MaxSessions = 1 // one session at a time (plan D2); further dials get no session
	m.mu.Lock()
	if m.revoked.Load() { // revoke raced the bind: nothing was published or served — close and quit
		m.mu.Unlock()
		srv.Close() // closes the pool listener with it
		return
	}
	m.srv = srv
	m.mu.Unlock()
	m.logf("scepter latch: armed on port %d (pairing inactive; one key-proven contact revives the cockpit)", m.port)
	go func() {
		// round-2 F10 (2026-11-22): wait for the first contact OR the server going away. A stand-down
		// without contact (the unit came alive, the credential rotated or was revoked) used to block on
		// srv.New forever — wat.Server.Close closes stop but not New, so this consumer leaked. The
		// gone-signal is m.srv != srv: standDown (alive again), rePair and revoke are the only writers.
		contact := func(s *wat.Session) {
			ps.StopListen() // first contact: stand the listener down without cutting this session's connections
			m.logf("scepter latch: contact; listener stands down until the pair needs it again")
			// Management only: no serveDgrams here — the latch carries the scepter stream, not UDP forwarding.
			go serveLatch(s, m.lo, m.hi, m.al, m.scepter, wat.LatchKey(pair), m)
			go func() { // reap when the contact session ends, so the monitor can re-arm if still inactive
				for range time.Tick(latchPoll) {
					if srv.Sessions() == 0 {
						srv.Close()
						m.mu.Lock()
						if m.srv == srv {
							m.srv = nil
						}
						m.mu.Unlock()
						return
					}
				}
			}()
		}
		tk := time.NewTicker(latchPoll)
		defer tk.Stop()
		for {
			select {
			case s, ok := <-srv.New:
				if !ok {
					return
				}
				contact(s)
				return
			case <-tk.C:
				// select picks randomly among ready cases: a contact that landed while the tick fired
				// must still win over the stand-down check, so drain New non-blockingly first.
				select {
				case s, ok := <-srv.New:
					if ok {
						contact(s)
						return
					}
				default:
				}
				m.mu.Lock()
				gone := m.srv != srv
				m.mu.Unlock()
				if gone && srv.Sessions() == 0 {
					srv.Close() // stood down with no contact: nothing to preserve — exit, do not leak
					return
				}
				if gone { // a contact session raced the stand-down and still holds the server: serve what
					select { // New holds; the session ends on its own (standDown's rule)
					case s, ok := <-srv.New:
						if ok {
							contact(s)
						}
					default:
					}
					return
				}
			}
		}
	}()
}

// standDown is called when the unit is alive again: the normal in-band channel serves the cockpit, so a never
// contacted latch stops listening. A live contact session is left alone — cutting it could drop an in-flight
// command; it ends on its own and the reaper cleans up.
func (m *latchMonitor) standDown() {
	m.mu.Lock()
	srv := m.srv
	m.srv = nil
	m.mu.Unlock()
	if srv != nil && srv.Sessions() == 0 {
		srv.Close()
	}
}

// revoke marks the credential gone (the .pairing poller disarmed the ScepterState, 2026-11-22 wave 2):
// the latch stops arming and its listener stands down — a revoked pair's latch must not keep accepting
// key proofs (the arm-time LatchKey would otherwise stay valid forever).
func (m *latchMonitor) revoke() {
	m.revoked.Store(true)
	m.standDown()
	m.logf("scepter latch: pairing revoked — the latch stands down permanently")
}

// rePair swaps the credential after a rotation: the next arm derives the latch PSK from the NEW key. The
// old listener's PSK is stale, so the listener stands down and re-arms on a later cycle; a live contact
// session is left alone (standDown's rule — it ends on its own). Round-2 F9 (2026-11-22): a re-pair after
// a revocation also REVIVES the latch — the run loop exited on the revocation and never cleared it, so the
// cockpit could revive the pair and the latch would stay dead until a process restart with no hint. The
// revoked clear sits under mu, where the run loop's exit check also sits, so the two are atomic: either
// this section runs first and the loop never sees the old revocation, or the loop already exited and the
// spawn below brings a fresh one up.
func (m *latchMonitor) rePair(p *wat.PairingConfig) {
	m.mu.Lock()
	m.pair = p
	m.revoked.Store(false)
	revive := !m.loopUp
	m.mu.Unlock()
	m.standDown()
	if revive {
		m.logf("scepter latch: pairing restored after revocation — the latch watches again")
		go m.run() // run's own loopUp guard keeps this single even if two revivals race
	}
}

// contacted counts an authenticated latch contact (the proof in wat.ServeScepterLatch passed).
func (m *latchMonitor) contacted() { m.contacts.Add(1) }

// refused counts a rejected contact and closes its session: no command was served on it.
func (m *latchMonitor) refused(sess *wat.Session) {
	m.rejected.Add(1)
	m.logf("scepter latch: contact without a valid key proof rejected; session closed")
	sess.Close()
}

// status is the latch's /scepter endpoint fragment (nil monitor = pairing without -latch-port).
func (m *latchMonitor) status() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false}
	}
	m.mu.Lock()
	armed := m.srv != nil
	m.mu.Unlock()
	return map[string]any{"enabled": true, "port": m.port, "armed": armed, "revoked": m.revoked.Load(),
		"contacts": m.contacts.Load(), "rejected": m.rejected.Load()}
}

// scepterSnapshot is what the loopback /scepter endpoint serves: the doctor's ONLY view of the management
// plane (plan A.3). nil state = no pairing: the endpoint answers null and nothing else leaks.
func scepterSnapshot(ss *wat.ScepterState, m *latchMonitor) any {
	if ss == nil {
		return nil
	}
	uuid, caps := ss.PairingInfo()
	return map[string]any{
		"paired": true, "uuid": uuid, "caps": wat.CapName(caps), "caps_mask": caps,
		"state_seq": ss.StateSeq(), "recent": ss.Recent(), "latch": m.status(),
	}
}

// scepterNow/latchNow: the /scepter handler is registered with the metrics mux before the server block arms
// the management state, so it must read the live values, not a startup-time snapshot (registration happens
// first; arming happens later in main).
var (
	scepterNow atomic.Pointer[wat.ScepterState]
	latchNow   atomic.Pointer[latchMonitor]
)

func scepterServeHTTP() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scepterSnapshot(scepterNow.Load(), latchNow.Load()))
	}
}

// contactLatch is -latch-dial: the cockpit-side drill primitive. Dial the latch on Kharej, prove the pairing
// key, run the pairing hello and one ping, report and return — the caller then revives the pair (phase B
// commands) or just reads state. A denied proof or a dead latch is an error, never a hang: the pool dials
// carry their own timeouts.
func contactLatch(addr string, pair *wat.PairingConfig) error {
	sess, c, err := dialLatchSession(addr, pair)
	if err != nil {
		return err
	}
	defer sess.Close()
	defer c.Close()
	seq, _ := c.Hello["state_seq"].(float64)
	log.Printf("scepter latch: revived (peer %s, caps %s, state_seq %.0f)", c.Hello["ver"], c.Hello["caps"], seq)
	return nil
}

// dialLatchSession is one latch contact: pool client → session (the latch PSK) → key proof → pairing hello
// → one ping. Shared by the -latch-dial drill and the automatic revival below so the two never drift (the
// drill once built its session without the latch PSK and could never connect — H2, 2026-11-22; Key = the
// latch PSK, same derivation as the server's arm in latchMonitor.arm: sessionAEAD mixes cfg.Key, so a
// Key-less config seals packets the server cannot open). On success the caller owns sess and c; on any
// error everything is already closed.
func dialLatchSession(addr string, pair *wat.PairingConfig) (*wat.Session, *wat.ScepterClient, error) {
	pc, err := wat.NewWSPoolClient(addr, 2, wat.HTTPClientOptions{Path: wat.LatchPath(pair), Secure: true})
	if err != nil {
		return nil, nil, err
	}
	sess, err := wat.NewSession(wat.Config{Key: wat.LatchKey(pair), Pairing: pair, Logf: log.Printf}, pc)
	if err != nil {
		return nil, nil, err
	}
	c, err := wat.DialScepterLatch(sess, wat.LatchKey(pair))
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	if _, code := c.Call("scepter.ping", nil); code != wat.CodeOK {
		c.Close()
		sess.Close()
		return nil, nil, fmt.Errorf("scepter latch: ping answered code %d", code)
	}
	return sess, c, nil
}

// ---- client-side automatic revival (owner directive 2026-11-22) ----
//
// The latch contact used to wait for a manual -latch-dial; with `latch-port: N` in a client config it is
// automatic: while the tunnel is DOWN the client dials peerhost:N, proves the pairing key and keeps the
// revived channel warm, so the cockpit stays reachable while the tunnel is dark. The tunnel's own recovery
// stays with the existing mechanisms (pool-carrier self-heal, the manager's heal timer): the engine adds no
// restart loop, the latch only keeps the management channel alive — and when the tunnel comes back, the
// in-band channel is re-opened once per revival (the loop main started dies with the tunnel).

// Var, not const (the latchPoll precedent): the tests shrink the cadences.
var (
	latchRevivePoll = 5 * time.Second  // revival loop cadence
	latchRetryEvery = 30 * time.Second // rate limit: at most one latch attempt per 30 s while the tunnel is down
	latchWarmEvery  = 30 * time.Second // ping cadence of a revived channel
)

// latchPeerHost is the host half of the tunnel's peer address (the first endpoint of a bond/pool list,
// port stripped): the latch is dialed at peerhost:N where N is the config's latch-port.
func latchPeerHost(peer string) string {
	if i := strings.Index(peer, ","); i >= 0 {
		peer = peer[:i]
	}
	if h, _, err := net.SplitHostPort(peer); err == nil {
		return h
	}
	return peer
}

// latchRevive is the client-side revival loop (see the section comment above). Started only when the run
// is a client, cfg.Pairing != nil and latch-port > 0 — without a pairing there is no key to prove and no
// path to dial. Skew note: after a rotation the server's .pairing store and the client's token drift
// apart, the derived latch key no longer matches, and every contact fails at the proof, logged at the
// retry cadence until the new token is pasted — the same mixed-credential posture as the in-band channel's
// hello, which tolerates the drift; the latch cannot (the proof is key-bound by design).
type latchRevive struct {
	alive  func() bool // the tunnel's liveness (tunnel.alive in main; tests drive it directly)
	pair   *wat.PairingConfig
	addr   string // peerhost:N
	inband func() // called once per revival when the tunnel is back: re-open the in-band channel
	logf   func(string, ...any)

	mu      sync.Mutex
	sess    *wat.Session // the open latch contact (nil = none; while set, no new attempt)
	revived bool         // a contact succeeded and has not yet been handed back to the in-band channel
	lastTry time.Time

	contacts atomic.Int64 // successful automatic contacts (test seam; not exported anywhere user-facing)
}

func startLatchRevive(r *latchRevive) { go r.run() }

func (r *latchRevive) run() {
	for range time.Tick(latchRevivePoll) {
		r.tick()
	}
}

// tick is one revival-loop step (split from run so the tests drive it without sleeping).
func (r *latchRevive) tick() {
	if r.alive() {
		r.resume()
		return
	}
	r.mu.Lock()
	due := r.sess == nil && time.Since(r.lastTry) >= latchRetryEvery
	if due {
		r.lastTry = time.Now()
	}
	r.mu.Unlock()
	if !due {
		return
	}
	sess, c, err := dialLatchSession(r.addr, r.pair)
	if err != nil {
		r.logf("scepter latch: automatic contact with %s failed (%v); retrying while the tunnel is down", r.addr, err)
		return
	}
	r.mu.Lock()
	r.sess, r.revived = sess, true
	r.mu.Unlock()
	r.contacts.Add(1)
	seq, _ := c.Hello["state_seq"].(float64)
	r.logf("scepter latch: revived automatically via %s (peer %s, caps %s, state_seq %.0f); the tunnel keeps its normal recovery",
		r.addr, c.Hello["ver"], c.Hello["caps"], seq)
	go r.keepWarm(sess, c)
}

// keepWarm pings the revived channel until the tunnel is back (resume closes the contact on its next tick)
// or the contact is no longer ours (closed by resume or superseded) or a ping fails (the retry loop takes
// over, still rate-limited by lastTry).
func (r *latchRevive) keepWarm(sess *wat.Session, c *wat.ScepterClient) {
	for range time.Tick(latchWarmEvery) {
		r.mu.Lock()
		mine := r.sess == sess
		r.mu.Unlock()
		if !mine || r.alive() {
			return
		}
		if _, code := c.Call("scepter.ping", nil); code != wat.CodeOK {
			r.mu.Lock()
			if r.sess == sess {
				r.sess = nil
			}
			r.mu.Unlock()
			sess.Close()
			r.logf("scepter latch: revived channel down (code %d); the revival loop retries", code)
			return
		}
	}
}

// resume drops the latch contact when the tunnel is back and re-opens the in-band channel once per
// revival — the loop main started exits when the channel goes down, so the revival is the moment to try
// again (at most one contact at a time keeps this from ever stacking in-band loops).
func (r *latchRevive) resume() {
	r.mu.Lock()
	sess := r.sess
	r.sess = nil
	wasRevived := r.revived
	r.revived = false
	r.mu.Unlock()
	if sess != nil {
		sess.Close()
		r.logf("scepter latch: tunnel is back; the latch contact is dropped, the in-band channel serves")
	}
	if wasRevived && r.inband != nil {
		r.inband()
	}
}
