// Scepter latch cmd-side tests (3.5.0): the monitor's arm/stand-down transitions, the /scepter doctor
// endpoint, and the hidden-infrastructure pin — the latch and the scepter session must never appear in /stats
// or any user-facing listing (plan D2; they show ONLY in doctor output).

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func testLatchPairing() *wat.PairingConfig {
	p, err := wat.ParsePairingLine("watp1:1|0a0b0c0d-0e0f-1011-1213-141516171819|" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|manage")
	if err != nil {
		panic(err)
	}
	return p
}

// TestLatchMonitorArmStandDown: armed while the unit is inactive, down again the moment it is alive — the
// transitions without a contact (the full contact drill is wat's TestLatchDrill).
func TestLatchMonitorArmStandDown(t *testing.T) {
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var alive atomic.Bool
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return alive.Load() },
		port: 0, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	t.Cleanup(m.standDown) // the final re-arm would otherwise leave a parked arm goroutine behind
	m.arm()                // port 0: an ephemeral loopback-free bind still succeeds (":0")
	if m.status()["armed"] != true {
		t.Fatalf("latch must be armed while inactive: %v", m.status())
	}
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil || srv.Sessions() != 0 {
		t.Fatal("armed latch has no server/session")
	}
	alive.Store(true)
	m.standDown()
	if m.status()["armed"] != false {
		t.Fatalf("latch must stand down when the unit is alive: %v", m.status())
	}
	// re-arm after the unit dies again, then let a stand-down with a live session keep the session (no cut)
	m.arm()
	if m.status()["armed"] != true {
		t.Fatal("latch must re-arm after the unit goes inactive again")
	}
}

// TestLatchRevokeBlocksArm (round-2 F8, 2026-11-22): a revoked monitor must not arm at all — arm snapshots
// the credential once under mu and re-checks revoked before installing the listener, so a revoke racing an
// in-flight arm cannot leave a listener accepting key proofs for a credential that no longer exists. The
// concurrent interleaving itself (rePair/revoke mid-bind) is exercised by TestLatchArmCredentialHammer and
// CI's -race run; arm used to read m.pair unsnapshot three times, so a rotation mid-arm could mix one
// credential's path with another's key.
func TestLatchRevokeBlocksArm(t *testing.T) {
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return false },
		port: 0, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	m.revoke()
	m.arm()
	st := m.status()
	if st["armed"] != false || st["revoked"] != true {
		t.Fatalf("a revoked monitor must not arm: %v", st)
	}
}

// TestLatchArmCredentialHammer (round-2 F8, 2026-11-22): arm, rePair and stand-down churned together must
// never wedge the monitor — every arm works from ONE credential snapshot (the fix) and settles back into a
// state that arms and stands down cleanly. alive stays true through the churn so the run loop rePair may
// spawn stays inert (it only stands down, never arms); the settle flips it so the loop cannot stand down
// what the settle arm installed.
func TestLatchArmCredentialHammer(t *testing.T) {
	oldPoll := latchPoll
	latchPoll = 10 * time.Millisecond
	t.Cleanup(func() { latchPoll = oldPoll })
	pair := testLatchPairing()
	pair2, err := wat.ParsePairingLine(testPairingLine("full"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var alive atomic.Bool
	alive.Store(true)
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return alive.Load() },
		port: 0, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the rotation churn (the poller's shape)
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				m.rePair(pair2)
			}
		}
	}()
	go func() { // the arm churn (the monitor loop's shape)
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				m.arm()
				m.standDown()
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	m.standDown()
	alive.Store(false)
	m.arm()                          // settle: the monitor must still arm on the current credential (the loop will not stand it
	if m.status()["armed"] != true { // down now — alive is false and its arm quiet time is far away)
		t.Fatalf("arm after the churn: %v", m.status())
	}
	m.standDown() // ...and stand down cleanly
	if m.status()["armed"] != false {
		t.Fatalf("stand-down after the churn: %v", m.status())
	}
}

// TestLatchRePairRevivesAfterRevoke (round-2 F9, 2026-11-22): revoke ends the run loop, and rePair used to
// leave it dead — revoked stayed set, the cockpit could revive the pair and the latch never armed again
// until a process restart with no hint. rePair must clear the revocation and bring the loop back up: the
// monitor arms again on liveness. Driven by the shrunk poll/arm seams (latchPoll, latchArmAfter).
func TestLatchRePairRevivesAfterRevoke(t *testing.T) {
	oldPoll, oldArm := latchPoll, latchArmAfter
	latchPoll, latchArmAfter = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { latchPoll, latchArmAfter = oldPoll, oldArm })
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var alive atomic.Bool
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return alive.Load() },
		port: 0, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	go m.run()
	m.revoke()
	// the loop exits on the next tick; wait for it to be gone
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		dead := !m.loopUp
		m.mu.Unlock()
		if dead && m.status()["revoked"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run loop must have exited on the revocation")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// rePair after the revoke: revoked cleared, loop restarted, and it arms from the NEW credential
	p2, err := wat.ParsePairingLine(testPairingLine("full"))
	if err != nil {
		t.Fatal(err)
	}
	m.rePair(p2)
	if m.status()["revoked"] != false {
		t.Fatalf("rePair must clear the revocation: %v", m.status())
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if m.status()["armed"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revived loop must arm again while the unit is inactive: %v", m.status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	alive.Store(true) // and the normal rule resumes: alive again → stands down
	deadline = time.Now().Add(2 * time.Second)
	for {
		if m.status()["armed"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revived loop must stand down when the unit is alive: %v", m.status())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestLatchConsumerExitsOnStandDown (round-2 F10, 2026-11-22): arm then stand down with no contact — the
// pre-contact consumer used to block on srv.New forever (wat.Server.Close closes stop but not New), one
// leaked goroutine per stand-down. Pinned by goroutine-stack scan: after the stand-down no arm goroutine
// may remain parked.
func TestLatchConsumerExitsOnStandDown(t *testing.T) {
	oldPoll := latchPoll
	latchPoll = 10 * time.Millisecond
	t.Cleanup(func() { latchPoll = oldPoll })
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return false },
		port: 0, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	buf := make([]byte, 1<<20)
	parked := func() int { // arm goroutines parked anywhere in the process (other tests may keep some)
		n := runtime.Stack(buf, true)
		return strings.Count(string(buf[:n]), "(*latchMonitor).arm")
	}
	base := parked()
	m.arm()
	if m.status()["armed"] != true {
		t.Fatalf("must arm for the drill: %v", m.status())
	}
	m.standDown()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if parked() <= base {
			return // the consumer (and the server internals with it) are gone
		}
		if time.Now().After(deadline) {
			t.Fatal("the pre-contact consumer leaked: an arm goroutine is still parked on srv.New")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestScepterEndpointIsDoctorOnly: /scepter serves the doctor view (pairing, caps, latch, recent commands) and
// /stats never mentions any of it — the ONLY user-visible trace of the management plane is this endpoint.
func TestScepterEndpointIsDoctorOnly(t *testing.T) {
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp := state.Handle(wat.ScepterRequest{ID: "d1", V: 1, Cmd: "scepter.ping"}, pair.Caps); resp.Code != 0 {
		t.Fatal("ping must succeed for the doctor view")
	}
	rec := state.Recent()
	if len(rec) != 1 || rec[0].Cmd != "scepter.ping" {
		t.Fatalf("recent commands: %+v", rec)
	}
	mon := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return false }, port: 8443,
		lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	scepterNow.Store(state)
	latchNow.Store(mon)
	t.Cleanup(func() { scepterNow.Store(nil); latchNow.Store(nil) }) // the handler reads the live refs
	h := scepterServeHTTP()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/scepter", nil))
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("/scepter body: %v (%s)", err, w.Body.String())
	}
	if doc["paired"] != true || doc["uuid"] != pair.UUIDString() || doc["caps"] != "manage" {
		t.Fatalf("/scepter doctor view: %v", doc)
	}
	latch, _ := doc["latch"].(map[string]any)
	if latch["enabled"] != true || latch["port"] != float64(8443) {
		t.Fatalf("/scepter latch view: %v", latch)
	}
	// no pairing: the endpoint answers null — nothing about a default run leaks either
	scepterNow.Store(nil)
	latchNow.Store(nil)
	w2 := httptest.NewRecorder()
	scepterServeHTTP()(w2, httptest.NewRequest(http.MethodGet, "/scepter", nil))
	if strings.TrimSpace(w2.Body.String()) != "null" {
		t.Fatalf("unpaired /scepter must be null, got %q", w2.Body.String())
	}
}

// TestContactLatchDrill pins the shipped -latch-dial path end to end (H2, 2026-11-22): contactLatch against a
// real armed latch monitor on loopback, hello + one ping. Regression: contactLatch once built its session
// without the latch PSK (Config{Pairing: pair} had no Key) while the server arms with Key = wat.LatchKey(pair)
// — every packet failed the AEAD and the dial could never connect; the wat drill (TestLatchDrill) masked it
// because it hand-builds BOTH configs with the derived key.
func TestContactLatchDrill(t *testing.T) {
	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// a free port for the monitor to bind: arm() builds its own pool, so the address must be reserved here
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return false },
		port: port, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	m.arm()
	if m.status()["armed"] != true {
		t.Fatalf("latch must be armed for the drill: %v", m.status())
	}
	t.Cleanup(m.standDown)
	if err := contactLatch(fmt.Sprintf("127.0.0.1:%d", port), pair); err != nil {
		t.Fatalf("contactLatch (the shipped -latch-dial path): %v", err)
	}
	// the ping was answered by the time contactLatch returned, so the server state recorded it
	last := state.Recent()
	if len(last) == 0 || last[len(last)-1].Cmd != "scepter.ping" {
		t.Fatalf("the drill's ping never reached the latch state: %+v", last)
	}
}

// TestLatchAutoRevive pins the client-side automatic revival (owner directive 2026-11-22: the latch
// contact must not wait for a manual -latch-dial). Tunnel down + `latch-port: N` → the contact happens
// within the rate limit, proves the key and STAYS OPEN (the channel is kept warm); tunnel back → the
// contact is dropped and the in-band channel re-opened exactly once per revival; down again → the
// monitor's re-arm hands the latch over and a second contact succeeds, still rate-limited. Driven by the
// shrunk cadence seams (latchRevivePoll, latchRetryEvery, latchPoll, latchArmAfter), ticks called directly.
func TestLatchAutoRevive(t *testing.T) {
	oldPoll, oldRetry, oldRvPoll := latchPoll, latchRetryEvery, latchRevivePoll
	oldArm := latchArmAfter
	latchPoll, latchArmAfter = 10*time.Millisecond, 20*time.Millisecond
	latchRevivePoll, latchRetryEvery = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		latchPoll, latchArmAfter = oldPoll, oldArm
		latchRevivePoll, latchRetryEvery = oldRvPoll, oldRetry
	})

	pair := testLatchPairing()
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// a free port for the monitor to bind: arm() builds its own pool, so the address must be reserved here
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	m := &latchMonitor{pair: pair, scepter: state, alive: func() bool { return false },
		port: port, lo: 1, hi: 65535, al: newAllow("", ""), logf: func(string, ...any) {}}
	m.arm()
	t.Cleanup(m.standDown)
	go m.run() // re-arms after each contact ends (the revived monitor hands the latch over for contact 2)

	var alive atomic.Bool
	var inbands atomic.Int64
	r := &latchRevive{
		alive:  func() bool { return alive.Load() },
		pair:   pair,
		addr:   fmt.Sprintf("127.0.0.1:%d", port),
		logf:   t.Logf,
		inband: func() { inbands.Add(1) },
	}

	// tunnel down: the contact happens within the rate limit and the channel stays open (kept warm)
	deadline := time.Now().Add(3 * time.Second)
	for r.contacts.Load() == 0 {
		r.tick()
		if time.Now().After(deadline) {
			t.Fatal("the latch contact must happen within the rate limit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	open := r.sess != nil
	r.mu.Unlock()
	if !open {
		t.Fatal("a revived contact must stay open (the channel is kept warm while the tunnel is down)")
	}
	last := state.Recent()
	if len(last) == 0 || last[len(last)-1].Cmd != "scepter.ping" {
		t.Fatalf("the automatic contact's ping never reached the latch state: %+v", last)
	}

	// tunnel back: the contact is dropped, the in-band channel re-opened exactly once per revival
	alive.Store(true)
	r.tick()
	r.mu.Lock()
	open = r.sess != nil
	r.mu.Unlock()
	if open {
		t.Fatal("the latch contact must be dropped when the tunnel is back")
	}
	if inbands.Load() != 1 {
		t.Fatalf("the in-band channel must be re-opened once per revival, got %d", inbands.Load())
	}

	// tunnel down again: the monitor re-arms after the contact ends, and a second contact succeeds. The
	// stand-down here drives what production reaches on its own (the contact session ends → the reaper
	// closes the server → the run loop re-arms); the test cannot wait for the janitor, because the test
	// monitor's zero Config carries the 45 s IdleTimeout floor (in production the revived channel is kept
	// warm at 30 s, under the floor, so a live contact never idles out).
	alive.Store(false)
	m.mu.Lock()
	old := m.srv
	m.srv = nil
	m.mu.Unlock()
	if old != nil {
		old.Close() // fully reaps the old server (its lingering session included) — standDown's own move
	}
	deadline = time.Now().Add(3 * time.Second)
	for m.status()["armed"] != true { // the run loop binds a fresh listener within latchArmAfter
		if time.Now().After(deadline) {
			t.Fatalf("the monitor must re-arm after the ended contact: %v", m.status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	deadline = time.Now().Add(3 * time.Second)
	for r.contacts.Load() < 2 {
		r.tick()
		if time.Now().After(deadline) {
			t.Fatalf("a second contact must succeed after the re-arm (rate-limited): contacts %d", r.contacts.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	alive.Store(true)
	r.tick()
	if inbands.Load() != 2 {
		t.Fatalf("each revival re-opens the in-band channel once, got %d", inbands.Load())
	}
}

// TestStatsHandlerHidesScepter pins the hidden-infrastructure rule at the source (plan D2): the /stats handler
// in main.go must not mention the management plane — no "scepter", "pairing" or "latch" key. A static pin,
// because the handler is built inline in main(): adding a key there fails this test before any dashboard
// picks it up. The doctor reads /scepter instead.
func TestStatsHandlerHidesScepter(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, `mux.HandleFunc("/stats"`)
	j := strings.Index(src[i:], "\n\t\t\t})")
	if i < 0 || j < 0 {
		t.Fatal("cannot locate the /stats handler in main.go")
	}
	body := src[i : i+j]
	for _, word := range []string{"scepter", "Scepter", "pairing", "Pairing", "latch"} {
		if strings.Contains(body, word) {
			t.Fatalf("the /stats handler mentions %q — the management plane is doctor-only (/scepter)", word)
		}
	}
	if !strings.Contains(src, "/scepter") {
		t.Fatal("main.go must register /scepter (the doctor's only view of the management plane)")
	}
}
