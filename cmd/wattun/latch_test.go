// Scepter latch cmd-side tests (3.5.0): the monitor's arm/stand-down transitions, the /scepter doctor
// endpoint, and the hidden-infrastructure pin — the latch and the scepter session must never appear in /stats
// or any user-facing listing (plan D2; they show ONLY in doctor output).

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

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
	m.arm() // port 0: an ephemeral loopback-free bind still succeeds (":0")
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
