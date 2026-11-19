package wat

import (
	"testing"
	"time"
)

// R4 Phoenix (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md, disposition
// table). Phoenix's automatic discovery/escalation ladder is deferred; what survives is: "reporting endpoint
// failure and bounded failover among operator-configured paths, with hysteresis and a manual override."
//
// Everything the surviving scope needs already exists in the bond's pathSet (paths.go): per-carrier failure
// reporting (PathStats → /stats), failover bounded by the Silence floor and the probe backoff, anti-flap via the
// same floor plus the revival ramp, and the manual override (PathMuter.ToggleMute). What did NOT exist was a test
// pinning the two behaviors an operator would notice: a short link blip must NOT kill a leg (hysteresis), and a
// muted leg must carry nothing even while alive (override wins over health).

// TestPhoenixBlipDoesNotKillLeg: a 200 ms link failure is shorter than the Silence floor (300 ms with the rig's
// fastTimings), so the leg must NOT be declared dead - no probe cycle, no share loss beyond the blip itself - and
// the download rides on as if nothing happened.
func TestPhoenixBlipDoesNotKillLeg(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	const n = 24 << 20
	done := make(chan error, 1)
	go func() { _, _, err := bondDownload(rig.cli, n); done <- err }()
	time.Sleep(1 * time.Second)

	sent0 := rig.cli.CarrierStats()[0].Sent
	links[0].blocked.Store(true)
	time.Sleep(200 * time.Millisecond) // < Silence (300 ms): a blip, not an outage
	links[0].blocked.Store(false)
	time.Sleep(300 * time.Millisecond)

	cs := rig.cli.CarrierStats()
	if !cs[0].Alive {
		t.Fatal("a 200 ms blip declared the leg dead (Silence floor must hysteresis it out)")
	}
	if cs[0].Sent <= sent0+50 {
		t.Fatalf("the leg stopped carrying after a 200 ms blip: Sent %d -> %d", sent0, cs[0].Sent)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed across the blip: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("download timed out across the blip")
	}
}

// TestPhoenixMuteOverridesHealth: the manual override beats the health engine - a muted leg stays configured
// and healthy but carries nothing (stats() reports Alive=false WITH Muted=true: Alive means "currently
// carrying", see the inline note below), and the session rides the others; unmuting puts it back to work. This
// is the operator control the surviving Phoenix scope requires (ToggleMute is already exposed via
// /stats-adjacent APIs and the bond's PathMuter interface).
func TestPhoenixMuteOverridesHealth(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	muter, ok := rig.cli.IO().(interface{ ToggleMute(int) bool })
	if !ok {
		t.Fatal("the client bond does not expose ToggleMute")
	}
	const n = 32 << 20
	done := make(chan error, 1)
	go func() { _, _, err := bondDownload(rig.cli, n); done <- err }()
	time.Sleep(1 * time.Second)

	if !muter.ToggleMute(0) {
		t.Fatal("ToggleMute reported the leg was already muted")
	}
	// paths.go stats() computes Alive = state==pLive && !muted, so a muted leg reports Alive=false WITH
	// Muted=true: Alive means "currently carrying", Muted is the operator-override marker. The assertion is that
	// the operator can always tell an override (Muted=true) from a failure (Muted=false + dead).
	deadline := time.Now().Add(3 * time.Second)
	var frozen uint64
	for time.Now().Before(deadline) {
		cs := rig.cli.CarrierStats()[0]
		if !cs.Muted {
			t.Fatal("ToggleMute returned true but the leg does not report Muted in stats")
		}
		frozen = cs.Sent
		break
	}
	time.Sleep(1 * time.Second)
	mid := rig.cli.CarrierStats()
	if mid[0].Sent > frozen+20 { // Sent counts packets: a muted leg gets at most a stray packet
		t.Fatalf("the muted leg still carried traffic: Sent %d -> %d packets", frozen, mid[0].Sent)
	}
	if mid[1].Sent < 100 {
		t.Fatal("the surviving leg did not take the muted leg's traffic")
	}

	// unmute: the leg returns to carrying
	muter.ToggleMute(0)
	sent := mid[0].Sent
	deadline = time.Now().Add(5 * time.Second)
	back := false
	for time.Now().Before(deadline) {
		if cs := rig.cli.CarrierStats()[0]; !cs.Muted && cs.Sent > sent+50 {
			back = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !back {
		t.Fatalf("the unmuted leg never carried again: %+v", rig.cli.CarrierStats()[0])
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed across the mute cycle: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("download timed out across the mute cycle")
	}
}
