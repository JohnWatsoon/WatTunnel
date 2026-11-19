package wat

import (
	"sync/atomic"
	"testing"
	"time"
)

// R2 Bifrost (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md, disposition
// table). No production CLI, no :tx/:rx syntax, no wire change. This is the QUEUED prerequisite before Bifrost
// itself may be designed: "prove leg-specific liveness on a simulator: two sending legs, fail just one, keep the
// session healthy, stop assigning data to the failed leg and verify recovery. Session-wide ACKs alone cannot
// prove this."
//
// The subtle failure mode the test guards against: a bond whose health check only looks at SESSION-WIDE ack
// arrival would keep a dead leg "alive" forever, because the surviving leg's acks keep the session chatty. The
// assertion below therefore requires the dead leg's OWN counters to freeze (no new data assigned, its own
// witnesses go quiet) while the survivor's counters keep climbing on the same session.
//
// Reuses the bond rig's emulated links (bond_test.go): a link's blocked flag drops every packet in both
// directions, including those already in flight.

// TestBifrostLegLiveness: two sending legs under one bulk download; hard-fail leg 0 mid-transfer and require
// (a) the session delivers every byte intact (no reset), (b) leg 0 is declared dead despite leg 1's acks
// flowing session-wide, (c) after death, NO new data is assigned to leg 0 (its Sent freezes) while leg 1's Sent
// climbs, and (d) after healing, leg 0 carries traffic again.
func TestBifrostLegLiveness(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	const n = 48 << 20
	done := make(chan error, 1)
	var got int
	go func() {
		g, _, err := bondDownload(rig.cli, n)
		got = g
		done <- err
	}()
	time.Sleep(1500 * time.Millisecond) // both legs warm and carrying

	cs := rig.cli.CarrierStats()
	if len(cs) != 2 || !cs[0].Alive || !cs[1].Alive {
		t.Fatalf("precondition: 2 live carriers expected, got %+v", cs)
	}
	links[0].blocked.Store(true)

	// (b) death declared while the session-wide acks keep flowing on leg 1
	deadline := time.Now().Add(5 * time.Second)
	for rig.cli.CarrierStats()[0].Alive && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rig.cli.CarrierStats()[0].Alive {
		t.Fatal("leg 0 never declared dead although its own acks stopped (session-wide acks from leg 1 must not mask it)")
	}
	sent0AtDeath := rig.cli.CarrierStats()[0].Sent
	sent1AtDeath := rig.cli.CarrierStats()[1].Sent

	// (c) over the next second of transfer: leg 0's Sent freezes (in-flight tail only), leg 1 carries everything.
	// Sent counts PACKETS (pathSet.onSend): a 6 Mbps leg with the rig's 700 B cap is ~1000 packets/s at line rate.
	time.Sleep(1 * time.Second)
	mid := rig.cli.CarrierStats()
	if mid[0].Alive {
		t.Fatal("leg 0 resurrected without its link healing")
	}
	if grew := mid[0].Sent - sent0AtDeath; grew > 50 {
		// a small tail is legitimate (packets assigned while the leg was still suspect); a steady stream is not
		t.Fatalf("leg 0 kept receiving data after death: Sent grew %d packets", grew)
	}
	if mid[1].Sent <= sent1AtDeath+200 {
		t.Fatalf("leg 1 did not take over the traffic: Sent %d -> %d packets in 1 s", sent1AtDeath, mid[1].Sent)
	}

	// (a) the transfer is still running; unblock leg 0 NOW so it can carry again (a completed transfer has no
	// traffic to assign, which is why this check happens mid-download)
	sent0BeforeHeal := rig.srv.CarrierStats()[0].Sent
	links[0].blocked.Store(false)
	t1 := time.Now()
	healed := atomic.Bool{}
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ss := rig.srv.CarrierStats()
		// The SERVER's assignment is what must resume (it owns the download direction). The client's ACK packets
		// legitimately concentrate on leg 1 after healing: the interactive chooser spreads acks only within 25%+5ms
		// of the best score, and the revived leg's probe-measured SRTT (with probe scheduling inflation) sits above
		// that window until real traffic re-measures it.
		if ss[0].Alive && ss[0].Sent > sent0BeforeHeal+200 { // >200 packets assigned to the healed leg
			healed.Store(true)
			t.Logf("leg 0 healed and carrying after %v (server Sent %d -> %d, share %.2f)",
				time.Since(t1).Round(time.Millisecond), sent0BeforeHeal, ss[0].Sent, ss[0].Share)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healed.Load() {
		t.Fatalf("leg 0 never carried bulk again after healing: srv %+v cli %+v",
			rig.srv.CarrierStats()[0], rig.cli.CarrierStats()[0])
	}

	// (a) and the session rides both legs to the end, bytes intact
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed: %v (got %d of %d)", err, got, n)
		}
		if got != n {
			t.Fatalf("short download: %d of %d", got, n)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("download timed out")
	}
}
