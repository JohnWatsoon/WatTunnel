package wat

import (
	"testing"
	"time"
)

// TestGovernorLearnsCeiling: sustained bulk with a stable base RTT arms the governor; a base-RTT jump (the
// reroute signature) sets a ceiling at 80 % of the pre-jump rate, held for govHold; quiet windows creep it
// back up and release it at 1.25x the trigger rate.
func TestGovernorLearnsCeiling(t *testing.T) {
	old := governorOn.Load()
	governorOn.Store(true)
	defer governorOn.Store(old)
	now := time.Now()
	g := &govState{}
	rate := 40e6 // 40 MB/s bulk
	// 4 stable windows at base RTT 40 ms: armed, no ceiling yet
	for w := 0; w < 4; w++ {
		for i := 0; i < 10; i++ {
			g.govSample(40*time.Millisecond, rate, now)
			now = now.Add(200 * time.Millisecond)
		}
	}
	if !g.armed {
		t.Fatalf("governor never armed after 4 stable windows")
	}
	if g.ceiling != 0 {
		t.Fatalf("ceiling set without a signature: %f", g.ceiling)
	}
	// the signature: base RTT jumps to 76 ms (the field's 40 -> 76)
	g.govSample(76*time.Millisecond, rate, now)
	now = now.Add(govWindow)
	g.govSample(76*time.Millisecond, rate, now) // close the window with the jump
	if g.ceiling == 0 {
		t.Fatalf("no ceiling learned from the base-RTT jump")
	}
	want := rate * govCut
	if g.ceiling < want*0.99 || g.ceiling > want*1.01 {
		t.Fatalf("ceiling %f, want ~%f (80%% of the pre-jump rate)", g.ceiling, want)
	}
	if !g.holdUntil.After(now) {
		t.Fatalf("no hold after the signature")
	}
	// holding: samples inside the hold neither raise nor lower it
	g.govSample(76*time.Millisecond, 80e6, now)
	if g.ceiling < want*0.99 {
		t.Fatalf("hold changed the ceiling")
	}
	// recovery: after the hold, quiet windows at the old base creep the ceiling up and release it
	now = g.holdUntil.Add(time.Second)
	for w := 0; w < 40; w++ {
		g.govSample(40*time.Millisecond, g.ceiling*0.5, now)
		now = now.Add(govWindow)
	}
	if g.ceiling != 0 {
		t.Fatalf("ceiling never released after quiet recovery: %f", g.ceiling)
	}
}

// TestGovernorOffByDefault: without SetGovernor(true), nothing is learned and nothing caps the rate.
func TestGovernorOffByDefault(t *testing.T) {
	// Own the global switch instead of skipping when another test left it on: a skip here was a silent hole
	// in the suite and made the test order-dependent (audit 2026-11-03).
	old := governorOn.Load()
	governorOn.Store(false)
	t.Cleanup(func() { governorOn.Store(old) })
	now := time.Now()
	g := &govState{}
	for i := 0; i < 100; i++ {
		g.govSample(40*time.Millisecond, 50e6, now)
		now = now.Add(200 * time.Millisecond)
	}
	g.govSample(200*time.Millisecond, 50e6, now) // a jump
	if g.ceiling != 0 || g.armed {
		t.Fatalf("governor learned while disabled (ceiling %f armed %v)", g.ceiling, g.armed)
	}
}

// TestGovernorUnarmedJitterConvergence verifies that an RTT jump while unarmed does not lock the governor out,
// but resets consecutive arming counters and converges to the new baseline.
func TestGovernorUnarmedJitterConvergence(t *testing.T) {
	old := governorOn.Load()
	governorOn.Store(true)
	defer governorOn.Store(old)
	now := time.Now()
	g := &govState{}
	rate := 30e6

	stepWindow := func(rtt time.Duration) {
		for i := 0; i < 10; i++ {
			g.govSample(rtt, rate, now)
			now = now.Add(200 * time.Millisecond)
		}
	}

	// 1. One window at 40 ms
	stepWindow(40 * time.Millisecond)

	// 2. Window at 80 ms while unarmed: closes window 1 (arms=1, base=40ms), then accumulates 80ms
	stepWindow(80 * time.Millisecond)
	if g.armed || g.arms != 1 || g.base != 40*time.Millisecond {
		t.Fatalf("after window 1: armed=%v arms=%d base=%v", g.armed, g.arms, g.base)
	}

	// 3. Next window at 80 ms: closes the 80ms window.
	// Since base was 40ms and closed is 80ms (>1.25*base) while !armed,
	// it must reset arms to 0 and converge base to 80ms.
	stepWindow(80 * time.Millisecond)
	if g.armed || g.arms != 0 || g.base != 80*time.Millisecond {
		t.Fatalf("after unarmed jump: armed=%v arms=%d base=%v", g.armed, g.arms, g.base)
	}

	// 4. Three consecutive stable windows at 80 ms: arms must count 1, 2, 3 and become armed.
	for w := 0; w < 3; w++ {
		stepWindow(80 * time.Millisecond)
	}
	if !g.armed {
		t.Fatalf("governor failed to arm after convergence to new baseline: arms=%d base=%v", g.arms, g.base)
	}

	// 5. Now a censorship jump to 160 ms triggers the signature
	g.govSample(160*time.Millisecond, rate, now)
	now = now.Add(govWindow)
	g.govSample(160*time.Millisecond, rate, now)
	if g.ceiling == 0 {
		t.Fatalf("governor failed to trigger signature after convergence")
	}
}
