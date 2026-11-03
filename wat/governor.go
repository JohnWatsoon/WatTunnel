package wat

// ICMP ceiling governor (-governor, 2.9.0). The path's hard limit is not bandwidth but a packet-rate /
// volume limit that answers sustained bulk above ~30 MB/s with a reroute inside Iran (base RTT 40 -> 76 ms
// for minutes, field 2026-10-12: docs/TECHNICAL.md "Volume limit"). The pacer's delay rule alone only reacts
// AFTER the queue built, and happily probes right back up into the next reroute. The governor learns the
// highest rate that did NOT trigger the reroute signature, and holds the delay rule's growth under it:
//
//	- baseline: minRTT is watched per window (2 s). A stable baseline (low jitter) for >= 3 windows arms the
//	  governor, so it never learns from an already-rerouted or still-converging path.
//	- signature: the window's base RTT jumps > 25 % above the stable baseline. The reroute has happened; the
//	  ceiling is set to the max rate seen in the 4 s BEFORE the jump, cut 20 %, and held for 60 s.
//	- recovery: after the hold, the ceiling creeps up 2 % per quiet window (no signature, no delay cuts) so a
//	  path that got faster is followed. A new signature repeats the cut from the newest observation.
//
// The sim tests pin the ICMP pacer's delay behaviour; the governor only ever LOWERS maxRate-shaped growth
// behind an explicit ceiling and is opt-in, so the pins hold. Field-validated? No — flag it (see handoff).

import (
	"sync/atomic"
	"time"
)

// governorOn enables the ceiling governor for every session of this process (opt-in, like -loss-ceiling).
var governorOn atomic.Bool

// SetGovernor switches the ICMP ceiling governor on or off (cmd: -governor).
func SetGovernor(on bool) { governorOn.Store(on) }

// governorWindow is the observation window; the signature is judged per window.
const (
	govWindow     = 2 * time.Second
	govArmWindows = 3    // stable windows before armed
	govJump       = 1.25 // base-RTT jump that counts as the reroute signature
	govHold       = 60 * time.Second
	govCreep      = 1.02
	govPreWindow  = 4 * time.Second // rate history kept for the "rate before the jump" ceiling
	govCut        = 0.80
)

// govState is the per-session governor state inside cc (guarded by the session's cc lock discipline: all
// fields are touched only from cc.sample / cc.tick, which run under the session lock).
type govState struct {
	base       time.Duration // stable baseline RTT
	stableAt   time.Time     // window start
	winMin     time.Duration // this window's minimum RTT sample
	winMaxRate float64       // max rate seen this window (rate at window end is the ceiling candidate)
	arms       int           // consecutive stable windows
	armed      bool
	holdUntil  time.Time
	ceiling    float64 // bytes/s; 0 = none learned yet
	trigger    float64 // the rate that caused the current ceiling (release bound)
	rateRing   []govRate
}

type govRate struct {
	at time.Time
	r  float64
}

// govSample is called from cc.sample (every RTT sample, session lock held).
func (g *govState) govSample(rtt time.Duration, rate float64, now time.Time) {
	if !governorOn.Load() || rtt <= 0 {
		return
	}
	if g.winMin == 0 || rtt < g.winMin {
		g.winMin = rtt
	}
	if rate > g.winMaxRate {
		g.winMaxRate = rate
	}
	g.rateRing = append(g.rateRing, govRate{now, rate})
	// keep the full govPreWindow of history (the jump verdict reads back that far); a count-only cap
	// covered well under 4 s on fast paths, where samples arrive once per RTT (audit 2026-10-21)
	if cut := now.Add(-govPreWindow); len(g.rateRing) > 0 && g.rateRing[0].at.Before(cut) {
		i := 0
		for i < len(g.rateRing) && g.rateRing[i].at.Before(cut) {
			i++
		}
		g.rateRing = append(g.rateRing[:0], g.rateRing[i:]...)
	}
	if len(g.rateRing) > 4096 { // count backstop for sub-millisecond RTTs
		g.rateRing = g.rateRing[len(g.rateRing)-4096:]
	}
	if g.stableAt.IsZero() {
		g.stableAt = now
	} else if now.Sub(g.stableAt) >= govWindow {
		g.govWindow(now)
	}
}

// govWindow closes the current window and judges the signature (session lock held).
func (g *govState) govWindow(now time.Time) {
	closed := g.winMin
	if closed == 0 {
		g.stableAt, g.winMin, g.winMaxRate = now, 0, 0
		return
	}
	defer func() { g.winMin, g.winMaxRate = 0, 0 }()
	defer func() { g.stableAt = now }()
	if g.holdUntil.After(now) {
		return // holding below the ceiling; nothing to learn while the path reroutes back
	}
	if g.base > 0 && float64(closed) > govJump*float64(g.base) && g.armed {
		// signature: the base RTT jumped while we were armed. Ceiling = the max rate shortly before,
		// cut; held so the delay rule's own recovery cannot probe straight back into the next reroute.
		pre := g.maxRateBefore(now.Add(-govPreWindow))
		if pre > 0 {
			g.ceiling = pre * govCut
			g.trigger = pre
			g.holdUntil = now.Add(govHold)
		}
		g.base, g.arms, g.armed = closed, 0, false // re-baseline on the new (rerouted) path
		return
	}
	// stability: a window whose base is within the jump threshold of the incumbent baseline is "stable".
	if g.base == 0 || float64(closed) <= govJump*float64(g.base) {
		if g.base == 0 || closed < g.base {
			g.base = closed // snap down immediately on lower physical RTT
		} else {
			g.base = time.Duration((7*int64(g.base) + int64(closed)) / 8) // slow follow within the band
		}
		g.arms++
		if g.arms >= govArmWindows {
			g.armed = true
		}
	} else {
		// Base RTT jumped while not yet armed: reset consecutive arm counter and converge base
		// to the new baseline so governor doesn't lock out from arming.
		g.arms = 0
		g.base = closed
	}
	// quiet creep: no signature for a full window lifts the ceiling 2 %, released at 1.25x the rate that
	// triggered it (the learned ceiling must not outlive its evidence by much)
	if g.armed && g.ceiling > 0 && g.winMaxRate <= g.ceiling {
		g.ceiling *= govCreep
		if g.trigger > 0 && g.ceiling > g.trigger*1.25 {
			g.ceiling, g.trigger = 0, 0
		}
	}
}

// maxRateBefore returns the highest observed rate since t (bounded history).
func (g *govState) maxRateBefore(t time.Time) float64 {
	m := 0.0
	for i := len(g.rateRing) - 1; i >= 0; i-- {
		if g.rateRing[i].at.Before(t) {
			break
		}
		if g.rateRing[i].r > m {
			m = g.rateRing[i].r
		}
	}
	return m
}
