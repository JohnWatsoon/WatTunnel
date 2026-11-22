package mgr

// Animation primitives (design-motion: purposeful motion only — a spinner
// while something works, live values that settle instead of jumping, nothing
// looping for no reason). Every primitive is static when UseAnim is off, so
// anim-off output is byte-stable across refreshes.

import (
	"math"
	"time"
)

// spinnerFrames are the braille dot frames. sys.go's update loop still keeps
// its own local copy of the same set; it adopts these when that screen is next
// touched (out of this lane's scope).
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// Spinner hands out one frame per call. With UseAnim off every call returns
// the first frame, so a caller can always print Frame() and nothing moves.
type Spinner struct{ n int }

// Frame returns the next spinner frame.
func (sp *Spinner) Frame() string {
	if !UseAnim {
		return string(spinnerFrames[0])
	}
	f := string(spinnerFrames[sp.n%len(spinnerFrames)])
	sp.n++
	return f
}

// animNow is the clock the animation primitives read; tests swap it for a
// fake clock and restore it (the same seam pattern as Stdout/In).
var animNow = time.Now

// tweenTau is the settle time: after one gap of this length a tween has moved
// ~63% of the way to its target, so a 1 s dashboard refresh eases over about
// two refreshes instead of teleporting (design-motion: motion follows data).
const tweenTau = 600 * time.Millisecond

// Tween settles a displayed number toward its target across refreshes. Steps
// are frame-rate independent: each call moves cur by the fraction of the gap
// the elapsed time implies (exponential decay with time constant tweenTau),
// so ten 100 ms steps and one 1 s step land in the same place. UseAnim off
// snaps straight to the target (static values).
type Tween struct {
	cur float64
	at  time.Time
}

// NewTween starts a tween displaying v.
func NewTween(v float64) *Tween {
	return &Tween{cur: v, at: animNow()}
}

// Val returns the value to display now.
func (t *Tween) Val() float64 { return t.cur }

// Step records the new target and returns the value to display now.
func (t *Tween) Step(target float64) float64 {
	if !UseAnim {
		t.cur = target
		return t.cur
	}
	at := animNow()
	dt := at.Sub(t.at).Seconds()
	t.at = at
	if dt > 0 {
		t.cur += (target - t.cur) * (1 - math.Exp(-dt/tweenTau.Seconds()))
		if math.Abs(target-t.cur) < 1e-9 {
			t.cur = target
		}
	}
	return t.cur
}

// clamp01 clamps v into 0..1.
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Fill eases a bar's 0..1 fill toward its target: the smooth fill behind a
// GradBar meter (the meter glides to the new rate, it does not snap). Render
// it with GradBar(f.cur*max, max, w), or GradBar(f.cur, 1, w) for a
// percentage bar.
type Fill struct{ Tween }

// NewFill starts a fill at v (clamped to 0..1).
func NewFill(v float64) *Fill { return &Fill{*NewTween(clamp01(v))} }

// Step eases the fill toward target (clamped to 0..1) and returns it.
func (f *Fill) Step(target float64) float64 { return f.Tween.Step(clamp01(target)) }
