package mgr

// Animation primitives (design-motion: purposeful motion only — a spinner
// while something works, live values that settle instead of jumping, nothing
// looping for no reason). Every primitive is static when UseAnim is off, so
// anim-off output is byte-stable across refreshes.

import (
	"math"
	"strings"
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
	// debug round 3 (2026-11-23): a non-finite target is garbage (a bad parse,
	// a 0 division) and the old math poisoned cur forever — NaN stayed NaN, and
	// +Inf turned into NaN on the next step (Inf-Inf). Garbage reads 0, so the
	// value settles back honestly instead of wedging.
	if math.IsNaN(target) || math.IsInf(target, 0) {
		target = 0
	}
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

// clamp01 clamps v into 0..1; NaN/±Inf are garbage and read 0 (the same rule
// as Tween.Step, debug round 3 (2026-11-23): the old comparisons let NaN
// through and a poisoned Fill never recovered).
func clamp01(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
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

// Breath is the slow two-state pulse for a live "working" tell (the pair
// line's dot while a refresh is in flight): it flips each flip interval on the
// animNow clock, so a 2 s redraw cadence still alternates and tests can step
// it. Static bright when anim is off — nothing loops for no reason.
func Breath(flip time.Duration) bool {
	if !UseAnim {
		return true
	}
	if flip <= 0 {
		flip = time.Second
	}
	return animNow().UnixNano()/int64(flip)%2 == 0
}

// GradSweep is the header band mid-boot-sweep: the ramp is revealed left to
// right over the quiet grey rule, phase 0 being the plain rule and phase 1
// byte-identical to GradLine, so the sweep lands exactly on the static band
// (ui_grad.go). Colour off degenerates to GradLine at every phase — nothing
// moves when colour cannot show it.
func GradSweep(w int, phase float64) string {
	phase = clamp01(phase)
	if ColorTier == 0 || phase >= 1 {
		return GradLine(w)
	}
	cut := int(float64(w)*phase + 0.5)
	var b strings.Builder
	last := ""
	for i := 0; i < w; i++ {
		if i >= cut {
			if last != GRY {
				b.WriteString(GRY)
				last = GRY
			}
			b.WriteRune('━')
			continue
		}
		t := 0.0
		if w > 1 {
			t = float64(i) / float64(w-1)
		}
		if e := GradRGB(t); e != last {
			b.WriteString(e)
			last = e
		}
		b.WriteRune('━')
	}
	b.WriteString(RST)
	return b.String()
}
