package mgr

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestSpinnerParkedWhenAnimOff(t *testing.T) {
	UseAnim = false
	var sp Spinner
	for i := 0; i < 5; i++ {
		if f := sp.Frame(); f != string(spinnerFrames[0]) {
			t.Errorf("anim-off Frame() = %q, want the parked glyph", f)
		}
	}
}

func TestSpinnerCyclesAllFrames(t *testing.T) {
	UseAnim = true
	defer func() { UseAnim = false }()
	var sp Spinner
	seen := map[string]bool{}
	for i := 0; i < len(spinnerFrames); i++ {
		seen[sp.Frame()] = true
	}
	if len(seen) != len(spinnerFrames) {
		t.Errorf("one cycle showed %d distinct frames, want %d", len(seen), len(spinnerFrames))
	}
}

func TestTweenSnapsWhenAnimOff(t *testing.T) {
	UseAnim = false
	tw := NewTween(0)
	if got := tw.Step(100); got != 100 || tw.Val() != 100 {
		t.Errorf("anim-off Step = %v, want the target (static values)", got)
	}
}

func TestTweenEasesTowardTarget(t *testing.T) {
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	tw := NewTween(0)
	// no elapsed time, no movement
	if got := tw.Step(100); got != 0 {
		t.Errorf("first Step with a still clock = %v, want 0", got)
	}
	// one tau: ~63 % of the gap; two: ~86 %
	at = at.Add(tweenTau)
	if v := tw.Step(100); v < 60 || v > 67 {
		t.Errorf("after one tau = %v, want ~63", v)
	}
	at = at.Add(tweenTau)
	if v := tw.Step(100); v < 84 || v > 89 {
		t.Errorf("after two tau = %v, want ~86", v)
	}
	for i := 0; i < 50; i++ {
		at = at.Add(tweenTau)
		tw.Step(100)
	}
	if tw.Val() != 100 {
		t.Errorf("tween must converge exactly, got %v", tw.Val())
	}
}

// Frame-rate independence: ten 100 ms steps and one 1 s step land in the same
// place (exponential decay, exact by construction).
func TestTweenFrameRateIndependent(t *testing.T) {
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	fine := NewTween(0)
	for i := 0; i < 10; i++ {
		at = at.Add(100 * time.Millisecond)
		fine.Step(64)
	}
	coarse := NewTween(0)
	at = at.Add(time.Second)
	coarse.Step(64)
	if math.Abs(fine.Val()-coarse.Val()) > 1e-9 {
		t.Errorf("10x100ms = %v, 1x1s = %v", fine.Val(), coarse.Val())
	}
}

// NaN/±Inf are garbage: clamp01 reads them 0 and Tween reads a non-finite
// target 0, so a poisoned value can never wedge cur forever (debug round 3,
// 2026-11-23 — the old clamp01(NaN) returned NaN and every later Step kept
// it; a +Inf target became NaN on the next step via Inf-Inf).
func TestTweenFillRejectNonFinite(t *testing.T) {
	UseAnim = false
	defer func() { UseAnim = false }()
	if clamp01(math.NaN()) != 0 || clamp01(math.Inf(1)) != 0 || clamp01(math.Inf(-1)) != 0 {
		t.Error("clamp01 must read garbage as 0")
	}
	f := NewFill(0)
	if got := f.Step(math.NaN()); got != 0 {
		t.Errorf("anim-off Fill.Step(NaN) = %v, want 0", got)
	}
	if got := f.Step(0.5); got != 0.5 {
		t.Errorf("after NaN, Step(0.5) = %v, want 0.5 (no poison)", got)
	}
	// anim on: the garbage eases the value back toward 0 and recovery works
	UseAnim = true
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	g := NewFill(0.8)
	at = at.Add(tweenTau)
	if v := g.Step(math.NaN()); math.IsNaN(v) || v >= 0.8 {
		t.Errorf("Step(NaN) = %v, want the fill easing back to 0 (alive)", v)
	}
	at = at.Add(tweenTau)
	if v := g.Step(0.5); v <= 0 || v >= 0.5 {
		t.Errorf("after NaN, Step(0.5) = %v, want easing toward 0.5", v)
	}
	for i := 0; i < 40; i++ {
		at = at.Add(tweenTau)
		g.Step(0.5)
	}
	if g.Val() != 0.5 {
		t.Errorf("fill must converge exactly after the NaN, got %v", g.Val())
	}
	tw := NewTween(100)
	at = at.Add(tweenTau)
	tw.Step(math.Inf(1)) // target reads 0: cur eases down, never Inf
	if v := tw.Val(); math.IsInf(v, 0) || math.IsNaN(v) {
		t.Errorf("Step(+Inf) = %v, want a finite value easing toward 0", v)
	}
	at = at.Add(tweenTau)
	for i := 0; i < 40; i++ {
		at = at.Add(tweenTau)
		tw.Step(0.5)
	}
	if tw.Val() != 0.5 {
		t.Errorf("tween must converge exactly after the Inf, got %v", tw.Val())
	}
	// GradBar of a garbage level renders the empty-but-alive bar (no panic)
	if got := StripANSI(GradBar(math.NaN(), 10, 4)); got != "▱▱▱▱" {
		t.Errorf("GradBar(NaN) = %q, want the empty bar", got)
	}
}

func TestFillClampsAndSnaps(t *testing.T) {
	UseAnim = false
	f := NewFill(0)
	if got := f.Step(0.5); got != 0.5 {
		t.Errorf("Step(0.5) = %v", got)
	}
	if got := f.Step(2); got != 1 {
		t.Errorf("Step(2) = %v, want clamped 1", got)
	}
	if got := f.Step(-1); got != 0 {
		t.Errorf("Step(-1) = %v, want clamped 0", got)
	}
	if v := NewFill(5).Val(); v != 1 {
		t.Errorf("NewFill(5) = %v, want clamped 1", v)
	}
	// anim on: the fill eases toward the target, never past it
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	g := NewFill(0)
	at = at.Add(tweenTau)
	if v := g.Step(1); v <= 0 || v >= 1 {
		t.Errorf("mid-flight fill = %v, want between 0 and 1", v)
	}
}

// The band sweep (boot intro): phase 0 is the plain grey rule, phase 1 lands
// byte-identically on the static GradLine, mid-flight differs from both ends,
// and colour off degenerates to the static band at every phase.
func TestGradSweepPhases(t *testing.T) {
	const w = 10
	InitColor(true, 8)
	if got := GradSweep(w, 0); got != GRY+Rep("━", w)+RST {
		t.Errorf("phase 0 = %q, want the plain grey rule", got)
	}
	if got := GradSweep(w, 1); got != GradLine(w) {
		t.Errorf("phase 1 must land on the static band:\n%q\nwant\n%q", got, GradLine(w))
	}
	mid := GradSweep(w, 0.5)
	if mid == GradLine(w) || mid == GradSweep(w, 0) {
		t.Errorf("mid sweep must differ from both ends: %q", mid)
	}
	if !strings.Contains(mid, CYN) || !strings.Contains(mid, GRY) {
		t.Errorf("mid sweep must carry the revealed half and the grey half: %q", mid)
	}
	if got := StripANSI(mid); got != Rep("━", w) {
		t.Errorf("mid sweep glyphs = %q, want a full-width band", got)
	}
	InitColor(false, 8)
	if got := GradSweep(w, 0.3); got != GradLine(w) {
		t.Errorf("colour off must degenerate to the static band: %q", got)
	}
}

// Breath flips each flip interval on the animNow clock and is parked bright
// when anim is off.
func TestBreath(t *testing.T) {
	UseAnim = false
	if !Breath(600 * time.Millisecond) {
		t.Error("anim off: breath must park bright")
	}
	UseAnim = true
	defer func() { UseAnim = false }()
	at := time.Unix(0, 0)
	animNow = func() time.Time { return at }
	defer func() { animNow = time.Now }()
	if !Breath(600 * time.Millisecond) {
		t.Error("first interval is bright")
	}
	at = at.Add(700 * time.Millisecond)
	if Breath(600 * time.Millisecond) {
		t.Error("second interval is dim")
	}
	at = at.Add(600 * time.Millisecond)
	if !Breath(600 * time.Millisecond) {
		t.Error("third interval is bright again")
	}
}
