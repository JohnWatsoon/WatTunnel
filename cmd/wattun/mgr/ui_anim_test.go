package mgr

import (
	"math"
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
