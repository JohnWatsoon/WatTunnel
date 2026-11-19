package comp

import (
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

func TestLabelUppercasesAndDims(t *testing.T) {
	if got := Label("carriers"); got != Dim.Render("CARRIERS") {
		t.Errorf("Label = %q, want Dim.Render(CARRIERS)", got)
	}
}

func TestTitleIsBoldAccent(t *testing.T) {
	if got := Title("dashboard"); got != Accent.Bold(true).Render("dashboard") {
		t.Errorf("Title = %q, want Accent.Bold render", got)
	}
}

func TestKeyHintFormat(t *testing.T) {
	want := Dim.Render("(m mute · s stop · q back)")
	got := KeyHint([2]string{"m", "mute"}, [2]string{"s", "stop"}, [2]string{"q", "back"})
	if got != want {
		t.Errorf("KeyHint = %q, want %q", got, want)
	}
	if got := KeyHint(); got != Dim.Render("()") {
		t.Errorf("KeyHint() = %q, want %q", got, Dim.Render("()"))
	}
}

func TestCardBorder(t *testing.T) {
	if got := Card(false).Render("hello"); got != "hello" {
		t.Errorf("unfocused Card changed content: %q", got)
	}
	if got := Card(true).Render("hello"); !strings.Contains(got, "╭") || !strings.Contains(got, "hello") {
		t.Errorf("focused Card has no rounded border: %q", got)
	}
}

func TestBarThresholdsAndClamp(t *testing.T) {
	cases := []struct {
		pct  float64
		fill int
		st   func(...string) string // lipgloss Render signature
	}{
		{0, 0, Ok.Render},
		{50, 5, Ok.Render},
		{69.9, 7, Ok.Render},
		{70, 7, Warn.Render},
		{89.9, 9, Warn.Render},
		{90, 9, Bad.Render},
		{100, 10, Bad.Render},
	}
	for _, c := range cases {
		want := c.st(strings.Repeat("█", c.fill)) + Dim.Render(strings.Repeat("░", 10-c.fill))
		if got := Bar(c.pct, 10); got != want {
			t.Errorf("Bar(%v, 10) = %q, want %q", c.pct, got, want)
		}
	}
	// clamps: over 100 fills the whole bar, below 0 empties it
	if got := Bar(150, 10); got != Bad.Render(strings.Repeat("█", 10)) {
		t.Errorf("Bar(150, 10) did not clamp to full: %q", got)
	}
	if got := Bar(-5, 10); got != Ok.Render(strings.Repeat("░", 10)) {
		t.Errorf("Bar(-5, 10) did not clamp to empty: %q", got)
	}
	if got := Bar(50, 0); got != "" {
		t.Errorf("Bar(50, 0) = %q, want empty", got)
	}
}

func TestDot(t *testing.T) {
	if got := Dot(true); got != Ok.Render("●") {
		t.Errorf("Dot(true) = %q, want Ok dot", got)
	}
	if got := Dot(false); got != Dim.Render("●") {
		t.Errorf("Dot(false) = %q, want Dim dot", got)
	}
}

// otherMsg is a foreign message type for the Spin.Update pass-through check.
type otherMsg struct{}

func TestSpinCycles(t *testing.T) {
	s := NewSpin()
	if cmd := s.Init(); cmd == nil {
		t.Fatal("Init returned no cmd")
	}
	f0 := s.View()
	if utf8.RuneCountInString(f0) != 1 {
		t.Errorf("frame is not one rune: %q", f0)
	}
	var cmd tea.Cmd
	s2 := s
	for range len(spinFrames) {
		s2, cmd = s2.Update(TickMsg{})
		if cmd == nil {
			t.Fatal("Update(TickMsg) returned no cmd")
		}
	}
	if s2.View() != f0 {
		t.Errorf("after a full cycle the frame did not wrap: %q != %q", s2.View(), f0)
	}
	if s3, cmd := s2.Update(otherMsg{}); s3.View() != s2.View() || cmd != nil {
		t.Error("Update with a foreign message advanced the spinner or produced a cmd")
	}
	m := s.Tick()
	if _, ok := m.(TickMsg); !ok {
		t.Errorf("Tick() returned %T, want TickMsg", m)
	}
}

func TestSparkWidthAndAutoscale(t *testing.T) {
	sp := NewSpark(8)
	for i := range 20 {
		sp.Add(float64(i)) // the window keeps 12..19, max 19
	}
	if got := sp.View(); utf8.RuneCountInString(got) != 8 {
		t.Errorf("View width = %d runes, want 8: %q", utf8.RuneCountInString(got), got)
	}
	if got := sp.View(); !strings.HasSuffix(got, "█") {
		t.Errorf("the max sample did not render as the top glyph: %q", got)
	}
	if got := NewSpark(4).View(); got != "▁▁▁▁" {
		t.Errorf("empty spark = %q, want all ▁", got)
	}
	allZero := NewSpark(4)
	for range 4 {
		allZero.Add(0)
	}
	if got := allZero.View(); got != "▁▁▁▁" {
		t.Errorf("all-zero spark = %q, want all ▁", got)
	}
	// stability: same data, same rendering
	if sp.View() != sp.View() {
		t.Error("View is not stable across calls")
	}
	// autoscale: 0 then max must be ▁█
	two := NewSpark(2)
	two.Add(0)
	two.Add(100)
	if got := two.View(); got != "▁█" {
		t.Errorf("0/100 spark = %q, want ▁█", got)
	}
}

func TestSparkSlidingWindow(t *testing.T) {
	sp := NewSpark(3)
	for _, v := range []float64{1, 2, 3, 4} {
		sp.Add(v)
	}
	// the window is now 2,3,4 autoscaled to max 4: 2/4*7+0.5 → ▅, 3/4 → ▆, 4/4 → █
	if got := sp.View(); got != "▅▆█" {
		t.Errorf("slid window = %q, want ▅▆█", got)
	}
}
