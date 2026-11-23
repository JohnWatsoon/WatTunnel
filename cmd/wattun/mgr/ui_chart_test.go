package mgr

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// chartSeries builds a 3-sample ring: down 400 B/s steady, up 100 B/s steady,
// RTT 40→50 ms. The two steps land in one braille cell per band.
func chartSeries(t *testing.T) []chartSample {
	t.Helper()
	t0 := time.Unix(1732161000, 0)
	return []chartSample{
		{T: t0, Down: 400, Up: 100, RTT: 50},
		{T: t0.Add(2 * time.Second), Down: 400, Up: 100, RTT: 40},
		{T: t0.Add(4 * time.Second), Down: 400, Up: 100, RTT: 50},
	}
}

func resetChart() { chartHist = map[string][]chartSample{} }

// Pin the grid math: one cell, both dot columns. Down (max of the shared
// scale) fills all 8 levels -> full cell in both rows; up at a quarter of the
// max fills only the bottom 3 levels of the bottom row — which also pins the
// shared y auto-scale (up on its own scale would fill the cell too).
func TestBrailleGridAutoScale(t *testing.T) {
	down := brailleGrid([]float64{400, 400}, 400, 2, true)
	if string(down[0]) != "⣿" || string(down[1]) != "⣿" {
		t.Errorf("down band = %q %q, want full cells", down[0], down[1])
	}
	up := brailleGrid([]float64{100, 100}, 400, 2, true)
	if string(up[0]) != " " || string(up[1]) != "⣼" {
		t.Errorf("up band = %q %q, want empty top + 3-level bottom", up[0], up[1])
	}
	// thin trace: single dots at their level, no fill
	rtt := brailleGrid([]float64{40, 50}, 50, 1, false)
	if string(rtt[0]) != "⠃" {
		t.Errorf("rtt trace = %q, want ⠃", rtt[0])
	}
}

// Tier 0: solid chars, byte-exact rows, no escapes anywhere.
func TestRateChartTier0Pinned(t *testing.T) {
	InitColor(false, 8)
	defer InitColor(false, 8)
	var b bytes.Buffer
	paintChartGrid(&b, "  ↓ ", string(brailleGrid([]float64{400, 400}, 400, 2, true)[0]), false)
	if got := b.String(); got != "  ↓ ⣿\n" {
		t.Errorf("tier 0 band row = %q", got)
	}

	resetChart()
	var out bytes.Buffer
	RateChart(&out, "t · live rate", chartSeries(t), 40)
	s := out.String()
	if strings.Contains(s, "\x1b") {
		t.Error("tier 0 chart must carry no escapes")
	}
	for _, want := range []string{"⣿", "⣼", "⠃", "↓400.0 B/s", "↑100.0 B/s", "rtt 50 ms"} {
		if !strings.Contains(s, want) {
			t.Errorf("tier 0 chart missing %q in:\n%s", want, s)
		}
	}
	// both directions present
	if !strings.Contains(s, "  ↓ ") || !strings.Contains(s, "  ↑ ") {
		t.Errorf("direction gutters missing:\n%s", s)
	}
}

// Fresh start: fewer than 2 samples is an honest placeholder, no invented data.
func TestRateChartCollecting(t *testing.T) {
	InitColor(false, 8)
	defer InitColor(false, 8)
	resetChart()
	var out bytes.Buffer
	RateChart(&out, "t", []chartSample{{T: time.Now(), Down: 400, Up: 100}}, 76)
	if !strings.Contains(out.String(), "collecting samples… (1/2 ticks)") {
		t.Errorf("placeholder missing: %q", out.String())
	}
	if strings.Contains(out.String(), "⣿") {
		t.Error("placeholder must not plot data")
	}
}

// Colour tiers: 8 is solid cyan down / saffron up; 24 paints the ramp along
// the series (a one-cell series sits at the turquoise end = CYN).
func TestRateChartTiers(t *testing.T) {
	InitColor(true, 8)
	defer InitColor(false, 8)
	resetChart()
	var out bytes.Buffer
	RateChart(&out, "t", chartSeries(t), 40)
	s := out.String()
	if !strings.Contains(s, CYN+"⣿") {
		t.Errorf("tier 8 down band not solid cyan: %q", s)
	}
	if !strings.Contains(s, SAF+"⣼") {
		t.Errorf("tier 8 up band not solid saffron: %q", s)
	}

	InitColor(true, 24)
	out.Reset()
	RateChart(&out, "t", chartSeries(t), 40)
	s = out.String()
	if !strings.Contains(s, CYN+"⣿") { // ramp start = gradAt(0) = CYN
		t.Errorf("tier 24 ramp start missing: %q", s)
	}
	// a wide series walks the ramp: 40 values = 20 cells
	wide := make([]float64, 40)
	for i := range wide {
		wide[i] = 100
	}
	if got := brailleGrid(wide, 100, 2, true); len(got[0]) != 20 {
		t.Errorf("wide series cell count = %d, want 20", len(got[0]))
	}
}

// Narrow terminals compress: fewer columns, never a wrapped chart row.
func TestRateChartNarrow(t *testing.T) {
	InitColor(false, 8)
	defer InitColor(false, 8)
	resetChart()
	t0 := time.Unix(1732161000, 0)
	many := chartSeries(t)
	for i := 3; i < 60; i++ { // 59 samples: more than a narrow chart can show
		many = append(many, chartSample{T: t0.Add(time.Duration(i) * 2 * time.Second),
			Down: 400, Up: 100, RTT: 50})
	}
	var out bytes.Buffer
	RateChart(&out, "t", many, 30)
	// the plotted rows must fit 30 columns (the header/figures text lines span
	// the screen like every other row here; the chart itself compresses)
	narrow := 0
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.ContainsAny(line, "⣿⣼⠃") {
			continue
		}
		if rlen(line) > 30 {
			t.Errorf("chart row wraps at width 30 (rlen %d): %q", rlen(line), line)
		}
		narrow = rlen(line)
	}
	if narrow == 0 {
		t.Fatal("narrow chart must still plot data")
	}
	// and compression is real: the same series on a wide chart plots more columns
	var wide bytes.Buffer
	RateChart(&wide, "t", many, 100)
	wideCols := 0
	for _, line := range strings.Split(wide.String(), "\n") {
		if strings.Contains(line, "⣿") && rlen(line) > wideCols {
			wideCols = rlen(line)
		}
	}
	if wideCols <= narrow {
		t.Errorf("wide chart (%d cols) did not compress at width 30 (%d cols)", wideCols, narrow)
	}
}

// chartPush feeds the ring the monitor redraws from; the cap holds and keeps
// the newest end.
func TestChartPushRing(t *testing.T) {
	resetChart()
	t0 := time.Unix(1732161000, 0)
	for i := 0; i < chartCap+10; i++ {
		chartPush("t", t0.Add(time.Duration(i)*2*time.Second), 400, 100, 50)
	}
	if len(chartHist["t"]) != chartCap {
		t.Errorf("ring len = %d, want cap %d", len(chartHist["t"]), chartCap)
	}
	last := chartHist["t"][chartCap-1]
	if !last.T.Equal(t0.Add(time.Duration(chartCap+9) * 2 * time.Second)) {
		t.Error("ring kept the wrong end")
	}
}
