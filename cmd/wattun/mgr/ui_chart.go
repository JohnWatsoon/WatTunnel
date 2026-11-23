package mgr

// The monitor's live rate chart (owner request 2026-11-23): the dual-direction
// replacement for the bash-era sparkline. The data is the shared sampler's
// (home.go sampleTunnel/samples): byte-counter deltas per tick with the role's
// direction applied (down is what users receive — bytes in on Iran, bytes out
// on Kharej), so every plotted point is two real counter readings apart, never
// a fabricated or smoothed value; the only interpolation is the braille grid's
// vertical quantisation. This ring adds the per-step RTT the sampler does not
// keep. Down (↓) and up (↑) share one y scale auto-sized to the visible max;
// RTT rides below as a thin grey dot trace on its own scale. Colour tiers
// mirror the rest of the ui: truecolor/256 paint the ramp along the series
// (GradRGB), 8 is solid cyan/saffron per direction (down cyan, up saffron —
// the palette's direction semantics), 0 is the same glyphs with no escapes.

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// chartSample is one monitor tick of the shared sampler's rates plus the RTT
// reading that went with them.
type chartSample struct {
	T             time.Time
	Down, Up, RTT float64
}

// chartCap bounds the per-tunnel ring: 240 samples at the 2 s tick is 8 minutes,
// enough to fill a wide terminal's chart (each braille cell spans 2 samples).
const chartCap = 240

var chartHist = map[string][]chartSample{}

// chartPush appends one tick to the tunnel's ring; the monitor calls this for
// the selected rendering on every refresh (down/up come from sampleTunnel).
func chartPush(name string, at time.Time, down, up, rtt float64) {
	s := append(chartHist[name], chartSample{T: at, Down: down, Up: up, RTT: rtt})
	if len(s) > chartCap {
		s = s[len(s)-chartCap:]
	}
	chartHist[name] = s
}

// brailleDot is the bit for dot column x (0/1) and dot row y (0 top) inside a
// U+2800 braille cell.
func brailleDot(x, y int) rune { return rune(1 << (y*2 + x)) }

// brailleGrid lays vals out as braille cells: rows cells tall (rows*4 vertical
// dot levels), 2 samples per cell (left/right dot columns). Filled plots the
// area from the baseline; filled=false plots one dot per value (the thin RTT
// trace). Returns the grid top row first; empty cells are spaces.
func brailleGrid(vals []float64, vmax float64, rows int, filled bool) [][]rune {
	chars := (len(vals) + 1) / 2
	grid := make([][]rune, rows)
	for r := range grid {
		grid[r] = make([]rune, chars)
	}
	if vmax > 0 {
		for j, v := range vals {
			lvl := int(v / vmax * float64(rows*4))
			if lvl >= rows*4 {
				lvl = rows*4 - 1
			}
			if lvl < 0 {
				lvl = 0
			}
			top := 0
			if !filled {
				top = lvl
			}
			for l := top; l <= lvl; l++ {
				y := rows*4 - 1 - l
				grid[y/4][j/2] |= brailleDot(j%2, y%4)
			}
		}
	}
	for r := range grid {
		for c := range grid[r] {
			if grid[r][c] == 0 {
				grid[r][c] = ' '
			} else {
				grid[r][c] += 0x2800
			}
		}
	}
	return grid
}

// chartBandColor: the ramp along the series at truecolor/256; the palette's
// direction semantics (down cyan, up saffron) at 8; "" at 0.
func chartBandColor(t float64, up bool) string {
	if ColorTier == 8 {
		if up {
			return SAF
		}
		return CYN
	}
	return GradRGB(t)
}

// paintChartGrid writes one braille row behind its gutter, the band's colour
// ramp run across the non-empty cells.
func paintChartGrid(w io.Writer, gutter, row string, up bool) {
	if ColorTier == 0 {
		fmt.Fprintf(w, "%s%s\n", gutter, row)
		return
	}
	chars := len([]rune(row))
	var b strings.Builder
	b.WriteString(gutter)
	last := ""
	for j, c := range []rune(row) {
		if c == ' ' {
			b.WriteRune(c)
			continue
		}
		t := 0.0
		if chars > 1 {
			t = float64(j) / float64(chars-1)
		}
		if e := chartBandColor(t, up); e != last {
			b.WriteString(e)
			last = e
		}
		b.WriteRune(c)
	}
	if last != "" {
		b.WriteString(RST)
	}
	fmt.Fprintln(w, b.String())
}

// chartMean averages v; 0 when empty.
func chartMean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

// chartMax is the series max (0 for empty).
func chartMax(v []float64) float64 {
	m := 0.0
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

// RateChart renders the monitor's live rate chart for one tunnel: two braille
// rows per direction on a shared y scale auto-sized to the visible max (the
// peak is labeled), a thin grey RTT trace, and the now/60s/avg figures under
// it. width is the content width (uiW); a narrow terminal just gets fewer
// columns, never a wrapped chart.
func RateChart(w io.Writer, title string, s []chartSample, width int) {
	if len(s) < 2 {
		secHdr(w, title, "live rate")
		fmt.Fprintf(w, "  %scollecting samples… (%d/2 ticks)%s\n", GRY, len(s), RST)
		return
	}
	cols := width - 6 // 4-rune gutter + margins
	show := len(s)
	if show > cols*2 {
		show = cols * 2
	}
	d, u, r := make([]float64, show), make([]float64, show), make([]float64, show)
	for i := 0; i < show; i++ {
		d[i], u[i], r[i] = s[len(s)-show+i].Down, s[len(s)-show+i].Up, s[len(s)-show+i].RTT
	}
	maxD, maxU := chartMax(d), chartMax(u)
	ymax := maxD
	if maxU > ymax {
		ymax = maxU
	}
	rmax := chartMax(r)
	secHdr(w, title, fmt.Sprintf("peak ↓%s/s ↑%s/s", Human(maxD), Human(maxU)))

	// 60s window: the samples within 60 s of the newest
	lastT := s[len(s)-1].T
	var d60, u60 []float64
	for i := len(s) - show; i < len(s); i++ {
		if s[i].T.Sub(lastT).Seconds() <= 60 {
			d60, u60 = append(d60, s[i].Down), append(u60, s[i].Up)
		}
	}

	if ymax <= 0 {
		ymax = 1 // all-flat: an honest baseline, not a divide-by-zero
	}
	if rmax <= 0 {
		rmax = 1
	}
	if cols >= 8 {
		for i, row := range brailleGrid(d, ymax, 2, true) {
			gutter := "    "
			if i == 0 {
				gutter = "  ↓ "
			}
			paintChartGrid(w, gutter, string(row), false)
		}
		for i, row := range brailleGrid(u, ymax, 2, true) {
			gutter := "    "
			if i == 0 {
				gutter = "  ↑ "
			}
			paintChartGrid(w, gutter, string(row), true)
		}
		for _, row := range brailleGrid(r, rmax, 1, false) {
			if ColorTier == 0 {
				fmt.Fprintf(w, "rtt %s\n", string(row))
			} else {
				fmt.Fprintf(w, "%srtt %s%s\n", GRY, string(row), RST)
			}
		}
	}
	last := s[len(s)-1]
	fmt.Fprintf(w, "  %snow ↓%s/s ↑%s/s · 60s ↓%s/s ↑%s/s · avg ↓%s/s ↑%s/s · rtt %.0f ms%s\n",
		GRY, Human(last.Down), Human(last.Up),
		Human(chartMean(d60)), Human(chartMean(u60)),
		Human(chartMean(d)), Human(chartMean(u)), last.RTT, RST)
}
