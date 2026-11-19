package comp

// Scrolling sparkline: the last width samples, autoscaled to the window max, rendered with the classic
// eight-step block glyphs. Add slides the window; View is stable for unchanged data and always exactly
// width glyphs wide (never-filled slots sit at the lowest level).

import "math"

// sparkGlyphs are the sparkline levels, low to high.
const sparkGlyphs = "▁▂▃▄▅▆▇█"

// Spark is a scrolling, autoscaled sparkline. Keep it by pointer (Add mutates).
type Spark struct {
	width int
	data  []float64
}

// NewSpark returns a sparkline holding the last width samples. (Constructor naming: see NewSpin.)
func NewSpark(width int) Spark {
	if width < 1 {
		width = 1
	}
	return Spark{width: width, data: make([]float64, 0, width)}
}

// Add appends one sample, sliding the window once it is full. NaN/Inf samples count as 0 so a bad
// reading cannot break rendering.
func (s *Spark) Add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	s.data = append(s.data, v)
	if len(s.data) > s.width {
		s.data = s.data[len(s.data)-s.width:]
	}
}

// View renders the window autoscaled to its max (max maps to █, 0 to ▁; an all-zero window renders all ▁).
func (s Spark) View() string {
	runes := []rune(sparkGlyphs)
	out := make([]rune, s.width)
	max := 0.0
	for _, v := range s.data {
		if v > max {
			max = v
		}
	}
	pad := s.width - len(s.data) // older slots not filled yet: lowest glyph keeps the width constant
	for i := range out {
		lvl := 0
		if i >= pad && max > 0 {
			lvl = int(s.data[i-pad]/max*float64(len(runes)-1) + 0.5)
			if lvl > len(runes)-1 {
				lvl = len(runes) - 1
			}
			if lvl < 0 {
				lvl = 0
			}
		}
		out[i] = runes[lvl]
	}
	return string(out)
}
