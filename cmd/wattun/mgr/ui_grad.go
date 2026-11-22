package mgr

// The gradient renders. The Firouzeh→saffron ramp (theme.go gradStops) is a
// screen's one bright moment (design-taste-frontend: quiet chrome everywhere
// else — gradients go in the moments, never on every surface). Three renders,
// the same shape at every tier:
//
//	GradLine/GradBand — a full-width gradient rule (the header band)
//	GradBar           — a proportional meter whose fill carries the ramp
//	GradRows          — the wordmark rows (the banner's gradient moment)
//
// All of them go through GradRGB, so the ramp is the same colour at the same
// position on every surface. With colour off (NONINTERACTIVE, NO_COLOR,
// TERM=dumb) every render falls back to the existing plain look byte-for-byte:
// tbar's ▰▱ for meters, the grey ─ rule for bands, Grad's flat ramp for text.

import (
	"fmt"
	"io"
	"strings"
)

// GradRGB is the foreground escape for ramp position t (0..1) at the current
// tier; "" when colour is off. The one interpolation every gradient render
// shares.
func GradRGB(t float64) string {
	if ColorTier == 0 {
		return ""
	}
	return fgRGB(gradAt(t))
}

// GradLine paints a w-column rule of ━ across the ramp: the wide header band a
// screen may use as its one bright moment (print it with GradBand). Coloured
// tiers draw ━ so the band reads heavier than the grey ─ chrome rules; colour
// off keeps the existing grey ─ rule exactly.
func GradLine(w int) string {
	if ColorTier == 0 {
		return GRY + Rep("─", w) + RST
	}
	var b strings.Builder
	last := ""
	for i := 0; i < w; i++ {
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

// GradBand prints the header band row: two-space indent, gradient rule, EL at
// the end like Banner's rows so a direct print to a tty erases behind itself
// (a Frame redraw adds its own \x1b[K; two erases are harmless).
func GradBand(w io.Writer, width int) {
	fmt.Fprintf(w, "  %s%s\n", GradLine(width), EL)
}

// GradBar paints a proportional meter: the filled cells carry the ramp from
// turquoise at the left edge to saffron at the fill's end, so any fill level
// shows the full arc (the live rate meter's bright moment); the track stays
// grey. The glyphs and fill count match tbar at every tier: colour off is
// tbar byte-for-byte, tier 8 is tbarC's cyan fill and grey track.
func GradBar(val, max float64, w int) string {
	switch ColorTier {
	case 0:
		return tbar(val, max, w)
	case 8:
		return tbarC(val, max, w)
	}
	if max <= 0 {
		max = 1
	}
	f := int(val*float64(w)/max + 0.5)
	if f < 0 {
		f = 0
	}
	if f > w {
		f = w
	}
	var b strings.Builder
	last := ""
	for i := 0; i < w; i++ {
		if i >= f {
			if last != GRY {
				b.WriteString(GRY)
				last = GRY
			}
			b.WriteRune('▱')
			continue
		}
		t := 0.0
		if f > 1 {
			t = float64(i) / float64(f-1)
		}
		if e := GradRGB(t); e != last {
			b.WriteString(e)
			last = e
		}
		b.WriteRune('▰')
	}
	b.WriteString(RST)
	return b.String()
}

// gradSheenTop is the wordmark's top-row brightness at truecolor: the top row
// starts a shade darker and the bottom row runs at full strength, so the mark
// reads as one lit surface instead of five identical stripes
// (design-taste-frontend: the banner is the bright moment — depth, not a
// second gradient). 0.86 keeps the teal vivid on a dark background.
const gradSheenTop = 0.86

// GradRows paints wordmark rows: the ramp runs across the full width of every
// row so stacked rows line up (Grad's contract, anchored to width); at
// truecolor each row is shaded by its height. Lower tiers keep Grad's flat
// per-row ramp — 256-colour quantisation would band the shading into mud.
func GradRows(rows []string, width int) []string {
	out := make([]string, len(rows))
	if ColorTier != 24 {
		for i, r := range rows {
			out[i] = Grad(r, width)
		}
		return out
	}
	n := len(rows)
	for i, r := range rows {
		shade := 1.0
		if n > 1 {
			shade = gradSheenTop + (1-gradSheenTop)*float64(i)/float64(n-1)
		}
		var b strings.Builder
		last := ""
		for j, c := range []rune(r) {
			if c == ' ' {
				b.WriteRune(c)
				continue
			}
			t := 0.0
			if width > 1 {
				t = float64(j) / float64(width-1)
			}
			base := gradAt(t)
			e := fgRGB(rgb{
				int(float64(base.r)*shade + 0.5),
				int(float64(base.g)*shade + 0.5),
				int(float64(base.b)*shade + 0.5),
			})
			if e != last {
				b.WriteString(e)
				last = e
			}
			b.WriteRune(c)
		}
		b.WriteString(RST)
		out[i] = b.String()
	}
	return out
}
