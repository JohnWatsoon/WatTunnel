package mgr

import (
	"strings"
	"testing"
)

func TestGradRGBTiers(t *testing.T) {
	InitColor(false, 8)
	if GradRGB(0.5) != "" {
		t.Error("colour-off GradRGB must be empty")
	}
	InitColor(true, 24)
	if GradRGB(0) != CYN || GradRGB(1) != SAF {
		t.Errorf("ramp ends wrong: %q %q", GradRGB(0), GradRGB(1))
	}
	InitColor(true, 8)
	if GradRGB(0.7) != CYN {
		t.Errorf("8-colour fallback = %q, want CYN", GradRGB(0.7))
	}
	InitColor(false, 8)
}

// Colour off, GradBar is tbar byte-for-byte (the pinned plain look).
func TestGradBarPlainPinned(t *testing.T) {
	InitColor(false, 8)
	if got := GradBar(5, 10, 10); got != "▰▰▰▰▰▱▱▱▱▱" {
		t.Errorf("GradBar(5,10,10) = %q", got)
	}
	if got := GradBar(0, 0, 4); got != "▱▱▱▱" {
		t.Errorf("GradBar(0,0,4) = %q", got)
	}
}

func TestGradBarTiers(t *testing.T) {
	InitColor(true, 8)
	defer InitColor(false, 8) // a failed assert must not leak colour state
	if got := GradBar(5, 10, 10); got != CYN+"▰▰▰▰▰"+GRY+"▱▱▱▱▱"+RST {
		t.Errorf("tier 8 = %q, want the tbarC form", got)
	}
	InitColor(true, 24)
	// full fill: the ramp spans the fill, turquoise to saffron
	g := GradBar(10, 10, 3)
	mid := "\x1b[38;2;127;214;164m" // gradAt(0.5)
	if g != CYN+"▰"+mid+"▰"+SAF+"▰"+RST {
		t.Errorf("tier 24 full fill = %q", g)
	}
	// partial fill: ramp in the fill, grey track behind
	if got := GradBar(3, 10, 4); got != CYN+"▰"+GRY+"▱▱▱"+RST {
		t.Errorf("tier 24 partial fill = %q", got)
	}
	if got := GradBar(0, 10, 4); got != GRY+"▱▱▱▱"+RST {
		t.Errorf("tier 24 empty fill = %q", got)
	}
	InitColor(true, 256)
	g = GradBar(10, 10, 3)
	if !strings.Contains(g, "\x1b[38;5;220m") { // to256(saffron)
		t.Errorf("tier 256 ramp end missing: %q", g)
	}
	if rlen(g) != 3 {
		t.Errorf("tier 256 keeps the shape: rlen = %d", rlen(g))
	}
	InitColor(false, 8)
}

func TestGradLineAndBand(t *testing.T) {
	InitColor(false, 8)
	oldEL := EL
	EL = ""
	defer func() { EL = oldEL }()
	if got, want := GradLine(10), GRY+Rep("─", 10)+RST; got != want {
		t.Errorf("plain GradLine = %q, want the grey rule %q", got, want)
	}
	out := capture(t, func() { GradBand(Stdout, 10) })
	if out != "  "+Rep("─", 10)+"\n" {
		t.Errorf("plain GradBand = %q", out)
	}
	InitColor(true, 24)
	g := GradLine(20)
	if !strings.HasPrefix(g, CYN) || !strings.HasSuffix(g, SAF+"━"+RST) {
		t.Errorf("band must span turquoise to saffron: %q", g)
	}
	if rlen(g) != 20 {
		t.Errorf("band = %d columns, want 20", rlen(g))
	}
	InitColor(false, 8)
}

func TestGradRowsSheen(t *testing.T) {
	InitColor(false, 8)
	rows := []string{"███", "███"}
	g := GradRows(rows, 3)
	for i := range rows {
		if g[i] != Grad(rows[i], 3) {
			t.Errorf("plain tier must keep Grad: row %d = %q", i, g[i])
		}
	}
	InitColor(true, 24)
	defer InitColor(false, 8)
	g = GradRows(rows, 3)
	// row 0 is the shaded top of the sheen, row 1 full strength
	top := "\x1b[38;2;40;169;157m"  // turquoise * 0.86
	full := "\x1b[38;2;46;196;182m" // turquoise
	if !strings.HasPrefix(g[0], top) || !strings.HasPrefix(g[1], full) {
		t.Errorf("sheen shading wrong: %q / %q", g[0], g[1])
	}
	if !strings.Contains(g[0], "\x1b[38;2;219;157;3m") { // saffron * 0.86
		t.Errorf("top row must still reach the saffron end: %q", g[0])
	}
	if StripANSI(g[0]) != "███" || StripANSI(g[1]) != "███" {
		t.Error("GradRows must keep the text")
	}
}

// The banner routes through GradRows: shaded top row, full-strength saffron at
// the bottom, same reveal frames as before.
func TestBannerTruecolor(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(true, 24)
	defer InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	if !strings.Contains(out, "\x1b[38;2;40;169;157m") {
		t.Errorf("banner top-row sheen missing:\n%q", out)
	}
	if !strings.Contains(out, "\x1b[38;2;255;183;3m█") {
		t.Errorf("banner bottom-row saffron missing:\n%q", out)
	}
}
