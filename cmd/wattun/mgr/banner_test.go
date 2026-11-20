package mgr

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func capture(t *testing.T, fn func()) string {
	t.Helper()
	old := Stdout
	var buf bytes.Buffer
	Stdout = &buf
	defer func() { Stdout = old }()
	fn()
	return buf.String()
}

func TestBannerWordmark(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	for _, r := range Wordmark() {
		if !strings.Contains(out, r) {
			t.Errorf("wordmark row %q missing:\n%s", r, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("colour-off banner still has escapes:\n%q", out)
	}
	// every row is the same width so the gradient lines up
	w := len([]rune(Wordmark()[0]))
	for _, r := range Wordmark() {
		if len([]rune(r)) != w {
			t.Errorf("row %q is %d wide, want %d", r, len([]rune(r)), w)
		}
	}
	if w+2 > wordmarkMinCols {
		t.Errorf("wordmark (%d) does not fit the %d-column floor", w, wordmarkMinCols)
	}
}

func TestBannerNarrowFallback(t *testing.T) {
	t.Setenv("COLUMNS", "40")
	InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	if !strings.Contains(out, "◆ WatTunnel") || strings.Contains(out, "██") {
		t.Errorf("narrow fallback wrong:\n%s", out)
	}
}

func TestRenderHeader(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	Ver = "3.4.0"
	defer func() { Ver = "" }()
	out := capture(t, func() { RenderHeader("Tunnels", "2 total", false) })
	if !strings.Contains(out, "[3.4.0]  Tunnels") || !strings.Contains(out, "2 total") || !strings.Contains(out, "──") {
		t.Errorf("header wrong:\n%s", out)
	}
	NonInteractive = true
	defer func() { NonInteractive = false }()
	out = capture(t, func() { RenderHeader("Tunnels", "2 total", false) })
	if out != "== Tunnels (2 total) ==\n" {
		t.Errorf("non-interactive header = %q", out)
	}
	out = capture(t, func() { RenderHeader("Tunnels", "", false) })
	if out != "== Tunnels ==\n" {
		t.Errorf("non-interactive header without subtitle = %q", out)
	}
}

func TestRenderSubpageHeader(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	out := capture(t, func() { Page("Update", "from GitHub") })
	if !strings.Contains(out, "  Update  · from GitHub") {
		t.Errorf("subpage header wrong:\n%s", out)
	}
}

func TestPageFullAnimatesOnce(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	UseAnim = false
	introDone = false
	capture(t, func() { PageFull("Tunnels", "1 total") })
	if !introDone {
		t.Error("PageFull must set introDone")
	}
}

func TestBannerAnimationFrames(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	UseAnim, IsTTY, EL = true, true, "\x1b[K"
	defer func() { UseAnim, IsTTY, EL = false, false, "" }()
	out := capture(t, func() { Banner(true) })
	if n := strings.Count(out, "\r\x1b[5A"); n != 5 {
		t.Errorf("expected 5 cursor-returns between 6 frames, got %d", n)
	}
	if !strings.Contains(out, Wordmark()[0]) {
		t.Errorf("last frame must be the whole mark:\n%s", out)
	}
}
func TestRepVlenStripANSI(t *testing.T) {
	InitColor(false, 8)
	if Rep("─", 5) != "─────" || Rep("x", 0) != "" {
		t.Error("Rep wrong")
	}
	s := CYN + "[q]" + RST + " quit"
	if Vlen(s) != 8 { // "[q] quit"
		t.Errorf("Vlen = %d, want 8", Vlen(s))
	}
	if StripANSI(s) != "[q] quit" {
		t.Errorf("StripANSI = %q", StripANSI(s))
	}
}

func TestInitColorPalette(t *testing.T) {
	InitColor(true, 256)
	if CYN != "\x1b[38;5;37m" || GRY != "\x1b[90m" || RST != "\x1b[0m" || ColorTier != 256 {
		t.Errorf("256-color palette wrong: CYN=%q GRY=%q", CYN, GRY)
	}
	InitColor(true, 24)
	if CYN != "\x1b[38;2;46;196;182m" || ColorTier != 24 || ACCBG == "" {
		t.Errorf("truecolor palette wrong: CYN=%q", CYN)
	}
	InitColor(true, 8)
	if CYN != "\x1b[36m" || ACCBG != "" {
		t.Errorf("8-color CYN = %q", CYN)
	}
	InitColor(false, 256)
	if CYN != "" || GRY != "" || ColorTier != 0 {
		t.Errorf("colour-off palette must be empty, got CYN=%q", CYN)
	}
}

func TestUIInitWidth(t *testing.T) {
	old := os.Getenv("COLUMNS")
	defer os.Setenv("COLUMNS", old)
	for _, c := range []struct {
		cols, want int
	}{{40, 44}, {60, 56}, {74, 70}, {80, 74}, {90, 76}} {
		os.Setenv("COLUMNS", itoa(c.cols))
		UIInitWidth()
		if UI_W != c.want {
			t.Errorf("COLUMNS=%d: UI_W = %d, want %d", c.cols, UI_W, c.want)
		}
		if BOXW != UI_W {
			t.Errorf("BOXW = %d, want UI_W", BOXW)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
