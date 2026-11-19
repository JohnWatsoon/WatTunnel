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

func TestBannerGlyphsSurvive(t *testing.T) {
	InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	// the ██ block mark and the ╱╲ kite are verbatim; do not substitute
	if !strings.Contains(out, "██   ██  ▄██▄  ██████ ██████ ██  ██ ██▄  ██") ||
		!strings.Contains(out, "██ █ ██ ██▄▄██   ██     ██   ██  ██ ██▀█▄██") ||
		!strings.Contains(out, " ▀█▀█▀  ██  ██   ██     ██   ▀████▀ ██  ▀██") {
		t.Errorf("banner mark corrupted:\n%s", out)
	}
	for _, k := range WATTUN_KITE {
		if !strings.Contains(out, k) {
			t.Errorf("kite line %q missing:\n%s", k, out)
		}
	}
	if !strings.Contains(out, "github.com/JohnWatsoon") || !strings.Contains(out, "t.me/WatxDev") {
		t.Errorf("meta line missing:\n%s", out)
	}
	// no colours: no escape bytes
	if strings.Contains(out, "\x1b") {
		t.Errorf("colour-off banner still has escapes:\n%q", out)
	}
}

func TestBannerWideShowsMeta(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	if !strings.Contains(out, "WatTunnel") || !strings.Contains(out, "github.com/JohnWatsoon") {
		t.Errorf("wide banner lost the side column:\n%s", out)
	}
	// at >=78 cols the meta line is in the banner, not repeated below
	if strings.Contains(out, "github.com/JohnWatsoon · t.me/") {
		t.Errorf("narrow meta line repeated at width:\n%s", out)
	}
}

func TestBannerNarrow78MetaLine(t *testing.T) {
	t.Setenv("COLUMNS", "70")
	InitColor(false, 8)
	out := capture(t, func() { Banner(false) })
	// <78: the meta collapses to one grey line below the mark
	if !strings.Contains(out, "github.com/JohnWatsoon · t.me/WatxDev") {
		t.Errorf("narrow meta line missing:\n%s", out)
	}
}

func TestBannerTinyFallback(t *testing.T) {
	t.Setenv("COLUMNS", "40")
	InitColor(false, 8)
	Ver = "9.9.9"
	defer func() { Ver = "" }()
	out := capture(t, func() { Banner(false) })
	if !strings.Contains(out, "◈ WatTunnel") || !strings.Contains(out, "v9.9.9") {
		t.Errorf("tiny fallback wrong:\n%s", out)
	}
	if strings.Contains(out, "██") {
		t.Errorf("tiny fallback must drop the mark:\n%s", out)
	}
}

func TestBannerVersionOnMark(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	Ver = "3.3.9"
	defer func() { Ver = "" }()
	out := capture(t, func() { Banner(false) })
	if !strings.Contains(out, "WatTunnel · v3.3.9") {
		t.Errorf("version missing from the side column:\n%s", out)
	}
}

func TestRenderHeader(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	out := capture(t, func() { RenderHeader("Tunnels", "2 total", false) })
	if !strings.Contains(out, "Tunnels") || !strings.Contains(out, "2 total") || !strings.Contains(out, "──") {
		t.Errorf("header wrong:\n%s", out)
	}
	// non-interactive: plain "== title (subtitle) =="
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
	Ver = "3.3.9"
	defer func() { Ver = "" }()
	out := capture(t, func() { Page("Update", "") })
	if !strings.Contains(out, "WatTunnel v3.3.9") || !strings.Contains(out, "Update") {
		t.Errorf("subpage header wrong:\n%s", out)
	}
}

func TestPageFullAnimatesOnce(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	UseAnim = false // keep the test instant; the frame math is covered above
	introDone = false
	capture(t, func() { PageFull("Tunnels", "1 total") })
	if !introDone {
		t.Error("PageFull must set introDone")
	}
}

func TestBannerAnimationFrames(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	InitColor(false, 8)
	UseAnim = true
	defer func() { UseAnim = false }()
	NonInteractive = false
	IsTTY = true
	EL = "\x1b[K"
	defer func() { EL = ""; IsTTY = false }()
	introDone = true
	out := capture(t, func() { Banner(true) })
	// the 3 pulse frames and the final kite+meta reveal all print
	for _, frag := range []string{"╺▸", "╺━▸", "╺━━╋▸", "┃"} {
		if !strings.Contains(out, frag) {
			t.Errorf("animation frame %q missing:\n%s", frag, out)
		}
	}
	if strings.Count(out, "\r\x1b[3A") != 4 {
		t.Errorf("expected 4 cursor-returns between 5 frames, got %d", strings.Count(out, "\r\x1b[3A"))
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
	if CYN != "\x1b[38;5;45m" || GRY != "\x1b[90m" || RST != "\x1b[0m" || BOLD != "\x1b[1m" {
		t.Errorf("256-color palette wrong: CYN=%q GRY=%q", CYN, GRY)
	}
	InitColor(true, 8)
	if CYN != "\x1b[36m" {
		t.Errorf("8-color CYN = %q", CYN)
	}
	InitColor(false, 256)
	if CYN != "" || GRY != "" {
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
