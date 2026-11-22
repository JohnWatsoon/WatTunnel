package mgr

import (
	"fmt"
	"strings"
	"time"
)

// Ver mirrors $VER: the wattun binary's version ("" when not installed).
var Ver string

// MetaTelegram mirrors META_TELEGRAM.
const MetaTelegram = "@WatxDev"

// Tagline sits next to the version badge under the wordmark.
const Tagline = "Tunnels that get through"

// introDone: only the first full page animates.
var introDone bool

// wordmarkMinCols is the narrowest terminal that gets the big mark; narrower
// ones (phone SSH apps) get the one-line form.
const wordmarkMinCols = 60

// Banner draws the gradient WATTUN wordmark. anim reveals it left to right once
// (6 frames, about 0.2 s). Below wordmarkMinCols it is one line.
func Banner(anim bool) {
	if TermCols() < wordmarkMinCols {
		fmt.Fprintf(Stdout, "  %s %sWatTunnel%s\n", Grad("◆", 1), BOLD, RST)
		return
	}
	rows := Wordmark()
	w := len([]rune(rows[0]))
	if anim && UseAnim && IsTTY {
		CurHide()
		for f := 1; f <= 6; f++ {
			cut := w * f / 6
			shown := make([]string, len(rows))
			for i, r := range rows {
				shown[i] = string([]rune(r)[:cut])
			}
			for _, r := range GradRows(shown, w) {
				fmt.Fprintf(Stdout, "  %s%s\n", r, EL)
			}
			if f < 6 {
				time.Sleep(35 * time.Millisecond)
				fmt.Fprint(Stdout, "\r\x1b[5A")
			}
		}
		CurShow()
		return
	}
	for _, r := range GradRows(rows[:], w) {
		fmt.Fprintf(Stdout, "  %s\n", r)
	}
}

// RenderHeader draws the full header: wordmark, then the version badge with the
// title (or the tagline) and a dim right-aligned subtitle, then a faint rule.
// Non-interactive prints "== title (subtitle) ==".
func RenderHeader(title, subtitle string, anim bool) {
	if NonInteractive {
		sub := ""
		if subtitle != "" {
			sub = " (" + subtitle + ")"
		}
		fmt.Fprintf(Stdout, "== %s%s ==\n", title, sub)
		return
	}
	UIInitWidth()
	ClearScreen()
	fmt.Fprintln(Stdout)
	Banner(anim)
	fmt.Fprintln(Stdout)
	if title == "" {
		title = Tagline
	}
	left := BOLD + title + RST
	if Ver != "" {
		left = Badge(Ver) + "  " + left
	}
	if subtitle != "" {
		right := GRY + subtitle + RST
		pad := UI_W - Vlen(left) - Vlen(right)
		if pad < 2 {
			fmt.Fprintf(Stdout, "  %s\n  %s\n", left, right)
		} else {
			fmt.Fprintf(Stdout, "  %s%s%s\n", left, strings.Repeat(" ", pad), right)
		}
	} else {
		fmt.Fprintf(Stdout, "  %s\n", left)
	}
	fmt.Fprintf(Stdout, "  %s%s%s\n\n", GRY, Rep("─", UI_W), RST)
}

// RenderSubpageHeader draws the one-line heading every other screen starts with.
func RenderSubpageHeader(title, subtitle string) {
	if NonInteractive {
		sub := ""
		if subtitle != "" {
			sub = " (" + subtitle + ")"
		}
		fmt.Fprintf(Stdout, "== %s%s ==\n", title, sub)
		return
	}
	UIInitWidth()
	ClearScreen()
	Title(Stdout, title, subtitle)
}

// PageFull draws the full header; the reveal animates once per run.
func PageFull(title, subtitle string) {
	anim := UseAnim && !introDone
	introDone = true
	RenderHeader(title, subtitle, anim)
}

// Page draws a one-line subpage header.
func Page(title, subtitle string) { RenderSubpageHeader(title, subtitle) }
