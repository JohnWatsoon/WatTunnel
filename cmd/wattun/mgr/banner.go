package mgr

import (
	"fmt"
	"time"
)

// Ver mirrors $VER: the wattun binary's version ("" when not installed).
var Ver string

// MetaTelegram mirrors META_TELEGRAM.
const MetaTelegram = "@WatxDev"

// WATTUN_KITE / WATTUN_BANNER copied VERBATIM from wattun-manager (L259-266):
// the ╱╲ and ██ block glyphs are the mark; do not substitute.
var WATTUN_KITE = [3]string{
	"   ╱╲  ",
	"  ╱──╲ ",
	" ╱ ╲╱  ",
}

var WATTUN_BANNER = [3]string{
	"██   ██  ▄██▄  ██████ ██████ ██  ██ ██▄  ██",
	"██ █ ██ ██▄▄██   ██     ██   ██  ██ ██▀█▄██",
	" ▀█▀█▀  ██  ██   ██     ██   ▀████▀ ██  ▀██",
}

// introDone mirrors INTRO_DONE: only the first full page animates.
var introDone bool

// bannerDrawFrame mirrors _banner_draw_frame.
func bannerDrawFrame(k0, k1, k2, wc, mc string, showMeta bool, gap, cols int) {
	ks := [3]string{k0, k1, k2}
	verPart := ""
	if Ver != "" {
		verPart = " · v" + Ver
	}
	side := [3]string{"WatTunnel" + verPart, "github.com/JohnWatsoon", "t.me/" + trimAt(MetaTelegram)}
	sp := ""
	if gap == 2 {
		sp = " "
	}
	for i := 0; i < 3; i++ {
		if cols >= 78 && showMeta {
			fmt.Fprintf(Stdout, "  %s%s%s  %s%s%s %s%s%s%s%s\n",
				CYN, ks[i], RST, wc, WATTUN_BANNER[i], RST, sp, mc, side[i], RST, EL)
		} else {
			fmt.Fprintf(Stdout, "  %s%s%s  %s%s%s%s\n",
				CYN, ks[i], RST, wc, WATTUN_BANNER[i], RST, EL)
		}
	}
}

func trimAt(s string) string { return s[1:] }

// Banner mirrors banner(): geometric kite + WATTUN mark, responsive at <78 and
// <56 cols, 0.45 s packet-pulse reveal (5 frames × 75 ms).
func Banner(anim bool) {
	cols := TermCols()
	gap := 2
	if cols < 80 {
		gap = 1
	}
	if cols < 56 {
		verPart := ""
		if Ver != "" {
			verPart = " " + GRY + "v" + Ver + RST
		}
		fmt.Fprintf(Stdout, "  %s◈%s %sWatTunnel%s%s\n", CYN, RST, BOLD, RST, verPart)
		return
	}
	if anim && UseAnim {
		CurHide()
		bannerDrawFrame("       "+GRY+"┃", " ╺▸    "+GRY+"┃", "╱      "+GRY+"┃", GRY, "", false, gap, cols)
		time.Sleep(75 * time.Millisecond)
		fmt.Fprint(Stdout, "\r\x1b[3A")
		bannerDrawFrame("       "+GRY+"┃", " ╺━▸   "+GRY+"┃", "╱      "+GRY+"┃", GRY, "", false, gap, cols)
		time.Sleep(75 * time.Millisecond)
		fmt.Fprint(Stdout, "\r\x1b[3A")
		bannerDrawFrame("       "+GRY+"┃", "   ╺━━╋▸", "╱      "+GRY+"┃", GRY, "", false, gap, cols)
		time.Sleep(75 * time.Millisecond)
		fmt.Fprint(Stdout, "\r\x1b[3A")
		bannerDrawFrame(WATTUN_KITE[0], WATTUN_KITE[1], WATTUN_KITE[2], BOLD, "", false, gap, cols)
		time.Sleep(75 * time.Millisecond)
		fmt.Fprint(Stdout, "\r\x1b[3A")
		bannerDrawFrame(WATTUN_KITE[0], WATTUN_KITE[1], WATTUN_KITE[2], BOLD, GRY, true, gap, cols)
		CurShow()
	} else {
		bannerDrawFrame(WATTUN_KITE[0], WATTUN_KITE[1], WATTUN_KITE[2], BOLD, GRY, true, gap, cols)
	}
	if cols < 78 {
		verPart := ""
		if Ver != "" {
			verPart = "v" + Ver + " · "
		}
		fmt.Fprintf(Stdout, "  %s%sgithub.com/JohnWatsoon · t.me/%s%s\n", GRY, verPart, trimAt(MetaTelegram), RST)
	}
}

// RenderHeader mirrors render_header(): clear, banner, hr, title (right-aligned
// grey subtitle). Non-interactive prints "== title (subtitle) ==".
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
	Hr()
	left := BOLD + title + RST
	if subtitle != "" {
		right := GRY + subtitle + RST
		pad := UI_W - Vlen(left) - Vlen(right)
		if pad < 2 {
			pad = 2
		}
		fmt.Fprintf(Stdout, "  %s%*s%s\n", left, pad, "", right)
	} else {
		fmt.Fprintf(Stdout, "  %s\n", left)
	}
	fmt.Fprintln(Stdout)
}

// RenderSubpageHeader mirrors render_subpage_header().
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
	fmt.Fprintln(Stdout)
	verPart := ""
	if Ver != "" {
		verPart = " v" + Ver
	}
	sub := ""
	if subtitle != "" {
		sub = "  " + GRY + subtitle + RST
	}
	fmt.Fprintf(Stdout, "  %sWatTunnel%s ·%s %s%s%s%s\n", GRY, verPart, RST, BOLD, title, RST, sub)
	Hr()
	fmt.Fprintln(Stdout)
}

// PageFull mirrors page_full(): full header, the reveal animates once per run.
func PageFull(title, subtitle string) {
	anim := false
	if UseAnim && !introDone {
		anim = true
	}
	introDone = true
	RenderHeader(title, subtitle, anim)
}

// Page mirrors page(): one-line subpage header.
func Page(title, subtitle string) { RenderSubpageHeader(title, subtitle) }
