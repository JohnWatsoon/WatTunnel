package mgr

// The manager's look (approved mockup, palette A "Firouzeh to saffron"): one
// gradient for the wordmark and graphs, one accent for the selected row, green,
// amber and red only for state, everything else grey. Every screen draws through
// these helpers so the look stays one thing.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ColorTier is 0 (no colour), 8, 256 or 24 (truecolor).
var ColorTier int

// ACCBG is the selected-row background ("" when the tier has no good one).
var ACCBG string

// SAF is the saffron end of the gradient (upload graphs).
var SAF string

type rgb struct{ r, g, b int }

var gradStops = []rgb{{0x2e, 0xc4, 0xb6}, {0x7f, 0xd6, 0xa4}, {0xff, 0xb7, 0x03}}

// Marks: four only. ✓ done, ! needs attention, ✗ failed, ? a question.
const (
	MarkOK   = "✓"
	MarkWarn = "!"
	MarkErr  = "✗"
	MarkAsk  = "?"
)

// colorTierFromEnv: truecolor from COLORTERM, 256 from TERM, else 8.
func colorTierFromEnv() int {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if ct == "truecolor" || ct == "24bit" {
		return 24
	}
	if v := os.Getenv("WAT_COLORS"); v == "24" || v == "256" || v == "8" {
		return atoi(v)
	}
	// SSH drops COLORTERM, and PuTTY/Termius send plain TERM=xterm yet draw 256 colours;
	// only the Linux console and unknown terminals stay on 8.
	if t := os.Getenv("TERM"); strings.Contains(t, "256color") || strings.HasPrefix(t, "xterm") ||
		strings.HasPrefix(t, "screen") || strings.HasPrefix(t, "tmux") || strings.HasPrefix(t, "rxvt") {
		return 256
	}
	return 8
}

func to256(c rgb) int {
	q := func(v int) int { return (v*5 + 127) / 255 }
	return 16 + 36*q(c.r) + 6*q(c.g) + q(c.b)
}

// fgRGB is the foreground escape for c at the current tier.
func fgRGB(c rgb) string {
	switch ColorTier {
	case 24:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", c.r, c.g, c.b)
	case 256:
		return fmt.Sprintf("\x1b[38;5;%dm", to256(c))
	case 8:
		return CYN
	}
	return ""
}

// gradAt returns the gradient colour at t in [0,1].
func gradAt(t float64) rgb {
	if t <= 0 {
		return gradStops[0]
	}
	if t >= 1 {
		return gradStops[len(gradStops)-1]
	}
	seg := t * float64(len(gradStops)-1)
	i := int(seg)
	f := seg - float64(i)
	a, b := gradStops[i], gradStops[i+1]
	mix := func(x, y int) int { return x + int(float64(y-x)*f+0.5) }
	return rgb{mix(a.r, b.r), mix(a.g, b.g), mix(a.b, b.b)}
}

// Grad paints s left to right across the gradient; width is the span the
// gradient covers (0 = the length of s), so stacked rows line up.
func Grad(s string, width int) string {
	if ColorTier == 0 {
		return s
	}
	if ColorTier == 8 {
		return CYN + s + RST
	}
	r := []rune(s)
	if width <= 0 {
		width = len(r)
	}
	var b strings.Builder
	last := ""
	for i, c := range r {
		if c == ' ' {
			b.WriteRune(c)
			continue
		}
		t := 0.0
		if width > 1 {
			t = float64(i) / float64(width-1)
		}
		if e := fgRGB(gradAt(t)); e != last {
			b.WriteString(e)
			last = e
		}
		b.WriteRune(c)
	}
	b.WriteString(RST)
	return b.String()
}

// ---- wordmark ----

var wordmarkFont = map[rune][5]string{
	'W': {"██     ██", "██     ██", "██  █  ██", "██ ███ ██", " ███ ███ "},
	'A': {" █████ ", "██   ██", "███████", "██   ██", "██   ██"},
	'T': {"████████", "   ██   ", "   ██   ", "   ██   ", "   ██   "},
	'U': {"██    ██", "██    ██", "██    ██", "██    ██", " ██████ "},
	'N': {"███    ██", "████   ██", "██ ██  ██", "██  ██ ██", "██   ████"},
}

// Wordmark returns the five rows of the big WATTUN mark (uncoloured).
func Wordmark() [5]string {
	var rows [5]string
	for i, c := range "WATTUN" {
		g := wordmarkFont[c]
		for r := 0; r < 5; r++ {
			if i > 0 {
				rows[r] += " "
			}
			rows[r] += g[r]
		}
	}
	return rows
}

// Badge is a solid accent label (version badge); plain "[x]" without colour.
func Badge(s string) string {
	if ColorTier == 0 {
		return "[" + s + "]"
	}
	bg := "\x1b[46m\x1b[30m"
	switch ColorTier {
	case 24:
		bg = "\x1b[48;2;46;196;182m\x1b[38;2;6;42;39m"
	case 256:
		bg = "\x1b[48;5;37m\x1b[38;5;16m"
	}
	return bg + BOLD + " " + s + " " + RST
}

// ---- frames: flicker-free full-screen redraw ----

// Frame draws buf over the previous frame: home the cursor, end every line with
// erase-to-end, erase below. Off a tty it just prints.
func Frame(buf *bytes.Buffer) {
	if !IsTTY {
		Stdout.Write(buf.Bytes())
		return
	}
	s := strings.ReplaceAll(buf.String(), "\n", "\x1b[K\n")
	fmt.Fprint(Stdout, "\x1b[H"+s+"\x1b[J")
}

// Title prints a subpage heading: bold title, dim meta, blank line.
func Title(w io.Writer, title, meta string) {
	fmt.Fprintln(w)
	if meta != "" {
		fmt.Fprintf(w, "  %s%s%s  %s· %s%s\n\n", BOLD, title, RST, GRY, meta, RST)
		return
	}
	fmt.Fprintf(w, "  %s%s%s\n\n", BOLD, title, RST)
}

// Keys prints the dim key line at the bottom of a screen: pairs of key, label.
func Keys(w io.Writer, pairs ...string) {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, pairs[i]+" "+pairs[i+1])
	}
	fmt.Fprintf(w, "\n  %s%s%s\n", GRY, strings.Join(parts, "   "), RST)
}

// ---- the selectable list ----

// Item is one row of a Choose list. Key is an optional one-character hotkey.
type Item struct {
	Key, Label, Desc string
	Off              bool // drawn dim (Exit, unavailable rows)
}

// Choose draws head, then items with *sel highlighted, then the key line, and
// waits for one key. It returns the picked index (Enter, a number, or an item
// hotkey), or -1 with the key for anything else: "esc", "q", "tick" when tick
// passed without a key, "eof" at end of input. The caller loops.
func Choose(head func(w io.Writer), items []Item, sel *int, keys []string, tick time.Duration) (int, string) {
	if *sel < 0 || *sel >= len(items) {
		*sel = 0
	}
	var buf bytes.Buffer
	head(&buf)
	drawItems(&buf, items, *sel)
	if len(keys) > 0 {
		Keys(&buf, keys...)
	}
	Frame(&buf)
	if !IsTTY && !NonInteractive {
		fmt.Fprintf(Stdout, "  %s›%s ", CYN, RST)
	}
	old := KeyNav
	KeyNav = true
	defer func() { KeyNav = old }()
	k, timedOut, ok := KeyRead(tick)
	switch {
	case !ok:
		return -1, "eof"
	case timedOut:
		return -1, "tick"
	}
	claimed := false // vi keys j/k move, unless an item uses the letter as its hotkey
	for _, it := range items {
		if it.Key != "" && strings.EqualFold(it.Key, k) {
			claimed = true
		}
	}
	switch {
	case claimed:
	case k == "up" || k == "k":
		*sel = (*sel - 1 + len(items)) % len(items)
		return -1, "move"
	case k == "down" || k == "j":
		*sel = (*sel + 1) % len(items)
		return -1, "move"
	}
	if k == "enter" {
		if len(items) == 0 {
			return -1, k
		}
		return *sel, k
	}
	if len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
		if n := int(k[0] - '0'); n <= len(items) && items[n-1].Key == "" {
			*sel = n - 1
			return n - 1, k
		}
	}
	for i, it := range items {
		if it.Key != "" && strings.EqualFold(it.Key, k) {
			*sel = i
			return i, k
		}
	}
	return -1, k
}

func drawItems(w io.Writer, items []Item, sel int) {
	lw := 0
	for _, it := range items {
		if n := rlen(it.Label); n > lw {
			lw = n
		}
	}
	width := uiW()
	for i, it := range items {
		pad := rep(" ", lw-rlen(it.Label)+3)
		hk := ""
		if k := itemKey(items, i); k != "" {
			hk = k + "  "
		}
		if i == sel {
			row := " " + CYN + "❯" + RST + " " + CYN + hk + RST + BOLD + CYN + it.Label + RST + pad + GRY + it.Desc + RST
			if n := width - rlen(row); n > 0 {
				row += rep(" ", n)
			}
			if ACCBG != "" {
				row = ACCBG + strings.ReplaceAll(row, RST, RST+ACCBG) + RST
			}
			fmt.Fprintf(w, " %s\n", row)
			continue
		}
		lab := BOLD + it.Label + RST
		if it.Off {
			lab = GRY + it.Label + RST
		}
		fmt.Fprintf(w, "    %s%s%s%s%s%s%s%s\n", GRY, hk, RST, lab, pad, GRY, it.Desc, RST)
	}
}

// itemKey is the key that picks items[i] in Choose: its one-key hotkey, else its
// number (1-9) unless another item claims that digit; "" when neither.
func itemKey(items []Item, i int) string {
	if k := items[i].Key; k != "" {
		if rlen(k) == 1 {
			return k
		}
		return ""
	}
	if i >= 9 {
		return ""
	}
	d := string(rune('1' + i))
	for _, it := range items {
		if it.Key == d {
			return ""
		}
	}
	return d
}

// ---- boxes, graphs, numbers ----

// Box draws a rounded accent box around lines, sized to the widest line.
func Box(w io.Writer, title string, lines ...string) {
	inner := rlen(title) + 4
	for _, l := range lines {
		if n := rlen(l) + 2; n > inner {
			inner = n
		}
	}
	top := "╭" + rep("─", inner) + "╮"
	if title != "" {
		top = "╭─ " + title + " " + rep("─", inner-rlen(title)-3) + "╮"
	}
	fmt.Fprintf(w, "  %s%s%s\n", CYN, top, RST)
	for _, l := range lines {
		fmt.Fprintf(w, "  %s│%s %s%s %s│%s\n", CYN, RST, l, rep(" ", inner-2-rlen(l)), CYN, RST)
	}
	fmt.Fprintf(w, "  %s╰%s╯%s\n", CYN, rep("─", inner), RST)
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// Spark is a one-row block graph of the last w values in the gradient; blank
// history shows as faint baseline.
func Spark(vals []float64, w int) string {
	if len(vals) > w {
		vals = vals[len(vals)-w:]
	}
	max := 0.0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for i := len(vals); i < w; i++ {
		b.WriteRune(sparkRunes[0])
	}
	for _, v := range vals {
		i := 0
		if max > 0 {
			i = int(v / max * 7)
		}
		b.WriteRune(sparkRunes[i])
	}
	if max == 0 {
		return GRY + b.String() + RST
	}
	return Grad(b.String(), w)
}

// Graph draws vals as an h-row block graph w columns wide in colour col, with
// the scale on the left. Each row holds eight levels.
func Graph(out io.Writer, vals []float64, w, h int, col string, scale func(float64) string) {
	if len(vals) > w {
		vals = vals[len(vals)-w:]
	}
	max := 0.0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	lead := w - len(vals)
	for row := h - 1; row >= 0; row-- {
		var b strings.Builder
		b.WriteString(rep(" ", lead))
		for _, v := range vals {
			lv := 0.0
			if max > 0 {
				lv = v / max * float64(h*8)
			}
			cell := lv - float64(row*8)
			switch {
			case cell >= 8:
				b.WriteRune('█')
			case cell >= 1:
				b.WriteRune(sparkRunes[int(cell)-1])
			default:
				b.WriteRune(' ')
			}
		}
		lab := "      "
		if row == h-1 && max > 0 {
			lab = fmt.Sprintf("%6s", scale(max))
		}
		fmt.Fprintf(out, "  %s%s%s %s%s%s\n", GRY, lab, RST, col, b.String(), RST)
	}
}

// Rate formats a byte rate: "15.4 MB/s".
func Rate(bps float64) string {
	if bps < 1 {
		return "0 B/s"
	}
	return Human(bps) + "/s"
}

// padR pads s with spaces to w visible columns (never cuts).
func padR(s string, w int) string {
	if n := w - rlen(s); n > 0 {
		return s + rep(" ", n)
	}
	return s
}

// padL right-aligns s in w visible columns.
func padL(s string, w int) string {
	if n := w - rlen(s); n > 0 {
		return rep(" ", n) + s
	}
	return s
}
