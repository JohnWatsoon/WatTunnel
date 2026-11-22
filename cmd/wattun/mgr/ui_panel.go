package mgr

// Panel and layout primitives (design-taste-frontend: quiet chrome — panels
// are containers, never coloured; spacing rhythm — one row height, one gap
// between sections, columns that line up). Later screens draw through these
// so the grid stays one thing. Colour off: everything renders plain.

import (
	"fmt"
	"io"
	"strings"
)

// Spacing rhythm, the 4-grid analog: every list row is RowH terminal rows,
// sections inside a panel sit SecGap blank rows apart, panels on a page
// PanelGap blank rows apart. Whole blank rows are the only spacing unit.
const (
	RowH     = 1
	SecGap   = 1
	PanelGap = 1
)

// Panel draws a full-width rounded panel with an optional title rule, then
// lines padded to the inner width. Quiet chrome: grey rules (Box stays the
// cyan accent for highlight moments). A line longer than the panel is cut
// with … so the right border never moves (boxRow's rule); an empty line is
// one blank row inside the panel.
func Panel(w io.Writer, title string, lines ...string) {
	inner := uiW() - 2
	top := "╭" + rep("─", inner) + "╮"
	if title != "" {
		rem := inner - rlen(title) - 3
		if rem < 1 {
			rem = 1
		}
		top = "╭─ " + title + " " + rep("─", rem) + "╮"
	}
	fmt.Fprintf(w, "  %s%s%s\n", GRY, top, RST)
	for _, l := range lines {
		f := panelFit(l, inner-2)
		fmt.Fprintf(w, "  %s│%s %s%s %s│%s\n", GRY, RST, f, rep(" ", inner-2-rlen(f)), GRY, RST)
	}
	fmt.Fprintf(w, "  %s╰%s╯%s\n", GRY, rep("─", inner), RST)
}

// panelFit cuts s to n visible columns with … (boxRow's rule); a short line
// passes through unchanged.
func panelFit(s string, n int) string {
	if rlen(s) <= n {
		return s
	}
	r := []rune(StripANSI(s))
	if len(r) > n-1 {
		r = r[:n-1]
	}
	return string(r) + "…"
}

// KV formats one aligned two-column row: the label left in lw columns (grey),
// the value after the gap. Rows stack into two columns that line up because
// every label is padded to the same lw.
func KV(lw int, label, value string) string {
	return GRY + padR(label, lw) + RST + " " + value
}

// unitNumW is the number field the unit formatters right-align inside: with
// every number in the same width, decimals and unit suffixes stack in line
// across rows (tabular alignment). "1023.9", the widest value under a unit
// rollover, sets the width.
const unitNumW = 6

// UnitRate right-aligns a byte rate ("15.4 MB/s") in w columns, decimals and
// unit suffixes aligned for a table column.
func UnitRate(bps float64, w int) string { return unitCell(Rate(bps), w) }

// UnitBytes right-aligns a humanized byte count ("1.2 GB") in w columns.
func UnitBytes(b float64, w int) string { return unitCell(Human(b), w) }

// unitCell splits "num unit", right-aligns the number inside unitNumW and the
// whole cell inside w (padL never cuts, so a too-small w just lets it through).
func unitCell(s string, w int) string {
	num, unit, _ := strings.Cut(s, " ")
	if unit == "" {
		return padL(num, w)
	}
	return padL(padL(num, unitNumW)+" "+unit, w)
}
