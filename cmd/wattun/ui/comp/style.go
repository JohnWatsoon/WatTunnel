package comp

// The shared palette and small rendering helpers of the wattun TUI. Everything renders through these styles so
// the whole UI stays consistent: Text is the default write style, Dim marks hints and labels, Accent highlights
// titles and focused cards, Ok/Warn/Bad carry health.

import (
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The six-colour palette. Text #e6e6e6 (default write style), Dim #8a8a8a (hints/labels), Accent cyan #22d3ee,
// Ok #34d399, Warn #fbbf24, Bad #f87171.
var (
	accentColor = lipgloss.Color("#22d3ee") // the raw colour, for places that want a TerminalColor not a style
	Text        = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6e6e6"))
	Dim         = lipgloss.NewStyle().Foreground(lipgloss.Color("#8a8a8a"))
	Accent      = lipgloss.NewStyle().Foreground(accentColor)
	Ok          = lipgloss.NewStyle().Foreground(lipgloss.Color("#34d399"))
	Warn        = lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24"))
	Bad         = lipgloss.NewStyle().Foreground(lipgloss.Color("#f87171"))
)

// Label renders s as a section label: uppercased and dimmed (the small-caps stand-in for terminals).
func Label(s string) string { return Dim.Render(strings.ToUpper(s)) }

// Title renders a bold accent section title.
func Title(s string) string { return Accent.Bold(true).Render(s) }

// KeyHint renders the dim footer line "(m mute · s stop · q back)" from key/desc pairs joined with " · ".
func KeyHint(pairs ...[2]string) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p[0] + " " + p[1]
	}
	return Dim.Render("(" + strings.Join(parts, " · ") + ")")
}

// Card is the container style of one panel: a rounded accent border with slight padding when focused, no
// border (and no padding) when not.
func Card(focused bool) lipgloss.Style {
	if focused {
		return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accentColor).Padding(0, 1)
	}
	return lipgloss.NewStyle()
}

// Bar renders a pct-filled bar of width cells (█ filled, ░ empty). Colour: Ok below 70 %, Warn below 90 %,
// Bad at 90 % or more; pct clamps to [0,100].
func Bar(pct float64, width int) string {
	if width <= 0 {
		return ""
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(math.Round(pct / 100 * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	style := Ok
	switch {
	case pct >= 90:
		style = Bad
	case pct >= 70:
		style = Warn
	}
	return style.Render(strings.Repeat("█", filled)) + Dim.Render(strings.Repeat("░", width-filled))
}

// Dot is the status dot: bright green when alive, dim otherwise.
func Dot(alive bool) string {
	if alive {
		return Ok.Render("●")
	}
	return Dim.Render("●")
}
