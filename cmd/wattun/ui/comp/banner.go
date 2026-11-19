package comp

// The WatTun identity block: kite + WATTUN wordmark (the mark the manager uses), the meta
// block right-aligned beside it, and the packet-pulse boot animation (5 frames, 75 ms each).
// Lifted from the manager's visual language (owner: these are the elements that made it look
// like a product) and rebuilt as plain styled strings for the bubbletea app.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// BannerKite + BannerWord: the 3-row mark. Kite is the geometric diamond, Word the WATTUN glyph row.
var BannerKite = []string{
	"   ╱╲  ",
	"  ╱──╲ ",
	" ╱ ╲╱  ",
}

var BannerWord = []string{
	"██   ██  ▄██▄  ██████ ██████ ██  ██ ██▄  ██",
	"██ █ ██ ██▄▄██   ██     ██   ██  ██ ██▀█▄██",
	" ▀█▀█▀  ██  ██   ██     ██   ▀████▀ ██  ▀██",
}

// Banner renders the identity block: kite + wordmark left, meta lines right-aligned, one blank
// line after. meta lines are the grey side block ("WatTunnel · v3.3.9", "github.com/...", ...).
// width is the terminal width the meta block aligns to.
func Banner(meta []string, width int) string {
	bold := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
	grey := Dim
	accent := Accent
	rows := make([]string, 3)
	for i := 0; i < 3; i++ {
		left := accent.Render(BannerKite[i]) + " " + bold.Render(BannerWord[i])
		var right string
		if i < len(meta) {
			right = grey.Render(meta[i])
		}
		pad := 0
		if w := lipgloss.Width(left); width > w+2 {
			pad = width - lipgloss.Width(right) - w - 2
			if pad < 2 {
				pad = 2
			}
		}
		rows[i] = left + strings.Repeat(" ", pad) + right
	}
	return strings.Join(rows, "\n")
}

// PulseFrames is the boot animation: 5 frames of the packet (▸) flying along the dashed line
// into the kite, then the settled mark. frame 0..4; frame >= 4 renders the settled banner rows.
func PulseFrames() []string {
	line := "       " + Dim.Render("┃")
	frames := []string{
		line + "\n ╺▸\n" + line,
		line + "\n ╺━▸\n" + line,
		line + "\n   ╺━━╋▸\n" + line,
	}
	return frames
}

// KeyBar renders the footer keybar the old UI made useful: "[1] open  [m] mute" — accent keys,
// dim labels. Pairs are key, label.
func KeyBar(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
	for _, p := range pairs {
		parts = append(parts, key.Render("["+p[0]+"]")+" "+Dim.Render(p[1]))
	}
	return strings.Join(parts, "  ")
}

// SectionLabel renders a "Tunnels            1 total" style section header: label left,
// counter right-aligned to width.
func SectionLabel(label, right string, width int) string {
	l := Label(label)
	if right == "" {
		return l
	}
	pad := width - lipgloss.Width(l) - lipgloss.Width(Dim.Render(right))
	if pad < 2 {
		pad = 2
	}
	return l + strings.Repeat(" ", pad) + Dim.Render(right)
}

// FormatBytes: 0 B, 12.3 KB, 45.6 MB, 1.2 GB — one decimal above 1024.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return itoa(n) + " B"
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB", "PB"}[exp]
	return f1(float64(n)/float64(div)) + " " + suffix
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func f1(v float64) string {
	whole := int(v)
	tenths := int(v*10+0.5) % 10
	return itoa(uint64(whole)) + "." + itoa(uint64(tenths))
}
