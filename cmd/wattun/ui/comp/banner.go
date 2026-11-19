package comp

// The WatTun identity block: kite + WATTUN wordmark (the mark the manager uses) with the meta
// block beside it. Lifted from the manager's visual language and rebuilt for the bubbletea app.
//
// Layout discipline (the hard-earned rule): lipgloss does ALL positioning — JoinHorizontal
// Top-aligns the art and the meta block as units, so no manual padding arithmetic can ever
// disagree with styled-string widths. ASCII-only art (no ambiguous-width glyphs). The block is
// exactly as wide as its content; callers center it with lipgloss.Place against the terminal.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var bannerKite = []string{
	`  /\  `,
	` /--\ `,
	`/  \/ `,
}

var bannerWord = []string{
	"##   ##  ####  ###### ###### ##  ## ###   ##",
	"## # ## ######   ##     ##   ##  ## ####  ##",
	" ## ### ##  ##   ##     ##   ###### ## #### ",
}

var (
	bannerKiteStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("22d3ee"))
	bannerWordStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
	bannerMetaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8a8a8a"))
	bannerKeyStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
)

// Banner renders the identity block: kite + wordmark left, up to 3 dim meta lines beside it,
// top-aligned as units (lipgloss.JoinHorizontal — no manual padding anywhere).
func Banner(meta []string) string {
	art := make([]string, 3)
	for i := 0; i < 3; i++ {
		art[i] = bannerKiteStyle.Render(bannerKite[i]) + " " + bannerWordStyle.Render(bannerWord[i])
	}
	left := strings.Join(art, "\n")
	var right string
	if len(meta) > 0 {
		m := make([]string, len(meta))
		for i, line := range meta {
			m[i] = bannerMetaStyle.Render(truncRunes(line, 28))
		}
		right = strings.Join(m, "\n")
	}
	if right == "" {
		return left
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

// KeyBar renders the footer keybar: "[1] open  [m] mute" — accent keys, dim labels.
func KeyBar(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, bannerKeyStyle.Render("["+p[0]+"]")+" "+Dim.Render(p[1]))
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

func truncRunes(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w <= 1 {
		return string(r[:w])
	}
	return string(r[:w-1]) + "…"
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
