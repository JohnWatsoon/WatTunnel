package comp

// The WatTun identity block: kite + WATTUN wordmark (the mark the manager uses), the meta
// block right-aligned beside it, and the packet-pulse boot animation frames.
// Lifted from the manager's visual language (owner: these are the elements that made it look
// like a product) and rebuilt as plain styled strings for the bubbletea app.
//
// Width discipline (learned from the first cut rendering ragged over SSH): every row of the
// banner block is EXACTLY bannerW cells wide — the art uses plain ASCII where a terminal's
// rune-width of a glyph could disagree with lipgloss (the wordmark is uniform # blocks, the
// kite uses / \ — nothing ambiguous), the meta block is joined at a FIXED column, and the
// terminal width is never used inside the block: a wide terminal sees the same centered block,
// a narrow one truncates instead of re-flowing. The mark cannot smear.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// bannerW is the fixed cell width of the identity block (kite + gap + wordmark + gap + meta).
const bannerW = 78

// bannerKite + bannerWord: the 3-row mark, ASCII-safe (no ambiguous-width glyphs).
var bannerKite = []string{
	`   /\   `,
	`  /--\  `,
	` /  \/  `,
}

var bannerWord = []string{
	"##   ##  ####  ###### ###### ##  ## ###   ##",
	"## # ## ######   ##     ##   ##  ## ####  ##",
	" ## ### ##  ##   ##     ##   ###### ## #### ",
}

// banner styles (created once).
var (
	bannerKiteStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("22d3ee"))
	bannerWordStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
	bannerMetaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8a8a8a"))
	bannerKeyStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("22d3ee"))
)

// Banner renders the identity block: kite + wordmark left, up to 3 meta lines joined at a FIXED
// column, every row exactly bannerW cells. meta lines longer than the meta column are truncated.
func Banner(meta []string) string {
	const metaW = 30
	const metaX = bannerW - metaW // fixed join column
	rows := make([]string, 3)
	for i := 0; i < 3; i++ {
		left := bannerKiteStyle.Render(bannerKite[i]) + " " + bannerWordStyle.Render(bannerWord[i])
		leftW := len(bannerKite[i]) + 1 + len(bannerWord[i]) // ASCII only: len == cells
		pad := metaX - leftW
		if pad < 1 {
			pad = 1
		}
		var right string
		if i < len(meta) {
			m := truncRunes(meta[i], metaW)
			right = bannerMetaStyle.Render(m) + strings.Repeat(" ", maxInt(metaW-len([]rune(m)), 0))
		} else {
			right = strings.Repeat(" ", metaW)
		}
		rows[i] = left + strings.Repeat(" ", pad) + right
	}
	return strings.Join(rows, "\n")
}

// PulseFrames is the boot animation: 3 frames of the packet (>) flying along the dashed line,
// then the settled mark (the caller renders Banner after the last frame). frame 0..2.
func PulseFrames() []string {
	line := "       |"
	return []string{
		line + "\n >\n" + line,
		line + "\n -->\n" + line,
		line + "\n   --x>\n" + line,
	}
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
