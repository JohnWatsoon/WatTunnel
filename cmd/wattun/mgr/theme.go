// Package mgr is the Go port of the bash wattun-manager (P1: terminal, theme,
// banner, config, systemd, stats, token and preset core). The bash file stays the
// source of truth: helper output here matches it byte-for-byte where feasible.
package mgr

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// The manager's palette (wattun-manager L150-160). Empty when colours are off
// (NONINTERACTIVE, NO_COLOR, TERM=dumb), exactly like the bash USE_COLOR gate.
var (
	RST  string
	BOLD string
	RED  string
	GRN  string
	YEL  string
	CYN  string
	BLU  string
	GRY  string
)

// UseColor mirrors USE_COLOR; UseAnim mirrors ANIM (tty + WAT_NO_ANIM + .manager.conf anim).
var UseColor, UseAnim bool

// Stdout/Stderr are swappable so tests can capture every helper's output.
var (
	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr
)

// InitColor sets the palette for a colour tier: useColor false empties every
// var; ncol is 8, 256 or 24 (truecolor). Palette A: turquoise accent (CYN),
// saffron highlight (SAF), green/amber/red only for state.
func InitColor(useColor bool, ncol int) {
	UseColor = useColor
	if !useColor {
		ColorTier = 0
		RST, BOLD, RED, GRN, YEL, CYN, BLU, GRY, ACCBG, SAF = "", "", "", "", "", "", "", "", "", ""
		return
	}
	RST, BOLD, BLU = "\x1b[0m", "\x1b[1m", "\x1b[34m"
	switch ncol {
	case 24:
		ColorTier = 24
		CYN, GRN, YEL, RED = "\x1b[38;2;46;196;182m", "\x1b[38;2;62;207;142m", "\x1b[38;2;242;184;75m", "\x1b[38;2;239;93;93m"
		GRY, SAF, ACCBG = "\x1b[38;2;107;117;134m", "\x1b[38;2;255;183;3m", "\x1b[48;2;18;48;50m"
	case 256:
		ColorTier = 256
		CYN, GRN, YEL, RED = "\x1b[38;5;37m", "\x1b[38;5;78m", "\x1b[38;5;221m", "\x1b[38;5;203m"
		GRY, SAF, ACCBG = "\x1b[90m", "\x1b[38;5;214m", "\x1b[48;5;23m"
	default:
		ColorTier = 8
		CYN, GRN, YEL, RED, GRY, SAF, ACCBG = "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[90m", "\x1b[33m", ""
	}
}

// ---- responsive layout width (bash L216-231) ----

var (
	UI_W  = 74
	BOXW  = 74
	TM_CW = 36
)

// TermCols mirrors term_cols(): $COLUMNS when a sane number, else the terminal
// width, else 80.
func TermCols() int {
	if c := os.Getenv("COLUMNS"); isDigits(c) && len(c) > 0 {
		if n := atoi(c); n >= 20 {
			return n
		}
	}
	if w := termWidth(); w >= 20 {
		return w
	}
	return 80
}

// UIInitWidth mirrors ui_init_width().
func UIInitWidth() {
	cols := TermCols()
	switch {
	case cols < 50:
		UI_W = 44
	case cols < 78:
		UI_W = cols - 4
	case cols >= 84:
		UI_W = 76
	default:
		UI_W = 74
	}
	BOXW = UI_W
	TM_CW = (UI_W - 2) / 2
}

// ---- plain messages (bash L233-241): byte-for-byte the same printf formats ----

// Say prints each argument on its own line (%b semantics: no escapes are
// interpreted here, callers embed the palette vars directly).
func Say(args ...string) {
	for _, a := range args {
		fmt.Fprintf(Stdout, "%s\n", a)
	}
}

var errN int // ERRN

// ErrN returns the error counter (bash ERRN).
func ErrN() int { return errN }

// ResetErrN zeroes the error counter (ni_run resets ERRN before each flow).
func ResetErrN() { errN = 0 }

// Ok prints a green check line.
func Ok(msg string) { fmt.Fprintf(Stdout, "  %s✓%s %s\n", GRN, RST, msg) }

// Warn prints a yellow ! line.
func Warn(msg string) { fmt.Fprintf(Stdout, "  %s!%s %s\n", YEL, RST, msg) }

// Err prints a red ✗ line (or plain "error:" on stderr when non-interactive).
func Err(msg string) {
	errN++
	if NonInteractive {
		fmt.Fprintf(Stderr, "error: %s\n", msg)
	} else {
		fmt.Fprintf(Stdout, "  %s✗%s %s\n", RED, RST, msg)
	}
}

// Hint prints a grey line.
func Hint(msg string) { fmt.Fprintf(Stdout, "  %s%s%s\n", GRY, msg, RST) }

// Hr prints the grey divider (two leading spaces, UI_W ─ characters).
func Hr() {
	if UI_W <= 0 {
		UIInitWidth()
	}
	fmt.Fprintf(Stdout, "  %s%s%s\n", GRY, Rep("─", UI_W), RST)
}

// KeyLabel prints/returns "[k]" in cyan; the bash prints, callers embed — here it
// returns so both uses compose the same bytes.
func KeyLabel(k string) string { return CYN + "[" + k + "]" + RST }

// SetRow prints one "[k] label  value" settings line (bash set_row).
func SetRow(key, label, value, unit, def string) {
	v := value
	if v != "" {
		if unit != "" {
			v += " " + unit
		}
	} else {
		switch def {
		case "off", "default route", "":
			v = GRY + def + RST
		default:
			v = def + " " + GRY + "(default)" + RST
		}
	}
	fmt.Fprintf(Stdout, "  %s %-16s %s\n", KeyLabel(key), label, v)
}

// MenuLine prints rows of "[k] label" items wrapped at UI_W (bash menu_line).
// The writer comes first so screens can print to the terminal or a buffer.
func MenuLine(wr io.Writer, pairs ...string) {
	var out strings.Builder
	w := 0
	maxw := UI_W
	if maxw == 0 {
		maxw = 74
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		iw := len(pairs[i]) + 3 + len(pairs[i+1])
		if w > 0 && w+2+iw > maxw {
			fmt.Fprintf(wr, "  %s\n", out.String())
			out.Reset()
			w = 0
		}
		if w > 0 {
			out.WriteString("  ")
			w += 2
		}
		out.WriteString(KeyLabel(pairs[i]) + " " + pairs[i+1])
		w += iw
	}
	fmt.Fprintf(wr, "  %s\n", out.String())
}

// ---- small pure helpers (bash rep/vlen/strip_ansi) ----

// Rep repeats s n times.
func Rep(s string, n int) string { return strings.Repeat(s, n) }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

// StripANSI removes SGR/CSI sequences (bash strip_ansi).
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// Vlen returns the visible length (bash vlen).
func Vlen(s string) int { return len(StripANSI(s)) }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
