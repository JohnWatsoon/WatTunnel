package mgr

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// NonInteractive mirrors NONINTERACTIVE: no tty, no stdin reads, no animation,
// no screen clearing; every prompt helper answers with its default.
var NonInteractive bool

// IsTTY mirrors IS_TTY ([ -t 1 ], forced off when non-interactive).
var IsTTY bool

// EL mirrors $EL: "\e[K" on a tty so redraws erase, empty otherwise.
var EL string

// KeyNav mirrors KEY_NAV: 1 makes KeyRead report arrows as up/down/left/right
// instead of swallowing them (tunnel page deck).
var KeyNav bool

// In is the key/line source; a *os.File in production, anything readable in tests.
var In io.Reader = os.Stdin

// InitTerm computes IsTTY/EL the way the bash does (stdout only; the bash never
// checks stdin for IS_TTY).
func InitTerm(f *os.File) {
	IsTTY = !NonInteractive && isTTY(f)
	if IsTTY {
		EL = "\x1b[K"
	} else {
		EL = ""
	}
}

// ClearScreen clears only on a tty, like the bash clear_screen (\e[H\e[2J).
func ClearScreen() {
	if IsTTY {
		fmt.Fprint(Stdout, "\x1b[H\x1b[2J")
	}
}

// CurHide/CurShow toggle the cursor (tty only).
func CurHide() {
	if IsTTY {
		fmt.Fprint(Stdout, "\x1b[?25l")
	}
}
func CurShow() {
	if IsTTY {
		fmt.Fprint(Stdout, "\x1b[?25h")
	}
}

// keyByte reads one byte from In; ok=false on EOF or error.
func keyByte() (byte, bool) {
	var b [1]byte
	if n, _ := In.Read(b[:]); n == 1 {
		return b[0], true
	}
	return 0, false
}

// keyByteTimeout reads one byte with a deadline; ok=false on timeout.
// shortcut: a goroutine per timed read; a timed-out read leaks its goroutine
// until the next byte arrives. Matches the bash read -t semantics; upgrade to
// poll/PeekNamedPipe if that ever matters.
func keyByteTimeout(d time.Duration) (byte, bool) {
	type res struct {
		b  byte
		ok bool
	}
	ch := make(chan res, 1)
	go func() {
		b, ok := keyByte()
		ch <- res{b, ok}
	}()
	select {
	case r := <-ch:
		return r.b, r.ok
	case <-time.After(d):
		return 0, false
	}
}

// KeyRead mirrors key_read: one key ("up"/"down"/"left"/"right" only when
// KeyNav, "esc", "enter", or a single character). timedOut mirrors rc 2.
// EOF on a non-interactive-free stream returns ok=false (the bash exits there).
func KeyRead(timeout time.Duration) (key string, timedOut, ok bool) {
	if NonInteractive {
		return "enter", false, true
	}
	for {
		var b byte
		if timeout > 0 {
			var got bool
			b, got = keyByteTimeout(timeout)
			if !got {
				return "", true, true
			}
		} else {
			var got bool
			b, got = keyByte()
			if !got {
				return "", false, false
			}
		}
		if b == 0x1b {
			// ESC followed by more bytes is an escape sequence (arrows, Home,
			// F-keys): swallowed and read again, except arrows on a deck page
			// (KeyNav). A lone ESC stays "esc".
			k2, more := keyByteTimeout(50 * time.Millisecond)
			if !more {
				return "esc", false, true
			}
			if k2 == '[' || k2 == 'O' {
				c := byte(0)
				for i := 0; i < 8; i++ {
					var got bool
					c, got = keyByteTimeout(50 * time.Millisecond)
					if !got {
						break
					}
					if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '~' || c == '@' {
						break
					}
				}
				if KeyNav {
					switch c {
					case 'A':
						return "up", false, true
					case 'B':
						return "down", false, true
					case 'C':
						return "right", false, true
					case 'D':
						return "left", false, true
					}
				}
			}
			continue
		}
		if b == '\r' || b == '\n' {
			return "enter", false, true
		}
		return string(rune(b)), false, true
	}
}

// ReadLine reads one line of digits/text after KeyRead opened it (bash
// `IFS= read -r -t 5 rest` for multi-digit tunnel numbers); ok=false on EOF or
// timeout. Trailing keys already buffered are consumed one byte at a time.
func ReadLine(timeout time.Duration) (string, bool) {
	var sb strings.Builder
	for {
		var b byte
		if timeout > 0 {
			var got bool
			b, got = keyByteTimeout(timeout)
			if !got {
				if sb.Len() == 0 {
					return "", false
				}
				return sb.String(), true
			}
		} else {
			var got bool
			b, got = keyByte()
			if !got {
				return sb.String(), sb.Len() > 0
			}
		}
		if b == '\r' || b == '\n' {
			return sb.String(), true
		}
		if b == 0x1b { // an escape sequence never belongs to a number
			continue
		}
		sb.WriteByte(b)
	}
}

// readLineEcho reads a line byte by byte echoing as it goes (raw mode has no
// kernel echo). Backspace deletes; ESC sequences are ignored.
// shortcut: no UTF-32 IME handling; the wizard answers are ASCII (names, ports,
// hosts). Add rune assembly if non-ASCII input ever matters.
func readLineEcho() string {
	var sb strings.Builder
	for {
		b, ok := keyByte()
		if !ok {
			fmt.Fprintln(Stdout)
			break
		}
		if b == '\r' || b == '\n' {
			fmt.Fprintln(Stdout)
			break
		}
		if b == 0x7f || b == 0x08 {
			if sb.Len() > 0 {
				s := sb.String()
				sb.Reset()
				sb.WriteString(s[:len(s)-1])
				fmt.Fprint(Stdout, "\b \b")
			}
			continue
		}
		if b == 0x1b {
			continue
		}
		if b < 0x20 {
			continue
		}
		sb.WriteByte(b)
		fmt.Fprintf(Stdout, "%c", b)
	}
	return sb.String()
}

// ReplyV mirrors REPLY_V: the answer of the last Ask.
var ReplyV string

// PMSG mirrors PMSG: one flashed message, shown after the next prompt caret.
var PMSG string

// Flash queues a message for the next prompt caret.
func Flash(msg string) { PMSG = msg }

// Ask mirrors ask(): prompt [default] -> free text; Enter keeps the default.
func Ask(prompt, def string) string {
	if NonInteractive {
		ReplyV = def
		return def
	}
	dpart := ""
	if def != "" {
		dpart = " " + GRY + "[" + def + "]" + RST
	}
	fmt.Fprintf(Stdout, "  %s?%s %s%s %s›%s ", CYN, RST, prompt, dpart, GRY, RST)
	v := readLineEcho()
	v = strings.TrimSpace(v)
	ReplyV = v
	if v == "" {
		ReplyV = def
	}
	return ReplyV
}

// AskOK mirrors ask_ok(): up to 3 tries; validator prints its own error.
func AskOK(prompt, def string, validator func(string) bool) bool {
	if NonInteractive {
		if validator(Ask(prompt, def)) {
			return true
		}
		Err("'" + prompt + "': '" + ReplyV + "' is not accepted (set it with the matching command-line flag)")
		return false
	}
	for t := 0; t < 3; t++ {
		Ask(prompt, def)
		if validator(ReplyV) {
			return true
		}
	}
	Err("Too many invalid answers, going back.")
	return false
}

// Confirm mirrors confirm(): prompt with a y/n default; Enter takes it.
func Confirm(prompt string, defYes bool) bool {
	lab := "Y/n"
	if !defYes {
		lab = "y/N"
	}
	if NonInteractive {
		ans := "no"
		if defYes {
			ans = "yes"
		}
		fmt.Fprintf(Stdout, "  ? %s -> %s\n", prompt, ans)
		return defYes
	}
	for t := 0; t < 3; t++ {
		fmt.Fprintf(Stdout, "  %s?%s %s %s[%s]%s ", CYN, RST, prompt, GRY, lab, RST)
		key, _, ok := KeyRead(0)
		if !ok {
			fmt.Fprintln(Stdout)
			return false // EOF: the bash eof_exit path
		}
		switch key {
		case "y", "Y":
			fmt.Fprintln(Stdout, "yes")
			return true
		case "n", "N":
			fmt.Fprintln(Stdout, "no")
			return false
		case "enter":
			fmt.Fprintln(Stdout)
			return defYes
		case "esc":
			fmt.Fprintln(Stdout)
			return false
		}
		fmt.Fprintln(Stdout)
	}
	return false
}

// Pause mirrors pause(): any key goes back.
func Pause() {
	fmt.Fprintf(Stdout, "\n  %sPress any key to go back...%s", GRY, RST)
	KeyRead(0)
	fmt.Fprintln(Stdout)
}

func sleep(d time.Duration) { time.Sleep(d) }
