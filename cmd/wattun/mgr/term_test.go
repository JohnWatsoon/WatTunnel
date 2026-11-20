package mgr

import (
	"strings"
	"testing"
	"time"
)

func feed(s string) func() {
	old := In
	In = strings.NewReader(s)
	return func() { In = old }
}

func TestKeyReadBasicKeys(t *testing.T) {
	defer feed("nq")()
	NonInteractive = false
	if k, _, ok := KeyRead(0); !ok || k != "n" {
		t.Errorf("key = %q ok=%v", k, ok)
	}
	if k, _, ok := KeyRead(0); !ok || k != "q" {
		t.Errorf("key = %q ok=%v", k, ok)
	}
	// enter: CR and LF both map to "enter"
	defer feed("\r\n")()
	if k, _, _ := KeyRead(0); k != "enter" {
		t.Errorf("CR = %q", k)
	}
	if k, _, _ := KeyRead(0); k != "enter" {
		t.Errorf("LF = %q", k)
	}
	// EOF ends the read
	defer feed("")()
	if _, _, ok := KeyRead(0); ok {
		t.Error("EOF must report !ok (the bash eof_exit path)")
	}
}

func TestKeyReadEscapeSequences(t *testing.T) {
	NonInteractive = false
	// arrows are swallowed when the page does not navigate a deck
	KeyNav = false
	defer feed("\x1b[Aq")()
	if k, _, _ := KeyRead(0); k != "q" {
		t.Errorf("arrow not swallowed, got %q", k)
	}
	// KeyNav reports them
	KeyNav = true
	for seq, want := range map[string]string{"\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left"} {
		defer feed(seq)()
		if k, _, _ := KeyRead(0); k != want {
			t.Errorf("%q -> %q, want %q", seq, k, want)
		}
	}
	KeyNav = false
	// a lone ESC stays "esc"
	defer feed("\x1b")()
	if k, _, _ := KeyRead(0); k != "esc" {
		t.Errorf("lone ESC = %q", k)
	}
	// a Home sequence is swallowed whole
	defer feed("\x1b[Hq")()
	if k, _, _ := KeyRead(0); k != "q" {
		t.Errorf("Home not swallowed, got %q", k)
	}
}

func TestKeyReadNonInteractive(t *testing.T) {
	NonInteractive = true
	defer func() { NonInteractive = false }()
	k, to, _ := KeyRead(0)
	if k != "enter" || to {
		t.Errorf("non-interactive key = %q timeout=%v", k, to)
	}
}

func TestKeyReadTimeout(t *testing.T) {
	defer feed("")() // nothing arrives
	k, to, ok := KeyRead(30 * time.Millisecond)
	if !ok || !to || k != "" {
		t.Errorf("timeout: key=%q timeout=%v ok=%v", k, to, ok)
	}
}

func TestReadLineDigits(t *testing.T) {
	defer feed("2\n")()
	NonInteractive = false
	got, ok := ReadLine(0)
	if !ok || got != "2" {
		t.Errorf("ReadLine = %q ok=%v", got, ok)
	}
	// the 5s continuation: digits then enter
	defer feed("10\r")()
	if got, _ := ReadLine(0); got != "10" {
		t.Errorf("ReadLine(10) = %q", got)
	}
	// a timeout mid-number keeps what arrived
	defer feed("9")()
	if got, ok := ReadLine(30 * time.Millisecond); !ok || got != "9" {
		t.Errorf("timed ReadLine = %q ok=%v", got, ok)
	}
}

func TestAskAndConfirm(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	defer feed("  myname \n")()
	if got := Ask("Tunnel name", "tun0"); got != "myname" {
		t.Errorf("Ask = %q", got)
	}
	if ReplyV != "myname" {
		t.Errorf("ReplyV = %q", ReplyV)
	}
	// empty answer keeps the default
	defer feed("\n")()
	if got := Ask("Tunnel name", "tun0"); got != "tun0" {
		t.Errorf("Ask default = %q", got)
	}
	// confirm: y / n / enter / esc
	cases := []struct {
		seq    string
		defYes bool
		want   bool
	}{
		{"y", false, true}, {"n", true, false}, {"\r", true, true}, {"\r", false, false}, {"\x1b", true, false},
	}
	for _, c := range cases {
		defer feed(c.seq)()
		if got := Confirm("sure?", c.defYes); got != c.want {
			t.Errorf("Confirm(%q, def=%v) = %v, want %v", c.seq, c.defYes, got, c.want)
		}
	}
}

func TestConfirmNonInteractive(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = true
	defer func() { NonInteractive = false }()
	if !Confirm("sure?", true) || Confirm("sure?", false) {
		t.Error("non-interactive confirm must take the default")
	}
}

func TestAskNonInteractive(t *testing.T) {
	NonInteractive = true
	defer func() { NonInteractive = false }()
	if got := Ask("name", "def"); got != "def" || ReplyV != "def" {
		t.Errorf("non-interactive Ask = %q ReplyV=%q", got, ReplyV)
	}
}

func TestAskOKValidator(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	// two bad answers then a good one
	defer feed("bad\nbad\n198.51.100.7\n")()
	calls := 0
	ok := AskOK("Address", "", func(v string) bool {
		calls++
		return v == "198.51.100.7"
	})
	if !ok {
		t.Error("AskOK gave up before the good answer")
	}
	if calls != 3 {
		t.Errorf("validator ran %d times, want 3", calls)
	}
}

func TestFlashAndMessageHelpers(t *testing.T) {
	InitColor(false, 8)
	ResetErrN()
	out := capture(t, func() {
		Ok("done")
		Warn("careful")
		Err("broken")
		Hint("note")
	})
	for _, want := range []string{"  ✓ done\n", "  ! careful\n", "  ✗ broken\n", "  note\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if ErrN() != 1 {
		t.Errorf("ErrN = %d, want 1", ErrN())
	}
	// non-interactive errors go to stderr
	NonInteractive = true
	old := Stderr
	var eb strings.Builder
	Stderr = &eb
	Err("plain")
	Stderr, NonInteractive = old, false
	if eb.String() != "error: plain\n" {
		t.Errorf("stderr err = %q", eb.String())
	}
}

func TestMenuLineWraps(t *testing.T) {
	InitColor(false, 8)
	UI_W = 20
	out := capture(t, func() { MenuLine(Stdout, "1", "one", "2", "two", "3", "three") })
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("MenuLine did not wrap at 20 cols: %q", out)
	}
	for _, l := range lines {
		if Vlen(l) > 22 {
			t.Errorf("wrapped line too long: %q", l)
		}
	}
	UI_W = 74
}

func TestKeyLabelAndSetRow(t *testing.T) {
	InitColor(false, 8)
	out := capture(t, func() { SetRow("q", "quit", "yes", "", "") })
	if !strings.Contains(out, "[q]") || !strings.Contains(out, "quit") || !strings.Contains(out, "yes") {
		t.Errorf("SetRow wrong: %q", out)
	}
	out = capture(t, func() { SetRow("x", "mode", "", "", "off") })
	if !strings.Contains(out, "off") {
		t.Errorf("SetRow default wrong: %q", out)
	}
	if KeyLabel("n") != "[n]" {
		t.Errorf("KeyLabel = %q", KeyLabel("n"))
	}
}
