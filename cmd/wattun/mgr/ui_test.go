package mgr

import (
	"io"
	"strings"
	"testing"
)

func TestChooseKeys(t *testing.T) {
	InitColor(false, 8)
	items := []Item{{Label: "Tunnels"}, {Label: "New tunnel", Key: "n"}, {Label: "Exit", Key: "q"}}
	head := func(w io.Writer) {}
	for _, c := range []struct {
		in       string
		idx, sel int
		key      string
	}{
		{"\r", 0, 0, "enter"},
		{"\x1b[B", -1, 1, "move"}, // down arrow moves, does not pick
		{"\x1b[A", -1, 2, "move"}, // up from 0 wraps to the last row
		{"n", 1, 1, "n"},          // hotkey picks and selects
		{"Q", 2, 2, "Q"},          // hotkeys ignore case
		{"1", 0, 0, "1"},          // a number picks a row without a hotkey
		{"2", -1, 0, "2"},         // ...but not one that has its own hotkey
		{"x", -1, 0, "x"},         // unknown keys go back to the caller
		{"\x1b", -1, 0, "esc"},
		{"", -1, 0, "eof"},
	} {
		restore := feed(c.in)
		sel := 0
		var idx int
		var key string
		capture(t, func() { idx, key = Choose(head, items, &sel, nil, 0) })
		restore()
		if idx != c.idx || key != c.key || sel != c.sel {
			t.Errorf("%q: got idx=%d key=%q sel=%d, want %d %q %d", c.in, idx, key, sel, c.idx, c.key, c.sel)
		}
	}
}

func TestChooseDrawsSelection(t *testing.T) {
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100")
	restore := feed("\r")
	defer restore()
	sel := 1
	out := capture(t, func() {
		Choose(func(w io.Writer) {}, []Item{{Label: "A", Desc: "first"}, {Label: "Bee", Desc: "second"}}, &sel, []string{"⏎", "open"}, 0)
	})
	// the drawn key is the one Choose acts on: hotkey, else number unless a hotkey owns it
	its := []Item{{Label: "a"}, {Label: "b", Key: "x"}, {Label: "c", Key: "1"}, {Label: "d"}, {Label: "e", Key: "esc"}}
	for i, want := range []string{"", "x", "1", "4", ""} {
		if got := itemKey(its, i); got != want {
			t.Errorf("itemKey(%d) = %q, want %q", i, got, want)
		}
	}
	if a, b := p2NewKey(), p2NewKey(); len(a) != 40 || a == b {
		t.Errorf("p2NewKey not a fresh 40-char key: %q %q", a, b)
	}
	if !strings.Contains(out, "  ❯ 2  Bee   second") || !strings.Contains(out, "    1  A     first") || !strings.Contains(out, "⏎ open") {
		t.Errorf("selection drawing wrong:\n%s", out)
	}
}

func TestGradAndSpark(t *testing.T) {
	InitColor(false, 8)
	if Grad("ab", 0) != "ab" {
		t.Error("colour-off Grad must be plain")
	}
	if s := Spark([]float64{0, 5, 10}, 5); s != "▁▁▁▄█" {
		t.Errorf("Spark = %q", s)
	}
	InitColor(true, 24)
	defer InitColor(false, 8)
	g := Grad("ab", 2)
	if !strings.HasPrefix(g, "\x1b[38;2;46;196;182ma") || !strings.Contains(g, "\x1b[38;2;255;183;3mb") {
		t.Errorf("gradient ends wrong: %q", g)
	}
	if StripANSI(Grad("█ █", 3)) != "█ █" {
		t.Error("Grad must keep the text")
	}
}

func TestGraphRows(t *testing.T) {
	InitColor(false, 8)
	out := capture(t, func() {
		Graph(Stdout, []float64{0, 4, 8}, 3, 2, "", func(v float64) string { return "8" })
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "  █") || !strings.HasSuffix(lines[1], " ██") {
		t.Errorf("graph wrong:\n%q", out)
	}
}

func TestBox(t *testing.T) {
	InitColor(false, 8)
	out := capture(t, func() { Box(Stdout, "Token", "wat1:abc", "hint") })
	want := "  ╭─ Token ──╮\n  │ wat1:abc │\n  │ hint     │\n  ╰──────────╯\n"
	if out != want {
		t.Errorf("box =\n%s\nwant\n%s", out, want)
	}
}

// j/k move the cursor unless an item uses the letter (the tunnel page's k = New key).
func TestChooseViKeysYieldToHotkeys(t *testing.T) {
	InitColor(false, 8)
	for _, c := range []struct {
		items    []Item
		in       string
		idx, sel int
	}{
		{[]Item{{Label: "A"}, {Label: "B"}}, "j", -1, 1},
		{[]Item{{Label: "A"}, {Label: "New key", Key: "k"}}, "k", 1, 1},
	} {
		restore := feed(c.in)
		sel := 0
		var idx int
		capture(t, func() { idx, _ = Choose(func(io.Writer) {}, c.items, &sel, nil, 0) })
		restore()
		if idx != c.idx || sel != c.sel {
			t.Errorf("%q: got idx=%d sel=%d, want %d %d", c.in, idx, sel, c.idx, c.sel)
		}
	}
}
