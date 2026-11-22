package mgr

import (
	"strings"
	"testing"
)

func TestPanelPlainPinned(t *testing.T) {
	InitColor(false, 8)
	t.Setenv("COLUMNS", "100") // uiW() = 76, inner = 74
	out := capture(t, func() { Panel(Stdout, "Carriers", "icmp up", "") })
	want := "  ╭─ Carriers " + rep("─", 63) + "╮\n" +
		"  │ icmp up" + rep(" ", 65) + " │\n" +
		"  │" + rep(" ", 74) + "│\n" +
		"  ╰" + rep("─", 74) + "╯\n"
	if out != want {
		t.Errorf("panel =\n%s\nwant\n%s", out, want)
	}
	// no title: an unbroken top rule
	out = capture(t, func() { Panel(Stdout, "", "x") })
	if !strings.HasPrefix(out, "  ╭"+rep("─", 74)+"╮\n") {
		t.Errorf("titleless panel top wrong:\n%s", out)
	}
	// every line keeps the same width; a long line is cut with … so the
	// right border never moves (rlen: box glyphs are multi-byte)
	out = capture(t, func() { Panel(Stdout, "T", rep("x", 80)) })
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if n := rlen(l); n != 78 {
			t.Errorf("panel line %d wide, want 78: %q", n, l)
		}
	}
	if !strings.Contains(out, rep("x", 71)+"…") {
		t.Errorf("long line not cut at the inner width:\n%s", out)
	}
}

func TestKVAligned(t *testing.T) {
	InitColor(false, 8)
	a := KV(11, "carrier", "icmp")
	b := KV(11, "rtt", "40 ms")
	// the value column starts at lw+1 in every row
	if a[12:] != "icmp" || b[12:] != "40 ms" {
		t.Errorf("KV values not aligned: %q / %q", a, b)
	}
	InitColor(true, 24)
	defer InitColor(false, 8)
	c := KV(11, "carrier", "icmp")
	if StripANSI(c) != a {
		t.Errorf("coloured KV changes the text: %q vs %q", StripANSI(c), a)
	}
	if Vlen(c) != Vlen(a) {
		t.Errorf("coloured KV changes the width: %d vs %d", Vlen(c), Vlen(a))
	}
}

// Unit formatters: decimals and unit suffixes stack in line across rows.
func TestUnitFormatters(t *testing.T) {
	InitColor(false, 8)
	mb := 1024.0 * 1024.0
	for _, c := range []struct {
		got, want string
	}{
		{UnitRate(15.4*mb, 0), "  15.4 MB/s"},
		{UnitRate(9.4*mb, 0), "   9.4 MB/s"},
		{UnitRate(512, 0), " 512.0 B/s"},
		{UnitRate(0.5, 0), "     0 B/s"},
		{UnitBytes(2<<30, 0), "   2.0 GB"},
		{UnitBytes(512, 0), " 512.0 B"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	// the unit suffix starts right after the fixed number field
	for _, c := range []string{
		UnitRate(15.4*mb, 0), UnitRate(9.4*mb, 0), UnitRate(512, 0),
		UnitRate(0.5, 0), UnitBytes(2<<30, 0), UnitBytes(512, 0),
	} {
		if c[unitNumW] != ' ' {
			t.Errorf("number field not %d wide: %q", unitNumW, c)
		}
	}
	// right-aligned inside the column width
	if got := UnitRate(15.4*mb, 14); got != rep(" ", 3)+"  15.4 MB/s" {
		t.Errorf("right-aligned = %q", got)
	}
	InitColor(true, 24)
	defer InitColor(false, 8)
	if strings.Contains(UnitRate(15.4*mb, 11), "\x1b") {
		t.Error("unit formatters stay plain (they colour through callers)")
	}
}
