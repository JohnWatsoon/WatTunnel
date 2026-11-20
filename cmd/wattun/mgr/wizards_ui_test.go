package mgr

import (
	"io"
	"testing"
)

// The carrier list keeps the bash keys: Enter = first row, 1-9 = rows, 0 = h2c, esc cancels.
func TestPickCarrierKeys(t *testing.T) {
	InitColor(false, 8)
	head := func(io.Writer) {}
	for _, c := range []struct {
		auto bool
		in   string
		want string
	}{
		{true, "\r", "auto"},
		{true, "2", "icmp"},
		{false, "1", "icmp"},
		{false, "3", "tcp"},
		{false, "0", "h2c"},
		{false, "\x1b", ""},
	} {
		restore := feed(c.in)
		var got string
		capture(t, func() { got = pickCarrier(c.auto, head) })
		restore()
		if got != c.want {
			t.Errorf("auto=%v %q: got %q, want %q", c.auto, c.in, got, c.want)
		}
	}
}
