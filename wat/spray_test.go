package wat

import "testing"

// ParseSprayPorts runs on every platform (this checkout is Windows); the socket tests are linux-tagged.
func TestParseSprayPorts(t *testing.T) {
	for _, tc := range []struct {
		in     string
		lo, hi int
		bad    bool
	}{
		{"41000-41999", 41000, 41999, false},
		{"41000", 41000, 41999, false}, // a single base port spans port..port+999
		{"41000-41005", 41000, 41005, false},
		{"", 0, 0, true},
		{"0", 0, 0, true},
		{"41999-41000", 0, 0, true}, // hi < lo
		{"65535", 0, 0, true},       // base+999 overflows 16 bits
		{"abc", 0, 0, true},
		{"41000-x", 0, 0, true},
	} {
		lo, hi, err := ParseSprayPorts(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseSprayPorts(%q) = %d,%d, want error", tc.in, lo, hi)
			}
			continue
		}
		if err != nil || lo != tc.lo || hi != tc.hi {
			t.Errorf("ParseSprayPorts(%q) = %d,%d,%v, want %d,%d", tc.in, lo, hi, err, tc.lo, tc.hi)
		}
	}
}
