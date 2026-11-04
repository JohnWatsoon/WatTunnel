package main

import (
	"math"
	"testing"
)

// F11 (3.3.0): -fec-on-loss/-fec-off-loss validation. The band must be 0 <= off < on <= 50; anything else is a
// startup error rather than a silently disabled loss gate.
func TestFecGatePct(t *testing.T) {
	for _, c := range []struct {
		name            string
		on, off         float64
		wantOn, wantOff float64
		wantErr         bool
	}{
		{"defaults", 2, 0.5, 0.02, 0.005, false},
		{"off may be zero", 2, 0, 0.02, 0, false},
		{"on at the ceiling", 50, 25, 0.5, 0.25, false},
		{"on above the ceiling", 50.1, 0.5, 0, 0, true},
		{"on zero", 0, 0, 0, 0, true},
		{"on negative", -1, 0, 0, 0, true},
		{"off negative", 2, -0.1, 0, 0, true},
		{"off equal to on", 2, 2, 0, 0, true},
		{"off above on", 1, 2, 0, 0, true},
		{"on NaN", math.NaN(), 0.5, 0, 0, true}, // M12: NaN compares false with every bound
		{"on +Inf", math.Inf(1), 0.5, 0, 0, true},
		{"on -Inf", math.Inf(-1), 0.5, 0, 0, true},
		{"off NaN", 2, math.NaN(), 0, 0, true},
		{"off +Inf", 2, math.Inf(1), 0, 0, true},
		{"off -Inf", 2, math.Inf(-1), 0, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			on, off, err := fecGatePct(c.on, c.off)
			if (err != nil) != c.wantErr {
				t.Fatalf("fecGatePct(%g, %g) err = %v, wantErr %v", c.on, c.off, err, c.wantErr)
			}
			if on != c.wantOn || off != c.wantOff {
				t.Fatalf("fecGatePct(%g, %g) = %g, %g; want %g, %g", c.on, c.off, on, off, c.wantOn, c.wantOff)
			}
		})
	}
}
