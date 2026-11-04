package main

// W7/F13 (3.3.0): validation of -shape-data, -noise/-noise-bps and -noise-window. A typo must fail the start instead
// of silently disabling shaping or sending filler around the clock.

import (
	"math"
	"testing"
)

func TestShapeDataPct(t *testing.T) {
	for _, c := range []struct {
		pct     float64
		want    float64
		wantErr bool
	}{
		{0, 0, false}, // off
		{10, 0.10, false},
		{25, 0.25, false}, // the hard cap
		{-0.1, 0, true},
		{25.1, 0, true},
		{100, 0, true},
		{math.NaN(), 0, true}, // M12: NaN/Inf are rejected, not silently treated as in-range
		{math.Inf(1), 0, true},
		{math.Inf(-1), 0, true},
	} {
		got, err := shapeDataPct(c.pct)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("shapeDataPct(%g) = %g, %v; want %g, err=%v", c.pct, got, err, c.want, c.wantErr)
		}
	}
}

func TestNoiseBudget(t *testing.T) {
	for _, c := range []struct {
		mode    string
		bps     int
		want    float64
		wantErr bool
	}{
		{"off", 0, 0, false},
		{"", 0, 0, false},
		{"low", 0, noiseLowBps, false},
		{"med", 0, noiseMedBps, false},
		{"custom", 64, 64, false},
		{"custom", 1_000_000, 1_000_000, false},
		{"custom", 63, 0, true},
		{"custom", 1_000_001, 0, true},
		{"custom", 0, 0, true}, // custom without a budget
		{"loud", 0, 0, true},   // unknown mode
		{"off", 128, 0, true},  // -noise-bps only with custom
		{"low", 128, 0, true},  // a preset and an explicit budget are contradictory
	} {
		got, err := noiseBudget(c.mode, c.bps)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("noiseBudget(%q, %d) = %g, %v; want %g, err=%v", c.mode, c.bps, got, err, c.want, c.wantErr)
		}
	}
}

func TestParseNoiseWindow(t *testing.T) {
	for _, c := range []struct {
		in       string
		from, to int
		wantErr  bool
	}{
		{"", 0, 0, false}, // all day
		{"  ", 0, 0, false},
		{"02:00-06:00", 120, 360, false},
		{"22:30-06:15", 1350, 375, false},
		{"0:00-23:59", 0, 1439, false},
		{"22:00-00:00", 1320, 0, false}, // ends at midnight
		{"2:05-3:07", 125, 187, false},
		{"02:00-02:00", 0, 0, true}, // zero-length window
		{"24:00-06:00", 0, 0, true}, // bad hour
		{"02:60-06:00", 0, 0, true}, // bad minute
		{"2:5-3:07", 0, 0, true},    // minute needs two digits
		{"0200-0600", 0, 0, true},   // missing colon
		{"02:00", 0, 0, true},       // missing end
		{"aa:bb-06:00", 0, 0, true}, // not a clock
	} {
		from, to, err := parseNoiseWindow(c.in)
		if (err != nil) != c.wantErr || from != c.from || to != c.to {
			t.Errorf("parseNoiseWindow(%q) = %d, %d, %v; want %d, %d, err=%v", c.in, from, to, err, c.from, c.to, c.wantErr)
		}
	}
}
