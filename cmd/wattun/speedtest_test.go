package main

import "testing"

// R2 (3.3.0): /speedtest's streams= default is 16 (was 8), the range stays 1..32, and anything absent or out of range
// falls back to the default so auto mode and `wattun speedtest` measure multi-stream capacity.
func TestSpeedTestStreams(t *testing.T) {
	if speedTestStreamsDefault != 16 {
		t.Fatalf("default streams = %d, want 16", speedTestStreamsDefault)
	}
	for _, c := range []struct {
		in   string
		want int
	}{
		{"", 16},
		{"16", 16},
		{"1", 1},
		{"8", 8},
		{"32", 32},
		{"33", 16},
		{"0", 16},
		{"-5", 16},
		{"abc", 16},
		{"1.5", 16},
	} {
		if got := speedTestStreams(c.in); got != c.want {
			t.Errorf("speedTestStreams(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
