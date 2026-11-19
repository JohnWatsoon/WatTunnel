package main

import (
	"testing"
	"time"
)

func TestParsePortRange(t *testing.T) {
	cases := []struct {
		in     string
		want   portRange
		wantOK bool
	}{
		{"41000-41999", portRange{41000, 41999}, true},
		{"40400", portRange{40400, 40400}, true},
		{" 49152-65535 ", portRange{49152, 65535}, true},
		{"0-100", portRange{}, false},       // port 0
		{"50000-49999", portRange{}, false}, // hi < lo
		{"abc-100", portRange{}, false},     // not a number
		{"70000", portRange{}, false},       // not uint16
		{"1-2-3", portRange{}, false},       // three parts: "2-3" is not uint16 either
		{"", portRange{}, false},
	}
	for _, c := range cases {
		got, ok := parsePortRange(c.in)
		if ok != c.wantOK || got != c.want {
			t.Errorf("parsePortRange(%q) = %v %v, want %v %v", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestTupleSched(t *testing.T) {
	sports := portRange{49152, 65535}
	dports := portRange{41000, 41099}
	s := newTupleSched(sports, dports, 7)
	seen := map[uint32]bool{}
	prevS, prevD := uint16(0), uint16(0)
	for i := 0; i < 5000; i++ {
		sp, dp, burst := s.next()
		if sp < sports.lo || sp > sports.hi || dp < dports.lo || dp > dports.hi {
			t.Fatalf("port out of range: %d %d", sp, dp)
		}
		// burst 12-20: every tuple must stay under the ~29-34-packet per-5-tuple cut
		if burst < 12 || burst > 20 {
			t.Fatalf("burst %d out of 12-20", burst)
		}
		if sp == prevS && dp == prevD {
			t.Fatal("consecutive tuples identical — no rotation")
		}
		seen[uint32(sp)<<16|uint32(dp)] = true
		prevS, prevD = sp, dp
	}
	if len(seen) < 4000 {
		t.Errorf("only %d distinct tuples in 5000 draws — rotation too repetitive", len(seen))
	}
}

func TestTokenBucket(t *testing.T) {
	// 5000/s, capacity 5000: the first 5000 are immediate, the 5001st must wait.
	b := newTokenBucket(5000)
	t0 := time.Unix(0, 0)
	b.last = t0 // drive refill from the simulated clock below, not from time.Now()
	for i := 0; i < 5000; i++ {
		if d := b.delay(t0); d != 0 {
			t.Fatalf("take %d: delay %v, want 0", i, d)
		}
	}
	d := b.delay(t0)
	if d <= 0 || d > time.Second {
		t.Fatalf("take 5001: delay %v, want in (0, 1s]", d)
	}
	// after a full second the bucket is full again
	if d := b.delay(t0.Add(time.Second)); d != 0 {
		t.Fatalf("after 1s refill: delay %v, want 0", d)
	}
	// refill never exceeds capacity: waiting a minute grants 5000 takes, not 300000
	for i := 0; i < 5000; i++ {
		if d := b.delay(t0.Add(2 * time.Second)); d != 0 {
			t.Fatalf("capped take %d: delay %v, want 0", i, d)
		}
	}
	if d := b.delay(t0.Add(2 * time.Second)); d <= 0 {
		t.Fatalf("beyond capacity: delay %v, want > 0", d)
	}
}
