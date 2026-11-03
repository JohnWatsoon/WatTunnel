package wat

import (
	"testing"
	"time"
)

func TestMergeProfiles(t *testing.T) {
	// Empty slice returns default non-zero profile
	empty := mergeProfiles(nil)
	if empty.MTU == 0 || empty.MaxMTU == 0 || empty.InitBps == 0 {
		t.Fatalf("empty mergeProfiles returned zero profile: %+v", empty)
	}

	p1 := Profile{Reliable: true, MTU: 4096, MaxMTU: 16384, InitBps: 8e6}
	p2 := Profile{Reliable: false, MTU: 1400, MaxMTU: 1400, InitBps: 1.5e6}

	merged := mergeProfiles([]Profile{p1, p2})
	if merged.Reliable {
		t.Error("expected unreliable when one carrier is unreliable")
	}
	if merged.MTU != 1400 {
		t.Errorf("MTU: got %d, want 1400", merged.MTU)
	}
	if merged.MaxMTU != 1400 {
		t.Errorf("MaxMTU: got %d, want 1400", merged.MaxMTU)
	}
	if merged.InitBps != 1.5e6 {
		t.Errorf("InitBps: got %v, want 1.5e6", merged.InitBps)
	}
}

func TestPathTimingsNorm(t *testing.T) {
	tm := PathTimings{
		ProbeFirst: 10 * time.Second,
		ProbeMax:   5 * time.Second,
	}.norm()

	if tm.ProbeFirst > tm.ProbeMax {
		t.Errorf("ProbeFirst (%v) > ProbeMax (%v)", tm.ProbeFirst, tm.ProbeMax)
	}
	if tm.Silence <= 0 || tm.Ramp <= 0 || tm.IdleProbe <= 0 {
		t.Errorf("zero defaults not set: %+v", tm)
	}
}

// In a bond only the icmp path is held to ICMPPathBps; bulk beyond it goes to the other carrier.
func TestICMPPathCap(t *testing.T) {
	ps := newPathSet([]string{"icmp", "tcp"}, true, PathTimings{})
	ps.p[1].w = 0.05 // the scheduler would put nearly everything on icmp without the cap
	var bytes [2]int
	start := time.Now()
	for time.Since(start) < 200*time.Millisecond {
		i := ps.choose(false)
		ps.onSend(i, 1400)
		bytes[i] += 1400
	}
	el := time.Since(start).Seconds()
	if got := float64(bytes[0]) / el; got > 1.3*ICMPPathBps {
		t.Fatalf("icmp path ran at %.1f MB/s, cap %.0f MB/s", got/1e6, ICMPPathBps/1e6)
	}
	if bytes[1] == 0 {
		t.Fatal("nothing went to tcp")
	}
	if solo := newPathSet([]string{"icmp"}, true, PathTimings{}); solo.p[0].capBps != 0 {
		t.Fatal("a lone icmp path is capped by the session ceiling, not by the path cap")
	}
}

func TestSndQueue(t *testing.T) {
	var q sndQueue
	want := make([]byte, 3*rdChunk+123)
	for i := range want {
		want[i] = byte(i * 7)
	}
	h0 := sndHeld.Load()
	q.write(want[:rdChunk-5])
	q.write(want[rdChunk-5:])
	if got := q.appendRange(nil, 0, len(want)); string(got) != string(want) {
		t.Fatal("round trip differs")
	}
	q.drop(rdChunk + 10) // frees the first chunk
	if len(q.ch) != 3 || q.n != len(want)-rdChunk-10 {
		t.Fatalf("after drop: %d chunks, %d bytes", len(q.ch), q.n)
	}
	if got := q.appendRange(nil, 100, 2*rdChunk); string(got) != string(want[rdChunk+110:3*rdChunk+110]) {
		t.Fatal("range across chunks differs")
	}
	q.drop(q.n)
	if len(q.ch) != 0 || sndHeld.Load() != h0 {
		t.Fatalf("drained queue holds %d chunks, held %d", len(q.ch), sndHeld.Load()-h0)
	}
}

// A lossy bond path loses most of its bulk share, not just the loss fraction.
func TestBondLossPenalty(t *testing.T) {
	ps := newPathSet([]string{"a", "b"}, true, PathTimings{})
	ps.p[1].loss = 0.15
	var n [2]int
	for range 24000 {
		n[ps.choose(false)]++
	}
	if share := float64(n[1]) / 24000; share > 0.40 {
		t.Fatalf("15 %%-loss path kept %.2f of the bulk", share)
	}
}
