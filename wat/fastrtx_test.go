package wat

import (
	"testing"
	"time"
)

// seedSent fills s.sent with fresh in-flight packets pn..pn+n-1 (ages young, so only the gap rule,
// not the age rule, can declare them lost).
// The caller holds s.mu (like loss_test): onAck runs under the session lock in production.
func seedSent(s *Session, n int, now time.Time) {
	for pn := 0; pn < n; pn++ {
		sp := s.newSent()
		sp.pn, sp.at, sp.size = uint64(pn), now, 100
		sp.ctrl = [][]byte{{frPing}} // lost-ping resends are filtered, but lose() counts it in Retrans
		s.sent = append(s.sent, sp)
		s.inflight += sp.size
	}
}

// Three consecutive ACKs that skip the oldest unacked packets must fast-lose them with -fast-rtx,
// while two must not (the counter is consecutive-gap based, not any-gap).
func TestFastRtxGapCounter(t *testing.T) {
	s := profSession(t, Profile{}, Config{FastRtx: true})
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seedSent(s, 4, now)
	ack := func() { s.onAck(3, 0, rangeSet{{3, 4}}, now) }
	for i := 0; i < 2; i++ {
		ack()
		if n := s.stats.Retrans; n != 0 {
			t.Fatalf("fast-loss fired after %d acks (Retrans=%d, want 3 acks)", i+1, n)
		}
	}
	ack() // compact() frees the lost records at once, so the observable is Retrans, not sp fields
	if n := s.stats.Retrans; n != 3 {
		t.Fatalf("Retrans=%d after 3 gap acks, want 3 (one fast-loss per skipped packet)", n)
	}
}

// Without the flag the same three gap acks must lose nothing by age (the packets are young) — the
// default behavior is unchanged.
func TestFastRtxOffByDefault(t *testing.T) {
	s := profSession(t, Profile{}, Config{})
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seedSent(s, 4, now)
	for i := 0; i < 3; i++ {
		s.onAck(3, 0, rangeSet{{3, 4}}, now)
	}
	if n := s.stats.Retrans; n != 0 {
		t.Fatalf("Retrans=%d with fast-rtx off, want 0 (young packets, gap < 4)", n)
	}
}

// A reliable carrier never fast-loses: its loss is by age only and spurious resends were costly there
// (cc.go relLossMul history). Same acks, Reliable profile, flag on — nothing lost while young.
func TestFastRtxNeverOnReliable(t *testing.T) {
	s := profSession(t, poolProfile, Config{FastRtx: true})
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seedSent(s, 4, now)
	for i := 0; i < 3; i++ {
		s.onAck(3, 0, rangeSet{{3, 4}}, now)
	}
	if n := s.stats.Retrans; n != 0 {
		t.Fatalf("Retrans=%d on a reliable carrier, want 0 (loss is by age only)", n)
	}
}

// Sim transfer correctness with FastRtx on: a lossy bulk download arrives byte-intact (the flag only
// changes WHEN a hole is resent, never what the receiver delivers).
func TestFastRtxTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("sim transfer")
	}
	mb, _ := bulkOnce(t, 0.02, 2<<20, Config{FastRtx: true})
	if mb < 1 {
		t.Fatalf("transfer too slow: %.2f MB/s", mb)
	}
}
