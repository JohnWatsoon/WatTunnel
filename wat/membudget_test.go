package wat

import (
	"testing"
	"time"
)

// The receive gate must admit a frame that fits the process budget exactly and refuse the first byte past it. The
// 4 MB base windows are not charged (stream.go rxHeld), so this is the whole test: a one-byte boundary.
func TestReceiveBudgetGate(t *testing.T) {
	old := memBudget.Load()
	SetMemBudget(1 << 20)
	defer memBudget.Store(old)
	if !rxRoom(1 << 20) {
		t.Fatal("a frame that exactly fits the budget was refused")
	}
	if rxRoom(1<<20 + 1) {
		t.Fatal("a frame one byte over the budget was admitted")
	}
}

// Fragment reassembly has its own process cap: pieces are stored before any stream-level gate sees them, and a peer
// can keep sets incomplete. A piece that would cross the cap is dropped and counted; the stored pieces of a set that
// completes are returned to the cap, so a healthy exchange leaves it empty.
func TestFragmentReassemblyBudget(t *testing.T) {
	old := reasmMaxBytes
	reasmMaxBytes = 100
	defer func() { reasmMaxBytes = old }()
	s := &Session{dgIn: make(chan Datagram, 8)}
	now := time.Now()
	// One 60-byte piece fits; the second of the same datagram does not.
	s.onDgramFrag(1, 80, 1, 0, 2, make([]byte, 60), now)
	s.onDgramFrag(1, 80, 1, 1, 2, make([]byte, 60), now)
	if got := s.stats.DgramDropRx; got != 1 {
		t.Fatalf("over-cap fragment: DgramDropRx=%d, want 1", got)
	}
	if got := reasmHeld.Load(); got != 60 {
		t.Fatalf("after one stored piece reasmHeld=%d, want 60", got)
	}

	// The sender retries once the cap allows it: the datagram completes and its bytes go back to the cap.
	reasmMaxBytes = 1 << 20
	s.onDgramFrag(1, 80, 1, 1, 2, make([]byte, 60), now)
	if got := reasmHeld.Load(); got != 0 {
		t.Fatalf("after completion reasmHeld=%d, want 0", got)
	}
	if d := <-s.dgIn; d.Flow != 1 || d.Port != 80 || len(d.Data) != 120 {
		t.Fatalf("reassembled datagram: flow=%d port=%d len=%d", d.Flow, d.Port, len(d.Data))
	}

	// A fresh two-piece datagram completes the same way and leaves nothing behind.
	s.onDgramFrag(2, 80, 1, 0, 2, make([]byte, 30), now)
	s.onDgramFrag(2, 80, 1, 1, 2, make([]byte, 30), now)
	if got := reasmHeld.Load(); got != 0 {
		t.Fatalf("after a fresh datagram reasmHeld=%d, want 0", got)
	}
	if got := s.stats.DgramReassembled; got != 2 {
		t.Fatalf("DgramReassembled=%d, want 2", got)
	}
}
