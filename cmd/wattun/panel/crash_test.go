package panel

import (
	"testing"
	"time"
)

// A unit systemd restarts 3 times in 5 minutes is a crash loop; old restarts age out, and a start by hand (the
// count drops) begins again.
func TestCrashes(t *testing.T) {
	s := &Server{crash: map[string][]crashMark{}}
	t0 := time.Unix(1000, 0)
	at := func(sec, n int) int {
		return s.crashes(Tunnel{Name: "a", Restarts: n}, t0.Add(time.Duration(sec)*time.Second))
	}
	if at(0, 7) != 0 || at(60, 8) != 1 || at(120, 10) != 3 {
		t.Fatal("3 restarts in 2 minutes not counted")
	}
	if got := at(330, 10); got != 2 {
		t.Fatalf("after 5 minutes the first restarts age out: %d, want 2", got)
	}
	if got := at(340, 0); got != 0 {
		t.Fatalf("start by hand: %d, want 0", got)
	}
}
