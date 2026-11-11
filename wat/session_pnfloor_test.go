package wat

import (
	"testing"
	"time"
)

// A server session never starts its packet numbers below SetPNFloor, even when the wall clock is behind it.
func TestServerPNFloor(t *testing.T) {
	defer SetPNFloor(0)
	floor := uint64(time.Now().Add(24 * time.Hour).UnixMicro())
	SetPNFloor(floor)
	k := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	defer k.Close()
	s, err := NewSession(Config{Key: []byte("pn-floor"), Server: true, SID: 7}, k)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	pn := s.nextPN &^ dirServerBit
	s.mu.Unlock()
	if pn < floor {
		t.Fatalf("server session starts at pn %d, below the floor %d", pn, floor)
	}
}
