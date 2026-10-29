package wat

import (
	"testing"
	"time"
)

// TestQuietClientKeepsServerLane pins the lane set a server sends on. A client quiet longer than the laneSeen
// prune (20 s, timers) used to empty it, and build() then returned nothing at all - not even the 1 Hz boot frame -
// until the client spoke again (2026-10-29). Silence alone must not mute a server; a newly seen lane must still
// replace the stale set.
func TestQuietClientKeepsServerLane(t *testing.T) {
	s := &Session{cfg: Config{Server: true}, lanes: []int{0, 3}, laneSeen: map[int]time.Time{}}
	s.rebuildLanes()
	if len(s.lanes) != 2 || s.lanes[0] != 0 || s.lanes[1] != 3 {
		t.Fatalf("a quiet client left the server with lanes %v, want the last known [0 3]", s.lanes)
	}
	s.laneSeen[7] = time.Now()
	s.rebuildLanes()
	if len(s.lanes) != 1 || s.lanes[0] != 7 {
		t.Fatalf("a live lane must replace the stale set: lanes %v, want [7]", s.lanes)
	}
}

// TestIdleByteBudget pins the idle keepalive cost. Measured 2026-10-29 (udp carrier, one session, this box):
// default ping-every, a client that does nothing cost ~16 kB per 120 s of session payload - 56 client packets
// (4.7 kB) and 176 server packets (17.3 kB), about 16 MB/day - and the server's frBoot frame at a fixed 1 Hz was
// over half of it. The boot frame now follows -ping-every, so at 10 s the server must stay well under 1 pkt/s.
// Raise these bounds only with a measurement; a cheaper keepalive passes (they are upper limits).
func TestIdleByteBudget(t *testing.T) {
	cli, _ := maskRig(t, Config{PingEvery: 10 * time.Second}, Config{PingEvery: 10 * time.Second})
	time.Sleep(1500 * time.Millisecond) // let the handshake and its acks settle
	before := cli.Stats()
	t0 := time.Now()
	time.Sleep(4 * time.Second)
	after := cli.Stats()
	dt := time.Since(t0).Seconds()
	in := float64(after.BytesIn-before.BytesIn) / dt
	inPkts := float64(after.PktsIn-before.PktsIn) / dt
	if inPkts > 0.5 || in > 80 {
		t.Fatalf("server sends %.2f pkt/s, %.0f B/s while idle at ping-every 10s (%.1f MB/day); want < 0.5 pkt/s and < 80 B/s",
			inPkts, in, in*86400/1e6)
	}
}
