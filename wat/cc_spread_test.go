package wat

import (
	"net"
	"testing"
	"time"
)

// udp-hop (3.3.9): each source port can take its own path, so a tick's samples spread 77-110 ms with no queue of ours.
// A Spread carrier judges delay by the tick's fastest sample and keeps its rate; a plain udp carrier cuts on the mean.
func TestCCSpreadJudgesByFastestSample(t *testing.T) {
	run := func(spread bool) (float64, uint64) {
		c := newCC(8e6, 2e5, 1e9, 5*time.Millisecond)
		c.spread = spread
		now := time.Now()
		c.tickAt = now
		for i := 0; i < 40; i++ {
			for _, ms := range []int{77, 95, 104, 110} {
				c.sample(time.Duration(ms)*time.Millisecond, now)
			}
			c.limited = true
			now = now.Add(60 * time.Millisecond)
			c.tick(now)
		}
		return c.rate, c.diag.DelayCuts
	}
	if r, cuts := run(true); cuts != 0 || r <= 8e6 {
		t.Errorf("spread: rate %.0f cuts %d, want growth and no cuts", r, cuts)
	}
	if _, cuts := run(false); cuts == 0 {
		t.Error("plain udp no longer cuts on a high mean RTT: the test lost its control")
	}
}

// The server marks a session Spread once its udp source port changed spreadHops times (a hopping client); a NAT
// rebinding or two does not.
func TestNoteSrcPortDetectsHopping(t *testing.T) {
	var nat, hop Session
	for _, p := range []int{4000, 4000, 5000, 5000, 6000} {
		nat.noteSrcPort(&net.UDPAddr{Port: p})
	}
	if nat.cc.spread {
		t.Error("two rebinds marked the session spread")
	}
	for p := 1; p <= spreadHops+1; p++ {
		hop.noteSrcPort(&net.UDPAddr{Port: 30000 + p})
	}
	if !hop.cc.spread {
		t.Error("a hopping client was not detected")
	}
	var icmp Session
	for i := 0; i < 20; i++ {
		icmp.noteSrcPort(&net.IPAddr{})
	}
	if icmp.cc.spread {
		t.Error("an ICMP peer (no port) was marked spread")
	}
}
