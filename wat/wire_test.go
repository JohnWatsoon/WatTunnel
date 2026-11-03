package wat

import (
	"testing"
	"time"
)

// The peer-reported ACK delay is a network field, not a trusted number: a negative difference is encoded as a huge
// uint64, and a huge positive value used to overflow the time.Duration built from it negative and mark the whole
// in-flight window lost (audit 2026-11-03). It is clamped, not rejected, because the ACK's ranges still matter.
func TestAckDelay(t *testing.T) {
	for _, c := range []struct {
		name string
		in   uint64
		want time.Duration
	}{
		{"zero", 0, 0},
		{"milliseconds", 5000, 5 * time.Millisecond},
		{"late-ACK sentinel", lateAckDelay, time.Duration(lateAckDelay) * time.Microsecond},
		{"at the ceiling", maxAckDelayUs, time.Duration(maxAckDelayUs) * time.Microsecond},
		{"above the ceiling", maxAckDelayUs + 1, 0},
		{"huge positive", 1 << 60, 0},
		{"negative encoded as uint64", 1<<64 - 514, 0},
		{"max uint64", ^uint64(0), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ackDelay(c.in); got != c.want {
				t.Errorf("ackDelay(%d) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// A hostile or negative-encoded delay must not drop the ACK: its ranges are delivery information the sender needs.
func TestParseAckKeepsRangesWithHostileDelay(t *testing.T) {
	mk := func(largest, delayUs, ranges, firstLen uint64) *reader {
		var b []byte
		b = appendUv(b, largest)
		b = appendUv(b, delayUs)
		b = appendUv(b, ranges)
		b = appendUv(b, firstLen)
		return &reader{b: b}
	}
	for _, delayUs := range []uint64{maxAckDelayUs + 1, 1 << 60, ^uint64(0)} {
		r := mk(1, delayUs, 1, 2) // one range: [0, 2)
		largest, gotDelay, rs := parseAckInto(r, nil)
		if r.err != nil || largest != 1 || len(rs) != 1 || rs[0] != (rng{0, 2}) || ackDelay(gotDelay) != 0 {
			t.Fatalf("delay %d: err=%v largest=%d ranges=%v delay=%v", delayUs, r.err, largest, rs, ackDelay(gotDelay))
		}
	}
}
