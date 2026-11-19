package main

// Shared, platform-independent pieces of the spray-raw probe: the 5-tuple rotation schedule and
// the new-tuple token bucket. No build tag so the scheduler tests run on any GOOS (this checkout
// is Windows; the sockets themselves live in sprayraw_linux.go).

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// portRange is an inclusive UDP port range, "lo-hi" or a single "port".
type portRange struct{ lo, hi uint16 }

func parsePortRange(s string) (portRange, bool) {
	lo, hi, isRange := strings.Cut(s, "-")
	if !isRange {
		hi = lo
	}
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return portRange{}, false
	}
	h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil || h < l || l == 0 {
		return portRange{}, false
	}
	return portRange{uint16(l), uint16(h)}, true
}

func (r portRange) span() int { return int(r.hi) - int(r.lo) + 1 }

// tupleSched hands out rotation plans for the spray-raw sender: a fresh (sport, dport) pair and
// how many packets to send on it. Burst is 12-20, jittered per tuple, so every 5-tuple stays well
// under the ~29-34-packet cut the 2026-11-14 field probe saw on per-5-tuple counters.
type tupleSched struct {
	sports, dports portRange
	rnd            *rand.Rand
}

func newTupleSched(sports, dports portRange, seed int64) *tupleSched {
	return &tupleSched{sports: sports, dports: dports, rnd: rand.New(rand.NewSource(seed))}
}

func (s *tupleSched) next() (sport, dport uint16, burst int) {
	sport = s.sports.lo + uint16(s.rnd.Intn(s.sports.span()))
	dport = s.dports.lo + uint16(s.rnd.Intn(s.dports.span()))
	burst = 12 + s.rnd.Intn(9)
	return sport, dport, burst
}

// tokenBucket caps the rate of a repeating event — new 5-tuple transitions — at rate per second
// (anti-scan discipline: measure what passes, don't hammer the middlebox with churn). Capacity
// equals one second of rate, so a stopped sender can never owe more than that.
type tokenBucket struct {
	rate, cap, tokens float64
	last              time.Time
}

func newTokenBucket(perSec float64) *tokenBucket {
	return &tokenBucket{rate: perSec, cap: perSec, tokens: perSec, last: time.Now()}
}

// delay returns how long the caller must wait before the next event is allowed (0 = go now).
func (b *tokenBucket) delay(now time.Time) time.Duration {
	if now.After(b.last) {
		b.tokens = min(b.cap, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}
