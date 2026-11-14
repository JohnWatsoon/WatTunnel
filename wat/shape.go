package wat

// Traffic shaping, both opt-in and off by default (3.3.0). They share one wire frame and one filler generator.
//
// W7 -shape-data (Config.ShapeData): pad packets that carry stream data to randomized, realistic total sizes, so a
// size classifier sees a spread of packet lengths instead of the application's request/response pattern. A byte
// budget (fraction of the stream bytes actually sent) bounds the overhead; the budget banks up to shapeDataBank
// bytes, so a small interactive packet can spend the allowance earned by earlier bulk traffic. Only data packets are
// padded: control-only packets are already padded by pad() (3.0.0) when masked, and datagram packets are left alone
// because frDgram must stay the last frame.
//
// F13 -noise (Config.NoiseBps): while the session has no user data in either direction for ~2 keepalive intervals,
// send randomly sized, non-ack-eliciting filler packets at the configured byte budget, with jittered intervals and an
// optional local-clock window. The keepalive cadence is deliberately untouched: noise is extra filler, not a
// replacement (that keeps kex retries and idle RTT samples working). Noise spends pacer tokens, so it cannot burst
// past the configured ceiling, but is never acked, never retransmitted, never in flight and never counted as stream
// data; it is counted in Stats (NoiseSent/NoiseBytes, and the session's BytesOut/PktsOut so /stats totals and quota
// accounting see it).
//
// Wire: both use frPad2 (uvarint length + filler), always the LAST frame of a packet. An older peer stops at the
// unknown type byte and loses nothing else; a 3.3.0 peer reads it and stops too. Nothing in the frame is interpreted,
// so no version gate is needed on sending it.

import (
	"math/bits"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	// shapeDataMinPad is the smallest padding worth appending (below it the frame header eats the gain).
	shapeDataMinPad = 16
	// shapeDataBank is how many padding bytes may be banked while no small packet goes out.
	shapeDataBank = 4 << 10
	// shapeDataLargeCap keeps the "large" bucket realistic: near the carrier MTU of the target path, not a direct
	// pool's 16 KB datagram (a 16 KB burst on a shaped link would cost a real RTT).
	shapeDataLargeCap = 1400

	// Noise packet sizing: small enough to look like keepalive chatter, never a second bulk flow.
	noiseMinPayload = 64
)

// padFill is the filler for frPad2. Random (not zeroes) so no unencrypted run is constant; generated once, lazily,
// because both features are off by default and a disabled session must not pay for it.
var (
	padFillOnce sync.Once
	padFill     [1 << 14]byte
)

func padFiller() []byte {
	padFillOnce.Do(func() {
		for i := range padFill {
			padFill[i] = byte(rand.Uint32())
		}
	})
	return padFill[:]
}

// uvarintLen is the encoded length of n as a uvarint (binary.AppendUvarint's size).
func uvarintLen(n int) int {
	if l := (bits.Len(uint(n)) + 6) / 7; l > 0 {
		return l
	}
	return 1
}

// framePad2Len is the frame overhead (type byte + length varint) that frPad2 adds on top of n filler bytes.
func framePad2Len(n int) int { return 1 + uvarintLen(n) }

// appendPad2 appends one frPad2 frame carrying n filler bytes; added is the number of plaintext bytes it cost.
func appendPad2(p []byte, n int) (out []byte, added int) {
	before := len(p)
	fill := padFiller()
	p = append(p, frPad2)
	p = appendUv(p, uint64(n))
	for n > 0 {
		c := min(n, len(fill))
		p = append(p, fill[:c]...)
		n -= c
	}
	return p, len(p) - before
}

// shapeData pads one packet that carries dataBytes of stream payload up to a randomized realistic size (under s.mu,
// only when Config.ShapeData > 0). It returns p unchanged when the packet is already large, the budget is empty or
// there is no room inside maxPlain. Padded bytes are counted in Stats.PadBytes.
func (s *Session) shapeData(dataBytes int, p []byte) []byte {
	if s.chooser != nil {
		// A bond sizes each packet for the path it will take after build; padding every packet to the slowest
		// path's MTU is out of scope here (cmd/wattun warns when -shape-data meets bonded carriers).
		return p
	}
	s.padAllow = min(s.padAllow+float64(dataBytes)*s.cfg.ShapeData, shapeDataBank)
	limit := s.maxPlain
	if s.fec != nil && limit > fecHdrMax {
		// F34: a padded packet above maxPlain-fecHdrMax would never be FEC-noted; keep the pad inside the ring.
		limit -= fecHdrMax
	}
	target := shapeTarget(limit, len(p))
	if target == 0 {
		return p
	}
	room := limit - len(p)
	pad := min(target-len(p), room-framePad2Len(room))
	if pad > 0 {
		pad = min(pad, int(s.padAllow))
	}
	if pad < shapeDataMinPad {
		return p
	}
	if over := framePad2Len(pad); len(p)+over+pad > limit { // one shrink is enough: the overhead only shrinks with pad
		pad = limit - len(p) - over
		if pad < shapeDataMinPad {
			return p
		}
	}
	var added int
	p, added = appendPad2(p, pad)
	s.padAllow -= float64(added)
	s.stats.PadBytes += uint64(added)
	return p
}

// shapeTarget draws a realistic total packet size above cur (small 100-300, medium 500-900, near the carrier MTU) and
// returns 0 when the packet is already too large for every bucket.
func shapeTarget(limit, cur int) int {
	large := min(limit, shapeDataLargeCap) - rand.IntN(min(64, max(1, limit/8)))
	if large < cur+shapeDataMinPad {
		return 0
	}
	for i := 0; i < 3; i++ {
		var t int
		switch rand.IntN(3) {
		case 0:
			t = 100 + rand.IntN(201)
		case 1:
			t = 500 + rand.IntN(401)
		default:
			t = large
		}
		if t >= cur+shapeDataMinPad && t <= limit {
			return t
		}
	}
	return 0
}

// noiseState is the idle-noise budget (Config.NoiseBps > 0; owned by the pump goroutine under s.mu).
type noiseState struct {
	bps    float64
	tokens float64
	last   time.Time
	next   time.Time
}

// noiseWindowOpen reports whether now's local clock is inside [from, to) minutes-of-day. Both zero = all day; the
// window may wrap past midnight (22:00-06:00).
func noiseWindowOpen(now time.Time, from, to int) bool {
	if from == 0 && to == 0 {
		return true
	}
	m := now.Hour()*60 + now.Minute()
	if from < to {
		return m >= from && m < to
	}
	return m >= from || m < to
}

// noiseDue builds one filler packet when the session has been idle for ~2 keepalive intervals and the byte budget
// allows one; the pump calls it once per round. Under s.mu.
func (s *Session) noiseDue(now time.Time) (outPkt, bool) {
	n := s.noise
	if n == nil || s.held || s.cc.tokens <= 0 || now.Sub(s.lastUser) < 2*s.cfg.PingEvery || !noiseWindowOpen(now, s.cfg.NoiseFrom, s.cfg.NoiseTo) {
		return outPkt{}, false
	}
	if n.last.IsZero() {
		n.last = now
	}
	if dt := now.Sub(n.last); dt > 0 {
		n.tokens = min(n.tokens+dt.Seconds()*n.bps, n.bps+float64(s.maxPlain))
		n.last = now
	}
	if now.Before(n.next) {
		return outPkt{}, false
	}
	hi := min(s.maxPlain-1-framePad2Len(s.maxPlain), max(noiseMinPayload, int(n.bps)))
	if hi < noiseMinPayload {
		hi = noiseMinPayload
	}
	size := noiseMinPayload + rand.IntN(hi-noiseMinPayload+1)
	if n.tokens < float64(size+framePad2Len(size)+overhead) {
		// M14: shrink to what the budget can pay for now instead of skipping the slot; the pump wakes at the deadline
		// noiseWake computes, so a wasted wake would turn into an under-delivered rate instead of a small packet.
		if size = int(n.tokens) - framePad2Len(size) - overhead; size < noiseMinPayload {
			return outPkt{}, false
		}
	}
	p, _ := appendPad2(s.noiseBuf[:0], size)
	s.noiseBuf = p[:0]
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	} else {
		lane = s.chooser.ChoosePath(len(p)+overhead, false)
	}
	out, _ := s.seal(p)
	n.tokens -= float64(len(out))
	n.next = now.Add(time.Duration((0.5 + rand.Float64()) * float64(len(out)) / n.bps * float64(time.Second)))
	s.cc.tokens -= float64(len(out) + ipIcmpHdr) // paced like FEC parity, but never tracked: no ack, no resend, no inflight
	// lastSend is deliberately not touched: the idle keepalive keeps its cadence, so the kex retry (which rides build
	// packets) and the ack-eliciting RTT samples keep working while noise is on.
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	s.stats.NoiseSent++
	s.stats.NoiseBytes += uint64(len(out))
	return outPkt{p: out, lane: lane, dupLane: -1}, true
}

// noiseWake is the pump's next-wake hint while idle noise is on (M14). The pump used to fall back to a fixed 100 ms
// idle tick whenever the batch was empty — and a noise packet is deliberately untracked, so that tick capped the
// delivered rate at a fraction of anything above ~8 KB/s (audit: 100 KB/s delivered as 8.6 KB/s, 1 MB/s as 72 KB/s).
// The pump clamps its idle sleep to this. It returns 0 when noise does not constrain the wake (off, held, busy, window
// closed, no pacer budget, no usable lane) and never a zero duration for a real deadline, so it cannot busy-spin.
func (s *Session) noiseWake(now time.Time) time.Duration {
	n := s.noise
	if n == nil || s.held || s.cc.tokens <= 0 {
		return 0
	}
	if now.Sub(s.lastUser) < 2*s.cfg.PingEvery || !noiseWindowOpen(now, s.cfg.NoiseFrom, s.cfg.NoiseTo) {
		return 0
	}
	if n.next.After(now) {
		return n.next.Sub(now)
	}
	if s.chooser == nil && len(s.lanes) == 0 { // no path to send on: the pump's idle tick is enough
		return 0
	}
	// Due now: wake immediately when the budget can pay for one minimal filler, else wake when it can. The minimum
	// reserves the largest possible frPad2 length varint (hi grows with the budget), so the wake is never wasted when
	// noiseDue then shrinks the packet to the affordable size.
	hi := min(s.maxPlain-1-framePad2Len(s.maxPlain), max(noiseMinPayload, int(n.bps)))
	if hi < noiseMinPayload {
		hi = noiseMinPayload
	}
	need := float64(noiseMinPayload + framePad2Len(hi) + overhead)
	if n.tokens >= need {
		return time.Millisecond
	}
	wait := time.Duration((need - n.tokens) / n.bps * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return wait
}
