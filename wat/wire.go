package wat

import (
	"encoding/binary"
	"errors"
	"time"
)

// Frame types inside the encrypted payload.
const (
	frStream    = 0x01 // sid, off, len, data
	frStreamFin = 0x02 // same, final offset = off+len
	frAck       = 0x03 // largest, delay_us, nranges, first len, then (gap, len)...
	frWindow    = 0x04 // sid, max offset the receiver accepts
	frRst       = 0x05 // sid
	frPing      = 0x06
	frBoot      = 0x07 // server boot id: a change means the server process restarted and lost every stream
	frDgram     = 0x08 // flow, port, len, data: an unreliable datagram (UDP forwarding); always the LAST frame of a packet
	frFec       = 0x09 // XOR parity over the last few small data packets (fec.go); alone in its packet
	frDgramFrag = 0x0a // flow, port, id, index, count, len, data: one piece of a datagram too big for one packet (2.5.0)
	frKex       = 0x0b // 32-byte ephemeral X25519 public key: the forward-secrecy key exchange (2.10.0, both ends; see session.go onKex); always the LAST frame of a packet
	frPad       = 0x0c // len (one byte, < 128), then len zero bytes: random padding (3.0.0, hdrmask.go); always the LAST frame of a packet, so an older peer stops at it
)

var errBadFrame = errors.New("wat: malformed frame")

// maxAckDelayUs is the largest peer-reported ACK delay kept as a duration. The field arrives from an authenticated
// (but not necessarily benign) peer; it becomes a time.Duration added to the loss timer, and a huge uvarint used to
// overflow that negative and mark the whole in-flight window lost (audit 2026-11-03). Normal delays are milliseconds,
// but the protocol itself uses lateAckDelay (1 h, session.go) as the sentinel for a deliberately late ACK marker, so
// the ceiling has to stay above it; ten times it is still far below the overflow range.
const maxAckDelayUs = 10 * lateAckDelay

// ackDelay decodes the wire's ACK-delay field. The sender writes uint64(now-rxAt / µs), which is a huge value when
// that difference is negative (emulated clocks in tests, timer slack), and a hostile peer can send anything; both are
// clamped to 0 rather than dropping the frame, because the ACK's ranges are still needed (rejecting the whole ACK
// lost delivery information and stalled bulk UDP transfers). Values up to maxAckDelayUs — including the lateAckDelay
// sentinel — pass through unchanged.
func ackDelay(delayUs uint64) time.Duration {
	if delayUs >= 1<<63 || delayUs > maxAckDelayUs {
		return 0
	}
	return time.Duration(delayUs) * time.Microsecond
}

func appendUv(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

type reader struct {
	b   []byte
	err error
}

func (r *reader) uv() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errBadFrame
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) take(n uint64) []byte {
	if r.err != nil || n > uint64(len(r.b)) {
		r.err = errBadFrame
		return nil
	}
	d := r.b[:n]
	r.b = r.b[n:]
	return d
}

func (r *reader) byte() byte {
	if r.err != nil || len(r.b) == 0 {
		r.err = errBadFrame
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

// appendAck encodes the newest `max` received ranges, highest first.
func appendAck(b []byte, rs rangeSet, delayUs uint64, max int) []byte {
	if len(rs) == 0 {
		return b
	}
	if len(rs) > max {
		rs = rs[len(rs)-max:]
	}
	top := rs[len(rs)-1]
	b = append(b, frAck)
	b = appendUv(b, top.hi-1)
	b = appendUv(b, delayUs)
	b = appendUv(b, uint64(len(rs)))
	b = appendUv(b, top.hi-top.lo)
	prevLo := top.lo
	for i := len(rs) - 2; i >= 0; i-- {
		b = appendUv(b, prevLo-rs[i].hi) // gap between ranges
		b = appendUv(b, rs[i].hi-rs[i].lo)
		prevLo = rs[i].lo
	}
	return b
}

// parseAck reverses appendAck; ranges come back ascending.
func parseAck(r *reader) (largest uint64, delayUs uint64, rs []rng) {
	return parseAckInto(r, nil)
}

// parseAckInto is parseAck decoding into buf (reused across calls; the result is only valid until the next call).
func parseAckInto(r *reader, buf []rng) (largest uint64, delayUs uint64, rs []rng) {
	largest = r.uv()
	delayUs = r.uv()
	n := r.uv()
	if r.err != nil || n == 0 || n > 64 {
		r.err = errBadFrame
		return
	}
	l := r.uv()
	if r.err != nil || l == 0 || l > largest+1 {
		r.err = errBadFrame
		return
	}
	hi := largest + 1
	rs = buf[:0]
	if cap(rs) < int(n) {
		rs = make([]rng, 0, n)
	}
	rs = append(rs, rng{hi - l, hi})
	lo := hi - l
	for i := uint64(1); i < n; i++ {
		gap := r.uv()
		ln := r.uv()
		// Validate without gap+ln: that sum wraps for a hostile range (gap=^uint64(0) passed the old check, then
		// hi=lo-gap wrapped too and the ACK became overlapping, bogus ranges that amplified onAck's walk). gap < lo.
		if r.err != nil || ln == 0 || gap >= lo || ln > lo-gap {
			r.err = errBadFrame
			return
		}
		hi = lo - gap
		lo = hi - ln
		rs = append(rs, rng{lo, hi})
	}
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	return
}
