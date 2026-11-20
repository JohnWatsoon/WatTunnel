package wat

import (
	"net"
	"time"
)

// Sliding-window coded repair (Config.Repair, off by default; both ends 3.4.3+). The design and the
// baseline numbers it is judged against are in docs/handoff/LOG.md (phase 2, Track A).
//
// Where fec.go sends one XOR parity over a group of SMALL packets after the burst (and only while the loss
// gate is open), repair covers EVERY data packet of the last repairWin window and sends a repair symbol
// every `every` data packets, interleaved with the data — so a lost downlink packet is usually rebuilt a few
// packets later (milliseconds at bulk rate) instead of after the sender's loss timer plus a retransmit round
// trip (~93 ms at 40 ms RTT). A rebuilt packet is recorded in the receive ranges, so the next ACK reports it
// delivered and the sender never retransmits it.
//
// A repair symbol k is the XOR of the zero-padded plaintexts of the window packets pn with cover(pn,k), a
// deterministic pseudo-random half-subset computed identically on both ends — no coefficient table on the
// wire. One symbol rides per frRepair packet (header + L bytes); the receiver keeps the last repairKeep
// symbols and solves the GF(2) system over the holes they cover, so a few consecutive symbols jointly
// recover multiple losses. Nothing about correctness depends on repair: a hole the system cannot solve keeps
// its place and the ordinary retransmit path owns it.
//
// Negotiation: frRepairCap (one byte) is sent ~1/s with the data while repair is on, and a sender emits
// repair symbols only after seeing the peer's cap. An old peer ignores both frames (frRepair sits ALONE in
// its packet, frRepairCap is followed only by frames an old peer ignores anyway), so a mixed pair sends no
// repair and behaves exactly like today. Both ends should run 3.4.3+ for repair to engage.
//
// Wire, frRepair = 0x0f (alone in its packet, not ack-eliciting):
//
//	base(uv) L(uv) k0(uv) n(uv) n×(pnOff(uv) len(uv)) poff(uv) parity-bytes-to-end
//
// base = window's first pn, n = members, k0 = the symbol's index, poff = this chunk's offset into the L-byte
// parity. A parity that fits one datagram is one chunk; a full bulk window's does not, so consecutive chunks
// repeat the header and the receiver stitches by k0. The member lengths ride along because a symbol is
// zero-padded to L and the true length of a LOST packet cannot be derived from the parity.
const (
	repairWin  = 32  // window: the last W data packets a symbol covers
	repairKeep = 8   // symbols the receiver keeps for a joint GF(2) solve
	repairRxN  = 128 // received plaintexts kept: the span the kept symbols cover (W + Keep x every), rounded up
	// repairHdrMax bounds the member table: 24 B of scalars + W×(2+3) uvarints.
	repairHdrMax = 24 + repairWin*5
)

// repairCover: is pn a member of symbol k? The high bit of a knuth-style product mix — deterministic on both
// ends, ~half the window, no table. Two distinct pns share a coverage pattern across k only by collision.
func repairCover(pn, k uint64) bool {
	return (pn*0x9E3779B97F4A7C15^k*0xC2B2AE3D27D4EB4F)>>63 == 1
}

type repairEnt struct {
	pn  uint64 // 0 = empty
	buf []byte
}

// rxSym is one received repair symbol in raw form (parity + member list); the constant term is re-derived at
// every solve attempt because arrivals only grow, so recomputing against the current ring is always valid.
type rxSym struct {
	k      uint64
	L      int
	pns    []uint64
	lens   []int
	parity []byte
}

type repairState struct {
	tx      [repairWin]repairEnt // sent plaintexts by pn%W
	txNext  uint64               // one past the newest pn noted
	k       uint64               // next symbol index to send
	every   int                  // data packets between repair packets (adaptive)
	pending int                  // data packets noted since the last repair packet
	loss    float64              // EWMA of lost/sent, the fec.onAck/onLoss shape
	peerOK  bool                 // the peer announced frRepairCap
	capAt   time.Time            // last frRepairCap we sent
	queue   [][]byte             // sealed-pending chunks of the current symbol
	rx      [repairRxN]repairEnt // received plaintexts by pn%repairRxN (wider than tx: kept symbols reach back)
	syms    []rxSym              // newest last, at most repairKeep
	part    map[uint64]*rxPart   // symbol chunks being stitched, by k
	out     []byte
}

// rxPart: a symbol whose chunks are still arriving.
type rxPart struct {
	buf  []byte
	have int
	pns  []uint64
	lens []int
	base uint64
}

func newRepair() *repairState {
	return &repairState{every: 400, part: map[uint64]*rxPart{}} // ~0.25 % overhead until loss is observed; shrinks with the EWMA
}

func (r *repairState) onAck() { r.loss -= r.loss / 256 }
func (r *repairState) onLoss() {
	r.loss += (1 - r.loss) / 256
	// step here too: an idle session (no symbols flowing) still re-aims as the estimate moves
	per := 1 + int(r.loss*float64(repairWin)*3)
	if per > 8 {
		per = 8
	}
	r.every = repairWin / per
}

// repairNoteSent remembers a data packet's plaintext for the next symbols (under s.mu, from build).
func (s *Session) repairNoteSent(pn uint64, p []byte) {
	r := s.repair
	e := &r.tx[pn%repairWin]
	e.pn, e.buf = pn, append(e.buf[:0], p...)
	if pn >= r.txNext {
		r.txNext = pn + 1
	}
	r.pending++
}

// repairCapDue appends frRepairCap while repair is on (build calls it just before frEndpoint, so an old peer
// that stops here loses only frames it ignores anyway). One byte payload = capability version.
func (s *Session) repairCapDue(p []byte, now time.Time) []byte {
	r := s.repair
	if now.Sub(r.capAt) < time.Second {
		return p
	}
	r.capAt = now
	return append(p, frRepairCap, 1)
}

// repairDue builds the next repair packet when `every` data packets have gone out since the last one
// (under s.mu, called from the pump beside fecDue). A symbol's parity (L = the window's max plaintext) plus
// the member table regularly exceeds one datagram on a full bulk window, so one symbol is CHUNKED: every
// packet repeats the header plus a parity offset, the receiver stitches the chunks by k. Paced and counted,
// never tracked in s.sent: like frFec it is never acked and never retransmitted.
func (s *Session) repairDue(now time.Time) (outPkt, bool) {
	r := s.repair
	if o := r.popQueued(s, now); o != nil {
		return *o, true
	}
	if !r.peerOK || r.txNext == 0 || r.pending < r.every {
		return outPkt{}, false
	}
	r.buildChunks(s)
	if o := r.popQueued(s, now); o != nil {
		return *o, true
	}
	return outPkt{}, false
}

// buildChunks computes the next symbol over the window and queues its chunk packets (plaintext frames).
func (r *repairState) buildChunks(s *Session) {
	hi := r.txNext
	lo := uint64(0)
	if hi > repairWin {
		lo = hi - repairWin
	}
	var pns []uint64
	var lens []int
	L := 0
	for pn := lo; pn < hi; pn++ {
		e := &r.tx[pn%repairWin]
		if e.pn != pn {
			continue
		}
		pns, lens = append(pns, pn), append(lens, len(e.buf))
		if len(e.buf) > L {
			L = len(e.buf)
		}
	}
	if len(pns) == 0 || L == 0 {
		r.pending = 0
		return
	}
	// the header, then as much parity per packet as fits
	hdr := append(r.out[:0], frRepair)
	hdr = appendUv(hdr, lo)
	hdr = appendUv(hdr, uint64(L))
	hdr = appendUv(hdr, r.k)
	hdr = appendUv(hdr, uint64(len(pns)))
	for i, pn := range pns {
		hdr = appendUv(hdr, pn-lo)
		hdr = appendUv(hdr, uint64(lens[i]))
	}
	parity := make([]byte, L)
	for _, pn := range pns {
		if repairCover(pn, r.k) {
			xorInto(parity, r.tx[pn%repairWin].buf)
		}
	}
	r.k++
	r.pending = 0
	budget := s.maxPlain - len(hdr) - 10 // 10 = the offset uvarint + slack
	if budget < 64 {
		// a maxPlain this small cannot carry the member table at all: repair stays off for this session
		r.every = 1 << 30
		return
	}
	for off := 0; off < L; off += budget {
		end := min(off+budget, L)
		q := append([]byte(nil), hdr...)
		q = appendUv(q, uint64(off))
		q = append(q, parity[off:end]...)
		r.queue = append(r.queue, q)
	}
	r.out = hdr[:0]
}

// popQueued seals and returns the next queued repair chunk (nil when the queue is empty).
func (r *repairState) popQueued(s *Session, now time.Time) *outPkt {
	if len(r.queue) == 0 {
		return nil
	}
	p := r.queue[0]
	r.queue = r.queue[1:]
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return nil
		}
	} else {
		lane = s.chooser.ChoosePath(len(p)+overhead, true)
	}
	out, _ := s.seal(p)
	s.cc.tokens -= float64(len(out) + ipIcmpHdr) // paced, but never tracked: no ack, no retransmit
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	if len(r.queue) == 0 { // one symbol per completed send
		s.stats.RepairSent++
	}
	return &outPkt{p: out, lane: lane, dupLane: -1}
}

// repairKeep stores a received data packet's plaintext (under s.mu) while repair is on.
func (s *Session) repairKeep(pn uint64, plain []byte) {
	e := &s.repair.rx[pn%repairRxN]
	e.pn, e.buf = pn, append(e.buf[:0], plain...)
}

// onRepair handles a frRepair chunk (r positioned after the type byte). Chunks of one symbol share the
// header and are stitched by k; once complete the symbol enters the solve set. Returns whether a rebuilt
// packet was ack-eliciting.
func (s *Session) onRepair(r *reader, now time.Time, src net.Addr) bool {
	base := r.uv()
	L := r.uv()
	k0 := r.uv()
	n := r.uv()
	if r.err != nil || n == 0 || n > repairWin || L == 0 || L > MaxPayloadHi {
		r.err = errBadFrame
		return false
	}
	var pns []uint64
	var lens []int
	for i := 0; i < int(n); i++ {
		off := r.uv()
		ln := r.uv()
		if r.err != nil || off >= repairWin || ln > L {
			r.err = errBadFrame
			return false
		}
		pns, lens = append(pns, base+off), append(lens, int(ln))
	}
	poff := r.uv()
	chunk := r.take(uint64(len(r.b)))
	if r.err != nil || poff > L || uint64(len(chunk)) > L-poff {
		r.err = errBadFrame
		return false
	}
	rep := s.repair
	if rep == nil {
		return false
	}
	// stitch chunks by k until the symbol's L bytes are complete
	pt := rep.part[k0]
	if pt == nil {
		if len(rep.part) >= 16 { // stale partials of a dead symbol: drop the oldest-ish entry
			for k := range rep.part {
				delete(rep.part, k)
				break
			}
		}
		pt = &rxPart{buf: make([]byte, L), lens: lens, pns: pns, base: base}
		rep.part[k0] = pt
	}
	copy(pt.buf[poff:], chunk)
	pt.have += len(chunk)
	if pt.have < int(L) {
		return false
	}
	delete(rep.part, k0)
	sy := rxSym{k: k0, L: int(L), pns: pt.pns, lens: pt.lens, parity: pt.buf}
	if len(rep.syms) == repairKeep {
		rep.syms = append(rep.syms[:0], rep.syms[1:]...)
	}
	rep.syms = append(rep.syms, sy)
	return s.repairSolve(now, src)
}

// repairSolve attempts a joint GF(2) solve over every kept symbol. Unknowns are the covered members the
// receiver does not have (a lost packet that is still pending; a member older than the rx ring also lands
// here, and the rank check rejects it — the retransmit path owns whatever we cannot isolate).
func (s *Session) repairSolve(now time.Time, src net.Addr) bool {
	rep := s.repair
	// unknowns and their lengths, collected while the rows are built (a member aged out of the ring is an
	// unknown like a fresh hole; its column usually has too few rows and the solve fails on it)
	var holes []uint64
	var hlen []int
	holeIdx := func(pn uint64, ln int) int {
		if i := indexOfPn(holes, pn); i >= 0 {
			return i
		}
		if s.rxAny && pn < s.rxLargest && s.rxLargest-pn >= repairRxN {
			return -1 // older than the ring: already delivered or beyond reach; never rebuild it
		}
		if len(holes) >= repairWin {
			return -1 // over a window of unknowns: not this frame's business
		}
		holes = append(holes, pn)
		hlen = append(hlen, ln)
		return len(holes) - 1
	}
	// rows: one per kept symbol, constant term = parity minus every covered member we DO have
	type row struct {
		mask uint64 // bits over holes
		b    []byte // padded XOR of the covered holes
	}
	var rows []row
	Lmax := 0
	for i := range rep.syms {
		if rep.syms[i].L > Lmax {
			Lmax = rep.syms[i].L
		}
	}
	if Lmax == 0 {
		return false
	}
	for si := range rep.syms {
		sy := &rep.syms[si]
		if len(sy.parity) != sy.L {
			continue
		}
		b := make([]byte, Lmax)
		copy(b, sy.parity)
		var m uint64
		ok := true
		for i, pn := range sy.pns {
			if !repairCover(pn, sy.k) {
				continue
			}
			if e := &rep.rx[pn%repairRxN]; e.pn == pn {
				xorInto(b[:len(e.buf)], e.buf)
				continue
			}
			h := holeIdx(pn, sy.lens[i])
			if h < 0 {
				ok = false
				break
			}
			m |= 1 << uint(h)
		}
		if ok && m != 0 {
			rows = append(rows, row{mask: m, b: b})
		}
	}
	if len(holes) == 0 {
		return false // everything covered already arrived
	}
	// Gauss-Jordan over GF(2): every hole column needs a pivot, then each pivot row is exactly that hole.
	e := len(holes)
	piv := make([]int, e)
	for i := range piv {
		piv[i] = -1
	}
	used := make([]bool, len(rows))
	for c := 0; c < e; c++ {
		pr := -1
		for ri := range rows {
			if !used[ri] && rows[ri].mask>>uint(c)&1 == 1 {
				pr = ri
				break
			}
		}
		if pr < 0 {
			return false // rank deficit: the retransmit path owns these holes
		}
		used[pr] = true
		piv[c] = pr
		for ri := range rows {
			if ri != pr && rows[ri].mask>>uint(c)&1 == 1 {
				rows[ri].mask ^= rows[pr].mask
				xorInto(rows[ri].b, rows[pr].b)
			}
		}
	}
	el := false
	for c := 0; c < e; c++ {
		rec := append([]byte(nil), rows[piv[c]].b[:hlen[c]]...)
		pn := holes[c]
		if !s.rxAny || pn > s.rxLargest {
			s.rxLargest, s.rxAny, s.rxAt = pn, true, now
		}
		s.rxRing[pn%s.replayWin] = pn + 1
		s.rxRanges.add(pn, pn+1)
		s.rxRanges.trim(s.rxKeep)
		s.repairKeep(pn, rec)
		s.stats.RepairRecovered++
		el = s.parse(rec, now, src) || el
	}
	return el
}

// repairReset drops the decoder state (server boot change: the old run's symbols describe a dead pn space).
func (s *Session) repairReset() {
	if s.repair != nil {
		s.repair.syms = s.repair.syms[:0]
		clear(s.repair.part)
		for i := range s.repair.rx {
			s.repair.rx[i] = repairEnt{}
		}
	}
}

func indexOfPn(pns []uint64, pn uint64) int {
	for i, v := range pns {
		if v == pn {
			return i
		}
	}
	return -1
}
