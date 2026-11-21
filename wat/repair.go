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
// zero-padded to L and the true length of a LOST packet cannot be derived from the parity. Periodic symbols
// keep pnOff < repairWin; a v2 ask-answer (targeted) symbol may also carry the asked pns as members, with
// offsets up to repairOffMax — both ends are 3.4.3+, so the wider bound is safe.
//
// v2 (Config.RepairAsk, on top of the periodic layer under the same -repair flag): the receiver watches its
// rxRanges gaps and names the holes — frRepairAsk 0x11, up to 8 absolute pns, oldest first, throttled to one
// per 40 ms, each hole at most twice — and the sender answers with one targeted symbol covering exactly the
// asked pns (plus the covered current window, whose recent members the receiver holds and cancels). The v1
// kill verdict was coverage thinness: at the adaptive spacing a window saw ~1.3 covering symbols, so ~half
// the holes were never covered; the ask names them instead of waiting on the periodic roll.
const (
	repairWin  = 32  // window: the last W data packets a symbol covers
	repairKeep = 8   // symbols the receiver keeps for a joint GF(2) solve
	repairRxN  = 128 // received plaintexts kept: the span the kept symbols cover (W + Keep x every), rounded up
	// repairHdrMax bounds the member table: 24 B of scalars + W×(2+3) uvarints.
	repairHdrMax = 24 + repairWin*5

	// v2 ask retention (Config.RepairAsk). The 32-packet tx window scrolls past a hole in ~9 ms at bulk
	// rate, but an ask needs up to the 40 ms throttle plus the one-way flight before the sender can answer —
	// measured 2026-11-21: with the v1 window every ask missed (29/29 in TestRepairAskRoundTrip). 1024
	// plaintexts ≈ 1.4 MB per direction per session (opt-in, only while the peer announced frRepairCap)
	// covers ~130 ms of 10 MB/s at the 640 B MTU, the worst packet rate the harness models.
	repairAskWin   = 1024
	repairOffMax   = repairAskWin + repairWin // largest member offset a targeted symbol can carry (onRepair bound)
	repairAskMem   = repairWin + 8            // members of a targeted symbol: covered window + asked pns
	repairAskEvery = 40 * time.Millisecond    // one frRepairAsk at most this often (v2 NACK throttle)
)

// repairCover: is pn a member of symbol k? A knuth-style product mix — deterministic on both ends, ~half
// the window, no table. The second multiply (2026-11-21) is load-bearing: any single bit of x^y is just
// bit(x)^bit(y), so the v1 form (top bit of pn*C1^k*C2) collapsed to cover(pn,k) = A(pn)^B(k) — only TWO
// distinct subsets existed across all k, and two pns in different halves were NEVER jointly covered, which
// is why v1's measured recovery stayed flat (the codec tests had happened to pick cross-half drop pairs).
// Multiplying the mix again spreads the input bits across the chosen bit, making coverage of different pns
// independent across k as the GF(2) solve assumes. Not a wire change (cover is computed, never sent), and
// 3.4.3 is unreleased, so no deployed peer computes the old subsets.
func repairCover(pn, k uint64) bool {
	return ((pn*0x9E3779B97F4A7C15^k*0xC2B2AE3D27D4EB4F)*0xC2B2AE3D27D4EB4F)>>63 == 1
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
	tx      [repairWin]repairEnt    // sent plaintexts by pn%W
	txNext  uint64                  // one past the newest pn noted
	askTx   [repairAskWin]repairEnt // v2: longer plaintext retention so an ask (~60 ms stale) still hits
	k       uint64                  // next symbol index to send
	every   int                     // data packets between repair packets (adaptive)
	pending int                     // data packets noted since the last repair packet
	loss    float64                 // EWMA of lost/sent, the fec.onAck/onLoss shape
	peerOK  bool                    // the peer announced frRepairCap
	capAt   time.Time               // last frRepairCap we sent
	queue   [][]byte                // sealed-pending chunks of the current symbol
	rx      [repairRxN]repairEnt    // received plaintexts by pn%repairRxN (wider than tx: kept symbols reach back)
	syms    []rxSym                 // newest last, at most repairKeep
	part    map[uint64]*rxPart      // symbol chunks being stitched, by k
	out     []byte
	// v2 ask layer (Config.RepairAsk): holes queued for the next frRepairAsk, per-hole ask counts, the
	// throttle clock and the targeted-symbol k cursor (kept above r.k and above every targeted k already
	// used, so a second ask for the same hole yields a NEW equation, not a repeat of the first).
	askQ    []uint64
	askN    map[uint64]int
	askAt   time.Time
	kAsk    uint64
	askSent uint64 // frRepairAsks emitted (test/harness visibility; not a /stats key yet)
	askHit  uint64 // asked pns answered with a targeted symbol
	askMiss uint64 // asked pns no longer in the tx ring
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
	return &repairState{every: 400, part: map[uint64]*rxPart{}, askN: map[uint64]int{}} // ~0.25 % overhead until loss is observed; shrinks with the EWMA
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

// repairNoteSent remembers a data packet's plaintext for the next symbols (under s.mu, from build). The
// copy waits for the peer's frRepairCap: a mixed pair never builds symbols, so it must not pay the
// per-packet copy either (the receive ring stays warm from the first packet — the peer's symbols may start
// arriving any time after OUR cap goes out).
func (s *Session) repairNoteSent(pn uint64, p []byte) {
	r := s.repair
	if !r.peerOK {
		return
	}
	e := &r.tx[pn%repairWin]
	e.pn, e.buf = pn, append(e.buf[:0], p...)
	if s.cfg.RepairAsk {
		a := &r.askTx[pn%repairAskWin]
		a.pn, a.buf = pn, append(a.buf[:0], p...)
	}
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
	k := r.k
	r.k++
	r.pending = 0
	r.buildChunks(s, k)
	if o := r.popQueued(s, now); o != nil {
		return *o, true
	}
	return outPkt{}, false
}

// buildChunks computes the symbol k over the window and queues its chunk packets (plaintext frames). It
// touches neither r.k nor r.pending: the periodic caller advances both, the ask path (repairOnAsk) passes a
// searched k and must not disturb the periodic schedule.
func (r *repairState) buildChunks(s *Session, k uint64) {
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
		return
	}
	// the header, then as much parity per packet as fits
	hdr := append(r.out[:0], frRepair)
	hdr = appendUv(hdr, lo)
	hdr = appendUv(hdr, uint64(L))
	hdr = appendUv(hdr, k)
	hdr = appendUv(hdr, uint64(len(pns)))
	for i, pn := range pns {
		hdr = appendUv(hdr, pn-lo)
		hdr = appendUv(hdr, uint64(lens[i]))
	}
	parity := make([]byte, L)
	for _, pn := range pns {
		if repairCover(pn, k) {
			xorInto(parity, r.tx[pn%repairWin].buf)
		}
	}
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

// repairKeep stores a received data packet's plaintext (under s.mu) while repair is on, and refreshes the
// ask queue with the holes the receive ranges now show (Config.RepairAsk).
func (s *Session) repairKeep(pn uint64, plain []byte) {
	r := s.repair
	e := &r.rx[pn%repairRxN]
	e.pn, e.buf = pn, append(e.buf[:0], plain...)
	s.repairNoteHoles()
}

// repairNoteHoles rebuilds the ask queue from the gaps between the receive ranges (under s.mu). Only holes
// more than 4 received packets old are asked — a gap at the tail is usually just a reorder or a packet still
// in flight — and a hole is asked at most twice (askN); after that the retransmit path owns it, the
// v1 verdict having shown that hammering the same thin coverage buys nothing.
func (s *Session) repairNoteHoles() {
	r := s.repair
	if !s.cfg.RepairAsk || !r.peerOK || !s.rxAny {
		return
	}
	r.askQ = r.askQ[:0]
	rs := s.rxRanges
	for i := 0; i+1 < len(rs) && len(r.askQ) < 8; i++ {
		for pn := rs[i].hi; pn < rs[i+1].lo && len(r.askQ) < 8; pn++ {
			if s.rxLargest-pn <= 4 {
				break // too young to ask about; later gaps are younger still
			}
			if r.askN[pn] < 2 {
				r.askQ = append(r.askQ, pn)
			}
		}
	}
	for pn := range r.askN { // filled holes leave the bookkeeping: askN stays bounded by real holes
		if s.rxRanges.contains(pn) {
			delete(r.askN, pn)
		}
	}
}

// repairAskDue appends frRepairAsk while the ask layer is on (build calls it right after repairCapDue):
// the queued holes, oldest first, at most one ask per 40 ms so a loss burst cannot turn the ask path into
// a second ACK stream. The frame is the LAST frame of its packet and never shares one with frEndpoint
// (same slot rule as the cap — see build).
func (s *Session) repairAskDue(p []byte, now time.Time) []byte {
	r := s.repair
	if !s.cfg.RepairAsk || !r.peerOK || len(r.askQ) == 0 || now.Sub(r.askAt) < repairAskEvery {
		return p
	}
	p = appendRepairAsk(p, r.askQ)
	for _, pn := range r.askQ {
		r.askN[pn]++
	}
	r.askQ = r.askQ[:0]
	r.askAt = now
	r.askSent++
	return p
}

// appendRepairAsk encodes frRepairAsk: n(uv) then n absolute pns, oldest first (n ≤ 8 by construction —
// repairNoteHoles caps the queue).
func appendRepairAsk(p []byte, pns []uint64) []byte {
	p = append(p, frRepairAsk)
	p = appendUv(p, uint64(len(pns)))
	for _, pn := range pns {
		p = appendUv(p, pn)
	}
	return p
}

// parseRepairAsk reads the ask payload; nil + r.err on anything but 1..8 pns.
func parseRepairAsk(r *reader) []uint64 {
	n := r.uv()
	if r.err != nil || n == 0 || n > 8 {
		r.err = errBadFrame
		return nil
	}
	pns := make([]uint64, 0, n)
	for i := uint64(0); i < n; i++ {
		pn := r.uv()
		if r.err != nil {
			return nil
		}
		pns = append(pns, pn)
	}
	return pns
}

// askCoverK searches deterministically upward from `from` for a symbol k covering every asked pn. Each k
// covers a given pn with an independent ~1/2, so the first covering k appears within ~2^e tries; the bound
// (64) gives up on e ≳ 6 — the periodic layer and the retransmit path still own those holes.
func askCoverK(want []uint64, from uint64) (uint64, bool) {
	for k := from; k < from+64; k++ {
		ok := true
		for _, pn := range want {
			if !repairCover(pn, k) {
				ok = false
				break
			}
		}
		if ok {
			return k, true
		}
	}
	return 0, false
}

// repairOnAsk answers a frRepairAsk with ONE targeted symbol covering every asked pn still retained
// (under s.mu, from parse). Retention is the askTx ring (1024 packets), not the 32-packet window — an ask
// arrives ~60 ms stale at bulk rate and the window has scrolled far past it by then. The periodic schedule
// is untouched: r.pending/r.every keep their values and the symbol index is a search above max(r.k, kAsk) —
// never the counter itself and never a k already used, so a repeated ask (a hole may be asked twice) adds a
// NEW equation to the receiver's joint solve instead of repeating the first. Asked pns aged out of retention
// are skipped: the retransmit path owns them.
func (s *Session) repairOnAsk(pns []uint64) {
	r := s.repair
	if !r.peerOK {
		return
	}
	want := pns[:0]
	for _, pn := range pns {
		if r.askTx[pn%repairAskWin].pn == pn {
			want = append(want, pn)
		}
	}
	if len(want) == 0 {
		r.askMiss++
		return
	}
	k, ok := askCoverK(want, max(r.k, r.kAsk))
	if !ok {
		return
	}
	r.kAsk = k + 1
	r.askHit += uint64(len(want))
	r.buildTargeted(s, want, k)
}

// buildTargeted queues the ask answer: a symbol whose members are the asked pns (all covered — that is what
// the k search guarantees) plus the k-covered members of the current window, so the row the receiver builds
// from it carries exactly the asked holes as unknowns. Same chunked form as buildChunks.
func (r *repairState) buildTargeted(s *Session, want []uint64, k uint64) {
	hi := r.txNext
	lo := uint64(0)
	if hi > repairWin {
		lo = hi - repairWin
	}
	var pns []uint64
	var lens []int
	L := 0
	add := func(pn uint64, buf []byte) {
		pns, lens = append(pns, pn), append(lens, len(buf))
		if len(buf) > L {
			L = len(buf)
		}
	}
	for _, pn := range want {
		add(pn, r.askTx[pn%repairAskWin].buf)
	}
	for pn := lo; pn < hi; pn++ {
		if indexOfPn(want, pn) >= 0 {
			continue // an asked pn inside the window rides once, as a want member (double membership would
			// cancel out of the parity and desync the receiver's row)
		}
		if e := &r.tx[pn%repairWin]; e.pn == pn && repairCover(pn, k) {
			add(pn, e.buf)
		}
	}
	if len(pns) == 0 || L == 0 {
		return
	}
	hdr := append(r.out[:0], frRepair)
	hdr = appendUv(hdr, lo)
	hdr = appendUv(hdr, uint64(L))
	hdr = appendUv(hdr, k)
	hdr = appendUv(hdr, uint64(len(pns)))
	for i, pn := range pns {
		hdr = appendUv(hdr, pn-lo)
		hdr = appendUv(hdr, uint64(lens[i]))
	}
	parity := make([]byte, L)
	for _, pn := range pns {
		xorInto(parity, r.askTx[pn%repairAskWin].buf)
	}
	budget := s.maxPlain - len(hdr) - 10 // 10 = the offset uvarint + slack
	if budget < 64 {
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

// onRepair handles a frRepair chunk (r positioned after the type byte). Chunks of one symbol share the
// header and are stitched by k; once complete the symbol enters the solve set. Returns whether a rebuilt
// packet was ack-eliciting.
func (s *Session) onRepair(r *reader, now time.Time, src net.Addr) bool {
	base := r.uv()
	L := r.uv()
	k0 := r.uv()
	n := r.uv()
	if r.err != nil || n == 0 || n > repairAskMem || L == 0 || L > MaxPayloadHi {
		r.err = errBadFrame
		return false
	}
	var pns []uint64
	var lens []int
	for i := 0; i < int(n); i++ {
		off := r.uv()
		ln := r.uv()
		if r.err != nil || off >= repairOffMax || ln > L {
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
		if s.rxAny && pn < s.rxLargest && s.rxLargest-pn >= repairOffMax {
			return -1 // beyond any symbol's reach (v2: targeted members reach repairOffMax back, not the rx ring)
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
			if s.rxRanges.contains(pn) {
				// delivered, but its plaintext has aged out of the rx ring: its contribution to the parity
				// cannot be removed, so this row is unusable (a raced retransmit landing mid-solve — rare)
				ok = false
				break
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
