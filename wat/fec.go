package wat

import "time"

// Adaptive FEC (Config.FEC, off by default): one XOR parity packet after a burst of small packets, so a single lost
// packet of the group is rebuilt by the receiver instead of waiting for a PTO (~1.25 RTT+) or for four later acks.
//
// Since 3.3.0 the sender also gates parity on measured loss (F11, fecGate): on the ~0.2-2 % random-loss target path a
// healthy link now pays no parity at all, and the overhead appears only after the loss estimate turns bad. The frame
// and its layout are unchanged, so an older peer reads the parity exactly as before and a peer without FEC ignores
// it; the gate is local policy, not a protocol change.
//
// The receiver follows the same idea without a wire signal: it copies small plaintexts into the reconstruction ring
// only while parity is arriving, and stops fecKeepAfter after the last frFec (fecKeep). A peer whose gate is closed
// sends none, so a healthy tunnel pays no FEC work in either direction; the cost is one group that cannot be rebuilt
// when parity resumes (the data before the first frFec was not kept). A zero-threshold caller has no gate at all, so
// it keeps every eligible plaintext (the time window only applies with a gate; F33). With FEC off the ring does not
// exist at all.
//
// Wire: frFec = n, base pn, n x (pn-base, plaintext length), then the parity bytes (to the end of the frame). The
// frame sits ALONE in its packet: an old peer stops at the unknown type and loses nothing else, and the packet is not
// ack-eliciting. Both ends must run FEC (>= 1.7.0) for it to help: a peer with FEC off parses and ignores the frame.
// Only packets whose plaintext is at most maxPlain-fecHdrMax are covered, so a parity packet always fits one
// datagram; in bulk the packets are full and nothing is covered (no overhead).
const (
	fecMaxK   = 16
	fecMinK   = 4
	fecRing   = 64 // received plaintexts kept for reconstruction
	fecHdrMax = 80 // frame header worst case: type, n, 10 B base, 16 x (2 + 2), length slack

	// fecInitLoss is the sender's starting loss estimate: the target path's usual random loss. It is also the first
	// k(), so the first group is a sane size before any sample lands, and with a gate at the default 2 % on
	// threshold the gate starts closed (loss > onLoss is false).
	fecInitLoss = 0.02
	// fecMinDwell is how long a gate decision is held before it may flip: the hysteresis band (on 2 %, off 0.5 %)
	// already stops most flapping, and the dwell keeps an estimate sitting on a threshold from toggling parity every
	// few packets.
	fecMinDwell = 2 * time.Second
	// fecKeepAfter is how long after the last frFec the receiver still copies small plaintexts into the ring. The
	// sender's parity follows its data within one burst, so 15 s tolerates lost parity packets and a quiet stream
	// while keeping a healthy (gate-closed) peer's receive path free of copies.
	fecKeepAfter = 15 * time.Second
)

type fecEnt struct {
	pn  uint64 // tx: packet number; rx: pn+1 (0 = empty)
	buf []byte
}

type fecState struct {
	tx    [fecMaxK]fecEnt // sent, not yet covered by a parity packet (oldest first)
	txN   int
	rx    [fecRing]fecEnt
	loss  float64   // EWMA of the packet loss rate seen by the sender
	keep  time.Time // received plaintexts are kept until this; extended by every frFec (F11 receiver side)
	inRec bool
	out   []byte
	gate  fecGate // F11: parity is sent only while the measured loss is above the on threshold
}

// fecGate is the sender-side loss gate (F11, 3.3.0): above onLoss parity starts, below offLoss it stops, and the band
// between the two plus a minimum dwell keeps a loss estimate on a threshold from flapping. Thresholds are fractions
// (0.02 = 2 %). The zero value (both 0) means "no gate": parity starts at any measured loss and never stops, which is
// the 1.7.0-3.2.x behavior for a Config.FEC caller that does not set the thresholds; cmd/wattun passes
// -fec-on-loss/-fec-off-loss explicitly.
type fecGate struct {
	on      bool
	since   time.Time // when on last changed; zero = never changed, so the first decision is immediate
	onLoss  float64
	offLoss float64
	dwell   time.Duration
}

// step re-decides the gate from the measured loss and reports whether parity may be sent now. A decision holds for at
// least dwell after every change.
func (g *fecGate) step(loss float64, now time.Time) bool {
	if !g.since.IsZero() && now.Sub(g.since) < g.dwell {
		return g.on
	}
	switch {
	case !g.on && loss > g.onLoss:
		g.on, g.since = true, now
	case g.on && loss < g.offLoss:
		g.on, g.since = false, now
	}
	return g.on
}

func newFec() *fecState {
	return &fecState{loss: fecInitLoss, gate: fecGate{dwell: fecMinDwell}}
}

// k adapts to the loss rate: the more loss, the smaller the group (a second loss inside a group is unrepairable).
func (f *fecState) k() int {
	k := fecMaxK
	if f.loss > 0 {
		k = int(0.2 / f.loss)
	}
	return min(max(k, fecMinK), fecMaxK)
}

func (f *fecState) onAck()  { f.loss -= f.loss / 256 }
func (f *fecState) onLoss() { f.loss += (1 - f.loss) / 256 }

// fecNoteSent remembers the plaintext of a data-bearing packet for the next parity. Nothing is copied while the loss
// gate is closed (F11): the ICMP path pays no FEC work while parity is off.
func (s *Session) fecNoteSent(pn uint64, p []byte) {
	f := s.fec
	if !f.gate.on || len(p) > s.maxPlain-fecHdrMax {
		return
	}
	if f.txN == fecMaxK { // keep the newest fecMaxK
		e := f.tx[0]
		copy(f.tx[:], f.tx[1:])
		f.tx[fecMaxK-1] = e
		f.txN--
	}
	e := &f.tx[f.txN]
	e.pn, e.buf = pn, append(e.buf[:0], p...)
	f.txN++
}

// fecDue builds the parity packet when a burst ended (nothing left to send) or k small packets went out while the
// session is not cwnd-limited. The loss gate is stepped here, once per pump round, so it tracks loss even while no
// small packet is going out.
func (s *Session) fecDue(now time.Time) (outPkt, bool) {
	f := s.fec
	if !f.gate.step(f.loss, now) {
		f.txN = 0 // gate closed mid-burst: drop the pending group, or busy() would keep the pump at 1 ms forever
		return outPkt{}, false
	}
	if f.txN == 0 || s.cc.tokens <= 0 {
		return outPkt{}, false
	}
	k := f.k()
	if s.hasWork() && (f.txN < k || s.cc.limited) {
		return outPkt{}, false
	}
	grp := f.tx[:f.txN]
	if len(grp) > k {
		grp = grp[len(grp)-k:]
	}
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	}
	L := 0
	for _, e := range grp {
		L = max(L, len(e.buf))
	}
	base := grp[0].pn
	p := append(f.out[:0], frFec)
	p = appendUv(p, uint64(len(grp)))
	p = appendUv(p, base)
	for _, e := range grp {
		p = appendUv(p, e.pn-base)
		p = appendUv(p, uint64(len(e.buf)))
	}
	at := len(p)
	for i := 0; i < L; i++ {
		p = append(p, 0)
	}
	for _, e := range grp {
		xorInto(p[at:], e.buf)
	}
	f.out = p[:0]
	f.txN = 0
	if s.chooser != nil {
		lane = s.chooser.ChoosePath(len(p)+overhead, true)
	}
	out, _ := s.seal(p)
	s.cc.tokens -= float64(len(out) + ipIcmpHdr) // paced, but not tracked: it is never acked and never retransmitted
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	s.stats.FecSent++
	return outPkt{p: out, lane: lane, dupLane: -1}, true
}

func xorInto(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

// fecKeep stores the plaintext of a received packet (under s.mu) while parity is arriving. The receive ring is not
// needed when the peer's gate is closed: nothing will come to rebuild, so the copy is pure overhead on a healthy
// path (F11 receiver side). Every frFec extends the window (onFec); the peer's gate state is not on the wire, so
// this is a heuristic: after fecKeepAfter with no parity the copies stop until the next frFec. A zero-threshold
// caller has no gate, so it keeps every eligible plaintext (session.go, F33). With FEC off s.fec is nil, so the
// ring does not exist at all.
func (s *Session) fecKeep(pn uint64, plain []byte, now time.Time) {
	f := s.fec
	// A zero-threshold gate (no loss gate configured) never closes; the time window only applies when a gate exists.
	gated := f.gate.onLoss != 0 || f.gate.offLoss != 0
	if (gated && now.After(f.keep)) || len(plain) > s.maxPlain-fecHdrMax {
		return
	}
	e := &f.rx[pn%fecRing]
	e.pn, e.buf = pn+1, append(e.buf[:0], plain...)
}

// onFec handles a parity frame (r is positioned after the type byte). It returns whether the rebuilt packet was
// ack-eliciting.
func (s *Session) onFec(r *reader, now time.Time) bool {
	n := r.uv()
	base := r.uv()
	if r.err != nil || n == 0 || n > fecMaxK {
		r.err = errBadFrame
		return false
	}
	var pns [fecMaxK]uint64
	var lens [fecMaxK]int
	for i := 0; i < int(n); i++ {
		pns[i] = base + r.uv()
		lens[i] = int(r.uv())
	}
	parity := r.take(uint64(len(r.b)))
	f := s.fec
	if r.err != nil || f == nil || f.inRec {
		return false
	}
	f.keep = now.Add(fecKeepAfter) // parity is arriving: keep small plaintexts again (F11 receiver side)
	miss := -1
	for i := 0; i < int(n); i++ {
		if lens[i] < 0 || lens[i] > len(parity) {
			// negative: a varint above 2^63 wrapped through int() — reject before rec[:lens[miss]] (audit 2026-10-21)
			r.err = errBadFrame
			return false
		}
		if s.rxAny && s.rxDup(pns[i]) {
			continue
		}
		if miss >= 0 {
			return false // two missing: one parity cannot repair them
		}
		miss = i
	}
	if miss < 0 {
		return false
	}
	rec := append([]byte(nil), parity...)
	for i := 0; i < int(n); i++ {
		if i == miss {
			continue
		}
		e := &f.rx[pns[i]%fecRing]
		if e.pn != pns[i]+1 || len(e.buf) != lens[i] {
			return false
		}
		xorInto(rec, e.buf)
	}
	rec = rec[:lens[miss]]
	pn := pns[miss]
	if !s.rxAny || pn > s.rxLargest {
		s.rxLargest, s.rxAny, s.rxAt = pn, true, now
	}
	s.rxRing[pn%s.replayWin] = pn + 1
	s.rxRanges.add(pn, pn+1)
	s.rxRanges.trim(s.rxKeep)
	s.fecKeep(pn, rec, now)
	s.stats.FecRecovered++
	f.inRec = true
	el := s.parse(rec, now)
	f.inRec = false
	return el
}
