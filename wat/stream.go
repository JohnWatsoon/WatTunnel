package wat

import (
	"errors"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrReset        = errors.New("wat: stream reset")
	ErrClosed       = errors.New("wat: closed")
	ErrTooManyConns = errors.New("wat: too many streams")
)

type frameRef struct {
	sid, off uint64
	n        int
	fin      bool
}

type seg struct {
	off  uint64
	data []byte
}

// Stream is one reliable, ordered byte stream (one TCP connection) inside a Session.
type Stream struct {
	s   *Session
	id  uint64
	pin int // direct pool: the stream's connection slot, handed out round-robin (Session.pinNext)

	rc, wc *sync.Cond // readers / writers wait on these (both guarded by s.mu)

	// send side
	snd       sndQueue // unacknowledged data; its first byte is stream offset sbase
	sbase     uint64
	snext     uint64 // next never-sent offset
	retx      []frameRef
	acked     rangeSet
	peerMax   uint64
	finQueued bool
	finSent   bool
	finAcked  bool
	finOff    uint64
	sentTotal uint64
	heat      float64   // recent bytes sent, halving every prioHalfLife (bulky)
	heatAt    time.Time // when heat was last decayed
	inActive  bool
	group     uint32 // fair-queue group (SetGroup): the public port the stream belongs to
	fg        *fairGroup

	// receive side
	rnext    uint64
	segs     []seg
	ready    rdQueue // in-order bytes Read has not taken yet
	slowWin  uint64  // >0: the smaller window advertised while the local reader lags (tuneSlow)
	slowAt   time.Time
	slowC    uint64
	consumed uint64
	advMax   uint64
	win      uint64 // window this end advertises beyond consumed: streamWindow, auto-tuned upward (see tuneWindow)
	tuneAt   time.Time
	tuneRx   uint64 // rnext at the start of the current measuring epoch
	rhigh    uint64 // highest stream offset received so far, in order or not (tuneWindow: did the sender hit our edge?)
	tuneEdge bool   // rhigh reached the advertised edge during the current measuring epoch
	peerFin  bool
	peerFinO uint64
	eof      bool
	rdClosed bool // the local reader is gone: drop buffered data and let the stream finish without it

	err  error
	dead bool
}

func (s *Session) newStream(id uint64) *Stream {
	st := &Stream{s: s, id: id, peerMax: streamWindow, advMax: streamWindow, win: streamWindow}
	st.rc = sync.NewCond(&s.mu)
	st.wc = sync.NewCond(&s.mu)
	st.pin = s.pinNext
	s.pinNext = (s.pinNext + 1) % (1 << 20)
	s.streams[id] = st
	return st
}

func (st *Stream) sendable() bool {
	if len(st.retx) > 0 {
		return true
	}
	if st.snext < st.sbase+uint64(st.snd.n) && st.snext < st.peerMax {
		return true
	}
	return st.finQueued && !st.finSent && st.snext == st.finOff
}

// Write queues data for sending; it blocks while the unacknowledged buffer is full.
func (st *Stream) Write(b []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for len(b) > 0 {
		n := 0 // writeCap read once: the process budget it checks moves with every other session
		for st.err == nil && !st.finQueued {
			if n = st.writeCap() - st.snd.n; n > 0 {
				break
			}
			st.wc.Wait()
		}
		if st.err != nil {
			return total, st.err
		}
		if st.finQueued {
			return total, ErrClosed
		}
		if n > len(b) {
			n = len(b)
		}
		st.snd.write(b[:n])
		b = b[n:]
		total += n
		s.activate(st)
	}
	return total, nil
}

// sendCap is how many unacknowledged bytes Write may buffer: 4 MB, or what the peer has advertised beyond that
// (a peer that never advertises more than the implicit 4 MB window keeps exactly the old behaviour).
func (st *Stream) sendCap() int {
	if st.peerMax > st.sbase+sendBufMax {
		return int(min(st.peerMax-st.sbase, st.s.winCap))
	}
	return sendBufMax
}

// writeCap is sendCap, but at most sendStage beyond what the peer's window lets us send: while a slow reader keeps
// the peer's window shut, there is no point holding another 4 MB here (2.4.3; the local source refills fast).
// Over the process memory budget every stream holds at most sendStage (3.2.0: a server with 32 clients was OOM-killed
// at 2.7 GB of send buffers).
func (st *Stream) writeCap() int {
	if sndHeld.Load() > memBudget.Load() {
		return sendStage
	}
	room := 0
	if st.peerMax > st.sbase {
		room = int(min(st.peerMax-st.sbase, st.s.winCap))
	}
	return min(st.sendCap(), room+sendStage)
}

// tuneSlow shrinks the window this end advertises while the local reader, not the tunnel, sets the pace. A user on a
// slow last mile otherwise parks a full window (4 MB) here and as much again at the sender (field 2026-10-12: 180
// streams held ~700 MB on each end). Once per RTT: if unread data keeps piling up, the window becomes slowWinRTTs
// RTTs of what the reader actually consumed (at least slowWinMin); when the backlog runs dry it grows back by half. The
// advertised limit never moves back, updates just pause, so an older sender is unaffected (2.4.3).
func (st *Stream) tuneSlow(now time.Time) {
	if st.slowAt.IsZero() {
		st.slowAt, st.slowC = now, st.consumed
		return
	}
	rtt := max(st.s.cc.srtt, 5*time.Millisecond)
	el := now.Sub(st.slowAt)
	if el < rtt {
		return
	}
	used := st.consumed - st.slowC
	st.slowAt, st.slowC = now, st.consumed
	lim := st.win
	if st.slowWin > 0 {
		lim = st.slowWin
	}
	if st.rnext-st.consumed > lim/2 {
		w := max(uint64(float64(used)*float64(rtt)/float64(el))*slowWinRTTs, slowWinMin)
		st.slowWin = w
		if w >= st.win {
			st.slowWin = 0
		}
	} else if st.slowWin > 0 && st.rnext-st.consumed < lim/4 { // the reader is starving: open up again
		st.slowWin += st.slowWin / 2
		if st.slowWin >= st.win {
			st.slowWin = 0
		}
	}
}

// tuneWindow grows the window this end advertises (receiver-driven; the sender just honours frWindow). Once per
// RTT it looks at how much arrived: a sender that fills most of the window every RTT is window-limited, so the
// window doubles toward 2x the observed bytes per RTT (cap maxStreamWin per stream, maxSessionWin extra per session).
// A reader that lags (more than a quarter of the window unread) stops the growth. The advertised limit never moves
// back, so nothing already granted is refused.
func (st *Stream) tuneWindow(now time.Time) {
	s := st.s
	if s.noWinTune {
		return
	}
	if st.tuneAt.IsZero() {
		st.tuneAt, st.tuneRx = now, st.rnext
		return
	}
	rtt := s.cc.srtt
	if rtt < 5*time.Millisecond {
		rtt = 5 * time.Millisecond
	}
	if now.Sub(st.tuneAt) < rtt {
		return
	}
	got := st.rnext - st.tuneRx
	edge := st.tuneEdge
	st.tuneAt, st.tuneRx, st.tuneEdge = now, st.rnext, false
	// Grow when the sender filled half the window in one RTT, or when it ran into the advertised edge at all. The
	// second case is a lossy multi-connection path (2.4.18): one connection stalled in a TCP retransmit holds the
	// in-order point back while the others fill the window with out-of-order data, so in-order arrivals per RTT never
	// reach half the window and a 4 MB window capped one stream at ~18 MB/s on an emulated 100 MB/s path.
	if st.win >= s.winCap || (got < st.win/2 && !edge) || st.rnext-st.consumed > st.win/4 {
		return
	}
	nw := min(max(2*got, st.win), 2*st.win, s.winCap)
	if edge {
		nw = min(2*st.win, s.winCap)
	}
	if nw <= st.win || s.winExtra+(nw-st.win) > s.maxSessionWin || winHeld.Load()+int64(nw-st.win) > memBudget.Load() {
		return
	}
	s.winExtra += nw - st.win
	winHeld.Add(int64(nw - st.win))
	st.win = nw
}

// CloseWrite sends FIN: the peer's Read returns io.EOF after the buffered data.
func (st *Stream) CloseWrite() error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.err != nil {
		return st.err
	}
	if !st.finQueued {
		st.finQueued = true
		st.finOff = st.sbase + uint64(st.snd.n)
		s.activate(st)
	}
	return nil
}

// Read returns in-order bytes, io.EOF after the peer's FIN.
func (st *Stream) Read(b []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for st.ready.n == 0 && !st.eof && st.err == nil {
		st.rc.Wait()
	}
	if st.ready.n == 0 {
		if st.err != nil {
			return 0, st.err
		}
		st.maybeFinish()
		return 0, io.EOF
	}
	n := st.ready.read(b)
	st.releaseRx(n)
	st.consumed += uint64(n)
	now := time.Now()
	st.tuneWindow(now)
	st.tuneSlow(now)
	lim := st.win
	if st.slowWin > 0 {
		lim = st.slowWin
	}
	if st.consumed+lim > st.advMax && st.consumed+lim-st.advMax >= lim/4 {
		st.advMax = st.consumed + lim
		var f []byte
		f = append(f, frWindow)
		f = appendUv(f, st.id)
		f = appendUv(f, st.advMax)
		s.ctrl = append(s.ctrl, f)
		s.kick()
	}
	st.maybeFinish()
	return n, nil
}

// Reset aborts the stream in both directions.
func (st *Stream) Reset() {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.dead {
		return
	}
	var f []byte
	f = append(f, frRst)
	f = appendUv(f, st.id)
	s.ctrl = append(s.ctrl, f)
	s.kick()
	s.killStream(st, ErrReset)
}

func (s *Session) killStream(st *Stream, err error) {
	if st.dead {
		return
	}
	st.dead = true
	if extra := st.win - streamWindow; extra > 0 {
		if s.winExtra >= extra {
			s.winExtra -= extra
		} else {
			s.winExtra = 0
		}
		winHeld.Add(-int64(extra))
	}
	st.snd.reset()
	if st.err == nil {
		st.err = err
	}
	delete(s.streams, st.id)
	s.tomb[st.id] = s.now
	st.dropRxBuffers()
	st.rc.Broadcast()
	st.wc.Broadcast()
}

// CloseRead abandons the receive side. The bridge calls it once the local connection is gone: any buffered-but-unread
// data is dropped so it no longer blocks the stream from finishing, and if the peer is still sending (no FIN yet) the
// stream is reset to stop it. Without this a stream whose local reader stopped with data still buffered -- common when
// a client connection closes mid-transfer -- never satisfied maybeFinish's "ready drained" test and leaked (the Iran
// client held streams with no local TCP behind them; field 2026-10-13).
func (st *Stream) CloseRead() {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.dead || st.rdClosed {
		return
	}
	st.rdClosed = true
	st.dropRxBuffers()
	if !st.eof { // peer has not closed: we can take no more, so abort both directions
		var f []byte
		f = append(f, frRst)
		f = appendUv(f, st.id)
		s.ctrl = append(s.ctrl, f)
		s.kick()
		s.killStream(st, ErrReset)
		return
	}
	st.maybeFinish() // peer already finished: drop what is left and retire once our own FIN is acked
}

// maybeFinish retires a stream once both directions are complete and drained.
func (st *Stream) maybeFinish() {
	if st.dead || !st.finAcked || st.sbase != st.finOff || !st.eof || (!st.rdClosed && st.ready.n > 0) {
		return
	}
	s := st.s
	st.dead = true
	delete(s.streams, st.id)
	s.tomb[st.id] = s.now
	if extra := st.win - streamWindow; extra > 0 {
		if s.winExtra >= extra {
			s.winExtra -= extra
		} else {
			s.winExtra = 0
		}
		winHeld.Add(-int64(extra))
	}
	st.snd.reset()
	st.dropRxBuffers()
	st.rc.Broadcast()
	st.wc.Broadcast()
}

func (st *Stream) onAcked(f frameRef) {
	if f.n > 0 {
		st.acked.add(f.off, f.off+uint64(f.n))
		if len(st.acked) > 0 && st.acked[0].lo <= st.sbase && st.acked[0].hi > st.sbase {
			drop := st.acked[0].hi - st.sbase
			if drop > uint64(st.snd.n) {
				drop = uint64(st.snd.n)
			}
			st.snd.drop(int(drop)) // acked chunks go back to the pool at once: nothing to shrink or re-copy
			st.sbase += drop
			if st.acked[0].hi <= st.sbase {
				st.acked = append(st.acked[:0], st.acked[1:]...)
			}
			st.wc.Broadcast()
		}
	}
	if f.fin {
		st.finAcked = true
	}
	st.maybeFinish()
}

func (st *Stream) onLost(f frameRef) {
	if f.n > 0 && (st.acked.covered(f.off, f.off+uint64(f.n)) || f.off+uint64(f.n) <= st.sbase) {
		return
	}
	if f.n == 0 && f.fin && st.finAcked {
		return
	}
	st.retx = append(st.retx, f)
	st.s.activate(st)
}

func uvlen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// emit appends at most one frame to p. fit=false means the next frame does not fit the remaining room.
func (st *Stream) emit(p []byte, sp *sentPkt, room int) (np []byte, sent, fit bool) {
	hdr := 1 + uvlen(st.id) + 10 + 2
	for len(st.retx) > 0 {
		f := st.retx[0]
		if f.n > 0 && (st.acked.covered(f.off, f.off+uint64(f.n)) || f.off+uint64(f.n) <= st.sbase) {
			st.retx = st.retx[1:]
			continue
		}
		if f.n == 0 && f.fin && st.finAcked {
			st.retx = st.retx[1:]
			continue
		}
		off, n := f.off, f.n
		if off < st.sbase { // the front part was acked and freed meanwhile
			cut := int(st.sbase - off)
			off, n = st.sbase, n-cut
		}
		fin := f.fin
		if hdr+n > room {
			piece := room - hdr
			if piece <= 0 {
				return p, false, false
			}
			st.retx[0] = frameRef{sid: st.id, off: off + uint64(piece), n: n - piece, fin: f.fin}
			n = piece
			fin = false
		} else {
			st.retx = st.retx[1:]
		}
		p = st.appendFrame(p, off, n, fin)
		sp.frames = append(sp.frames, frameRef{st.id, off, n, fin})
		sp.rtx = true
		return p, true, true
	}
	end := st.sbase + uint64(st.snd.n)
	limit := end
	if st.peerMax < limit {
		limit = st.peerMax
	}
	if st.snext < limit {
		n := int(limit - st.snext)
		if n > room-hdr {
			n = room - hdr
		}
		if n <= 0 {
			return p, false, false
		}
		fin := st.finQueued && st.snext+uint64(n) == st.finOff
		off := st.snext
		p = st.appendFrame(p, off, n, fin)
		sp.frames = append(sp.frames, frameRef{st.id, off, n, fin})
		st.snext += uint64(n)
		st.sentTotal += uint64(n)
		st.cool(st.s.now)
		st.heat += float64(n)
		if fin {
			st.finSent = true
		}
		return p, true, true
	}
	if st.finQueued && !st.finSent && st.snext == st.finOff {
		if hdr > room {
			return p, false, false
		}
		p = st.appendFrame(p, st.snext, 0, true)
		sp.frames = append(sp.frames, frameRef{st.id, st.snext, 0, true})
		st.finSent = true
		return p, true, true
	}
	return p, false, true
}

func (st *Stream) appendFrame(p []byte, off uint64, n int, fin bool) []byte {
	t := byte(frStream)
	if fin {
		t = frStreamFin
	}
	p = append(p, t)
	p = appendUv(p, st.id)
	p = appendUv(p, off)
	p = appendUv(p, uint64(n))
	if n > 0 {
		p = st.snd.appendRange(p, int(off-st.sbase), n)
	}
	return p
}

// insert stores received bytes without overlap, then delivers whatever became contiguous.
func (st *Stream) insert(off uint64, data []byte) {
	if end := off + uint64(len(data)); end > st.rhigh {
		st.rhigh = end
		if end+st.win/8 >= st.advMax {
			st.tuneEdge = true
		}
	}
	if off == st.rnext && len(st.segs) == 0 && len(data) > 0 { // in order, nothing buffered: no copy into a segment first
		st.holdRx(len(data))
		st.appendReady(data)
		st.rnext += uint64(len(data))
		data = nil
	}
	for len(data) > 0 {
		if off < st.rnext {
			skip := st.rnext - off
			if skip >= uint64(len(data)) {
				break
			}
			data, off = data[skip:], off+skip
			continue
		}
		i := sort.Search(len(st.segs), func(i int) bool { return st.segs[i].off+uint64(len(st.segs[i].data)) > off })
		if i < len(st.segs) && st.segs[i].off <= off {
			skip := st.segs[i].off + uint64(len(st.segs[i].data)) - off
			if skip >= uint64(len(data)) {
				break
			}
			data, off = data[skip:], off+skip
			continue
		}
		limit := uint64(len(data))
		if i < len(st.segs) && st.segs[i].off < off+limit {
			limit = st.segs[i].off - off
		}
		cp := append([]byte(nil), data[:limit]...)
		st.holdRx(len(cp))
		// Fast append: arrivals behind a hole usually ascend (retransmit stream order), so appending
		// skips the O(n) shift-insert that dominated the out-of-order path at a 4 MB window (audit
		// 2026-10-22); the shift stays for a true middle insert.
		if i == len(st.segs) {
			st.segs = append(st.segs, seg{off, cp})
		} else {
			st.segs = append(st.segs, seg{})
			copy(st.segs[i+1:], st.segs[i:])
			st.segs[i] = seg{off, cp}
		}
		data, off = data[limit:], off+limit
	}
	for len(st.segs) > 0 && st.segs[0].off == st.rnext {
		st.appendReady(st.segs[0].data)
		st.rnext += uint64(len(st.segs[0].data))
		st.segs[0].data = nil
		st.segs = st.segs[1:]
	}
	if len(st.segs) == 0 {
		st.segs = st.segs[:0]
	}
	if st.peerFin && st.rnext == st.peerFinO {
		st.eof = true
	}
	st.rc.Broadcast()
	st.maybeFinish()
}

// SetGroup puts the stream into a fair-queue group (the public port it serves). Bulk streams of different groups get
// equal shares of the link; streams in one group share that group's share. The default group is 0.
func (st *Stream) SetGroup(g uint32) {
	s := st.s
	s.mu.Lock()
	st.group = g
	s.mu.Unlock()
}

// appendReady adds in-order bytes for Read.
func (st *Stream) appendReady(data []byte) { st.ready.write(data) }

// holdRx charges bytes stored for Read against the process receive budget (session.go rxRoom).
func (st *Stream) holdRx(n int) { rxHeld.Add(int64(n)) }

// releaseRx returns the bytes Read consumed; by construction it never takes rxHeld below zero.
func (st *Stream) releaseRx(n int) { rxHeld.Add(-int64(n)) }

// dropRxBuffers frees everything the receive side still holds and returns its bytes to the process budget. It is
// idempotent: a second call finds the buffers empty and releases nothing.
func (st *Stream) dropRxBuffers() {
	n := st.ready.n
	for _, sg := range st.segs {
		n += len(sg.data)
	}
	rxHeld.Add(-int64(n))
	st.ready.reset()
	st.segs = nil
}

// rdQueue holds received in-order bytes as a queue of pooled 64 KB chunks (2.5.1). It was one contiguous slice that
// was dropped after each drain and re-grown by doubling, with the unread bytes moved to the front whenever the end
// was reached: on the Iran end of a download those copies, the zeroing of the new arrays and the GC behind them were
// ~25 % of the tunnel's CPU (field profile 2026-10-16, 16 streams). Now each byte is copied once in and once out, no
// array grows, and a drained or idle stream holds no memory.
type rdQueue struct {
	ch []*[rdChunk]byte
	r  int // read offset in ch[0]
	w  int // write offset in the last chunk
	n  int // unread bytes
}

const rdChunk = 64 << 10

var rdPool = sync.Pool{New: func() any { return new([rdChunk]byte) }}

func (q *rdQueue) write(p []byte) {
	for len(p) > 0 {
		if len(q.ch) == 0 || q.w == rdChunk {
			q.ch = append(q.ch, rdPool.Get().(*[rdChunk]byte))
			q.w = 0
		}
		c := copy(q.ch[len(q.ch)-1][q.w:], p)
		q.w += c
		q.n += c
		p = p[c:]
	}
}

func (q *rdQueue) read(b []byte) int {
	t := 0
	for t < len(b) && q.n > 0 {
		end := rdChunk
		if len(q.ch) == 1 {
			end = q.w
		}
		c := copy(b[t:], q.ch[0][q.r:end])
		t += c
		q.r += c
		q.n -= c
		if q.r == end {
			if len(q.ch) == 1 { // drained: keep nothing
				q.reset()
				break
			}
			rdPool.Put(q.ch[0])
			q.ch[0] = nil
			q.ch = q.ch[1:]
			q.r = 0
		}
	}
	return t
}

func (q *rdQueue) reset() {
	for _, c := range q.ch {
		if c != nil {
			rdPool.Put(c)
		}
	}
	clear(q.ch)
	*q = rdQueue{ch: q.ch[:0]}
}

// prioHalfLife is how fast a stream's recent volume decays when the scheduler sorts interactive from bulk (3.0.0).
// Before, a stream was interactive until it had sent prioBytes in its whole life, so a long-lived forwarded connection
// (a VPN inbound with mux, carrying one user's every flow) turned bulk within seconds and its game or ping packets
// queued behind downloads for good. Now a stream is bulk while it sends more than ~prioBytes per 1.4 s, about 44 KB/s
// steady, and turns interactive again a few seconds after it goes quiet. A fresh stream still turns bulk after its
// first prioBytes, as before.
const prioHalfLife = time.Second

// cool decays heat to now and returns it.
func (st *Stream) cool(now time.Time) float64 {
	if dt := now.Sub(st.heatAt); dt > 0 {
		st.heat *= math.Exp2(-dt.Seconds() / prioHalfLife.Seconds())
		st.heatAt = now
	}
	return st.heat
}

// bulky: the stream sent prioBytes or more recently (it goes to the fair-queued bulk class, not the interactive one).
func (st *Stream) bulky(now time.Time) bool { return st.cool(now) >= prioBytes }

// sndQueue holds a stream's unacknowledged bytes as pooled 64 KB chunks (3.2.0), like rdQueue on the receive side.
// It was one contiguous slice grown by doubling to twice the send cap and moved to the front as acks freed it: 28 %
// of the sending end's CPU in memmove and 7 % zeroing new arrays (2 Gbit/s field profile 2026-11-03), and 2x the
// window per stream held in memory plus the garbage of every array it outgrew.
type sndQueue struct {
	ch []*[rdChunk]byte
	r  int // offset of the first held byte in ch[0]
	n  int // bytes held
}

func (q *sndQueue) write(p []byte) {
	sndHeld.Add(int64(len(p)))
	for len(p) > 0 {
		e := q.r + q.n
		i, o := e/rdChunk, e%rdChunk
		if i == len(q.ch) {
			q.ch = append(q.ch, rdPool.Get().(*[rdChunk]byte))
		}
		c := copy(q.ch[i][o:], p)
		q.n += c
		p = p[c:]
	}
}

func (q *sndQueue) drop(k int) {
	k = min(k, q.n)
	sndHeld.Add(-int64(k))
	q.r += k
	q.n -= k
	if q.n == 0 {
		q.release()
		return
	}
	for q.r >= rdChunk {
		rdPool.Put(q.ch[0])
		q.ch[0] = nil
		q.ch = q.ch[1:]
		q.r -= rdChunk
	}
}

// appendRange appends k held bytes starting off bytes after the first one.
func (q *sndQueue) appendRange(p []byte, off, k int) []byte {
	pos := q.r + off
	for k > 0 {
		i, o := pos/rdChunk, pos%rdChunk
		c := min(k, rdChunk-o)
		p = append(p, q.ch[i][o:o+c]...)
		pos += c
		k -= c
	}
	return p
}

func (q *sndQueue) reset() {
	sndHeld.Add(-int64(q.n))
	q.release()
}

func (q *sndQueue) release() {
	for _, c := range q.ch {
		if c != nil {
			rdPool.Put(c)
		}
	}
	clear(q.ch)
	*q = sndQueue{ch: q.ch[:0]}
}

// Process-wide memory accounting (3.2.0): send bytes held by every stream of every session, and the receive-window
// growth granted beyond the 4 MB bases. Neither grows past memBudget (SetMemBudget; default an eighth of the RAM).
var sndHeld, winHeld, memBudget atomic.Int64

// rxHeld is received stream data buffered for Read (ready plus out-of-order segments) across every session. The base
// windows are deliberately not charged: 4 MB x 8192 streams would exhaust the budget on windows alone, while only the
// bytes actually stored can grow with a peer that ignores backpressure (session.go rxRoom gates them).
var rxHeld atomic.Int64

func init() { memBudget.Store(defaultMemBudget(HostProfile().TotalRAMMB)) }

func defaultMemBudget(ramMB int) int64 {
	if ramMB <= 0 {
		return 256 << 20
	}
	return max(int64(ramMB)<<20/8, 64<<20)
}

// SetMemBudget sets the process budget for stream buffers in bytes (0 = default: an eighth of the RAM).
func SetMemBudget(b int64) {
	if b <= 0 {
		b = defaultMemBudget(HostProfile().TotalRAMMB)
	}
	memBudget.Store(b)
}
