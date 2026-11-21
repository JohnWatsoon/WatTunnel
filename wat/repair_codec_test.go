package wat

// Codec-level tests of repair: synthetic sessions, no network. Data plaintexts are frPad packets (parse
// stops at the pad harmlessly), so what is under test is symbol build -> chunk -> stitch -> GF(2) solve ->
// recovered plaintext, independent of the transport.

import (
	"bytes"
	"testing"
	"time"
)

// bareRepairSession: a Session with just the fields buildChunks/onRepair touch.
func bareRepairSession(every int) *Session {
	s := &Session{maxPlain: 1350}
	s.replayWin, s.ackMax, s.rxKeep, s.ackEvery = 1024, 20, 64, 6
	s.rxRing = make([]uint64, s.replayWin)
	s.cfg.RepairAsk = true // the ask tests exercise the v2 path; the codec tests below never emit asks
	s.repair = newRepair()
	s.repair.peerOK = true
	s.repair.every = every
	return s
}

func padPacket(n int, fill byte) []byte {
	p := []byte{frPad, byte(n)}
	for i := 0; i < n; i++ {
		p = append(p, fill)
	}
	return p
}

// feed drains the sender's queue into the receiver, one chunk at a time, dropping the chunks named in lost.
func feed(t *testing.T, tx, rx *Session, lost map[int]bool) {
	t.Helper()
	k := tx.repair.k
	tx.repair.k++
	tx.repair.buildChunks(tx, k)
	for i, q := range tx.repair.queue {
		if lost[i] {
			continue
		}
		r := &reader{b: q}
		if r.byte() != frRepair {
			t.Fatalf("chunk %d: expected frRepair, got %#x", i, q[0])
		}
		rx.onRepair(r, time.Now(), nil)
	}
	tx.repair.queue = nil
}

// deliver: the rx path's bookkeeping for a packet that arrived normally.
func deliver(rx *Session, pn uint64, p []byte) {
	rx.rxRing[pn%rx.replayWin] = pn + 1
	if !rx.rxAny || pn > rx.rxLargest {
		rx.rxLargest, rx.rxAny, rx.rxAt = pn, true, time.Now()
	}
	rx.rxRanges.add(pn, pn+1)
	rx.repairKeep(pn, p)
}

func runCodec(t *testing.T, drops []uint64, syms int) {
	t.Helper()
	tx := bareRepairSession(1)
	rx := bareRepairSession(1)
	const N = 34
	drop := map[uint64]bool{}
	for _, d := range drops {
		drop[d] = true
	}
	var sent [N][]byte
	for pn := uint64(0); pn < N; pn++ {
		p := padPacket(40+int(pn%5)*300, byte('a'+pn%26)) // mixed sizes, none full
		sent[pn] = p
		tx.repairNoteSent(pn, p)
		if !drop[pn] {
			deliver(rx, pn, p)
		}
		if pn%4 == 3 { // a symbol every few packets: every drop stays inside some window
			feed(t, tx, rx, nil)
		}
	}
	for i := 0; i < syms; i++ {
		feed(t, tx, rx, nil)
	}
	if got := rx.stats.RepairRecovered; got != uint64(len(drops)) {
		t.Fatalf("recovered=%d, want %d (drops %v)", got, len(drops), drops)
	}
	for _, d := range drops {
		if rx.rxRing[d%rx.replayWin] != d+1 {
			t.Fatalf("drop %d not marked received", d)
		}
		e := rx.repair.rx[d%repairWin]
		if e.pn != d || !bytes.Equal(e.buf, sent[d]) {
			t.Fatalf("drop %d: recovered plaintext mismatch (pn=%d len=%d want len=%d)", d, e.pn, len(e.buf), len(sent[d]))
		}
	}
}

func TestRepairCodecSingleLoss(t *testing.T) {
	for _, d := range []uint64{3, 17, 31} { // slot-unique drops: pn d+32 stays out of the test range so the ring entry is not overwritten
		runCodec(t, []uint64{d}, 8)
	}
}

// two losses need two covering equations: several symbols jointly must solve them
func TestRepairCodecDoubleLoss(t *testing.T) {
	for _, drops := range [][]uint64{{5, 9}, {17, 18}, {2, 28}} {
		runCodec(t, drops, 12)
	}
}

// a lost chunk kills its symbol: with one symbol dropped the rest must still recover a single loss
func TestRepairCodecLostChunk(t *testing.T) {
	tx := bareRepairSession(1)
	rx := bareRepairSession(1)
	const N = 34
	var sent [N][]byte
	for pn := uint64(0); pn < N; pn++ {
		p := padPacket(1340, 'x') // L at the budget edge -> multi-chunk symbols
		sent[pn] = p
		tx.repairNoteSent(pn, p)
		if pn != 20 {
			deliver(rx, pn, p)
		}
		if pn%4 == 3 {
			feed(t, tx, rx, map[int]bool{0: true}) // every symbol loses its first chunk
		}
	}
	if got := rx.stats.RepairRecovered; got != 0 {
		t.Fatalf("symbols with a lost chunk recovered %d; they must decode nothing", got)
	}
	// now let symbols through whole: that single loss still recovers
	for i := 0; i < 4; i++ {
		feed(t, tx, rx, nil)
	}
	if got := rx.stats.RepairRecovered; got != 1 {
		t.Fatalf("recovered=%d after intact symbols, want 1", got)
	}
	e := rx.repair.rx[20%repairWin]
	if e.pn != 20 || !bytes.Equal(e.buf, sent[20]) {
		t.Fatal("recovered plaintext mismatch")
	}
}

// drainQueue delivers the queued chunks WITHOUT building a new symbol (feed builds one per call).
func drainQueue(t *testing.T, tx, rx *Session) {
	t.Helper()
	for _, q := range tx.repair.queue {
		r := &reader{b: q}
		if r.byte() != frRepair {
			t.Fatalf("queued chunk is %#x, expected frRepair", q[0])
		}
		rx.onRepair(r, time.Now(), nil)
	}
	tx.repair.queue = nil
}

// --- v2 ask layer (Config.RepairAsk) ---

// frRepairAsk round-trips through append/parse, up to the 8-pn ceiling; 0 and 9 pns are refused.
func TestRepairAskCodec(t *testing.T) {
	pns := []uint64{3, 900, 1 << 63}
	r := &reader{b: appendRepairAsk(nil, pns)}
	if r.byte() != frRepairAsk {
		t.Fatalf("expected frRepairAsk, got %#x", r.b[0])
	}
	got := parseRepairAsk(r)
	if r.err != nil || len(got) != len(pns) {
		t.Fatalf("parse: err=%v got=%v", r.err, got)
	}
	for i := range pns {
		if got[i] != pns[i] {
			t.Fatalf("pn[%d]=%d, want %d", i, got[i], pns[i])
		}
	}
	for _, bad := range []int{0, 9} {
		p := append([]byte{frRepairAsk}, byte(bad))
		for i := 0; i < bad; i++ {
			p = appendUv(p, uint64(i))
		}
		rr := &reader{b: p}
		if x := parseRepairAsk(rr); x != nil || rr.err == nil {
			t.Fatalf("n=%d accepted (%v)", bad, x)
		}
	}
}

// askCoverK finds, within its bound, a k covering every asked pn — deterministically.
func TestRepairAskCoverSearch(t *testing.T) {
	for _, set := range [][]uint64{{5}, {5, 9}, {0, 17, 33}, {1 << 63, 1<<63 + 9, 1<<63 + 20}} {
		k, ok := askCoverK(set, 0)
		if !ok {
			t.Fatalf("set %v: no covering k within the bound", set)
		}
		for _, pn := range set {
			if !repairCover(pn, k) {
				t.Fatalf("set %v: k=%d does not cover pn %d", set, k, pn)
			}
		}
		if k2, _ := askCoverK(set, 0); k2 != k {
			t.Fatalf("search not deterministic: %d then %d", k, k2)
		}
	}
	// the search starts at `from`, so a repeated ask gets a NEW equation, not a repeat
	k1, _ := askCoverK([]uint64{7}, 0)
	k2, _ := askCoverK([]uint64{7}, k1+1)
	if k2 <= k1 {
		t.Fatalf("second search returned k=%d after k=%d", k2, k1)
	}
}

// the ask throttle: at most one frRepairAsk per 40 ms, each hole at most twice, holes younger than 4
// received packets never asked.
func TestRepairAskThrottle(t *testing.T) {
	rx := bareRepairSession(1)
	rx.cfg.RepairAsk = true
	for pn := uint64(0); pn < 12; pn++ {
		if pn != 3 && pn != 7 { // holes at 3 and 7; rxLargest ends at 11, so 3 is old, 7 is exactly 4 back (too young)
			deliver(rx, pn, padPacket(40, 'a'))
		}
	}
	now := time.Now()
	rx.repair.askAt = now // pretend an ask just went out: the throttle must hold
	if p := rx.repairAskDue(nil, now.Add(10*time.Millisecond)); p != nil {
		t.Fatal("ask emitted inside the 40 ms window")
	}
	if p := rx.repairAskDue(nil, now.Add(41*time.Millisecond)); p == nil {
		t.Fatal("no ask after the window")
	} else {
		r := &reader{b: p}
		r.byte()
		if got := parseRepairAsk(r); len(got) != 1 || got[0] != 3 {
			t.Fatalf("ask pns = %v, want [3] (7 is too young)", got)
		}
	}
	// age hole 7 by receiving more, then ask it twice: the third time it must be dropped
	for pn := uint64(12); pn < 16; pn++ {
		deliver(rx, pn, padPacket(40, 'a'))
	}
	if rx.repair.askN[3] != 1 {
		t.Fatalf("hole 3 asked %d times, want 1", rx.repair.askN[3])
	}
	rx.repair.askAt = now // window open again (the throttle compares against the passed time)
	rx.repairNoteHoles()  // the queue is rebuilt on receive; emulate the next packet's arrival
	rx.repairAskDue(nil, now.Add(41*time.Millisecond))
	rx.repair.askAt = now
	rx.repairNoteHoles()
	rx.repairAskDue(nil, now.Add(41*time.Millisecond))
	if rx.repair.askN[7] != 2 {
		t.Fatalf("hole 7 asked %d times, want 2", rx.repair.askN[7])
	}
	rx.repair.askAt = now
	rx.repairNoteHoles()
	if p := rx.repairAskDue(nil, now.Add(41*time.Millisecond)); p != nil {
		t.Fatal("ask emitted with every hole already asked twice")
	}
}

// targeted symbols rebuild holes through the ordinary chunk/stitch/solve path. One ask = ONE symbol, and a
// cover-all symbol over e holes is ONE GF(2) equation, so a two-hole ask alone cannot isolate (that is the
// design's accepted limit — the ask layer rides ON TOP of the periodic symbols, whose varied masks complete
// the rank); a single-hole ask recovers outright. The periodic schedule stays untouched by the asks.
func TestRepairAskTargetedRoundTrip(t *testing.T) {
	tx := bareRepairSession(1 << 30) // periodic symbols never due: isolate the ask path
	rx := bareRepairSession(1)
	const N = 40
	for pn := uint64(0); pn < N; pn++ {
		p := padPacket(120+int(pn)%3*200, byte('a'+pn%26))
		tx.repairNoteSent(pn, p)
		if pn != 20 {
			deliver(rx, pn, p)
		}
	}
	pend0 := tx.repair.pending
	tx.repairOnAsk([]uint64{20})
	if len(tx.repair.queue) == 0 {
		t.Fatal("no targeted symbol queued")
	}
	drainQueue(t, tx, rx)
	if got := rx.stats.RepairRecovered; got != 1 {
		t.Fatalf("recovered=%d after a single-hole targeted symbol, want 1", got)
	}
	if rx.rxRing[20%rx.replayWin] != 21 {
		t.Fatal("hole 20 not marked received")
	}
	if tx.repair.pending != pend0 || tx.repair.every != 1<<30 {
		t.Fatalf("ask disturbed the periodic schedule: pending=%d (was %d) every=%d", tx.repair.pending, pend0, tx.repair.every)
	}
	// two holes: the cover-all ask is one equation over two unknowns — recovered only once a periodic symbol
	// with a separating mask arrives (the joint solve uses it together with the targeted row)
	tx2 := bareRepairSession(1 << 30)
	rx2 := bareRepairSession(1)
	for pn := uint64(0); pn < N; pn++ {
		p := padPacket(120+int(pn)%3*200, byte('b'+pn%26))
		tx2.repairNoteSent(pn, p)
		if pn != 20 && pn != 25 {
			deliver(rx2, pn, p)
		}
	}
	tx2.repairOnAsk([]uint64{20, 25})
	drainQueue(t, tx2, rx2)
	if got := rx2.stats.RepairRecovered; got != 0 {
		t.Fatalf("one cover-all symbol recovered %d holes; one equation cannot isolate two unknowns", got)
	}
	for i := 0; i < 20 && rx2.stats.RepairRecovered < 2; i++ {
		feed(t, tx2, rx2, nil) // periodic symbols: masks vary, one separates within a few
	}
	if got := rx2.stats.RepairRecovered; got != 2 {
		t.Fatalf("recovered=%d after the targeted row plus periodic symbols, want 2", got)
	}
	// a hole aged out of the ask retention ring (or never sent) is skipped, not answered
	tx2.repairOnAsk([]uint64{5000})
	if len(tx2.repair.queue) != 0 || tx2.repair.askMiss != 1 {
		t.Fatalf("stale ask answered: queue=%d miss=%d", len(tx2.repair.queue), tx2.repair.askMiss)
	}
}
