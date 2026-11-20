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
	tx.repair.buildChunks(tx)
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
