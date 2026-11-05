package wat

import (
	"bytes"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"
)

// Every possible single loss inside a random group is rebuilt byte-exactly and the data reaches the stream.
func TestFecReconstruct(t *testing.T) {
	// up is the server's receive direction: parity is injected through its channel so the session's
	// own recvLoop handles it (a direct rcv.handle would race the recvLoop under -race; simDir.send
	// would drop it — parity packets exceed the simulated 700 B link cap).
	snd, rcv, up, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	// The receiver only keeps plaintexts while parity is arriving (F11 receiver side); this test injects parity after
	// the data it covers, so open the ring by hand for the whole run.
	rcv.mu.Lock()
	rcv.fec.keep = time.Now().Add(time.Hour)
	rcv.mu.Unlock()
	rnd := rand.New(rand.NewSource(5))
	for trial := 0; trial < 60; trial++ {
		n := 1 + rnd.Intn(fecMaxK)
		miss := rnd.Intn(n)
		sid := uint64(trial + 1)
		pn0 := uint64(10000 + trial*100)
		var want []byte
		var plains [][]byte
		off := 0
		for i := 0; i < n; i++ {
			d := pattern(1+rnd.Intn(500), byte(trial*7+i))
			want = append(want, d...)
			typ := byte(frStream)
			if i == n-1 {
				typ = frStreamFin
			}
			p := append([]byte{typ}, appendUv(appendUv(appendUv(nil, sid), uint64(off)), uint64(len(d)))...)
			plains = append(plains, append(p, d...))
			off += len(d)
		}
		snd.mu.Lock()
		snd.cc.tokens = 1e9
		snd.fec.loss = 0.001   // k = 16: the whole group is covered
		snd.fec.gate.on = true // F11: this test drives fecDue directly, so its loss gate is opened by hand
		var sealed [][]byte
		for i, p := range plains {
			snd.nextPN = pn0 + uint64(i*2) // gaps in the pn sequence, like acks-only packets in between
			pkt, pn := snd.seal(p)
			sealed = append(sealed, append([]byte(nil), pkt...))
			snd.fecNoteSent(pn, p)
		}
		snd.nextPN = pn0 + uint64(2*n) // the parity pn must sit near the covered ones (replay window)
		o, ok := snd.fecDue(time.Now())
		snd.mu.Unlock()
		if !ok {
			t.Fatal("no parity built")
		}
		parity := append([]byte(nil), o.p...)
		for i, pkt := range sealed { // through rcv's own recvLoop: its rx state is recvLoop-owned (no lock on the dup check)
			if i != miss {
				up.out <- pkt
			}
		}
		up.out <- parity
		st, err := rcv.Accept()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := readAll(st)
		if !bytes.Equal(got, want) {
			t.Fatalf("trial %d (n=%d miss=%d): rebuilt stream differs (%d vs %d bytes)", trial, n, miss, len(got), len(want))
		}
	}
	if r := rcv.Stats().FecRecovered; r != 60 {
		t.Fatalf("recovered %d of 60", r)
	}
	if snd.Stats().FecSent != 60 {
		t.Fatalf("sent %d parity packets", snd.Stats().FecSent)
	}
}

// Two missing packets in one group cannot be rebuilt (and must not corrupt anything).
func TestFecTwoMissing(t *testing.T) {
	snd, rcv, up, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	var sealed [][]byte
	snd.mu.Lock()
	snd.cc.tokens = 1e9
	snd.fec.gate.on = true // F11: this test drives fecDue directly, so its loss gate is opened by hand
	snd.nextPN = 500
	for i := 0; i < 4; i++ {
		p := append([]byte{frStream, 1, byte(i * 10), 10}, pattern(10, byte(i))...)
		pkt, pn := snd.seal(p)
		sealed = append(sealed, append([]byte(nil), pkt...))
		snd.fecNoteSent(pn, p)
	}
	o, _ := snd.fecDue(time.Now())
	parity := append([]byte(nil), o.p...)
	snd.mu.Unlock()
	n0 := rcv.Stats().PktsIn
	up.out <- sealed[0] // packets 1 and 2 are lost; same injection route as TestFecReconstruct
	up.out <- sealed[3]
	up.out <- parity
	deadline := time.Now().Add(5 * time.Second)
	for rcv.Stats().PktsIn < n0+3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r := rcv.Stats().FecRecovered; r != 0 {
		t.Fatalf("recovered %d with two packets missing", r)
	}
}

// F33 (audit 2026-11-04): a Config.FEC caller that leaves both loss-gate thresholds at zero keeps the documented
// pre-3.3.0 behavior, and that includes the FIRST group: no gate means no time window, so a loss there is rebuilt.
// With thresholds set the gate starts closed and the first group is not kept (TestFecRxKeepFollowsParity).
func TestFecZeroThresholdFirstGroup(t *testing.T) {
	snd, rcv, up, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	const n, miss = 4, 1
	var want []byte
	plains := make([][]byte, n)
	off := 0
	for i := 0; i < n; i++ {
		d := pattern(50+i*30, byte(i))
		want = append(want, d...)
		typ := byte(frStream)
		if i == n-1 {
			typ = frStreamFin
		}
		p := append([]byte{typ}, appendUv(appendUv(appendUv(nil, 1), uint64(off)), uint64(len(d)))...)
		plains[i] = append(p, d...)
		off += len(d)
	}
	snd.mu.Lock()
	snd.cc.tokens = 1e9
	// Zero thresholds: this first fecDue steps the gate open, exactly as the pump does before the first burst. The
	// gate is deliberately not opened by hand here (unlike TestFecReconstruct/TestFecTwoMissing).
	if _, ok := snd.fecDue(time.Now()); ok {
		snd.mu.Unlock()
		t.Fatal("parity built with nothing noted")
	}
	var sealed [][]byte
	for i, p := range plains {
		snd.nextPN = 1000 + uint64(i*2)
		pkt, pn := snd.seal(p)
		sealed = append(sealed, append([]byte(nil), pkt...))
		snd.fecNoteSent(pn, p)
	}
	snd.nextPN = 1000 + uint64(2*n)
	o, ok := snd.fecDue(time.Now())
	snd.mu.Unlock()
	if !ok {
		t.Fatal("zero thresholds: no parity built for the first group")
	}
	for i, pkt := range sealed {
		if i != miss {
			up.out <- pkt // the first burst's loss reaches the receiver before any parity, as on the wire
		}
	}
	up.out <- append([]byte(nil), o.p...)
	st, err := rcv.Accept()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	go func() { b, _ := readAll(st); got <- b }()
	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Fatalf("first group: rebuilt stream differs (%d vs %d bytes)", len(b), len(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first-group loss was never rebuilt: the receive window was not seeded")
	}
	if r := rcv.Stats().FecRecovered; r != 1 {
		t.Fatalf("first-group loss rebuilt %d packets, want 1", r)
	}
}

// F34 (audit 2026-11-04): -shape-data + FEC. fecNoteSent only covers plaintexts up to maxPlain-fecHdrMax, so
// shapeData caps its padding target for FEC sessions; every padded packet must stay inside the ring.
func TestFecShapeDataCovered(t *testing.T) {
	snd, _, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true, ShapeData: 0.25, MaxPayload: 640})
	snd.mu.Lock()
	defer snd.mu.Unlock()
	cover := snd.maxPlain - fecHdrMax
	base := pattern(200, 1)
	snd.fec.gate.on = true // this test calls shapeData/fecNoteSent directly, so the gate is opened by hand
	var padded int
	for i := 0; i < 500; i++ {
		p := snd.shapeData(1000, append([]byte(nil), base...))
		if len(p) == len(base) {
			continue
		}
		padded++
		if len(p) > cover {
			t.Fatalf("a %d-byte padded packet exceeds the FEC line %d", len(p), cover)
		}
		snd.fec.txN = 0 // the ring holds at most fecMaxK entries; reset so "noted" is unambiguous per packet
		snd.fecNoteSent(uint64(i+1), p)
		if snd.fec.txN == 0 {
			t.Fatalf("a %d-byte padded packet (FEC line %d) was not noted", len(p), cover)
		}
	}
	if padded == 0 {
		t.Fatal("shapeData never padded: the draw changed")
	}
}

// F33 follow-up (audit fix review): a zero-threshold gate has no time window, so a long quiet gap must not lose
// the next first group (the old one-shot seed did).
func TestFecZeroThresholdKeepsAfterQuiet(t *testing.T) {
	_, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	rcv.fec.keep = time.Now().Add(-time.Hour) // the old seed would have expired
	p := pattern(200, 1)
	rcv.fecKeep(1, p, time.Now())
	if got := rcv.fec.rx[1%fecRing].pn; got != 2 {
		t.Fatalf("zero-threshold FEC dropped a plaintext after a quiet gap (rx pn=%d, want 2)", got)
	}
}

// F11 receiver side (3.3.0): the reconstruction ring follows the peer's parity. No frFec for fecKeepAfter means no
// plaintext copies (the peer's gate is closed, nothing will be rebuilt); the next frFec re-opens the ring. Thresholds
// are set here on purpose: the zero-threshold case keeps by design (TestFecZeroThresholdFirstGroup).
func TestFecRxKeepFollowsParity(t *testing.T) {
	_, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true, FECOnLoss: 0.02, FECOffLoss: 0.005})
	now := time.Now()
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	// no parity seen yet: a received plaintext must not be copied
	rcv.fecKeep(7, pattern(100, 1), now)
	if rcv.fec.rx[7%fecRing].pn != 0 {
		t.Fatal("kept a plaintext before any parity arrived")
	}
	// one frFec (n=1, covers pn 0, parity length 100) re-opens the ring; it repairs nothing here (no stored group)
	frame := appendUv(appendUv(appendUv(appendUv(nil, 1), 0), 0), 100)
	frame = append(frame, make([]byte, 100)...)
	if rcv.onFec(&reader{b: frame}, now) {
		t.Fatal("an unreconstructable parity frame must not be ack-eliciting")
	}
	if !rcv.fec.keep.After(now) {
		t.Fatal("frFec did not re-open the receive ring")
	}
	rcv.fecKeep(7, pattern(100, 2), now)
	if e := &rcv.fec.rx[7%fecRing]; e.pn != 8 || len(e.buf) != 100 {
		t.Fatalf("plaintext not kept after parity: pn=%d len=%d", e.pn, len(e.buf))
	}
	// and it closes again after fecKeepAfter without parity
	rcv.fec.keep = now
	rcv.fecKeep(9, pattern(100, 3), now.Add(fecKeepAfter+time.Second))
	if rcv.fec.rx[9%fecRing].pn != 0 {
		t.Fatal("kept a plaintext after the parity window lapsed")
	}
}

// k shrinks as the observed loss rises.
func TestFecAdaptiveK(t *testing.T) {
	f := newFec()
	for i := 0; i < 5000; i++ {
		f.onAck()
	}
	if f.k() != fecMaxK {
		t.Fatalf("clean link: k=%d", f.k())
	}
	for i := 0; i < 5000; i++ {
		if i%10 == 0 {
			f.onLoss()
		} else {
			f.onAck()
		}
	}
	if f.k() != fecMinK {
		t.Fatalf("10%% loss: k=%d", f.k())
	}
}

// F11 (3.3.0): the loss gate opens above the on threshold, closes below the off threshold, holds every decision for
// the minimum dwell, and stays put anywhere in the band between them.
func TestFecGateHysteresis(t *testing.T) {
	g := fecGate{onLoss: 0.02, offLoss: 0.005, dwell: fecMinDwell}
	t0 := time.Unix(1000, 0)
	for _, c := range []struct {
		name string
		at   time.Duration // since t0
		loss float64
		want bool
	}{
		{"healthy start stays off", 0, 0.01, false},                  // first decision, no dwell yet
		{"spike opens the gate", 100 * time.Millisecond, 0.03, true}, // immediate: nothing to hold yet
		{"dwell holds it on", 500 * time.Millisecond, 0.001, true},   // below off, but 0.4 s < dwell
		{"dwell over closes it", 2500 * time.Millisecond, 0.001, false},
		{"dwell holds it off", 3 * time.Second, 0.05, false},           // 0.5 s after closing
		{"still held off", 4400 * time.Millisecond, 0.05, false},       // 1.9 s after closing
		{"opens after the dwell", 4600 * time.Millisecond, 0.05, true}, // 2.1 s after closing
		{"band keeps it on", 7 * time.Second, 0.01, true},              // above off, below on: no change
		{"band keeps it on too", 9 * time.Second, 0.019, true},         // right under the on threshold
		{"below off closes it", 11 * time.Second, 0.004, false},        // dwell long over
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := g.step(c.loss, t0.Add(c.at)); got != c.want {
				t.Fatalf("at %v loss %.3f: gate %v, want %v", c.at, c.loss, got, c.want)
			}
		})
	}
}

// F11 (3.3.0): a wat.Config caller that sets only FEC (zero thresholds) keeps the pre-gate behavior: parity for every
// burst. cmd/wattun always passes real thresholds.
func TestFecGateZeroThresholdsAlwaysOn(t *testing.T) {
	g := fecGate{dwell: fecMinDwell}
	now := time.Unix(1000, 0)
	if !g.step(fecInitLoss, now) {
		t.Fatal("zero thresholds must open the gate at the initial loss estimate")
	}
	if !g.step(0, now.Add(time.Hour)) {
		t.Fatal("zero thresholds must never close the gate")
	}
}

// F11 (3.3.0): when the gate closes with a burst half-noted, the pending group is dropped: a stale txN would keep
// busy() true and the pump spinning at 1 ms forever.
func TestFecGateCloseDropsPendingGroup(t *testing.T) {
	snd, _, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true, FECOnLoss: 0.02, FECOffLoss: 0.005})
	snd.mu.Lock()
	defer snd.mu.Unlock()
	snd.cc.tokens = 1e9
	snd.fec.gate.on = true // opened by hand, as in TestFecReconstruct
	p := append([]byte{frStream, 1, 0, 10}, pattern(10, 1)...)
	_, pn := snd.seal(p)
	snd.fecNoteSent(pn, p)
	if snd.fec.txN == 0 {
		t.Fatal("no packet noted for the next parity")
	}
	snd.fec.loss = 0.001 // below the off threshold: the next step must close the gate
	if _, ok := snd.fecDue(time.Now()); ok {
		t.Fatal("built parity with the gate closed")
	}
	if snd.fec.txN != 0 {
		t.Fatalf("pending group kept (%d packets): busy() would spin the pump", snd.fec.txN)
	}
}

// 3 flights per exchange, each a single small packet each way: a loss costs a PTO without FEC.
func fecExchanges(t *testing.T, fec bool, n int) (lat []time.Duration, cli, srv Stats) {
	return fecExchangesAt(t, 0.02, Config{FEC: fec}, n)
}

// fecExchangesAt is fecExchanges over a link with the given loss and session config.
func fecExchangesAt(t *testing.T, loss float64, cfg Config, n int) (lat []time.Duration, cli, srv Stats) {
	c, s, _, _ := newPair(t, loss, 20*time.Millisecond, 10e6, cfg)
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 200)
				for {
					if _, err := readFull(st, buf); err != nil {
						return
					}
					st.Write(buf)
				}
			}()
		}
	}()
	buf := make([]byte, 200)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		st, _ := c.OpenStream()
		for f := 0; f < 3; f++ {
			st.Write(pattern(200, byte(i)))
			if _, err := readFull(st, buf); err != nil {
				t.Error(err)
				return
			}
		}
		lat = append(lat, time.Since(t0))
		st.CloseWrite()
	}
	return lat, c.Stats(), s.Stats()
}

func readFull(st *Stream, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := st.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func pct(lat []time.Duration, p float64) time.Duration {
	l := append([]time.Duration(nil), lat...)
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return l[int(float64(len(l)-1)*p)]
}

func TestFecTailLatency(t *testing.T) {
	var wg sync.WaitGroup
	var off, on []time.Duration
	var onC, onS, offC, offS Stats
	wg.Add(2)
	go func() { defer wg.Done(); off, offC, offS = fecExchanges(t, false, 200) }()
	go func() { defer wg.Done(); on, onC, onS = fecExchanges(t, true, 200) }()
	wg.Wait()
	if len(off) != 200 || len(on) != 200 {
		t.Fatal("incomplete run")
	}
	p95off, p95on := pct(off, 0.95), pct(on, 0.95)
	t.Logf("200 x 3-flight exchanges at 2%% loss: p50 off=%v on=%v  p95 off=%v on=%v  p99 off=%v on=%v  fec sent=%d recovered=%d",
		pct(off, .5), pct(on, .5), p95off, p95on, pct(off, .99), pct(on, .99), onC.FecSent+onS.FecSent, onC.FecRecovered+onS.FecRecovered)
	if offC.FecSent+offS.FecSent != 0 {
		t.Fatal("fec off sent parity")
	}
	if onC.FecRecovered+onS.FecRecovered == 0 {
		t.Fatal("fec on recovered nothing")
	}
	if float64(p95on) > 0.8*float64(p95off) {
		t.Fatalf("p95 with fec %v is not >= 20%% below %v", p95on, p95off)
	}
}

// F11 (3.3.0): with the thresholds cmd/wattun passes (2 % on, 0.5 % off), a healthy link sends no parity at all while
// a really lossy link opens the gate; /stats' fec_state follows the gate.
func TestFecGateThresholds(t *testing.T) {
	gate := Config{FEC: true, FECOnLoss: 0.02, FECOffLoss: 0.005}
	_, cleanC, cleanS := fecExchangesAt(t, 0, gate, 60)
	if n := cleanC.FecSent + cleanS.FecSent; n != 0 {
		t.Fatalf("clean link: sent %d parity packets, want 0", n)
	}
	if cleanC.FecState != "off" || cleanS.FecState != "off" {
		t.Fatalf("clean link: fec_state %q/%q, want off/off", cleanC.FecState, cleanS.FecState)
	}
	_, lossyC, lossyS := fecExchangesAt(t, 0.10, gate, 60)
	if n := lossyC.FecSent + lossyS.FecSent; n == 0 {
		t.Fatal("10 % loss: the gate never opened, no parity sent")
	}
	if lossyC.FecState != "on" && lossyS.FecState != "on" {
		t.Fatalf("10 %% loss: fec_state %q/%q, want on on at least one side", lossyC.FecState, lossyS.FecState)
	}
}

func fecUpload(t *testing.T, fec bool) (float64, Stats) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{FEC: fec})
	data := pattern(24<<20, 7)
	got := make(chan int, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			got <- -1
			return
		}
		b, _ := readAll(st)
		got <- len(b)
	}()
	st, _ := cli.OpenStream()
	t0 := time.Now()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case n := <-got:
		if n != len(data) {
			t.Fatalf("got %d bytes", n)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
	return float64(len(data)) / time.Since(t0).Seconds() / 1e6, cli.Stats()
}

func TestFecBulkThroughput(t *testing.T) {
	var off, on float64
	var st Stats
	for round := 0; round < 2; round++ { // interleaved, best of two: the sim is timing-noisy
		o, _ := fecUpload(t, false)
		n, s := fecUpload(t, true)
		off, on, st = max(off, o), max(on, n), s
	}
	t.Logf("bulk upload 2%% loss: off=%.2f MB/s on=%.2f MB/s, parity packets %d of %d", off, on, st.FecSent, st.PktsOut)
	if on < 0.95*off {
		t.Fatalf("fec bulk %.2f MB/s is more than 5%% below off %.2f", on, off)
	}
	if float64(st.FecSent) > 0.05*float64(st.PktsOut) {
		t.Fatalf("parity overhead %d of %d packets", st.FecSent, st.PktsOut)
	}
}

// TestFecLenOverflow: a crafted parity frame with a length varint >= 2^63 wraps to a negative int;
// before the audit fix the guard only rejected lens > len(parity), so rec[:lens[miss]] panicked on
// the missing slot and one malformed frame killed the process.
func TestFecLenOverflow(t *testing.T) {
	snd, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	defer snd.Close()
	defer rcv.Close()
	frame := appendUv(appendUv(appendUv(appendUv(nil, 1), 0), 0), 1<<63) // n=1 base=0 pn+0 len=2^63
	frame = append(frame, 0xAA)                                          // 1 byte of parity
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	r := &reader{b: frame}
	if rcv.onFec(r, time.Now()) {
		t.Fatal("overflow length must not repair anything")
	}
	if r.err == nil {
		t.Fatal("overflow length must mark the reader bad")
	}
}
