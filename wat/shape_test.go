package wat

// W7/F13 (3.3.0): opt-in traffic shaping. Data padding spends only the configured percent budget, never exceeds
// maxPlain, is framed as a last frPad2 (ignorable by older peers), and idle noise is budgeted, paced, idle-only and
// never counted as in-flight data.

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// echoLoop accepts every server stream and echoes it back.
func echoLoop(s *Session) {
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
}

// Data padding: framed as a last frPad2, inside maxPlain, randomized, and bounded by the percent budget plus the bank.
func TestShapeDataPad(t *testing.T) {
	snd, _, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{ShapeData: 0.25, MaxPayload: 640})
	snd.mu.Lock()
	defer snd.mu.Unlock()
	base := pattern(200, 1)
	var totalData int
	sizes := map[int]bool{}
	for i := 0; i < 200; i++ {
		p := snd.shapeData(1000, append([]byte(nil), base...))
		totalData += 1000
		if len(p) > snd.maxPlain {
			t.Fatalf("padded packet %d bytes, maxPlain %d", len(p), snd.maxPlain)
		}
		if len(p) > len(base) {
			if p[len(base)] != frPad2 {
				t.Fatalf("the frame after the data is %#x, want frPad2", p[len(base)])
			}
			sizes[len(p)] = true
		}
		if got, limit := float64(snd.stats.PadBytes), 0.25*float64(totalData)+shapeDataBank; got > limit {
			t.Fatalf("%.0f padded bytes for %d data bytes, budget %.0f", got, totalData, limit)
		}
	}
	if snd.stats.PadBytes == 0 {
		t.Fatal("shape-data padded nothing")
	}
	if len(sizes) < 2 {
		t.Fatalf("padded sizes are not randomized: %v", sizes)
	}
	// A packet that already fills maxPlain gets no padding (and no overflow).
	full := pattern(snd.maxPlain, 2)
	if got := snd.shapeData(1000, append([]byte(nil), full...)); len(got) != len(full) {
		t.Fatalf("a full packet was padded to %d (maxPlain %d)", len(got), snd.maxPlain)
	}
}

// End to end: padded data still round-trips byte-exactly, and pads only data packets (idle control traffic never
// counts as PadBytes).
func TestShapeDataEndToEnd(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.01, 2*time.Millisecond, 10e6, Config{ShapeData: 0.25, MaxPayload: 1400})
	echoLoop(srv)
	time.Sleep(300 * time.Millisecond) // idle control traffic (pings/acks) must not be counted as data padding
	if got := cli.Stats().PadBytes; got != 0 {
		t.Fatalf("control-only packets counted as padded data: %d bytes", got)
	}
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := pattern(150, 9)
	for i := 0; i < 200; i++ {
		if _, err := st.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("message %d corrupted through padded packets", i)
		}
	}
	if got := cli.Stats().PadBytes; got == 0 {
		t.Fatal("small data packets were not padded at all")
	}
}

// A packet made only of frPad2 is not ack-eliciting and carries no user data; when one is placed before a stream
// frame (never by a 3.3.0 sender) parsing stops there, exactly as an older peer's unknown-type handling does.
func TestPad2Parse(t *testing.T) {
	_, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	streamFrame := append([]byte{frStream}, appendUv(appendUv(appendUv(nil, 1), 0), 3)...)
	streamFrame = append(streamFrame, 1, 2, 3)
	pad, _ := appendPad2(nil, 100)
	if rcv.parse(pad, time.Now()) {
		t.Fatal("a padding-only packet was ack-eliciting")
	}
	if len(rcv.streams) != 0 || len(rcv.ctrl) != 0 {
		t.Fatal("a padding-only packet created state")
	}
	// stream frame, then the padding frame last: delivered and ack-eliciting, padding ignored
	if !rcv.parse(append(append([]byte(nil), streamFrame...), pad...), time.Now()) {
		t.Fatal("a data packet with trailing padding was not ack-eliciting")
	}
	st := rcv.streams[1]
	if st == nil || st.rnext != 3 {
		t.Fatal("stream data before a last padding frame was not delivered")
	}
	// padding before a frame: nothing after it is parsed (the frame's own bytes stay unknown to this peer)
	if rcv.parse(append(append([]byte(nil), pad...), streamFrame...), time.Now()) {
		t.Fatal("a frame after padding was parsed")
	}
}

// The local-clock noise window: all day when unset, inclusive start, exclusive end, wrapping past midnight.
func TestNoiseWindow(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.Local) }
	for _, c := range []struct {
		name     string
		from, to int
		now      time.Time
		want     bool
	}{
		{"all day", 0, 0, at(3, 0), true},
		{"inside", 120, 360, at(2, 0), true},
		{"inside last minute", 120, 360, at(5, 59), true},
		{"at the end", 120, 360, at(6, 0), false},
		{"before", 120, 360, at(1, 59), false},
		{"wrap after midnight", 1320, 360, at(23, 30), true},
		{"wrap before dawn", 1320, 360, at(5, 0), true},
		{"wrap outside", 1320, 360, at(12, 0), false},
		{"ending at midnight", 1320, 0, at(23, 0), true},
		{"ending at midnight outside", 1320, 0, at(0, 30), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := noiseWindowOpen(c.now, c.from, c.to); got != c.want {
				t.Fatalf("noiseWindowOpen(%v, %d, %d) = %v, want %v", c.now.Format("15:04"), c.from, c.to, got, c.want)
			}
		})
	}
}

// Noise is only sent while user data is idle, and its wire bytes stay inside the configured bytes/second budget.
func TestNoiseBudget(t *testing.T) {
	snd, _, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{NoiseBps: 256})
	snd.mu.Lock()
	defer snd.mu.Unlock()
	if o, ok := snd.noiseDue(time.Now()); ok { // session just started: not idle yet
		t.Fatalf("noise sent while the session is fresh: %d bytes", len(o.p))
	}
	snd.cc.tokens = 1e9
	snd.lastUser = time.Now().Add(-time.Hour)
	t0 := time.Now()
	var wire uint64
	for i := 0; i < 600; i++ { // 60 s of simulated idle time
		if o, ok := snd.noiseDue(t0.Add(time.Duration(i) * 100 * time.Millisecond)); ok {
			wire += uint64(len(o.p))
		}
	}
	if wire == 0 {
		t.Fatal("no idle noise was sent")
	}
	if limit := 256*60 + 256 + uint64(snd.maxPlain); wire > limit {
		t.Fatalf("%d noise bytes in 60 s at 256 B/s, limit %d", wire, limit)
	}
	if got := snd.stats.NoiseBytes; got < wire {
		t.Fatalf("NoiseBytes %d is below the %d bytes of built noise", got, wire)
	}
	// The budget refills after the window: another simulated minute still produces noise.
	if _, ok := snd.noiseDue(t0.Add(61 * time.Minute)); !ok {
		t.Fatal("idle noise stopped for good after the first window")
	}
}

// Noise is paced and counted, but it is never in flight, never retransmitted, never stream data and not ack-eliciting
// for the receiver (the frPad2 frame is consumed and parsing stops).
func TestNoiseNotTracked(t *testing.T) {
	snd, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{NoiseBps: 256})
	snd.mu.Lock()
	snd.cc.tokens = 1e9
	snd.lastUser = time.Now().Add(-time.Hour)
	inflight, tracked, retrans := snd.inflight, len(snd.sent), snd.stats.Retrans
	noiseBefore, pktsBefore := snd.stats.NoiseSent, snd.stats.PktsOut
	t0 := time.Now()
	var o outPkt
	ok := false
	for i := 0; i < 100 && !ok; i++ { // the first packet needs one budget interval to fill
		o, ok = snd.noiseDue(t0.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	noiseAfter, pktsAfter := snd.stats.NoiseSent, snd.stats.PktsOut
	if snd.inflight != inflight || len(snd.sent) != tracked || snd.stats.Retrans != retrans {
		snd.mu.Unlock()
		t.Fatal("a noise packet was tracked as in-flight data")
	}
	snd.mu.Unlock()
	if !ok || len(o.p) == 0 {
		t.Fatal("no noise packet built")
	}
	if noiseAfter != noiseBefore+1 || pktsAfter != pktsBefore+1 {
		t.Fatalf("noise counters: NoiseSent %d->%d, PktsOut %d->%d", noiseBefore, noiseAfter, pktsBefore, pktsAfter)
	}
	// The receiver's parse: padding is consumed, nothing is delivered and nothing is ack-eliciting.
	noise, _ := appendPad2(nil, 100)
	rcv.mu.Lock()
	pend, streams, ctrl := rcv.ackPend, len(rcv.streams), len(rcv.ctrl)
	el := rcv.parse(noise, time.Now())
	afterPend, afterStreams, afterCtrl := rcv.ackPend, len(rcv.streams), len(rcv.ctrl)
	rcv.mu.Unlock()
	if el {
		t.Fatal("a padding-only packet was ack-eliciting")
	}
	if afterPend != pend || afterStreams != streams || afterCtrl != ctrl {
		t.Fatalf("a padding-only packet created receiver state (%d/%d/%d before, %d/%d/%d after)",
			pend, streams, ctrl, afterPend, afterStreams, afterCtrl)
	}
}

// End to end over the simulated link: an idle noise-enabled session sends filler, receives it, and still carries
// user data normally afterwards.
func TestNoiseEndToEnd(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{NoiseBps: 256, PingEvery: 300 * time.Millisecond})
	echoLoop(srv)
	deadline := time.Now().Add(5 * time.Second)
	for (cli.Stats().NoiseSent == 0 || srv.Stats().PktsIn == 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cli.Stats().NoiseSent == 0 {
		t.Fatal("idle session sent no noise")
	}
	if b := cli.Stats().NoiseBytes; b == 0 {
		t.Fatal("NoiseBytes is zero while NoiseSent is not")
	}
	echoOnce(t, cli, 20000, 5) // user traffic still flows after the noise started
}

// M14 (audit 2026-11-04): the pump's idle sleep is clamped to the noise deadline, so the delivered rate follows
// -noise-bps instead of the fixed 100 ms tick. Unit-level: the hint is 0 when noise cannot constrain the wake, the
// next-filler deadline when one is scheduled, and a real wait (never 0) when the byte budget is still filling.
func TestNoiseWake(t *testing.T) {
	now := time.Now()
	mk := func(bps float64, lastUser time.Time, budget float64) *Session {
		s := &Session{
			cfg:      Config{PingEvery: 50 * time.Millisecond, NoiseBps: bps},
			noise:    &noiseState{bps: bps, tokens: budget},
			cc:       newCC(1e7, 2e5, 1e8, 8*time.Millisecond),
			lanes:    []int{0},
			lastUser: lastUser,
		}
		s.cc.tokens = 1e9
		s.maxPlain = 600
		return s
	}
	idle := now.Add(-time.Second)
	if d := mk(10000, idle, 1e6).noiseWake(now); d < time.Millisecond || d > 2*time.Millisecond {
		t.Fatalf("due with a full budget: wake %v, want ~1ms", d)
	}
	if d := mk(10000, idle, 0).noiseWake(now); d <= 0 || d > 100*time.Millisecond {
		t.Fatalf("due with an empty budget: wake %v, want the ~10ms refill wait (never 0)", d)
	}
	s := mk(10000, idle, 1e6)
	s.noise.next = now.Add(7 * time.Millisecond)
	if d := s.noiseWake(now); d != 7*time.Millisecond {
		t.Fatalf("scheduled filler: wake %v, want 7ms", d)
	}
	if d := mk(10000, now, 1e6).noiseWake(now); d != 0 {
		t.Fatalf("busy session: wake %v, want 0", d)
	}
	s = mk(10000, idle, 1e6)
	s.held = true
	if d := s.noiseWake(now); d != 0 {
		t.Fatalf("held carrier: wake %v, want 0", d)
	}
	s = mk(10000, idle, 1e6)
	s.lanes = nil
	if d := s.noiseWake(now); d != 0 {
		t.Fatalf("no usable lane: wake %v, want 0 (the pump must not spin)", d)
	}
	s = mk(10000, idle, 1e6)
	s.noise = nil
	if d := s.noiseWake(now); d != 0 {
		t.Fatalf("noise off: wake %v, want 0", d)
	}
}

// M14 lower bound: an idle session configured with NoiseBps=10000 must deliver at least 80 % of it. The audit measured
// 8.6 KB/s at -noise-bps 100000 before the pump clamp; this window is well below the timer ceiling, so it catches a
// return to the 100 ms idle tick.
func TestNoiseDeliveredRate(t *testing.T) {
	const bps = 10000.0
	cli, _ := memPair(t, Config{MaxPayload: 640, NoiseBps: bps, PingEvery: 50 * time.Millisecond})
	time.Sleep(300 * time.Millisecond) // session come-up + the 2*PingEvery idle window
	b0 := cli.Stats().NoiseBytes
	t0 := time.Now()
	time.Sleep(2 * time.Second)
	dt := time.Since(t0).Seconds()
	rate := float64(cli.Stats().NoiseBytes-b0) / dt
	if rate < 0.8*bps {
		t.Fatalf("noise delivered %.0f B/s of the configured %.0f B/s (M14: pump cadence caps the rate)", rate, bps)
	}
	if rate > 1.25*bps {
		t.Fatalf("noise delivered %.0f B/s, above the configured budget %.0f B/s", rate, bps)
	}
}

// L2: the idle clock exists only for -noise. With noise off, user traffic must not touch s.lastUser; with it on, data
// must restart the clock.
func TestLastUserOnlyWithNoise(t *testing.T) {
	plain, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
	echoLoop(srv)
	echoOnce(t, plain, 2000, 3)
	plain.mu.Lock()
	lu := plain.lastUser
	plain.mu.Unlock()
	if !lu.IsZero() {
		t.Fatalf("noise off, but lastUser was written for user data: %v", lu)
	}
	noisy, srv2, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{NoiseBps: 256})
	echoLoop(srv2)
	echoOnce(t, noisy, 2000, 4)
	noisy.mu.Lock()
	lu2 := noisy.lastUser
	noisy.mu.Unlock()
	if lu2.IsZero() {
		t.Fatal("noise on, but user data did not restart the idle clock")
	}
}
