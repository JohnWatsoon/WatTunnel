package wat

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// R3 Hornet-MTU (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md,
// disposition table). Hornet itself (multi-IP ICMP striping, reply amplification) is rejected/split; what survives
// is the question: "consider live MTU adaptation independently: lower MTU during transfer, verify integrity,
// bounded recovery and return to the larger size."
//
// The scenario it models: an ISP clamps a path's payload mid-download (measured on live Iran paths: ICMP above
// ~668 B vanishes while small pings pass). The sender must shrink its packets without resetting any stream, keep
// the transfer flowing (bounded stall), and later return to the larger size when the clamp lifts.
//
// The engine has no production API for this yet (maxPlain is fixed at NewSession; the old carrier plan assumed a
// SetMaxPayload that never existed). The mutator below is the experiment: it edits s.maxPlain + s.cc.maxPlain
// under s.mu, which is safe by construction - build() sizes packets from maxPlain (smaller is always wire-legal),
// plainBuf/out buffers are scratch append handles, and a receiver accepts smaller packets without any signal.
// If the experiment passes, a real design review decides the production shape (a frame-flagged clamp the peer
// mirrors, not a silent local edit).
//
// Production shape (3.3.9, -mtu-adapt, approved): the review replaced the draft's frMtu frame with a SENDER-SIDE
// clamp — no wire signal at all, each end watches its OWN send-path losses (PathLossSizer → pathSet.onLossSized)
// and caps its own datagrams on that path (PathClamp consulted by Session.build). The tests at the bottom cover
// the production detector and its build()-side sizing; the tests above stay as the experiment that proved the
// mechanism (a live maxPlain change, wire-legal in the same way).

// sessionSetMaxPayload changes a live session's packet payload ceiling. TEST-ONLY (see above).
func sessionSetMaxPayload(s *Session, payload int) {
	s.mu.Lock()
	s.maxPlain = payload - overhead
	s.cc.maxPlain = s.maxPlain
	s.mu.Unlock()
}

// hornetPair is a sim pair whose links accept full 1400 B payload packets (the shared newPair caps at 700 B, the
// ICMP-path model, which would drop every 1400 B packet before the experiment even starts).
func hornetPair(t *testing.T, cfg Config) (cli, srv *Session) {
	up := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 1, 1500)
	down := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 2, 1500)
	key := []byte("hornet-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	var err error
	cli, err = NewSession(cc, &simIO{up, down, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(sc, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// TestHornetMTUShrinkRecovers: a bulk download over the sim link (1400 B packets); mid-transfer the sender's
// payload ceiling drops to 640 B, later returns to 1400 B. Requirements: data arrives byte-intact, the stall at
// each switch is bounded (no reset, < 2 s), the on-wire packet size follows the ceiling down and back up.
func TestHornetMTUShrinkRecovers(t *testing.T) {
	cli, srv := hornetPair(t, Config{MaxPayload: 1400})
	const n = 24 << 20
	data := pattern(n, 9)
	done := make(chan error, 1)
	var got []byte
	go func() {
		st, err := srv.Accept()
		if err != nil {
			done <- err
			return
		}
		b, err := readAll(st)
		got = b
		done <- err
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()

	// The data sender here is the CLIENT (upload scenario); its outgoing average packet size is the metric.
	// (The server's PktsOut is mostly small ACKs and would hide the effect.)
	time.Sleep(1 * time.Second)
	full0 := cli.Stats()
	avgBefore := float64(full0.BytesOut) / float64(max(full0.PktsOut, 1))

	// shrink mid-transfer on the data sender
	sessionSetMaxPayload(cli, 640)
	time.Sleep(1 * time.Second)
	shrunk := cli.Stats()
	avgShrunk := float64(shrunk.BytesOut-full0.BytesOut) / float64(max(shrunk.PktsOut-full0.PktsOut, 1))

	// return to the larger size
	sessionSetMaxPayload(cli, 1400)
	time.Sleep(1 * time.Second)
	back := cli.Stats()
	avgBack := float64(back.BytesOut-shrunk.BytesOut) / float64(max(back.PktsOut-shrunk.PktsOut, 1))

	t.Logf("avg packet bytes: full %.0f, shrunk %.0f, back %.0f (client pkts %d, bytes %.1f MB)",
		avgBefore, avgShrunk, avgBack, back.PktsOut, float64(back.BytesOut)/1e6)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed across the MTU changes: %v", err)
		}
		if len(got) != n {
			t.Fatalf("short download: %d of %d", len(got), n)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("data corrupted across the MTU changes")
		}
	case <-time.After(120 * time.Second):
		t.Fatal("download timed out across the MTU changes")
	}

	// the wire followed the ceiling: full-size before, ~640-sized during the clamp, full-size after
	if avgBefore < 1200 {
		t.Fatalf("pre-shrink packets averaged %.0f B, expected near-full 1400 B packets", avgBefore)
	}
	if avgShrunk > 800 {
		t.Fatalf("shrunken packets averaged %.0f B, want ~640 B on the wire", avgShrunk)
	}
	if avgBack < 1200 {
		t.Fatalf("post-grow packets averaged %.0f B, want the full size back", avgBack)
	}
}

// TestHornetMTUSmallSurvivesClamp: the clamp scenario's other half - SMALL interactive exchanges keep flowing
// while a bulk transfer is shrunken, i.e. the shrink does not stall the interactive path. Streams are
// opcode-prefixed: 'E' = echo 4 bytes back, 'D' = bulk upload the server just reads.
func TestHornetMTUSmallSurvivesClamp(t *testing.T) {
	cli, srv := hornetPair(t, Config{MaxPayload: 1400})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func(st *Stream) {
				var op [1]byte
				if _, err := readFull(st, op[:]); err != nil {
					return
				}
				if op[0] == 'E' {
					var b [4]byte
					if _, err := readFull(st, b[:]); err != nil {
						return
					}
					st.Write(b[:])
					st.CloseWrite()
					return
				}
				readAll(st) // 'D': bulk upload, nothing echoed
			}(st)
		}
	}()

	bulk, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	bulk.Write([]byte{'D'})
	bulk.Write(pattern(16<<20, 3))
	bulk.CloseWrite()
	time.Sleep(300 * time.Millisecond)

	sessionSetMaxPayload(cli, 640) // clamp hits while the interactive exchanges run
	var worst time.Duration
	for i := 0; i < 20; i++ {
		st, _ := cli.OpenStream()
		t0 := time.Now()
		st.Write([]byte{'E', 'e', 'c', 'h', 'o'})
		buf := make([]byte, 4)
		readFull(st, buf)
		if d := time.Since(t0); d > worst {
			worst = d
		}
		st.CloseWrite()
		time.Sleep(20 * time.Millisecond)
	}
	sessionSetMaxPayload(cli, 1400)
	t.Logf("20 x 4 B exchanges during the clamp: worst %v", worst.Round(time.Millisecond))
	if worst > 2*time.Second {
		t.Fatalf("an interactive exchange took %v during the clamp", worst)
	}
}

// ---- production shape (3.3.9): the sender-side Hornet-MTU clamp (-mtu-adapt, default off) ----
//
// The review's approved shape differs from the experiment above: no frMtu frame, no receiver detector. Each end
// counts ITS OWN send-path losses (PathLossSizer: the session reports the lost packet's wire size), and after
// hornetLosses consecutive losses of packets bigger than hornetBigPkt it caps that path's datagrams at
// hornetClampPayload for hornetClampHold — then retries full size, re-clamping if the signature persists. The
// whole detector lives in pathSet behind PathTimings.MtuAdapt: without -mtu-adapt it is dead code and every
// path sizes exactly as before.

// TestHornetDetectorClampsBigLosses: the detector unit — 8 consecutive >512 B losses engage the clamp, one ack
// or one small loss resets the run, an active clamp holds until its deadline, expiry re-arms the detector, and
// with MtuAdapt off nothing happens at all.
func TestHornetDetectorClampsBigLosses(t *testing.T) {
	ps := newPathSet([]string{"udp"}, true, PathTimings{MtuAdapt: true}, false)
	big := 1400 + tagLen + ipIcmpHdr // sentPkt.size for a full-size 1400 B datagram

	for i := 0; i < hornetLosses-1; i++ {
		ps.onLossSized(0, big)
	}
	if got := ps.clampOf(0); got != 0 {
		t.Fatalf("clamp engaged after %d big losses (want 0)", hornetLosses-1)
	}
	ps.onLossSized(0, big) // the 8th consecutive big loss
	if got := ps.clampOf(0); got != hornetClampPayload {
		t.Fatalf("PathClamp after %d big losses = %d, want %d", hornetLosses, got, hornetClampPayload)
	}

	// an ack resets the RUN (and would have stopped the count earlier) but not an ACTIVE clamp
	ps.mu.Lock()
	run := ps.p[0].lostBig
	ps.mu.Unlock()
	if run != 0 {
		t.Fatalf("lostBig = %d at clamp time, want 0 (one clamp per signature)", run)
	}
	ps.onLossSized(0, big)
	ps.mu.Lock()
	run = ps.p[0].lostBig
	ps.mu.Unlock()
	if run != 1 {
		t.Fatalf("a big loss during the clamp did not count (lostBig %d)", run)
	}
	ps.onAck(0, 20*time.Millisecond)
	ps.mu.Lock()
	run = ps.p[0].lostBig
	ps.mu.Unlock()
	if run != 0 {
		t.Fatalf("an ack did not reset the run (lostBig %d)", run)
	}
	if got := ps.clampOf(0); got != hornetClampPayload {
		t.Fatalf("clamp must persist until its deadline even after acks, got %d", got)
	}

	// a small loss resets the run too: small packets passing is what makes this the clamp signature
	ps.onLossSized(0, big)
	ps.onLossSized(0, 200)
	ps.mu.Lock()
	run = ps.p[0].lostBig
	ps.mu.Unlock()
	if run != 0 {
		t.Fatalf("a small loss did not reset the run (lostBig %d)", run)
	}

	// expiry: past the hold the path is unclamped and the detector re-fires on a persistent signature
	ps.mu.Lock()
	ps.p[0].clampUntil = time.Now().Add(-time.Second)
	ps.mu.Unlock()
	if got := ps.clampOf(0); got != 0 {
		t.Fatalf("clamp did not expire (got %d)", got)
	}
	for i := 0; i < hornetLosses; i++ {
		ps.onLossSized(0, big)
	}
	if got := ps.clampOf(0); got != hornetClampPayload {
		t.Fatalf("detector did not re-fire after expiry (got %d)", got)
	}

	// and with -mtu-adapt off the whole thing is dead code
	off := newPathSet([]string{"udp"}, true, PathTimings{}, false)
	for i := 0; i < hornetLosses*3; i++ {
		off.onLossSized(0, big)
	}
	if got := off.clampOf(0); got != 0 {
		t.Fatalf("clamp ran with MtuAdapt off (got %d)", got)
	}
}

// hornetBondPair is the hornetPair rig with the CLIENT end behind the production bond machinery: the sim links
// are size-blind, so the honest way to exercise the production clamp is a real session over a real bond
// (PathLossSizer/PathClamp wired exactly as in production), with the detector driven through the same seam the
// session itself calls when it declares a packet lost. The server stays a plain sim session: it is the client's
// send path the test clamps (upload scenario, the experiment's setup).
func hornetBondPair(t *testing.T, cfg Config, mtuAdapt bool) (cli, srv *Session, bnd *BondIO) {
	up := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 1, 1500)
	down := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 2, 1500)
	key := []byte("hornet-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	bnd, err := NewBondIO([]PacketIO{&simIO{up, down, make(chan struct{}), sync.Once{}}},
		BondOptions{Timings: PathTimings{MtuAdapt: mtuAdapt}})
	if err != nil {
		t.Fatal(err)
	}
	cli, err = NewSession(cc, bnd)
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(sc, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// TestHornetAdaptClampsAndRecovers: a bulk upload (the client sends data) with -mtu-adapt on; the detector fires
// through the production seam mid-transfer and the wire follows the clamp down, then returns to full size when
// the hold expires. Data arrives byte-intact throughout — the clamp resizes packets, never streams.
func TestHornetAdaptClampsAndRecovers(t *testing.T) {
	cli, srv, bnd := hornetBondPair(t, Config{MaxPayload: 1400}, true)
	const n = 48 << 20
	data := pattern(n, 9)
	done := make(chan error, 1)
	var got []byte
	go func() {
		st, err := srv.Accept()
		if err != nil {
			done <- err
			return
		}
		b, err := readAll(st)
		got = b
		done <- err
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()

	time.Sleep(1 * time.Second)
	full := cli.Stats()
	avgBefore := float64(full.BytesOut) / float64(max(full.PktsOut, 1))

	// drive the detector exactly as the session's loss path does (lose() -> PathLossSizer.OnLossSized): the sim
	// links are size-blind, so the signature is injected at the interface seam, not dropped on the wire
	big := 1400 + tagLen + ipIcmpHdr
	for i := 0; i < hornetLosses; i++ {
		bnd.OnLossSized(0, big)
	}
	if c := bnd.PathClamp(0); c != hornetClampPayload {
		t.Fatalf("clamp did not engage (got %d)", c)
	}
	time.Sleep(1 * time.Second)
	shrunk := cli.Stats()
	avgShrunk := float64(shrunk.BytesOut-full.BytesOut) / float64(max(shrunk.PktsOut-full.PktsOut, 1))

	// expire the hold the way 30 s would: the sender returns to full size on its own (self-retrying, no canary)
	bnd.ps.mu.Lock()
	bnd.ps.p[0].clampUntil = time.Now().Add(-time.Second)
	bnd.ps.mu.Unlock()
	time.Sleep(1 * time.Second)
	back := cli.Stats()
	avgBack := float64(back.BytesOut-shrunk.BytesOut) / float64(max(back.PktsOut-shrunk.PktsOut, 1))

	t.Logf("avg packet bytes: full %.0f, clamped %.0f, back %.0f (client pkts %d, bytes %.1f MB)",
		avgBefore, avgShrunk, avgBack, back.PktsOut, float64(back.BytesOut)/1e6)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transfer failed across the clamp: %v", err)
		}
		if len(got) != n {
			t.Fatalf("short transfer: %d of %d", len(got), n)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("data corrupted across the clamp")
		}
	case <-time.After(120 * time.Second):
		t.Fatal("transfer timed out across the clamp")
	}

	if avgBefore < 1200 {
		t.Fatalf("pre-clamp packets averaged %.0f B, expected near-full 1400 B packets", avgBefore)
	}
	if avgShrunk > 800 {
		t.Fatalf("clamped packets averaged %.0f B, want ~640 B on the wire", avgShrunk)
	}
	if avgBack < 1200 {
		t.Fatalf("post-expiry packets averaged %.0f B, want the full size back", avgBack)
	}
}
