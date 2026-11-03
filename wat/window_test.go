package wat

import (
	"crypto/sha256"
	"runtime"
	"testing"
	"time"
)

// oneStreamDown runs one server->client stream over a lossless 150 ms RTT link and returns its MB/s.
func oneStreamDown(t *testing.T, oldReceiver bool, mb int) float64 {
	cfg := Config{InitBps: 40e6, MaxBps: 40e6}
	cli, srv, _, _ := newPair(t, 0, 75*time.Millisecond, 40e6, cfg)
	cli.noWinTune = oldReceiver
	for _, x := range []*Session{cli, srv} { // an unsampled path assumes a 120 ms loss timer; a 150 ms RTT needs a first sample
		x.mu.Lock()
		x.cc.srtt, x.cc.rttvar = 150*time.Millisecond, 10*time.Millisecond
		x.mu.Unlock()
	}
	data := pattern(mb<<20, 5)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		st.Write(data)
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte{1})
	st.CloseWrite()
	t0 := time.Now()
	done := make(chan []byte, 1)
	go func() { b, _ := readAll(st); done <- b }()
	select {
	case b := <-done:
		el := time.Since(t0)
		if sha256.Sum256(b) != sha256.Sum256(data) {
			t.Fatalf("data mismatch: got %d want %d bytes", len(b), len(data))
		}
		mbps := float64(len(data)) / el.Seconds() / 1e6
		t.Logf("old=%v: %.1f MB/s in %v (4 MB/RTT = %.1f MB/s)", oldReceiver, mbps, el.Round(time.Millisecond), 4.194304/0.150)
		return mbps
	case <-time.After(90 * time.Second):
		t.Fatal("timeout")
	}
	return 0
}

// A receiver that auto-tunes its window lets one stream go well past 4 MB per RTT; a peer that never advertises
// more than the implicit 4 MB window keeps exactly the old limit (and still works with a new sender).
func TestStreamWindowAutoTune(t *testing.T) {
	old := oneStreamDown(t, true, 96)
	nw := oneStreamDown(t, false, 96)
	if raceBuild {
		return
	}
	if old > 4.194304/0.150*1.15 {
		t.Fatalf("old-peer stream exceeded its 4 MB window: %.1f MB/s", old)
	}
	if nw < old*1.3 {
		t.Fatalf("auto-tuned window did not help: %.1f vs %.1f MB/s", nw, old)
	}
}

// Config.WinMax bounds the window this end advertises per stream, which is what caps the peer's sender buffering.
// 0 keeps the old 16 MB default; the value is clamped into [streamWindow, maxStreamWin], because it is a memory
// bound for a small VPS and not a way to grow past the default.
func TestWinMaxClamped(t *testing.T) {
	for _, c := range []struct{ in, want uint64 }{
		{0, HostProfile().WinCap}, // unset: exactly the old behaviour
		{1 << 20, streamWindow},   // below the base pins the window at 4 MB, it does not shrink it
		{5 << 20, 5 << 20},        // in range: used as given
		{100 << 20, 64 << 20},     // above the 64 MB ceiling: clamped down
	} {
		cli, srv, _, _ := newPair(t, 0, time.Millisecond, 40e6, Config{WinMax: c.in})
		if cli.winCap != c.want || srv.winCap != c.want {
			t.Fatalf("WinMax=%d: winCap client=%d server=%d, want %d", c.in, cli.winCap, srv.winCap, c.want)
		}
	}
}

// The cap must actually hold during a transfer (tuneWindow grows the window every RTT and stops only at winCap), and
// capping it must not corrupt or truncate the stream. st.win only ever grows, so its final value is the maximum it
// advertised at any point.
func TestWinMaxHoldsUnderTransfer(t *testing.T) {
	const wc = 5 << 20
	cfg := Config{InitBps: 40e6, MaxBps: 40e6, WinMax: wc}
	cli, srv, _, _ := newPair(t, 0, 75*time.Millisecond, 40e6, cfg)
	for _, x := range []*Session{cli, srv} { // a 150 ms RTT needs a first sample, as in oneStreamDown
		x.mu.Lock()
		x.cc.srtt, x.cc.rttvar = 150*time.Millisecond, 10*time.Millisecond
		x.mu.Unlock()
	}
	data := pattern(32<<20, 9)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		st.Write(data)
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte{1})
	st.CloseWrite()
	done := make(chan []byte, 1)
	go func() { b, _ := readAll(st); done <- b }()
	select {
	case b := <-done:
		if sha256.Sum256(b) != sha256.Sum256(data) {
			t.Fatalf("capped window corrupted the stream: got %d bytes, want %d", len(b), len(data))
		}
	case <-time.After(90 * time.Second):
		t.Fatal("timeout")
	}
	cli.mu.Lock()
	win := st.win
	cli.mu.Unlock()
	if win > wc {
		t.Fatalf("advertised window grew past WinMax: %d > %d", win, wc)
	}
	if win < streamWindow {
		t.Fatalf("advertised window fell below the base: %d < %d", win, streamWindow)
	}
	t.Logf("32 MB delivered, window held at %.2f MB (cap %.2f MB, default %.2f MB)",
		float64(win)/1e6, float64(wc)/1e6, float64(maxStreamWin)/1e6)
}

// A reader slower than the tunnel (a user on a slow last mile) must not park a full 4 MB window at the receiver and
// another 4 MB at the sender: field 2026-10-12, 180 such streams held ~700 MB on each end (2.4.3).
func TestSlowReaderBuffersBounded(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0, 75*time.Millisecond, 40e6, Config{InitBps: 40e6, MaxBps: 40e6})
	for _, x := range []*Session{cli, srv} {
		x.mu.Lock()
		x.cc.srtt, x.cc.rttvar = 150*time.Millisecond, 10*time.Millisecond
		x.mu.Unlock()
	}
	var sst *Stream
	got := make(chan *Stream, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		got <- st
		st.Write(pattern(64<<20, 7))
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte{1})
	sst = <-got
	buf := make([]byte, 32<<10)
	t0 := time.Now()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	next := time.Second
	for time.Since(t0) < 8*time.Second { // ~1-2 MB/s
		st.Read(buf)
		time.Sleep(16 * time.Millisecond)
		if time.Since(t0) > next {
			next += time.Second
			cli.mu.Lock()
			t.Logf("t=%v unread %.2f MB win %.2f MB ready %.2f", time.Since(t0).Round(time.Second), float64(st.rnext-st.consumed)/1e6, float64(st.slowWin)/1e6, float64(st.ready.n)/1e6)
			cli.mu.Unlock()
		}
	}
	cli.mu.Lock()
	unread := st.rnext - st.consumed
	cli.mu.Unlock()
	srv.mu.Lock()
	held, capb := sst.snd.n, len(sst.snd.ch)*rdChunk
	srv.mu.Unlock()
	t.Logf("receiver unread %.2f MB, sender buffered %.2f MB (cap %.2f MB)", float64(unread)/1e6, float64(held)/1e6, float64(capb)/1e6)
	runtime.ReadMemStats(&m1)
	if a := m1.TotalAlloc - m0.TotalAlloc; a > 1<<30 { // 2.4.3 re-copied the send buffer on every ack: ~6.6 GB here
		t.Fatalf("buffer churn: %d MB allocated while ~16 MB were read", a>>20)
	}
	if unread > 2<<20 || held > 3<<20 || capb > 6<<20 {
		t.Fatalf("slow reader pins too much: unread %d, sender %d (cap %d)", unread, held, capb)
	}
}
