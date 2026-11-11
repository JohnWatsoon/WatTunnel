package wat

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fairShare runs a download of 8 bulk streams of port A and 1 of port B over a 4 MB/s link for a few seconds and
// returns B's share of the received bytes. grouped=false leaves every stream in group 0 (the old behaviour).
func fairShare(t *testing.T, grouped bool) float64 {
	cli, srv, _, _ := newPair(t, 0, 5*time.Millisecond, 4e6, Config{})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				var h [1]byte
				if _, err := st.Read(h[:]); err != nil {
					return
				}
				if grouped {
					st.SetGroup(uint32(h[0]))
				}
				buf := make([]byte, 16<<10)
				for {
					if _, err := st.Write(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	var got [2]atomic.Int64
	var wg sync.WaitGroup
	open := func(port byte) {
		st, err := cli.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		st.Write([]byte{port})
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32<<10)
			for {
				n, err := st.Read(buf)
				got[port-1].Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		open(1)
	}
	open(2)
	time.Sleep(2 * time.Second) // ramp-up and the interactive phase of every stream
	a0, b0 := got[0].Load(), got[1].Load()
	time.Sleep(5 * time.Second)
	a, b := got[0].Load()-a0, got[1].Load()-b0
	cli.Close()
	srv.Close()
	wg.Wait()
	return float64(b) / float64(a+b)
}

// One port's eight heavy downloads must not starve another port's single one: its share has to be near half.
func TestFairQueueBetweenPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("7 s")
	}
	share := fairShare(t, true)
	t.Logf("single-stream port share with fair queuing: %.0f%%", share*100)
	if share < 0.40 {
		t.Fatalf("single stream got %.0f%% of the bulk throughput, want >= 40%%", share*100)
	}
}

// Documents what the fair queue replaces: without groups the single stream gets about one ninth.
func TestFairQueueUngroupedIsPerStream(t *testing.T) {
	if testing.Short() {
		t.Skip("7 s")
	}
	share := fairShare(t, false)
	t.Logf("single-stream share without groups: %.0f%%", share*100)
	if share > 0.25 {
		t.Fatalf("ungrouped streams are no longer scheduled per stream: single got %.0f%%", share*100)
	}
}

func TestFairQueueUnit(t *testing.T) {
	var f fairQ
	mk := func(g uint32) *Stream { return &Stream{group: g} }
	a1, a2, a3, b1 := mk(1), mk(1), mk(1), mk(2)
	for _, st := range []*Stream{a1, a2, a3, b1} {
		f.push(st)
	}
	// equal charge per turn: groups alternate, streams of one group rotate
	var order []*Stream
	for i := 0; i < 6; i++ {
		st := f.pop()
		f.charge(st, 100)
		f.push(st)
		order = append(order, st)
	}
	nb := 0
	for _, st := range order {
		if st == b1 {
			nb++
		}
	}
	if nb != 3 {
		t.Fatalf("group 2 got %d of 6 turns, want 3", nb)
	}
	if f.n != 4 {
		t.Fatalf("queue length %d", f.n)
	}
}

// batchMemIO is a carrier that takes bursts (like the sendmmsg path of the icmp and udp carriers).
type batchMemIO struct {
	*memIO
	calls, pkts atomic.Int64
}

func (b *batchMemIO) SendBatch(ps [][]byte, lanes []int) error {
	b.calls.Add(1)
	b.pkts.Add(int64(len(ps)))
	for i, p := range ps {
		b.memIO.Send(p, lanes[i])
	}
	return nil
}

func transfer(t *testing.T, cli, srv *Session, n int) {
	t.Helper()
	data := pattern(n, 5)
	got := make(chan []byte, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			got <- nil
			return
		}
		b, _ := readAll(st)
		got <- b
	}()
	st, _ := cli.OpenStream()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case b := <-got:
		if string(b) != string(data) {
			t.Fatalf("data mismatch: %d of %d bytes", len(b), len(data))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSendBatchUsedAndLossless(t *testing.T) {
	t.Setenv("WAT_BATCH", "1") // batching is opt-in since 2026-10-10
	a, b := newMemDir(), newMemDir()
	cfg := Config{Key: []byte("k"), SID: 9, InitBps: 100e6, MaxBps: 100e6}
	cio := &batchMemIO{memIO: &memIO{tx: a, rx: b, done: make(chan struct{})}}
	sio := &batchMemIO{memIO: &memIO{tx: b, rx: a, done: make(chan struct{})}}
	cli, _ := NewSession(cfg, cio)
	cfg.Server = true
	srv, _ := NewSession(cfg, sio)
	t.Cleanup(func() { cli.Close(); srv.Close() })
	if cli.batcher == nil {
		t.Fatal("batch carrier not detected")
	}
	transfer(t, cli, srv, 8<<20)
	if cio.calls.Load() == 0 || cio.pkts.Load() <= cio.calls.Load() {
		t.Fatalf("client batches: %d calls for %d packets", cio.calls.Load(), cio.pkts.Load())
	}
	t.Logf("client sent %d packets in %d sendmmsg-style calls", cio.pkts.Load(), cio.calls.Load())
}

// A carrier that does not declare Copier (it may queue the slice) never gets its buffers recycled; one that does, does.
func TestBufferOwnership(t *testing.T) {
	cli, srv := memPair(t, Config{})
	if !cli.copier || cli.outFree == nil {
		t.Fatal("copying carrier should recycle buffers")
	}
	transfer(t, cli, srv, 4<<20)
	plain, _, _, _ := newPair(t, 0, time.Millisecond, 1e7, Config{})
	if plain.copier || plain.outFree != nil || plain.batcher != nil {
		t.Fatal("a carrier without Copier must keep fresh buffers and single sends")
	}
}

// TestStreamBulkyDecays: a stream turns bulk after prioBytes and interactive again once it has been quiet (3.0.0).
func TestStreamBulkyDecays(t *testing.T) {
	t0 := time.Now()
	st := &Stream{}
	st.cool(t0)
	st.heat += prioBytes - 1
	if st.bulky(t0) {
		t.Fatal("bulk below prioBytes")
	}
	st.heat += 2
	if !st.bulky(t0) {
		t.Fatal("not bulk after prioBytes")
	}
	st.heat = 4 * prioBytes
	if !st.bulky(t0.Add(prioHalfLife)) { // 2x prioBytes left
		t.Fatal("cooled too fast")
	}
	if st.bulky(t0.Add(3 * prioHalfLife)) { // 0.5x prioBytes left
		t.Fatal("still bulk after going quiet")
	}
}

// TestYoungSmallLatePacket: a small packet is hedged even deep into its stream; a large late one is not.
func TestYoungSmallLatePacket(t *testing.T) {
	s := &Session{streams: map[uint64]*Stream{4: {}}}
	if !s.young(&sentPkt{frames: []frameRef{{sid: 4, off: 64 << 10, n: 300}}}) {
		t.Fatal("a 300-byte frame at 64 KB must be young")
	}
	if s.young(&sentPkt{frames: []frameRef{{sid: 4, off: 64 << 10, n: 1200}}}) {
		t.Fatal("a 1200-byte frame at 64 KB must not be young")
	}
	if !s.young(&sentPkt{frames: []frameRef{{sid: 4, off: 0, n: 1200}}}) {
		t.Fatal("a large frame at the start of its stream must be young")
	}
}
