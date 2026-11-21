//go:build diag

// The speed-swarm diagnostics (2026-11-21): measurement tools, NOT regression pins — they add ~7 min to
// the suite, so they build only under the diag tag:  go test -tags diag -run Diag ./wat/
package wat

// diagprof_test.go — CPU/allocation diagnostics for the engine's per-packet path (diagnostic agent,
// 2026-11-21). Windows-measurable only: no raw sockets, no sendmmsg; the sim/mem pairs carry the real
// seal/frame/ack/lock path. Run:
//
//	go test -count=1 -run DiagProf ./wat/
//	go test -run XXX -bench DiagProf -benchtime 2s ./wat/
//	go test -count=1 -run DiagProfBulk -v -cpuprofile diagprof_cpu.out -blockprofile diagprof_blk.out ./wat/
//	    go tool pprof -top wat.test diagprof_cpu.out   (add -block for the block profile)

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// diagPfIO is a zero-delay lossless link over the pooled memDir buffers, WITHOUT a Profile: the session
// sees the zero Profile (640 B MaxPayload, non-reliable, delay-paced) — the ICMP engine shape, minus the
// raw socket. Like a socket it copies on Send and recycles its buffers via CopiesOnSend.
type diagPfIO struct {
	tx, rx *memDir
	prev   []byte
	done   chan struct{}
	once   sync.Once
}

func (m *diagPfIO) Send(p []byte, lane int) error {
	select {
	case b := <-m.tx.free:
		select {
		case m.tx.out <- append(b[:0], p...):
		default:
			m.tx.free <- b
		}
	default:
	}
	return nil
}

func (m *diagPfIO) Recv() ([]byte, int, net.Addr, error) {
	if m.prev != nil {
		m.rx.free <- m.prev
		m.prev = nil
	}
	select {
	case p := <-m.rx.out:
		m.prev = p
		return p, 0, nil, nil
	case <-m.done:
		return nil, 0, nil, io.EOF
	}
}

func (m *diagPfIO) SetPeer(net.Addr)   {}
func (m *diagPfIO) Close() error       { m.once.Do(func() { close(m.done) }); return nil }
func (m *diagPfIO) CopiesOnSend() bool { return true }

// diagPfPair: client/server over diagPfIO at an unbounded pace, so the engine (not the pacer floor) is the load.
func diagPfPair(tb testing.TB, cfg Config) (cli, srv *Session) {
	a, b := newMemDir(), newMemDir()
	cfg.Key, cfg.SID = []byte("diag-key"), 0x1234567
	cfg.InitBps, cfg.MaxBps = 500e6, 500e6
	cc, sc := cfg, cfg
	sc.Server = true
	var err error
	if cli, err = NewSession(cc, &diagPfIO{tx: a, rx: b, done: make(chan struct{})}); err != nil {
		tb.Fatal(err)
	}
	if srv, err = NewSession(sc, &diagPfIO{tx: b, rx: a, done: make(chan struct{})}); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// TestDiagProfBulk runs ~5 s of single-stream bulk over the 640 B ICMP-shaped engine path and reports
// throughput, allocation rate and GC, so the external cpu/block profiles have a denominator (bytes, packets).
func TestDiagProfBulk(t *testing.T) {
	cli, srv := diagPfPair(t, Config{})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, st); st.CloseWrite() }()
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	var wrote int
	for time.Since(start) < 5*time.Second {
		n, err := st.Write(chunk)
		if err != nil {
			t.Fatal(err)
		}
		wrote += n
	}
	st.CloseWrite()
	// let the tail drain so the packet counts cover the bytes
	for i := 0; i < 200; i++ {
		cli.mu.Lock()
		done := st.finAcked
		cli.mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	el := time.Since(start)
	runtime.ReadMemStats(&m1)
	cs, ss := cli.Stats(), srv.Stats()
	pkts := cs.PktsOut + ss.PktsOut
	mb := float64(wrote) / 1e6
	t.Logf("DiagProfBulk: %.1f MB in %.2fs = %.1f MB/s (640B path, in-process)", mb, el.Seconds(), mb/el.Seconds())
	t.Logf("pkts: cli.out=%d srv.out=%d total=%d (%.0f pkt/s), wire-out=%.1f MB wire-in=%.1f MB",
		cs.PktsOut, ss.PktsOut, pkts, float64(pkts)/el.Seconds(), float64(cs.BytesOut)/1e6, float64(ss.BytesOut)/1e6)
	t.Logf("allocs: total=%.1f MB  per-MB-user=%.2f MB  per-pkt=%.0f B  (Mallocs=%d, %.0f/pkt)",
		float64(m1.TotalAlloc-m0.TotalAlloc)/1e6,
		float64(m1.TotalAlloc-m0.TotalAlloc)/float64(wrote),
		float64(m1.TotalAlloc-m0.TotalAlloc)/float64(pkts),
		m1.Mallocs-m0.Mallocs, float64(m1.Mallocs-m0.Mallocs)/float64(pkts))
	t.Logf("gc: %d cycles, %.1f ms paused; retrans=%d rxdup=%d", m1.NumGC-m0.NumGC,
		float64(m1.PauseTotalNs-m0.PauseTotalNs)/1e6, cs.Retrans+ss.Retrans, cs.RxDup+ss.RxDup)
	if pkts == 0 || wrote == 0 {
		t.Fatal("no traffic")
	}
}

// ---- micro-benchmarks ----

func diagPfAEAD(tb testing.TB) cipher.AEAD {
	a, err := sessionAEAD([]byte("diag-key"), 0x1234567)
	if err != nil {
		tb.Fatal(err)
	}
	return a
}

// BenchmarkDiagProfSeal640 / 1400: one seal + one open of a full plaintext packet (maxPlain at that MTU),
// the pure crypto cost per packet on the wire.
func BenchmarkDiagProfSeal640(b *testing.B)  { diagSeal(b, MaxPayload-overhead) }
func BenchmarkDiagProfSeal1400(b *testing.B) { diagSeal(b, MaxPayloadHi-overhead) }

func diagSeal(b *testing.B, plain int) {
	a := diagPfAEAD(b)
	pt := pattern(plain, 1)
	out := make([]byte, hdrLen, hdrLen+plain+tagLen)
	var nonce [12]byte
	dst := make([]byte, 0, plain)
	b.SetBytes(int64(plain))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(out[8:], uint64(i))
		copy(nonce[4:], out[8:16])
		sealed := a.Seal(out, nonce[:], pt, out[:8])
		q, err := a.Open(dst[:0], nonce[:], sealed[hdrLen:], sealed[:8])
		if err != nil || len(q) != plain {
			b.Fatal("seal/open roundtrip failed")
		}
	}
}

// BenchmarkDiagProfFrame: header write + plaintext copy + buffer recycle (session.frame + putOut), the
// non-crypto half of packet serialization.
func BenchmarkDiagProfFrame(b *testing.B) {
	cli, _ := diagPfPair(b, Config{})
	pt := pattern(cli.maxPlain, 2)
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cli.mu.Lock()
		out, _ := cli.frame(pt)
		cli.mu.Unlock()
		cli.putOut(out)
	}
}

// BenchmarkDiagProfBuild: the whole build() under s.mu (scheduling, emit, frame, bookkeeping) on a
// never-acked session with the window artificially freed, so each iteration produces one full data packet.
func BenchmarkDiagProfBuild(b *testing.B) {
	cli, _ := diagPfPair(b, Config{})
	st, err := cli.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 256<<10)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := st.Write(chunk); err != nil {
				return
			}
		}
	}()
	defer close(stop)
	time.Sleep(50 * time.Millisecond) // let the writer fill the buffers
	// Stop the session's own pump/recvLoop goroutines (they drain the stream queues and would make every
	// manual build() find nothing), leaving the session state for the benchmark to drive directly. Setting
	// closed keeps the Cleanup Close() from closing s.stop a second time (a panic on a closed channel).
	cli.mu.Lock()
	cli.closed = true
	close(cli.stop)
	st.peerMax = 1 << 40 // no peer answers frWindow in this bench: open the window manually
	st.wc.Broadcast()    // wake the writer (it parked on the closed window before peerMax was raised)
	cli.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	now := time.Now()
	miss := 0
	b.SetBytes(int64(cli.maxPlain))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cli.mu.Lock()
		if i&1023 == 0 { // pretend everything was acked: keep inflight/sent/snd from growing unbounded
			for j := cli.sentHead; j < len(cli.sent); j++ {
				cli.sent[j].done = true
			}
			cli.inflight = 0
			cli.compact()
			st.acked = st.acked[:0]
			if consumed := int(st.snext - st.sbase); consumed > 0 { // free exactly the bytes build consumed
				st.snd.drop(consumed)
				st.sbase = st.snext
				st.wc.Broadcast()
			}
		}
		cli.cc.tokens = 1e9
		_, ok := cli.build(now)
		cli.mu.Unlock()
		if !ok {
			// A miss means the writer goroutine had not refilled the queue yet: wake it, do not abort —
			// the fake-ack window and the real writer's schedule are never in lockstep.
			cli.mu.Lock()
			cli.inflight = 0
			st.wc.Broadcast()
			cli.mu.Unlock()
			miss++
		}
	}
	if miss*10 > b.N/10 {
		b.Fatalf("writer starved: %d/%d misses", miss, b.N)
	}
}

// BenchmarkDiagProfRefill: the pacer's per-tick token refill (runs under s.mu every pump wake).
func BenchmarkDiagProfRefill(b *testing.B) {
	c := newCC(500e6, 2e5, 500e6, 8*time.Millisecond)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.refill(time.Millisecond)
	}
}

// BenchmarkDiagProfRxRanges: the receiver's per-packet replay bookkeeping (in-order add + trim).
func BenchmarkDiagProfRxRanges(b *testing.B) {
	var rs rangeSet
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.add(uint64(i), uint64(i)+1)
		rs.trim(512)
	}
}

// BenchmarkDiagProfAckEncode: appendAck with 20 SACK ranges (the non-reliable default ackMax).
func BenchmarkDiagProfAckEncode(b *testing.B) {
	var rs rangeSet
	for i := 0; i < 20; i++ {
		rs.add(uint64(2*i), uint64(2*i+1))
	}
	buf := make([]byte, 0, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = appendAck(buf[:0], rs, 100, 20)
	}
}
