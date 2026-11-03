package wat

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Userspace model of the bench link (ab_loop.sh: 20 ms each way, 0.2 % loss, 100 Mbit, 1000-packet netem queue).
// Run it with  WAT_EMU=tcp|udp  go test -run TestEmu -v ./wat/  (add -cpuprofile cpu.out to profile). It is skipped
// otherwise: it is a measuring tool, not a pass/fail gate.
//
// The datagram model (udp) is a lossy rate-limited queue. The stream model (tcp) cannot drop bytes, so a lost
// "segment" instead stalls its whole connection for one extra RTT (fast retransmit), which is what makes TCP
// head-of-line block; the other connections of the pool keep flowing.

type emuWire struct {
	mu      sync.Mutex
	bps     float64
	delay   time.Duration
	loss    float64
	qMax    time.Duration // queue limit as time at the link rate (netem: 1000 packets)
	rtt     time.Duration
	free    time.Time
	stall   time.Duration // tcp model: how long a lost segment holds its connection (default: one RTT + 20 ms)
	rnd     *rand.Rand
	dropped int
	stalled int
}

// EMU_MBPS (MB/s) and EMU_QMS (queue limit in ms) override the link: a slow last leg behind a deep CDN buffer is
// EMU_MBPS=4 EMU_QMS=2000.
func newEmuWire(seed int64) *emuWire {
	w := &emuWire{bps: 12.5e6, delay: 20 * time.Millisecond, loss: 0.002, qMax: 120 * time.Millisecond,
		rtt: 40 * time.Millisecond, rnd: rand.New(rand.NewSource(seed))}
	if n, _ := strconv.ParseFloat(os.Getenv("EMU_MBPS"), 64); n > 0 {
		w.bps = n * 1e6
	}
	if n, _ := strconv.Atoi(os.Getenv("EMU_QMS")); n > 0 {
		w.qMax = time.Duration(n) * time.Millisecond
	}
	// EMU_DELAY_MS (one way), EMU_LOSS (fraction) and EMU_STALL_MS model the CDN path seen from Iran (2026-10-12:
	// ~100 ms RTT, a lossy last leg whose TCP retransmits hold a connection for an RTO): EMU_DELAY_MS=50
	// EMU_LOSS=0.01 EMU_STALL_MS=300.
	if n, _ := strconv.Atoi(os.Getenv("EMU_DELAY_MS")); n > 0 {
		w.delay, w.rtt = time.Duration(n)*time.Millisecond, 2*time.Duration(n)*time.Millisecond
	}
	if n, err := strconv.ParseFloat(os.Getenv("EMU_LOSS"), 64); err == nil && n >= 0 && os.Getenv("EMU_LOSS") != "" {
		w.loss = n
	}
	w.stall = w.rtt + 20*time.Millisecond
	if n, _ := strconv.Atoi(os.Getenv("EMU_STALL_MS")); n > 0 {
		w.stall = time.Duration(n) * time.Millisecond
	}
	return w
}

// admit returns when a packet of n bytes sent now arrives; ok=false when the queue is full or the packet is lost.
func (w *emuWire) admit(n int) (at time.Time, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	start := w.free
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > w.qMax {
		w.dropped++
		return time.Time{}, false
	}
	w.free = start.Add(time.Duration(float64(n+28) / w.bps * float64(time.Second)))
	if w.rnd.Float64() < w.loss {
		w.dropped++
		return time.Time{}, false
	}
	return w.free.Add(w.delay), true
}

// ---- datagram model

type emuDgDir struct {
	w   *emuWire
	max int
	q   chan simItem
	out chan []byte
}

func newEmuDgDir(w *emuWire, max int) *emuDgDir {
	d := &emuDgDir{w: w, max: max, q: make(chan simItem, 1<<16), out: make(chan []byte, 1<<16)}
	go func() {
		for it := range d.q {
			if x := time.Until(it.at); x > 0 {
				time.Sleep(x)
			}
			select {
			case d.out <- it.p:
			default:
			}
		}
	}()
	return d
}

func (d *emuDgDir) send(p []byte) {
	if len(p) > d.max {
		return
	}
	if at, ok := d.w.admit(len(p)); ok {
		d.q <- simItem{at, append([]byte(nil), p...)}
	}
}

type emuDgIO struct {
	tx, rx *emuDgDir
	done   chan struct{}
	once   sync.Once
	prof   Profile
}

func (s *emuDgIO) Send(p []byte, lane int) error { s.tx.send(p); return nil }
func (s *emuDgIO) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-s.rx.out:
		return p, 0, nil, nil
	case <-s.done:
		return nil, 0, nil, io.EOF
	}
}
func (s *emuDgIO) SetPeer(net.Addr) {}
func (s *emuDgIO) Close() error     { s.once.Do(func() { close(s.done) }); return nil }
func (s *emuDgIO) Profile() Profile { return s.prof }

// ---- stream model: a TCP proxy that delays, rate-limits and stalls

type emuChunk struct {
	at time.Time
	b  []byte
}

// EMU_CONNQ bounds how many ~MSS chunks one connection holds in flight (default 8192, i.e. effectively unbounded). A
// real TCP socket stops taking data once cwnd plus its unsent low-water mark are used, so a stalled connection pushes
// back on the pool's writer; ~400 models a 100 MB/s, 40 ms path split over 8 connections.
func emuConnQ() int {
	if n, _ := strconv.Atoi(os.Getenv("EMU_CONNQ")); n > 0 {
		return n
	}
	return 8192
}

func emuPipe(w *emuWire, src, dst net.Conn) {
	q := make(chan emuChunk, emuConnQ())
	go func() { // reader: timestamp every ~MSS chunk
		defer close(q)
		buf := make([]byte, 1448)
		var prev time.Time
		for {
			n, err := src.Read(buf)
			if n > 0 {
				at, ok := w.admit(n)
				if !ok { // lost or tail-dropped: delivered one retransmit RTT later, and everything behind it waits
					w.mu.Lock()
					w.stalled++
					at = w.free.Add(w.delay + w.stall)
					w.mu.Unlock()
				}
				if at.Before(prev) {
					at = prev
				}
				prev = at
				q <- emuChunk{at, append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range q {
		if x := time.Until(c.at); x > 300*time.Microsecond {
			time.Sleep(x)
		}
		if _, err := dst.Write(c.b); err != nil {
			break
		}
	}
	dst.Close()
	src.Close()
}

func emuProxy(t testing.TB, target string, up, down *emuWire) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go emuPipe(up, c, s)
			go emuPipe(down, s, c)
		}
	}()
	return ln.Addr().String()
}

// ---- measurement

func emuServe(srv *Server) {
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() {
						var h [5]byte
						if _, err := io.ReadFull(st, h[:]); err != nil {
							return
						}
						n := int(binary.BigEndian.Uint32(h[1:]))
						buf := make([]byte, 32<<10)
						for n > 0 {
							k := min(n, len(buf))
							if _, err := st.Write(buf[:k]); err != nil {
								return
							}
							n -= k
						}
						st.CloseWrite()
					}()
				}
			}(s)
		}
	}()
}

func emuGet(cli *Session, n int) (int, error) {
	st, err := cli.OpenStream()
	if err != nil {
		return 0, err
	}
	var h [5]byte
	binary.BigEndian.PutUint32(h[1:], uint32(n))
	st.Write(h[:])
	st.CloseWrite()
	return int(mustCopy(st)), nil
}

func mustCopy(r io.Reader) int64 { n, _ := io.Copy(io.Discard, r); return n }

func emuRun(t *testing.T, cli *Session, srv *Server) {
	emuServe(srv)
	t0 := time.Now()
	if os.Getenv("EMU_TRACE") != "" {
		stopTr := make(chan struct{})
		defer close(stopTr)
		go func() {
			var last uint64
			for {
				select {
				case <-stopTr:
					return
				case <-time.After(250 * time.Millisecond):
				}
				st := srv.Stats()
				t.Logf("t=%.2f rate %.1f MB/s inflight %d srtt %v out %.2f MB/s retr %d", time.Since(t0).Seconds(), st.RateBps/1e6, st.Inflight, st.SRTT, float64(st.BytesOut-last)/0.25/1e6, st.Retrans)
				last = st.BytesOut
			}
		}()
	}
	n, _ := emuGet(cli, emuSize()<<20)
	single := float64(n) / time.Since(t0).Seconds() / 1e6
	t0 = time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	tot := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, _ := emuGet(cli, 2<<20)
			mu.Lock()
			tot += k
			mu.Unlock()
		}()
	}
	wg.Wait()
	par := float64(tot) / time.Since(t0).Seconds() / 1e6
	// latency of small requests while a bulk download runs
	bulk := make(chan struct{})
	go func() { emuGet(cli, 32<<20); close(bulk) }()
	time.Sleep(time.Second)
	var lat []time.Duration
	for i := 0; i < 30; i++ {
		t1 := time.Now()
		emuGet(cli, 1024)
		lat = append(lat, time.Since(t1))
	}
	<-bulk
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	ss, cs := srv.Stats(), cli.Stats()
	t.Logf("single %.2f MB/s | 16x2MB %.2f MB/s | small-req p50 %v p95 %v | server pkts %d retrans %d (%.1f%%) rate %.1f MB/s srtt %v min %v",
		single, par, lat[len(lat)/2], lat[len(lat)*95/100], ss.PktsOut, ss.Retrans, 100*float64(ss.Retrans)/float64(max(ss.PktsOut, 1)),
		ss.RateBps/1e6, ss.SRTT, ss.MinRTT)
	t.Logf("server out %d client in %d (bytes %d vs %d), client late-acked %d dup %d too-old %d", ss.PktsOut, cs.PktsIn, ss.BytesOut, cs.BytesIn, cs.AckLate, cs.RxDup, cs.RxTooOld)
	t.Logf("server cc %+v floor %.1f MB/s cwnd %d losstime %v x%.2f winblocked %d", ss.CC, ss.FloorBps/1e6, ss.Cwnd, ss.LossTime, ss.RelLossMul, ss.WinBlocked)
}

func emuInit() float64 { n, _ := strconv.ParseFloat(os.Getenv("EMU_INIT"), 64); return n * 1e6 }

func emuSlack() time.Duration {
	n, _ := strconv.Atoi(os.Getenv("EMU_SLACK"))
	return time.Duration(n) * time.Millisecond
}

// emuMax is the pace ceiling for both ends (EMU_MAX MB/s); default 1250, the wattun default for non-ICMP carriers
// (the session's own default of 16 would cap the emulated link far below its rate).
func emuMax() float64 {
	if n, _ := strconv.ParseFloat(os.Getenv("EMU_MAX"), 64); n > 0 {
		return n * 1e6
	}
	return 1250e6
}

func emuMTU() int { n, _ := strconv.Atoi(os.Getenv("EMU_MTU")); return n }

func TestEmu(t *testing.T) {
	mode := os.Getenv("WAT_EMU")
	if mode == "" {
		t.Skip("set WAT_EMU=tcp|udp to run the link emulation")
	}
	key := []byte("emu-key")
	switch mode {
	case "udp":
		up, down := newEmuWire(1), newEmuWire(2)
		a, b := newEmuDgDir(up, 1500), newEmuDgDir(down, 1500)
		prof := Profile{} // filled in by the capability under test
		if os.Getenv("EMU_PROFILE") != "" {
			prof = udpProfile
		}
		sio := &emuDgIO{tx: b, rx: a, done: make(chan struct{}), prof: prof}
		cio := &emuDgIO{tx: a, rx: b, done: make(chan struct{}), prof: prof}
		cli, err := NewSession(Config{Key: key, MaxPayload: emuMTU(), SID: 77}, cio)
		if err != nil {
			t.Fatal(err)
		}
		srv := NewServer(Config{Key: key, MaxPayload: emuMTU(), InitBps: emuInit()}, &emuRaw{sio})
		t.Cleanup(func() { cli.Close(); srv.Close() })
		emuRun(t, cli, srv)
	case "tcp", "tcpdirect": // tcpdirect: no emulated link, as fast as the loopback allows (CPU profiling)
		up, down := newEmuWire(1), newEmuWire(2)
		ps, err := NewTCPPoolServer("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		direct := os.Getenv("EMU_DIRECT") != ""
		srv := NewServer(Config{Key: key, MaxPayload: emuMTU(), InitBps: emuInit(), MaxBps: emuMax(), Direct: direct}, ps)
		addr := ps.Addr().String()
		if mode == "tcp" {
			addr = emuProxy(t, addr, up, down)
		}
		conns := 8
		if n, _ := strconv.Atoi(os.Getenv("EMU_CONNS")); n > 0 {
			conns = n
		}
		pc, err := NewTCPPoolClient(addr, conns)
		if err != nil {
			t.Fatal(err)
		}
		cli, err := NewSession(Config{Key: key, MaxPayload: emuMTU(), InitBps: emuInit(), MaxBps: emuMax(), Slack: emuSlack(), Direct: direct}, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cli.Close(); srv.Close() })
		time.Sleep(300 * time.Millisecond)
		emuRun(t, cli, srv)
		t.Logf("wire stalls: up %d down %d, pool queue drops %d, slow conns closed %d", up.stalled, down.stalled, poolDrops.Load(), poolSlowKills.Load())
	}
}

// emuRaw adapts the in-memory datagram pipe to the server side (one fixed client).
type emuRaw struct{ io *emuDgIO }

func (r *emuRaw) Recv() ([]byte, int, net.Addr, error) {
	p, l, _, err := r.io.Recv()
	return p, l, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}, err
}
func (r *emuRaw) SendTo(p []byte, lane int, dst net.Addr) error {
	return r.io.Send(p, lane)
}
func (r *emuRaw) Close() error     { return r.io.Close() }
func (r *emuRaw) Profile() Profile { return r.io.prof }

func emuSize() int {
	if n, _ := strconv.Atoi(os.Getenv("EMU_SIZE")); n > 0 {
		return n
	}
	return 32
}
