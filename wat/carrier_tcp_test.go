package wat

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// poolRig is a real Server on a loopback tcp/tls pool listener (same stream protocol as udpRig).
type poolRig struct {
	srv    *Server
	ps     *TCPPoolServer
	addr   string
	tap    *sizeTap
	key    []byte
	mtu    int
	tlsOpt TLSClientOptions
	tls    bool
}

func newPoolRig(t *testing.T, mtu int, useTLS bool) *poolRig {
	t.Helper()
	var ps *TCPPoolServer
	var err error
	if useTLS {
		ps, err = NewTLSPoolServer("127.0.0.1:0", "", "")
	} else {
		ps, err = NewTCPPoolServer("127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := &poolRig{ps: ps, addr: ps.Addr().String(), tap: &sizeTap{}, key: []byte("pool-key"), mtu: mtu, tls: useTLS}
	srv := NewServer(Config{Key: r.key, MaxPayload: mtu}, tapServer{ps, r.tap})
	srv.IdleTimeout = 5 * time.Second
	r.srv = srv
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go serveUDPStream(st)
				}
			}(s)
		}
	}()
	t.Cleanup(srv.Close)
	return r
}

// tlsOptions are the tls carrier's client options; tlsOpt (when set by a test) adds the 2.2.0 tuning.
func (r *poolRig) tlsOptions() TLSClientOptions {
	o := r.tlsOpt
	o.ServerName = "example.com"
	return o
}

func (r *poolRig) pio(t *testing.T) *TCPPoolClient {
	t.Helper()
	var c *TCPPoolClient
	var err error
	if r.tls {
		c, err = NewTLSPoolClient(r.addr, 8, r.tlsOptions())
	} else {
		c, err = NewTCPPoolClient(r.addr, 8)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *poolRig) client(t *testing.T, key []byte) *Session {
	t.Helper()
	s, err := NewSession(Config{Key: key, MaxPayload: r.mtu}, tapClient{r.pio(t), r.tap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// kill closes n connections of the server's busiest pool from the server side.
func (s *TCPPoolServer) kill(n int) {
	s.mu.Lock()
	var victims []*poolConn
	for _, set := range s.pools {
		for pc := range set {
			if len(victims) < n {
				victims = append(victims, pc)
			}
		}
	}
	s.mu.Unlock()
	for _, pc := range victims {
		pc.fail()
	}
}

func poolBulk(t *testing.T, r *poolRig, cli *Session, n int) {
	t.Helper()
	t0 := time.Now()
	up := pattern(n, 3)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(append([]byte{'U'}, up...)); st.CloseWrite() }()
	sum, err := readAll(st)
	want := sha256.Sum256(up)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("upload digest mismatch: err=%v len=%d", err, len(sum))
	}
	tUp := time.Since(t0)
	t0 = time.Now()
	st, err = cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{'D', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(req[1:], uint32(n))
	go func() { st.Write(req); st.CloseWrite() }()
	got, err := readAll(st)
	if err != nil || !bytes.Equal(got, pattern(n, 7)) {
		t.Fatalf("download mismatch: err=%v got %d want %d", err, len(got), n)
	}
	t.Logf("mtu %d: up %v down %v, max datagram %d", r.mtu, tUp, time.Since(t0), r.tap.max.Load())
}

func poolBulkTest(t *testing.T, mtu int, useTLS bool) {
	r := newPoolRig(t, mtu, useTLS)
	poolBulk(t, r, r.client(t, r.key), 4<<20)
}

func TestTCPBulk(t *testing.T) { poolBulkTest(t, 0, false) }
func TestTLSBulk(t *testing.T) { poolBulkTest(t, 0, true) }

func TestTCPLargeDatagrams(t *testing.T) {
	r := newPoolRig(t, 1400, false)
	poolBulk(t, r, r.client(t, r.key), 4<<20)
	if m := r.tap.max.Load(); m <= MaxPayload || m > 1400 {
		t.Fatalf("largest datagram %d, want in (%d, 1400]", m, MaxPayload)
	}
}

func TestTCPManyStreams(t *testing.T) {
	r := newPoolRig(t, 0, false)
	cli := r.client(t, r.key)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			udpEcho(t, cli, 100+(i%10)*20000, byte(i))
		}(i)
	}
	waitOrFail(t, &wg, 30*time.Second)
}

func TestTCPTwoClientsSameKey(t *testing.T) {
	r := newPoolRig(t, 0, false)
	a, b := r.client(t, r.key), r.client(t, r.key)
	var wg sync.WaitGroup
	for i, c := range []*Session{a, b} {
		wg.Add(1)
		go func(i int, c *Session) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				udpEcho(t, c, 600000, byte(10*i+j))
			}
		}(i, c)
	}
	waitOrFail(t, &wg, 30*time.Second)
	if n := r.srv.Sessions(); n != 2 {
		t.Fatalf("server has %d sessions, want 2", n)
	}
	if n := r.ps.Pools(); n != 2 {
		t.Fatalf("server has %d pools, want 2", n)
	}
}

func TestTCPRejectsForeignKey(t *testing.T) {
	r := newPoolRig(t, 0, false)
	bad := r.client(t, []byte("other-key"))
	st, err := bad.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("Ehello"))
	time.Sleep(500 * time.Millisecond)
	if n := r.srv.Sessions(); n != 0 {
		t.Fatalf("server admitted %d sessions from a foreign key", n)
	}
	udpEcho(t, r.client(t, r.key), 50000, 1)
}

func TestTCPKillConnsMidTransfer(t *testing.T) {
	r := newPoolRig(t, 0, false)
	pio := r.pio(t)
	cli, err := NewSession(Config{Key: r.key}, pio)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	stop := make(chan struct{})
	go func() {
		for _, d := range []time.Duration{150, 400} {
			select {
			case <-time.After(d * time.Millisecond):
				r.ps.kill(3)
			case <-stop:
				return
			}
		}
	}()
	poolBulk(t, r, cli, 6<<20)
	close(stop)
	deadline := time.Now().Add(5 * time.Second)
	for pio.Conns() < 8 || r.ps.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: client %d, server %d conns", pio.Conns(), r.ps.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTCPNoGoroutineLeak(t *testing.T) {
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	for _, useTLS := range []bool{false, true} {
		r := newPoolRig(t, 0, useTLS)
		cli := r.client(t, r.key)
		udpEcho(t, cli, 200000, 5)
		cli.Close()
		r.srv.Close()
	}
	var n int
	for i := 0; i < 50; i++ {
		if n = runtime.NumGoroutine(); n <= base+2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	t.Fatalf("goroutines %d, baseline %d\n%s", n, base, buf[:runtime.Stack(buf, true)])
}

func TestTLSPinAndTLS13(t *testing.T) {
	r := newPoolRig(t, 0, true)
	// wrong pin: the pool never comes up
	bad, err := NewTLSPoolClient(r.addr, 2, TLSClientOptions{PinSHA256: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	time.Sleep(600 * time.Millisecond)
	if bad.Conns() != 0 {
		t.Fatal("client connected despite a wrong pin")
	}
	// plain TLS 1.2 is refused by the server
	c, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	if err == nil {
		c.Close()
		t.Fatal("server accepted TLS 1.2")
	}
}

// A conn whose socket write is blocked (a CDN edge in TCP backoff) must not be picked while a healthy one exists,
// and one stuck past poolStallKill is closed so the client redials it (2.4.5).
func TestLeastQueuedSkipsStalled(t *testing.T) {
	mk := func() *poolConn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return newPoolConn(a)
	}
	stalled, stuck, ok := mk(), mk(), mk()
	now := time.Now().UnixNano()
	stalled.wbusy.Store(now - int64(time.Second))
	stuck.wbusy.Store(now - int64(10*time.Second))
	ok.q <- getPkt(10) // longer queue than the others, still preferred
	for i := 0; i < 6; i++ {
		if pc := leastQueued([]*poolConn{stalled, stuck, ok}, i); pc != ok {
			t.Fatal("picked a stalled conn while a healthy one exists")
		}
	}
	select {
	case <-stuck.done:
	case <-time.After(time.Second):
		t.Fatal("a conn stuck past poolStallKill was not closed")
	}
	select {
	case <-stalled.done:
		t.Fatal("a briefly stalled conn was closed")
	default:
	}
	if pc := leastQueued([]*poolConn{stalled}, 0); pc != stalled { // all stalled: the path is slow, keep sending
		t.Fatal("no conn picked when every conn is stalled")
	}
}

// A connection that delivers under half its share for three windows in a row is closed; even spreads, young
// connections and idle pools never are.
func TestJudgeSlow(t *testing.T) {
	old := time.Now().Add(-time.Minute)
	mk := func(n int) []*poolConn {
		cs := make([]*poolConn, n)
		for i := range cs {
			cs[i] = &poolConn{born: old}
		}
		return cs
	}
	feed := func(cs []*poolConn, per ...uint64) {
		for i, pc := range cs {
			pc.rx.Add(per[i])
		}
	}
	now := time.Now()
	cs := mk(4)
	for w := 0; w < 10; w++ {
		feed(cs, 30, 25, 20, 28) // uneven but healthy
		if pc := judgeSlow(cs, now); pc != nil {
			t.Fatal("healthy pool: a connection was judged slow")
		}
	}
	for w := 0; w < 10; w++ {
		feed(cs, 2, 1, 0, 3) // idle
		if pc := judgeSlow(cs, now); pc != nil {
			t.Fatal("idle pool was judged")
		}
	}
	var got *poolConn
	for w := 1; w <= 3; w++ {
		feed(cs, 60, 60, 5, 60)
		got = judgeSlow(cs, now)
		if w < 3 && got != nil {
			t.Fatalf("closed after %d windows", w)
		}
	}
	if got != cs[2] {
		t.Fatal("slow connection not closed after three windows")
	}
	young := mk(4)
	young[3].born = now
	for w := 0; w < 5; w++ {
		feed(young, 60, 60, 60, 0)
		if judgeSlow(young, now) != nil {
			t.Fatal("young connection judged")
		}
	}
}

func TestTCPPoolClientOptionsLocalAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan net.Addr, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			done <- c.RemoteAddr()
			c.Close()
		}
	}()

	opt := TCPClientOptions{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
	}
	client, err := NewTCPPoolClientOptions(ln.Addr().String(), 1, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case remote := <-done:
		tcpAddr, ok := remote.(*net.TCPAddr)
		if !ok || !tcpAddr.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("expected remote to see local 127.0.0.1, got %v", remote)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial timed out")
	}
}

func TestJudgeSlowSkipsDeadConnections(t *testing.T) {
	old := time.Now().Add(-time.Minute)
	alive1 := &poolConn{born: old, done: make(chan struct{})}
	alive2 := &poolConn{born: old, done: make(chan struct{})}
	alive3 := &poolConn{born: old, done: make(chan struct{})}
	dead := &poolConn{born: old, done: make(chan struct{})}
	close(dead.done)

	alive1.rx.Store(100)
	alive2.rx.Store(100)
	alive3.rx.Store(100)
	dead.rx.Store(0)

	now := time.Now()
	conns := []*poolConn{alive1, alive2, alive3, dead}
	// Run judgeSlow 3 times; dead connection must not be picked as slow
	for i := 0; i < 4; i++ {
		slow := judgeSlow(conns, now)
		if slow == dead {
			t.Fatal("dead connection was judged slow")
		}
	}
}

func TestRotatePickSkipsDeadConnections(t *testing.T) {
	now := time.Now()
	c := &TCPPoolClient{
		slots: make([]atomic.Pointer[poolConn], 3),
	}
	old := now.Add(-time.Hour)
	dead := &poolConn{born: old, done: make(chan struct{})}
	close(dead.done)
	dead.rot.Store(&rotateBudget{at: now.Add(-time.Minute)})

	aliveDue := &poolConn{born: now.Add(-30 * time.Minute), done: make(chan struct{})}
	aliveDue.rot.Store(&rotateBudget{at: now.Add(-time.Minute)})

	aliveFresh := &poolConn{born: now.Add(-10 * time.Minute), done: make(chan struct{})}
	aliveFresh.rot.Store(&rotateBudget{at: now.Add(time.Hour)})

	c.slots[0].Store(dead)
	c.slots[1].Store(aliveDue)
	c.slots[2].Store(aliveFresh)

	pick := c.rotatePick(now)
	if pick == dead {
		t.Fatal("rotatePick returned an already-dead connection")
	}
	if pick != aliveDue {
		t.Fatalf("rotatePick returned %v, want aliveDue", pick)
	}
}

func TestEnqueueDeadConnDrainsAndReturnsBuffer(t *testing.T) {
	pc := &poolConn{
		q:    make(chan []byte, 16),
		done: make(chan struct{}),
	}
	close(pc.done)

	// In a dead connection, enqueue must never leave stranded packets in pc.q
	for i := 0; i < 50; i++ {
		p := getPkt(256)
		ok := pc.enqueue(p)
		if ok {
			t.Fatalf("enqueue returned true on closed connection (iter %d)", i)
		}
	}
	if len(pc.q) != 0 {
		t.Fatalf("pc.q contains %d stranded packets after enqueue on closed connection", len(pc.q))
	}
}

// TestPoolExpressLane: with 3+ connections bulk (pinned) packets never take the first one, interactive packets take
// the least-queued connection by bytes, and a byte-full connection counts as full (3.0.0).
func TestPoolExpressLane(t *testing.T) {
	mk := func() *poolConn { return &poolConn{q: make(chan []byte, poolQueue), done: make(chan struct{})} }
	conns := []*poolConn{mk(), mk(), mk(), mk()}
	for l := 0; l < 64; l++ {
		if pickConn(conns, PinLaneBase+l, l) == conns[0] {
			t.Fatalf("bulk lane %d took the express connection", l)
		}
	}
	for _, pc := range conns[1:] { // every bulk connection holds a 16 KB payload
		pc.enqueue(make([]byte, 16<<10))
	}
	if got := pickConn(conns, 0, 1); got != conns[0] {
		t.Fatal("an interactive packet did not take the empty express connection")
	}
	conns[1].enqueue(make([]byte, poolBacklogBytes))
	if !conns[1].full() || backlogged(conns) {
		t.Fatalf("full=%v backlogged=%v, want true/false", conns[1].full(), backlogged(conns))
	}
	if two := conns[:2]; expressSkip(len(two)) != 0 || pickConn(two, PinLaneBase, 0) == nil {
		t.Fatal("a 2-connection pool must not reserve an express lane")
	}
	for _, pc := range conns[2:] { // every bulk connection full, the express lane empty: bulk must wait
		pc.enqueue(make([]byte, poolBacklogBytes))
	}
	if !backlogged(conns) {
		t.Fatal("bulk connections full but the pool is not backlogged (the express lane's room counted)")
	}

	// client: while only the express slot is up (the others still dialing), bulk falls back to it
	c := &TCPPoolClient{slots: make([]atomic.Pointer[poolConn], 4), done: make(chan struct{})}
	only := mk()
	c.slots[0].Store(only)
	if c.Backlogged() {
		t.Fatal("client backlogged with an empty live connection")
	}
	c.Send(make([]byte, 100), PinLaneBase+1)
	if only.qb.Load() != 100 {
		t.Fatal("bulk packet dropped while only the express slot was live")
	}
	c.slots[1].Store(mk())
	c.Send(make([]byte, 100), PinLaneBase+1)
	if only.qb.Load() != 100 {
		t.Fatal("bulk packet took the express slot while a bulk slot was live")
	}
}

// Every conn stuck past poolStallKill is closed even though no healthy one exists (3.0.1; before, "the whole path is
// slow" kept them for the ~15 min the kernel retries), and none is handed out; a conn that is only stalled is kept.
func TestLeastQueuedClosesAllStuck(t *testing.T) {
	mk := func(stuckFor time.Duration) *poolConn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		pc := newPoolConn(a)
		pc.wbusy.Store(time.Now().UnixNano() - int64(stuckFor))
		return pc
	}
	conns := []*poolConn{mk(10 * time.Second), mk(20 * time.Second), mk(6 * time.Second)}
	if pc := leastQueued(conns, 0); pc != nil {
		t.Fatal("handed out a stuck conn")
	}
	for i, pc := range conns {
		select {
		case <-pc.done:
		case <-time.After(time.Second):
			t.Fatalf("conn %d, stuck past poolStallKill, was not closed", i)
		}
	}
	slow, stuck := mk(time.Second), mk(10*time.Second)
	if pc := leastQueued([]*poolConn{slow, stuck}, 0); pc != slow {
		t.Fatal("a stalled but recoverable conn must still be used")
	}
	select {
	case <-stuck.done:
	case <-time.After(time.Second):
		t.Fatal("the stuck conn was not closed")
	}
}

// blackholeProxy relays loopback tcp to dst; hole() makes every connection that exists at that moment stop moving data
// (nothing is read, nothing closed: the sockets stall like a path that drops established flows), while new ones pass.
type blackholeProxy struct {
	ln  net.Listener
	gen atomic.Int64
}

func newBlackholeProxy(t *testing.T, dst string) *blackholeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &blackholeProxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			g := p.gen.Load()
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetReadBuffer(8 << 10) // a small window: once held, the sender's socket fills and its writer blocks
			}
			d, err := net.Dial("tcp", dst)
			if err != nil {
				c.Close()
				continue
			}
			t.Cleanup(func() { c.Close(); d.Close() })
			for _, pair := range [][2]net.Conn{{c, d}, {d, c}} {
				go func(from, to net.Conn) {
					buf := make([]byte, 32<<10)
					for {
						if p.gen.Load() != g {
							time.Sleep(50 * time.Millisecond) // held: the proxy stops reading, the senders' buffers fill
							continue
						}
						from.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
						n, err := from.Read(buf)
						if n > 0 {
							to.Write(buf[:n])
						}
						if err != nil && !os.IsTimeout(err) {
							return
						}
					}
				}(pair[0], pair[1])
			}
		}
	}()
	return p
}

func (p *blackholeProxy) hole() { p.gen.Add(1) }

// All pool conns stall at once while the session keeps sending (prod outage 2026-10-26): the client closes them and
// redials, and traffic flows again within seconds, not after the kernel's retry timeout.
func TestTCPPoolRedialsWhenAllConnsStall(t *testing.T) {
	r := newPoolRig(t, 0, false)
	px := newBlackholeProxy(t, r.addr)
	pio, err := NewTCPPoolClient(px.ln.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: r.key}, pio)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	poolBulk(t, r, cli, 1<<20) // the pool works
	deaths := pio.ConnDeaths()
	t0 := time.Now()
	px.hole()
	stop := make(chan struct{})
	stopOnce := sync.Once{}
	stopUploads := func() { stopOnce.Do(func() { close(stop) }) }
	defer stopUploads()
	for i := 0; i < 8; i++ { // keep the session sending: bulk streams into the hole
		go func() {
			st, err := cli.OpenStream()
			if err != nil {
				return
			}
			go func() { <-stop; st.Reset() }() // drops the stream and its queued data, so the check below is not behind it
			b := make([]byte, 64<<10)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := st.Write(append([]byte{'U'}, b...)); err != nil {
					return
				}
			}
		}()
	}
	deadline := time.Now().Add(25 * time.Second)
	for pio.ConnDeaths() < deaths+4 {
		if time.Now().After(deadline) {
			t.Fatalf("stalled conns were not closed: %d deaths since the blackhole", pio.ConnDeaths()-deaths)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("all closed after %v", time.Since(t0))
	for pio.Conns() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not redial: %d conns", pio.Conns())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("redialed after %v", time.Since(t0))
	stopUploads() // the check below is recovery, not a race with eight senders still draining their backlog
	// The upload direction is the one the client controls and recovers at once. The download waits on the server's own
	// idle sockets, which look healthy to it until it writes into them, so it is not asserted here.
	up := pattern(256<<10, 3)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(append([]byte{'U'}, up...)); st.CloseWrite() }()
	sum, err := readAll(st)
	if want := sha256.Sum256(up); err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("upload after the redial: err=%v", err)
	}
	t.Logf("carries data after %v", time.Since(t0))
}

// A pool listener must not let a stranger hold a slot forever: a connection that sends only the 8-byte pool id
// and then idles used to live until its TCP stack died (audit 2026-11-03).
func TestPoolReapsNeverUsedConns(t *testing.T) {
	oldIdle := poolIdleNever
	poolIdleNever = 100 * time.Millisecond
	t.Cleanup(func() { poolIdleNever = oldIdle })

	srv, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("id000000")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the listener kept an unused pool connection open")
	}
}

// One source address cannot take every pool slot: conns beyond poolMaxPerIP from the same IP are refused
// (audit 2026-11-03).
func TestPoolPerIPCap(t *testing.T) {
	old := poolMaxPerIP
	poolMaxPerIP = 2
	t.Cleanup(func() { poolMaxPerIP = old })

	srv, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		id := []byte("id000000")
		id[7] = byte('0' + i)
		if _, err := c.Write(id); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond) // let the server accept it
	}
	last := conns[2]
	_ = last.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := last.Read(make([]byte, 1)); err == nil {
		t.Fatal("listener accepted more conns than poolMaxPerIP from one IP")
	}
}
