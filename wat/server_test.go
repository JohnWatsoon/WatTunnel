package wat

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// simHub is one server socket with several clients behind it, each with its own lossy up and down link.
type simHub struct {
	in      chan hubPkt
	mu      sync.Mutex
	done    chan struct{}
	downs   map[string]*simDir
	reflect map[string]bool // destinations whose host bounces every packet back (a kernel echo reply)
}

type hubPkt struct {
	p    []byte
	src  strAddr
	lane int
}

type strAddr string

func (a strAddr) Network() string { return "sim" }
func (a strAddr) String() string  { return string(a) }

func (h *simHub) Recv() ([]byte, int, net.Addr, error) {
	select {
	case r := <-h.in:
		return r.p, r.lane, r.src, nil
	case <-h.quit():
		return nil, 0, nil, io.EOF
	}
}

func (h *simHub) quit() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

func (h *simHub) SendTo(p []byte, lane int, dst net.Addr) error {
	h.mu.Lock()
	d := h.downs[dst.String()]
	bounce := h.reflect[dst.String()]
	h.mu.Unlock()
	if d != nil {
		d.send(p)
	}
	if bounce {
		select {
		case h.in <- hubPkt{append([]byte(nil), p...), strAddr(dst.String()), lane}:
		default:
		}
	}
	return nil
}

// Close ends the current server's Recv; the next server starts with a fresh channel.
func (h *simHub) Close() error {
	h.mu.Lock()
	if h.done != nil {
		close(h.done)
		h.done = nil
	}
	h.mu.Unlock()
	return nil
}

// client returns a PacketIO for client `name` plus its closer.
func (h *simHub) client(name string, loss float64, delay time.Duration, bps float64, seed int64) PacketIO {
	up := newSimDir(loss, delay, bps, 100*time.Millisecond, seed)
	down := newSimDir(loss, delay, bps, 100*time.Millisecond, seed+1)
	h.mu.Lock()
	h.downs[name] = down
	h.mu.Unlock()
	go func() {
		for p := range up.out {
			h.in <- hubPkt{p, strAddr(name), 0}
		}
	}()
	return &simIO{up, down, make(chan struct{}), sync.Once{}}
}

func newHub(t *testing.T) (*simHub, *Server) {
	h := &simHub{in: make(chan hubPkt, 1<<16), downs: map[string]*simDir{}}
	srv := NewServer(Config{Key: []byte("hub-key")}, h)
	srv.IdleTimeout = 3 * time.Second
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() { io.Copy(st, st); st.CloseWrite() }()
				}
			}(s)
		}
	}()
	t.Cleanup(srv.Close)
	return h, srv
}

func echoOnce(t *testing.T, cli *Session, n int, seed byte) {
	t.Helper()
	data := pattern(n, seed)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()
	got := make(chan []byte, 1)
	go func() { b, _ := readAll(st); got <- b }()
	select {
	case b := <-got:
		if !bytes.Equal(b, data) {
			t.Fatalf("echo mismatch: got %d want %d", len(b), n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("echo timeout")
	}
}

// Two client processes on the same key at once (the two slots of a handover) must not disturb each other.
func TestTwoClientsSameKey(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a", 0.02, 20*time.Millisecond, 10e6, 10))
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("b", 0.02, 20*time.Millisecond, 10e6, 20))
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	for i, c := range []*Session{a, b} {
		wg.Add(1)
		go func(i int, c *Session) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				echoOnce(t, c, 600000, byte(10*i+j))
			}
		}(i, c)
	}
	wg.Wait()
	if n := srv.Sessions(); n != 2 {
		t.Fatalf("server has %d sessions, want 2", n)
	}
}

// A client that restarts within two seconds is a new session; the old one expires on its own, nothing hangs.
func TestClientRestart(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a1", 0.02, 20*time.Millisecond, 10e6, 30))
	echoOnce(t, a, 200000, 1)
	a.Close() // killed without a goodbye
	time.Sleep(2 * time.Second)
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a2", 0.02, 20*time.Millisecond, 10e6, 40))
	defer b.Close()
	for j := 0; j < 3; j++ { // stream ids restart at 1 in the new process: must not collide with the old one's
		echoOnce(t, b, 300000, byte(j+5))
	}
	// The old session (a) must expire on its own; keep b authenticated for the same 6 s. A silent b can lose a
	// 2 %-loss keepalive and exceed the rig's 3 s idle timeout, which flaked this test ~7 % on the release gate
	// (audit 2026-11-03). A ping every second makes that impossible without changing what the test checks.
	for i := 0; i < 6; i++ {
		echoOnce(t, b, 300000, byte(0x10+i))
		time.Sleep(time.Second)
	}
	if n := srv.Sessions(); n != 1 {
		t.Fatalf("server still holds %d sessions after the old one went idle, want 1", n)
	}
}

// The server's cumulative counters must not go backwards when a client session closes: the stats log subtracts
// the previous total, and a smaller total wrapped to ~1.8e19 ("out=18446744073709551594").
func TestServerStatsMonotonicAfterSessionCloses(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("m1", 0, 10*time.Millisecond, 10e6, 50))
	echoOnce(t, a, 200000, 3)
	before := srv.Stats()
	if before.PktsOut == 0 || before.PktsIn == 0 {
		t.Fatalf("no traffic counted: %+v", before)
	}
	a.Close()
	deadline := time.Now().Add(10 * time.Second)
	for srv.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if n := srv.Sessions(); n != 0 {
		t.Fatalf("session did not expire (%d left)", n)
	}
	after := srv.Stats()
	if after.PktsOut < before.PktsOut || after.PktsIn < before.PktsIn || after.BytesOut < before.BytesOut || after.BytesIn < before.BytesIn {
		t.Fatalf("totals went backwards after the session closed: before %+v after %+v", before, after)
	}
}

// Reverse ICMP: the client host's kernel answers each of the server's requests with a copy of it. Those copies must
// not keep a dead client's session alive (before 2.0.1 they did, so every client restart leaked a session slot), and
// LastRecv must only move on authenticated client packets.
func TestServerIgnoresReflections(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, h.client("rf1", 0, 10*time.Millisecond, 10e6, 80))
	echoOnce(t, a, 50000, 4)
	h.mu.Lock()
	h.reflect = map[string]bool{"rf1": true}
	h.mu.Unlock()
	a.Close()
	last := srv.LastRecv()
	if last.IsZero() || time.Since(last) > 2*time.Second {
		t.Fatalf("LastRecv %v after live traffic", last)
	}
	deadline := time.Now().Add(10 * time.Second)
	for srv.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if n := srv.Sessions(); n != 0 {
		t.Fatalf("reflected packets kept the dead session alive (%d left)", n)
	}
	if got := srv.LastRecv(); !got.Equal(last) && got.Sub(last) > 100*time.Millisecond {
		t.Fatalf("LastRecv moved on reflections: %v -> %v", last, got)
	}
}

// A too-small pooled buffer must go back without blocking: a concurrent putBuf can refill the freed slot first, and a
// blocking send then wedges the server's only receive loop for good (field: every speed test after the first failed,
// audit 2026-10-27).
func TestGetBufNeverBlocks(t *testing.T) {
	srv := &Server{free: make(chan []byte, 1)}
	srv.free <- make([]byte, 16)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // readers take the tiny buffer and find it too small
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					srv.getBuf(make([]byte, 4096))
				}
			}
		}()
	}
	for i := 0; i < 4; i++ { // writers race to refill the slot the reader just freed
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					srv.putBuf(make([]byte, 16))
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("getBuf blocked forever returning a too-small buffer")
	}
}

// A draining server serves its sessions to the end but takes no new ones.
func TestDrain(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, h.client("d1", 0, 10*time.Millisecond, 10e6, 50))
	defer a.Close()
	echoOnce(t, a, 100000, 2)
	srv.Drain()
	echoOnce(t, a, 100000, 3) // existing session keeps working
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, h.client("d2", 0, 10*time.Millisecond, 10e6, 60))
	defer b.Close()
	time.Sleep(500 * time.Millisecond)
	if n := srv.Sessions(); n != 1 {
		t.Fatalf("draining server has %d sessions, want 1", n)
	}
}

// The server process restarts (new boot id, no memory of any stream): the client must notice, drop its dead streams
// and carry on with new ones. Before the boot frame existed the old connections just hung; since 2.10.0 the kex
// switch reintroduced the hang (a restarted server cannot open the switched client's fresh key) until the PSK
// restart probe — the kexWait below pins that the switch has really happened before the restart.
func TestServerRestart(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4, Logf: t.Logf}, h.client("r1", 0.01, 15*time.Millisecond, 10e6, 70))
	defer a.Close()
	echoOnce(t, a, 100000, 1)
	kexWait(t, "the client to switch keys before the restart", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.kexDone
	})
	// a stream that is open while the server dies
	hang, _ := a.OpenStream()
	hang.Write([]byte("hello"))
	if _, err := io.ReadFull(hang, make([]byte, 5)); err != nil { // the old server echoes it
		t.Fatal(err)
	}
	srv.Close()
	time.Sleep(200 * time.Millisecond)
	srv2 := NewServer(Config{Key: []byte("hub-key"), Logf: t.Logf}, h)
	srv2.IdleTimeout = 5 * time.Second
	go func() {
		for s := range srv2.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() { io.Copy(st, st); st.CloseWrite() }()
				}
			}(s)
		}
	}()
	defer srv2.Close()
	done := make(chan error, 1)
	go func() { _, err := hang.Read(make([]byte, 10)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("old stream read succeeded after the server restarted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("old stream still hangs 10 s after the server restarted")
	}
	echoOnce(t, a, 200000, 2) // new streams on the same client session work
}

// tapIO copies every datagram a client puts on the wire, so a test can replay it later.
type tapIO struct {
	PacketIO
	mu   sync.Mutex
	last []byte
}

func (t *tapIO) Send(p []byte, lane int) error {
	t.mu.Lock()
	t.last = append(t.last[:0], p...)
	t.mu.Unlock()
	return t.PacketIO.Send(p, lane)
}

func (t *tapIO) packet() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.last...)
}

// A captured packet must not keep its session alive after the client dies, and must not open a new session once the
// old one has left the table: before 2026-10-28 any packet with a known sid refreshed the idle clock, and admit
// accepted any valid old packet as a new session.
func TestServerRejectsSessionReplay(t *testing.T) {
	h, srv := newHub(t) // IdleTimeout 3 s
	tap := &tapIO{PacketIO: h.client("rp1", 0, 5*time.Millisecond, 10e6, 90)}
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, tap)
	echoOnce(t, a, 50000, 8)
	time.Sleep(200 * time.Millisecond) // a fresh authenticated packet lands in the tap
	pkt := tap.packet()
	if len(pkt) < hdrLen+tagLen+1 {
		t.Fatalf("captured packet is %d bytes, too short to replay", len(pkt))
	}
	a.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(200 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				select {
				case h.in <- hubPkt{append([]byte(nil), pkt...), strAddr("rp1"), 0}:
				default:
				}
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for srv.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := srv.Sessions(); n != 0 {
		t.Fatalf("replayed packets kept the dead session alive (%d left)", n)
	}
	h.in <- hubPkt{append([]byte(nil), pkt...), strAddr("rp1"), 0} // one more replay: retired pn, must not open a session
	time.Sleep(300 * time.Millisecond)
	if n := srv.Sessions(); n != 0 {
		t.Fatalf("a replayed packet opened a new session")
	}
}

// Alive and the server idle timeout follow -ping-every: a raised keepalive gap must not read as a dead link.
func TestAliveScalesWithPingEvery(t *testing.T) {
	s := &Session{cfg: Config{PingEvery: 10 * time.Second}}
	s.lastAuth = time.Now().Add(-20 * time.Second)
	if !s.Alive() {
		t.Fatal("20 s of silence with a 10 s ping interval read as dead (limit is 3x = 30 s)")
	}
	s.lastAuth = time.Now().Add(-31 * time.Second)
	if s.Alive() {
		t.Fatal("silence past 3x PingEvery read as alive")
	}
	h := &simHub{in: make(chan hubPkt, 1), downs: map[string]*simDir{}}
	srv := NewServer(Config{Key: []byte("hub-key"), PingEvery: 40 * time.Second}, h)
	defer srv.Close()
	if srv.IdleTimeout < 120*time.Second {
		t.Fatalf("IdleTimeout %v with a 40 s ping interval, want >= 120 s", srv.IdleTimeout)
	}
}

// A full server gives the slot of a silent session to a new client instead of refusing it until the idle timeout.
func TestServerEvictsStaleWhenFull(t *testing.T) {
	old := staleAfter
	staleAfter = 300 * time.Millisecond
	defer func() { staleAfter = old }()
	h, srv := newHub(t)
	srv.MaxSessions = 1
	srv.IdleTimeout = time.Hour
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("e1", 0, 5*time.Millisecond, 10e6, 50))
	echoOnce(t, a, 20000, 1)
	a.Close() // gone without the server noticing
	time.Sleep(500 * time.Millisecond)
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("e2", 0, 5*time.Millisecond, 10e6, 50))
	defer b.Close()
	echoOnce(t, b, 20000, 2)
	if n := srv.Sessions(); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}
