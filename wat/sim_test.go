package wat

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// simDir is one direction of a lossy, delayed, rate-limited link with a size cap (700 B default: the ICMP-path
// model; the R3 Hornet-MTU experiment needs a wider pipe: newSimDirCap).
type simDir struct {
	mu       sync.Mutex
	loss     float64
	delay    time.Duration
	bps      float64
	maxQueue time.Duration
	capBytes int
	free     time.Time
	q        chan simItem
	out      chan []byte
	rnd      *rand.Rand
	dropped  int
	sent     int
	recQ     bool            // record the queueing delay every packet met
	qd       []time.Duration // (recQ only)
}

type simItem struct {
	at time.Time
	p  []byte
}

func newSimDir(loss float64, delay time.Duration, bps float64, maxQueue time.Duration, seed int64) *simDir {
	return newSimDirCap(loss, delay, bps, maxQueue, seed, 700)
}

// newSimDirCap is newSimDir with a different per-packet size cap.
func newSimDirCap(loss float64, delay time.Duration, bps float64, maxQueue time.Duration, seed int64, capBytes int) *simDir {
	d := &simDir{loss: loss, delay: delay, bps: bps, maxQueue: maxQueue, capBytes: capBytes,
		q: make(chan simItem, 1<<16), out: make(chan []byte, 1<<16), rnd: rand.New(rand.NewSource(seed))}
	go func() {
		for it := range d.q {
			if w := time.Until(it.at); w > 0 {
				time.Sleep(w)
			}
			select {
			case d.out <- it.p:
			default:
			}
		}
	}()
	return d
}

func (d *simDir) send(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent++
	now := time.Now()
	if len(p) > d.capBytes {
		d.dropped++
		return
	}
	start := d.free
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > d.maxQueue {
		d.dropped++
		return
	}
	if d.recQ {
		d.qd = append(d.qd, start.Sub(now))
	}
	d.free = start.Add(time.Duration(float64(len(p)+28) / d.bps * float64(time.Second)))
	if d.rnd.Float64() < d.loss {
		d.dropped++
		return
	}
	d.q <- simItem{d.free.Add(d.delay), append([]byte(nil), p...)}
}

type simIO struct {
	tx, rx *simDir
	done   chan struct{}
	once   sync.Once
}

func (s *simIO) Send(p []byte, lane int) error { s.tx.send(p); return nil }
func (s *simIO) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-s.rx.out:
		return p, 0, nil, nil
	case <-s.done:
		return nil, 0, nil, io.EOF
	}
}
func (s *simIO) SetPeer(net.Addr) {}
func (s *simIO) Close() error     { s.once.Do(func() { close(s.done) }); return nil }

func newPair(t testing.TB, loss float64, delay time.Duration, bps float64, cfg Config) (cli, srv *Session, up, down *simDir) {
	up = newSimDir(loss, delay, bps, 100*time.Millisecond, 1)
	down = newSimDir(loss, delay, bps, 100*time.Millisecond, 2)
	key := []byte("test-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	cc.Paths = 4
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

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(int64(seed)))
	r.Read(b)
	return b
}

func readAll(st *Stream) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, st)
	return buf.Bytes(), err
}

// Upload: client -> server, 2% loss, 20 ms one way, 10 MB/s link.
func TestUploadLossy(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	data := pattern(24<<20, 7)
	got := make(chan []byte, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			got <- nil
			return
		}
		b, _ := readAll(st)
		got <- b
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	t0 := time.Now()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case b := <-got:
		el := time.Since(t0)
		if sha256.Sum256(b) != sha256.Sum256(data) {
			t.Fatalf("data mismatch: got %d want %d bytes", len(b), len(data))
		}
		s := cli.Stats()
		t.Logf("upload %.1f MB/s in %v, retrans=%d rate=%.1fMB/s srtt=%v min=%v", float64(len(data))/el.Seconds()/1e6, el.Round(time.Millisecond), s.Retrans, s.RateBps/1e6, s.SRTT, s.MinRTT)
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
}

// Download: server -> client over the same link.
func TestDownloadLossy(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	data := pattern(24<<20, 9)
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
		s := srv.Stats()
		t.Logf("download %.1f MB/s in %v, retrans=%d rate=%.1fMB/s srtt=%v min=%v", float64(len(data))/el.Seconds()/1e6, el.Round(time.Millisecond), s.Retrans, s.RateBps/1e6, s.SRTT, s.MinRTT)
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
}

// 200 streams at once, each echoed through the server, mixed sizes.
func TestManyStreams(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			size := 100 + (i%10)*30000
			data := pattern(size, byte(i))
			st, err := cli.OpenStream()
			if err != nil {
				t.Error(err)
				return
			}
			go func() { st.Write(data); st.CloseWrite() }()
			b, err := readAll(st)
			if err != nil || !bytes.Equal(b, data) {
				t.Errorf("stream %d: err=%v got %d want %d", i, err, len(b), len(data))
			}
		}(i)
	}
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(90 * time.Second):
		t.Fatal("timeout")
	}
}

// Small request/response latency while a bulk download is running: the interactive-first scheduler and the
// pacer's short queues should keep this near the link RTT (40 ms).
func TestInteractiveDuringBulk(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	bulk := pattern(64<<20, 3)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulk)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(3 * time.Second) // let the bulk flow ramp up
	var lat []time.Duration
	for i := 0; i < 40; i++ {
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		time.Sleep(50 * time.Millisecond)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	s := srv.Stats()
	t.Logf("interactive during bulk: p50=%v p90=%v max=%v (server rate %.1f MB/s srtt=%v min=%v)", lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)-1], s.RateBps/1e6, s.SRTT, s.MinRTT)
	if lat[len(lat)/2] > 250*time.Millisecond {
		t.Fatalf("interactive latency too high: p50=%v", lat[len(lat)/2])
	}
}

func TestRejectsForeignKey(t *testing.T) {
	cli, srv, up, _ := newPair(t, 0, 5*time.Millisecond, 10e6, Config{})
	_ = cli
	// a packet sealed with another key must never create a stream
	other, _ := NewSession(Config{Key: []byte("other"), Paths: 1, SID: 0x1234567}, &simIO{up, newSimDir(0, 0, 1e6, time.Second, 5), make(chan struct{}), sync.Once{}})
	defer other.Close()
	st, _ := other.OpenStream()
	st.Write([]byte("hello"))
	time.Sleep(300 * time.Millisecond)
	srv.mu.Lock()
	n := len(srv.streams)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("server accepted %d streams from a foreign key", n)
	}
}

// streamCount reports how many streams the session still holds.
func streamCount(s *Session) int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }

// waitStreams waits (up to 5 s) for a session's stream count to reach want.
func waitStreams(t *testing.T, s *Session, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if streamCount(s) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stream count stayed at %d, want %d", streamCount(s), want)
}

// TestCloseReadReapsLingeringStream pins the stream-leak fix. A stream whose local reader stops while data is still
// buffered (peer finished) -- or while the peer is still sending -- must be reaped by CloseRead, not held forever.
// Before the fix the client kept such streams open with no local connection behind them (field 2026-10-13: Iran
// stuck at 76 streams with zero established TCP on the load port).
func TestCloseReadReapsLingeringStream(t *testing.T) {
	// (a) peer sent everything and FIN'd, local reader consumed nothing.
	t.Run("peer_finished_unread", func(t *testing.T) {
		cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
		go func() {
			ss, err := srv.Accept()
			if err != nil {
				return
			}
			ss.Write(pattern(200000, 3))
			ss.CloseWrite()
			readAll(ss) // drain our FIN side so the server stream can retire too
		}()
		st, _ := cli.OpenStream()
		st.Write([]byte{0})
		st.CloseWrite()
		// wait until the peer's data+FIN is buffered but unread
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			cli.mu.Lock()
			ok := st.eof && st.ready.n > 0
			cli.mu.Unlock()
			if ok {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cli.mu.Lock()
		eof, ready := st.eof, st.ready.n
		cli.mu.Unlock()
		if !eof || ready == 0 {
			t.Fatalf("setup: want buffered-unread data with peer FIN, got eof=%v ready=%d", eof, ready)
		}
		st.CloseRead()
		waitStreams(t, cli, 0) // the lingering stream must be reaped, not held
	})

	// (b) peer still sending, local reader gone: CloseRead must reset the stream so both ends reap.
	t.Run("peer_sending_reset", func(t *testing.T) {
		cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
		go func() {
			ss, err := srv.Accept()
			if err != nil {
				return
			}
			for i := 0; i < 200; i++ { // keep sending; the reset will end it
				if _, err := ss.Write(pattern(4096, byte(i))); err != nil {
					return
				}
			}
		}()
		st, _ := cli.OpenStream()
		st.Write([]byte{0})
		waitStreams(t, cli, 1) // stream is open
		st.CloseRead()         // reader gone while peer is still sending
		waitStreams(t, cli, 0)
		waitStreams(t, srv, 0) // the RST reaches the server and it reaps too
	})
}

// TestSilenceWatchdogRearms pins the 30 s silence watchdog fix (audit 2026-10-22): the watchdog used to
// zero lastRecv after one reset and so fired exactly once — a session that stayed silent afterward kept
// accepting streams whose writes blocked forever. After a reset the watchdog must fire again in the next
// silence window, and a stream opened across a dead link must fail instead of hanging.
func TestSilenceWatchdogRearms(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
	_ = srv
	st, _ := cli.OpenStream()
	st.Write([]byte("hi"))
	waitStreams(t, cli, 1)
	// simulate 30 s of silence without waiting: rewind lastRecv on both ends
	rewind := func(s *Session) {
		s.mu.Lock()
		s.lastRecv = time.Now().Add(-31 * time.Second)
		s.mu.Unlock()
	}
	rewind(cli)
	rewind(srv)
	// one pump tick on each end resets the stream tables
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && streamCount(cli) != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if streamCount(cli) != 0 {
		t.Fatal("watchdog did not fire on the first silence")
	}
	// the path stays silent: the watchdog must fire AGAIN (before the fix it was disarmed)
	rewind(cli)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cli.mu.Lock()
		armed := !cli.lastRecv.IsZero()
		cli.mu.Unlock()
		if !armed { // lastRecv zeroed would mean the old one-shot path ran
			t.Fatal("watchdog was disarmed again (one-shot regression)")
		}
		// after the second window it must have reset again: lastRecv re-armed to now each time
		cli.mu.Lock()
		fired := time.Since(cli.lastRecv) < time.Second
		cli.mu.Unlock()
		if fired {
			return // second reset ran and re-armed: the fix holds
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("watchdog did not re-arm after the first reset")
}
