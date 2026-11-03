package wat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// revIran is the Iran side of a reverse pool: a listener (merged pool) plus the session client on top of it.
type revIran struct {
	ps  *TCPPoolServer
	io  *ReverseListenIO
	cli *Session
}

func revListen(t *testing.T, flavor, addr string, key []byte) *revIran {
	t.Helper()
	var ps *TCPPoolServer
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for { // a restart rebinds the same port: allow the old socket a moment to go away
		switch flavor {
		case "ws":
			ps, err = NewWSPoolServer(addr, HTTPServerOptions{Path: "/wat"})
		default:
			ps, err = NewTCPPoolServer(addr)
		}
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	rio := NewReverseListenIO(ps)
	cli, err := NewSession(Config{Key: key}, rio)
	if err != nil {
		t.Fatal(err)
	}
	r := &revIran{ps: ps, io: rio, cli: cli}
	t.Cleanup(r.stop)
	return r
}

func (r *revIran) stop() { r.cli.Close(); r.io.Close() }

// revKharej is the Kharej side: a session server whose RawIO dials the Iran listener out.
func revKharej(t *testing.T, flavor, addr string, key []byte) (*Server, *ReverseDialRaw) {
	t.Helper()
	var c *TCPPoolClient
	var err error
	switch flavor {
	case "ws":
		c, err = NewWSPoolClient(addr, 8, HTTPClientOptions{Path: "/wat", Host: "cdn.example.com"})
	default:
		c, err = NewTCPPoolClient(addr, 8)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw := NewReverseDialRaw(c)
	srv := NewServer(Config{Key: key}, raw)
	srv.IdleTimeout = 5 * time.Second
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-srv.New:
				go func(s *Session) {
					for {
						st, err := s.Accept()
						if err != nil {
							return
						}
						go serveUDPStream(st)
					}
				}(s)
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); srv.Close() })
	return srv, raw
}

func revBulk(t *testing.T, cli *Session, n int) {
	t.Helper()
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
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func revBulkTest(t *testing.T, flavor string) {
	key := []byte("rev-key")
	ir := revListen(t, flavor, "127.0.0.1:0", key)
	revKharej(t, flavor, ir.io.Addr().String(), key)
	t0 := time.Now()
	revBulk(t, ir.cli, 4<<20)
	t.Logf("%s reverse 4 MiB up+down in %v", flavor, time.Since(t0))
}

func TestReverseTCPBulk(t *testing.T) { revBulkTest(t, "tcp") }
func TestReverseWSBulk(t *testing.T)  { revBulkTest(t, "ws") }

// The Iran side restarts (new listener on the same port, new session): the Kharej side redials by itself and a
// new session's streams work.
func TestReverseListenerRestart(t *testing.T) {
	for _, flavor := range []string{"tcp", "ws"} {
		key := []byte("rev-key")
		addr := freeAddr(t)
		ir := revListen(t, flavor, addr, key)
		_, raw := revKharej(t, flavor, addr, key)
		revBulk(t, ir.cli, 1<<20)
		ir.stop()
		for end := time.Now().Add(time.Second); raw.Conns() != 0 && time.Now().Before(end); {
			time.Sleep(10 * time.Millisecond)
		}
		ir2 := revListen(t, flavor, addr, key)
		deadline := time.Now().Add(10 * time.Second)
		for ir2.io.Conns() < 8 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: server did not redial: %d conns", flavor, ir2.io.Conns())
			}
			time.Sleep(50 * time.Millisecond)
		}
		revBulk(t, ir2.cli, 1<<20)
	}
}

func TestReverseKillConnsMidTransfer(t *testing.T) {
	key := []byte("rev-key")
	ir := revListen(t, "tcp", "127.0.0.1:0", key)
	_, raw := revKharej(t, "tcp", ir.io.Addr().String(), key)
	stop := make(chan struct{})
	go func() {
		for _, d := range []time.Duration{150, 400} {
			select {
			case <-time.After(d * time.Millisecond):
				ir.ps.kill(3)
			case <-stop:
				return
			}
		}
	}()
	revBulk(t, ir.cli, 6<<20)
	close(stop)
	deadline := time.Now().Add(8 * time.Second)
	for raw.Conns() < 8 || ir.io.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: dialer %d, listener %d", raw.Conns(), ir.io.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestReverseDialHook(t *testing.T) {
	key := []byte("rev-hook-key")
	ir := revListen(t, "tcp", "127.0.0.1:0", key)
	var hooked atomic.Int32
	// the option, not SetDialHook: slots start dialing at once, a later hook misses the first redial
	c, err := NewTCPPoolClientOptions(ir.io.Addr().String(), 4, TCPClientOptions{DialHook: func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error) {
		conn, err := inner(ctx, slot)
		if err == nil {
			hooked.Add(1)
		}
		return conn, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw := NewReverseDialRaw(c)
	srv := NewServer(Config{Key: key}, raw)
	srv.IdleTimeout = 5 * time.Second
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-srv.New:
				go func(s *Session) {
					for {
						st, err := s.Accept()
						if err != nil {
							return
						}
						go serveUDPStream(st)
					}
				}(s)
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); srv.Close(); raw.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for hooked.Load() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("hooked %d conns, want at least 4", hooked.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	revBulk(t, ir.cli, 64<<10)
}

// stubConn lets the pool tests build poolConns without a socket: only Close is ever touched by the code under test.
type stubConn struct{ closed atomic.Bool }

func (c *stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { c.closed.Store(true); return nil }
func (c *stubConn) LocalAddr() net.Addr              { return nil }
func (c *stubConn) RemoteAddr() net.Addr             { return nil }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func newTrustedTestPool() *TCPPoolServer {
	s := &TCPPoolServer{pools: map[string]map[*poolConn]struct{}{}, ordered: map[string][]*poolConn{},
		done: make(chan struct{})}
	s.merge.Store(true)
	return s
}

func testPoolConn(t *testing.T, ip string) *poolConn {
	t.Helper()
	pc := newPoolConn(&stubConn{})
	pc.ip = ip
	t.Cleanup(pc.fail)
	return pc
}

// A stranger who merely opened a connection to a reverse listener must never be chosen to receive the tunnel's
// packets: only a source that delivered an authenticated packet is in the send set (audit 2026-11-03).
func TestReversePoolSendsOnlyToAuthenticatedSource(t *testing.T) {
	s := newTrustedTestPool()
	good := testPoolConn(t, "10.0.0.1")
	bad := testPoolConn(t, "10.0.0.2")
	bad.born = time.Now().Add(-time.Minute) // past its trust grace: an old connection that never authenticated
	s.pools[reverseKey] = map[*poolConn]struct{}{good: {}, bad: {}}
	s.ordered[reverseKey] = []*poolConn{good, bad}

	// Before any source authenticated there is nothing to protect yet: the pool still starts up.
	if err := s.SendTo([]byte("hello"), 0, poolAddr{key: reverseKey}); err != nil {
		t.Fatal(err)
	}
	if n := len(good.q) + len(bad.q); n != 1 {
		t.Fatalf("before trust %d datagrams queued, want 1", n)
	}
	s.addTrustedIP("10.0.0.1")
	for range 16 {
		if err := s.SendTo([]byte("data"), 0, poolAddr{key: reverseKey}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-bad.done:
	default:
		t.Fatal("unauthenticated connection was never closed")
	}
	if s.ipTrusted("10.0.0.2") {
		t.Fatal("unauthenticated source reported trusted")
	}
	if !s.ipTrusted("10.0.0.1") {
		t.Fatal("authenticated source reported untrusted")
	}
}

// A full merged reverse pool must still admit a new dialer (evicting the oldest conn) instead of letting strangers
// lock the real side out of its own pool.
func TestReversePoolEvictsForNewDialer(t *testing.T) {
	s := newTrustedTestPool()
	conns := make([]*poolConn, 0, poolMaxConns+1)
	for i := 0; i < poolMaxConns+1; i++ {
		pc := testPoolConn(t, "10.0.0.1")
		conns = append(conns, pc)
		if !s.add(reverseKey, pc) {
			t.Fatalf("add %d refused: a full reverse pool must evict instead", i)
		}
	}
	if n := len(s.ordered[reverseKey]); n != poolMaxConns {
		t.Fatalf("pool holds %d conns, want %d", n, poolMaxConns)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-conns[0].done:
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("oldest connection was not evicted")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The reverse carrier must turn a session-authenticated source address into a pool trust pin, and ignore anything
// that is not a pool address.
func TestReversePeerAuthenticatedPinsSource(t *testing.T) {
	s := newTrustedTestPool()
	rio := NewReverseListenIO(s)
	rio.PeerAuthenticated(poolAddr{key: reverseKey, ip: "192.0.2.7"})
	rio.PeerAuthenticated(poolAddr{key: reverseKey, ip: "192.0.2.7"}) // duplicate is harmless
	if !s.ipTrusted("192.0.2.7") {
		t.Fatal("authenticated source not trusted")
	}
	if s.ipTrusted("192.0.2.8") {
		t.Fatal("a different source was trusted")
	}
	rio.PeerAuthenticated(nil) // no address: ignored
	if got := len(*s.trusted.Load()); got != 1 {
		t.Fatalf("trusted set has %d addresses, want 1", got)
	}
}
