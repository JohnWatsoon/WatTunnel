package wat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bondDir is one direction of an emulated carrier: delay, a rate limit with a drop-tail queue and a 700 B size cap,
// like simDir, but its delivery goroutine ends with the link (simDir's lives for the whole test binary, which adds
// up under the race detector when many rigs are built).
type bondDir struct {
	mu       sync.Mutex
	delay    time.Duration
	bps      float64
	maxQueue time.Duration
	free     time.Time
	q        chan simItem
	out      chan []byte
	done     chan struct{}
	drops    atomic.Int64
}

func newBondDir(delay time.Duration, bps float64, done chan struct{}) *bondDir {
	d := &bondDir{delay: delay, bps: bps, maxQueue: 100 * time.Millisecond, done: done,
		q: make(chan simItem, 8192), out: make(chan []byte, 8192)}
	go func() {
		for {
			select {
			case <-done:
				return
			case it := <-d.q:
				if w := time.Until(it.at); w > 0 {
					time.Sleep(w)
				}
				select {
				case d.out <- it.p:
				default:
				}
			}
		}
	}()
	return d
}

func (d *bondDir) send(p []byte) {
	if len(p) > 700 {
		return
	}
	d.mu.Lock()
	now := time.Now()
	start := d.free
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > d.maxQueue {
		d.mu.Unlock()
		d.drops.Add(1)
		return
	}
	d.free = start.Add(time.Duration(float64(len(p)+28) / d.bps * float64(time.Second)))
	at := d.free.Add(d.delay)
	d.mu.Unlock()
	select {
	case d.q <- simItem{at, append([]byte(nil), p...)}:
	default:
	}
}

// bondLink is one emulated carrier that can be hard-blocked (every packet dropped in both directions, including
// those already in flight).
type bondLink struct {
	up, down *bondDir
	blocked  atomic.Bool
	prof     Profile
	done     chan struct{}
}

func newBondLink(t testing.TB, delay time.Duration, bps float64) *bondLink {
	l := &bondLink{done: make(chan struct{})}
	l.up, l.down = newBondDir(delay, bps, l.done), newBondDir(delay, bps, l.done)
	t.Cleanup(func() { close(l.done) })
	return l
}

type linkClient struct {
	l    *bondLink
	port int // local UDP port the leg reports (Bifrost frEndpoint announce, 3.3.9); 0 = no bound socket
	done chan struct{}
	once sync.Once
}

func (c *linkClient) Send(p []byte, path int) error {
	if !c.l.blocked.Load() {
		c.l.up.send(p)
	}
	return nil
}

func (c *linkClient) Recv() ([]byte, int, net.Addr, error) {
	for {
		select {
		case p := <-c.l.down.out:
			if c.l.blocked.Load() {
				continue
			}
			return p, 0, strAddr("srv"), nil
		case <-c.done:
			return nil, 0, nil, io.EOF
		}
	}
}
func (c *linkClient) SetPeer(net.Addr) {}
func (c *linkClient) Close() error     { c.once.Do(func() { close(c.done) }); return nil }
func (c *linkClient) Profile() Profile { return c.l.prof }

// PathLocalPort reports the leg's bound local port for the Bifrost frEndpoint announce (3.3.9); 0 = none.
func (c *linkClient) PathLocalPort() int { return c.port }

type linkRaw struct {
	l    *bondLink
	done chan struct{}
	once sync.Once
}

func (r *linkRaw) Recv() ([]byte, int, net.Addr, error) {
	for {
		select {
		case p := <-r.l.up.out:
			if r.l.blocked.Load() {
				continue
			}
			// an IP-bearing source, like a real udp raw reports: the server-side Bifrost path (SetPathEndpoint,
			// 3.3.9) binds an announced ":down" port to the authenticated source address
			return p, 0, &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 4444}, nil
		case <-r.done:
			return nil, 0, nil, io.EOF
		}
	}
}
func (r *linkRaw) SendTo(p []byte, lane int, dst net.Addr) error {
	if !r.l.blocked.Load() {
		r.l.down.send(p)
	}
	return nil
}
func (r *linkRaw) Close() error     { r.once.Do(func() { close(r.done) }); return nil }
func (r *linkRaw) Profile() Profile { return r.l.prof }

// A bonded session must leave path choice to the chooser: its own pin lanes (PinLaneBase+slot) are not chooser paths,
// so a pinned bulk packet fell back to carrier 0 on the client (BondIO clamps) or was dropped as out of range on a
// reverse bond (multiSubIO rejects it).
func TestBondChooserDisablesPin(t *testing.T) {
	l := newBondLink(t, 0, 1e9)
	l.prof = Profile{Reliable: true, MTU: directMTU, MaxMTU: 64 << 10}
	b, err := NewBondIO([]PacketIO{&linkClient{l: l, done: make(chan struct{})}}, BondOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: []byte("bond-key"), Direct: true}, b)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if cli.chooser == nil {
		t.Fatal("bonded session has no chooser")
	}
	if !cli.cc.direct {
		t.Fatal("fixture is not on a direct carrier")
	}
	if cli.pin {
		t.Fatal("bonded session pins bulk packets to lanes the chooser cannot route")
	}
}

var fastTimings = PathTimings{Silence: 300 * time.Millisecond, ProbeFirst: 200 * time.Millisecond, ProbeMax: time.Second, Ramp: 500 * time.Millisecond, IdleProbe: time.Second}

type bondRig struct {
	links []*bondLink
	srv   *Server
	cli   *Session
	key   []byte
}

func newBondRig(t *testing.T, links []*bondLink, tm PathTimings) *bondRig {
	t.Helper()
	key := []byte("bond-key")
	raws := make([]RawIO, len(links))
	names := make([]string, len(links))
	for i, l := range links {
		raws[i] = &linkRaw{l: l, done: make(chan struct{})}
		names[i] = "link" + string(rune('0'+i))
	}
	srv := NewServer(Config{Key: key, Bond: tm}, NewMultiRaw(names, raws))
	srv.IdleTimeout = 20 * time.Second
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
	return &bondRig{links: links, srv: srv, key: key, cli: bondClient(t, links, key, tm, 0)}
}

func bondClient(t *testing.T, links []*bondLink, key []byte, tm PathTimings, sid uint64) *Session {
	t.Helper()
	kids := make([]PacketIO, len(links))
	names := make([]string, len(links))
	for i, l := range links {
		kids[i] = &linkClient{l: l, done: make(chan struct{})}
		names[i] = "link" + string(rune('0'+i))
	}
	b, err := NewBondIO(kids, BondOptions{Names: names, Timings: tm})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key, SID: sid}, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	return cli
}

// bondDownload requests n bytes of pattern(n, 7), verifies them as they arrive (nothing is buffered: the race
// detector multiplies memory) and returns the byte count, the longest gap between two reads and any error.
func bondDownload(cli *Session, n int) (got int, maxGap time.Duration, err error) {
	st, err := cli.OpenStream()
	if err != nil {
		return 0, 0, err
	}
	var h [5]byte
	h[0] = 'D'
	binary.BigEndian.PutUint32(h[1:], uint32(n))
	st.Write(h[:])
	want := rand.New(rand.NewSource(7)) // pattern(n, 7) is this generator's first n bytes
	b, w := make([]byte, 64<<10), make([]byte, 64<<10)
	last := time.Now()
	for {
		k, e := st.Read(b)
		if k > 0 {
			want.Read(w[:k])
			if !bytes.Equal(b[:k], w[:k]) {
				return got, maxGap, errors.New("data corrupted")
			}
			got += k
			if g := time.Since(last); g > maxGap {
				maxGap = g
			}
			last = time.Now()
		}
		if e == io.EOF {
			return got, maxGap, nil
		}
		if e != nil {
			return got, maxGap, e
		}
	}
}

func twoLinks(t testing.TB) []*bondLink {
	return []*bondLink{newBondLink(t, 20*time.Millisecond, 6e6), newBondLink(t, 20*time.Millisecond, 6e6)}
}

// (a) hard-block one carrier mid-transfer: the transfer completes intact, nothing is reset, the stall stays short.
func TestBondBlockMidTransfer(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, PathTimings{})
	const n = 40 << 20
	go func() {
		time.Sleep(1500 * time.Millisecond)
		links[0].blocked.Store(true)
	}()
	t0 := time.Now()
	got, gap, err := bondDownload(rig.cli, n)
	if err != nil || got != n {
		t.Fatalf("download failed (stream reset?): %v after %d bytes", err, got)
	}
	cs := rig.cli.CarrierStats()
	t.Logf("%.1f MB/s total, max stall %v, client %+v server %+v", float64(n)/time.Since(t0).Seconds()/1e6, gap.Round(time.Millisecond), cs, rig.srv.CarrierStats())
	if gap > 2*time.Second {
		t.Errorf("stall %v >= 2 s", gap)
	}
	if cs[0].Alive {
		t.Errorf("blocked carrier still reported alive")
	}
	if ss := rig.srv.CarrierStats(); ss[0].Alive || ss[1].Acked == 0 {
		t.Errorf("server did not move to the surviving carrier: %+v", ss)
	}
}

// (b) unblock: the self-probe revives the dead carrier and it carries traffic again (production backoff is 2 s ..
// 30 s so a revival is at most ~30 s after the path heals; the test uses short timings and checks the mechanism).
func TestBondProbeRevives(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	done := make(chan error, 1)
	go func() { _, _, err := bondDownload(rig.cli, 96<<20); done <- err }()
	time.Sleep(time.Second)
	links[0].blocked.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for rig.cli.CarrierStats()[0].Alive && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rig.cli.CarrierStats()[0].Alive {
		t.Fatal("blocked carrier never declared dead")
	}
	time.Sleep(2 * time.Second) // dead, probes backing off
	before := rig.srv.CarrierStats()[0]
	links[0].blocked.Store(false)
	t1 := time.Now()
	for time.Since(t1) < 8*time.Second {
		c, cc := rig.srv.CarrierStats()[0], rig.cli.CarrierStats()[0]
		if c.Alive && cc.Alive && c.Acked > before.Acked+500 {
			t.Logf("revived and carrying after %v: server %+v client %+v", time.Since(t1).Round(time.Millisecond), c, cc)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("carrier not carrying traffic again: before %+v now server %+v client %+v", before, rig.srv.CarrierStats()[0], rig.cli.CarrierStats()[0])
}

// (c) one carrier 40 ms RTT, the other 150 ms: small interactive exchanges stay near the fast path's delay while a
// bulk download uses both.
func TestBondAsymmetricInteractive(t *testing.T) {
	links := []*bondLink{newBondLink(t, 20*time.Millisecond, 6e6), newBondLink(t, 75*time.Millisecond, 6e6)}
	rig := newBondRig(t, links, PathTimings{})
	bulk := make(chan error, 1)
	var bulkBytes int
	t0 := time.Now()
	go func() {
		d, _, err := bondDownload(rig.cli, 48<<20)
		bulkBytes = d
		bulk <- err
	}()
	time.Sleep(2 * time.Second)
	var lat []time.Duration
	for i := 0; i < 40; i++ {
		st, err := rig.cli.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		st.Write([]byte{'E', 1, 2, 3, 4, 5, 6, 7, 8})
		var rb [9]byte
		if _, err := io.ReadFull(st, rb[:8]); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t1))
		st.Reset()
		time.Sleep(20 * time.Millisecond)
	}
	if err := <-bulk; err != nil {
		t.Fatal(err)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	t.Logf("interactive p50 %v p95 %v; bulk %.1f MB/s; carriers %+v; queue drops down %d/%d; server out %d client in %d retrans %d", lat[len(lat)/2], lat[len(lat)*95/100],
		float64(bulkBytes)/time.Since(t0).Seconds()/1e6, rig.srv.CarrierStats(), links[0].down.drops.Load(), links[1].down.drops.Load(), rig.srv.Stats().PktsOut, rig.cli.Stats().PktsIn, rig.srv.Stats().Retrans)
	if p := lat[len(lat)/2]; p > 90*time.Millisecond {
		t.Errorf("interactive p50 %v, want near the 40 ms carrier", p)
	}
	ss := rig.srv.CarrierStats()
	if ss[1].Acked < 2000 {
		t.Errorf("slow carrier unused by bulk: %+v", ss)
	}
	for _, c := range ss { // the link drops almost nothing: a high loss count means packets are being retransmitted although they arrived
		if c.Sent > 1000 && float64(c.Lost) > 0.1*float64(c.Sent) {
			t.Errorf("carrier %s: %d of %d packets declared lost on a near-lossless link", c.Name, c.Lost, c.Sent)
		}
	}
}

// (d) the client's preferred carrier dies: the server's replies move to the other one on their own.
func TestBondServerMigrates(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	done := make(chan error, 1)
	go func() { _, _, err := bondDownload(rig.cli, 48<<20); done <- err }()
	var before []CarrierStat
	for t1 := time.Now(); time.Since(t1) < 20*time.Second; time.Sleep(50 * time.Millisecond) {
		if before = rig.srv.CarrierStats(); len(before) == 2 && before[0].Alive && before[1].Alive && before[0].Sent > 300 && before[1].Sent > 300 {
			break
		}
	}
	if len(before) != 2 || !before[0].Alive || !before[1].Alive {
		t.Fatalf("both carriers should be in use before the failure: %+v", before)
	}
	links[0].blocked.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for rig.srv.CarrierStats()[0].Alive && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	mid := rig.srv.CarrierStats()
	if mid[0].Alive || mid[1].Share < 0.9 {
		t.Fatalf("server did not migrate: %+v", mid)
	}
	time.Sleep(time.Second)
	after := rig.srv.CarrierStats()
	if after[1].Sent <= mid[1].Sent+500 {
		t.Fatalf("server stopped sending on the live carrier: %+v -> %+v", mid, after)
	}
	if err := <-done; err != nil {
		t.Fatalf("download broke: %v", err)
	}
}

// (e) a client with the wrong key is rejected on every carrier: no session, no reply.
func TestBondForeignKeyRejected(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, PathTimings{})
	for i, set := range [][]*bondLink{{links[0]}, {links[1]}, links} {
		cli := bondClient(t, set, []byte("not-the-key"), PathTimings{}, uint64(100+i))
		st, err := cli.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		st.Write([]byte{'E', 1, 2, 3})
		go func() { time.Sleep(1200 * time.Millisecond); cli.Close() }()
		if _, err := st.Read(make([]byte, 4)); err == nil {
			t.Fatalf("set %d: foreign client got an answer", i)
		}
	}
	if n := rig.srv.Sessions(); n != 1 { // only the rig's own authorised client
		t.Fatalf("%d sessions on the server, want 1: a foreign key was admitted", n)
	}
	// the right key still works afterwards, over each carrier alone and bonded
	for i, set := range [][]*bondLink{{links[0]}, {links[1]}, links} {
		cli := bondClient(t, set, rig.key, PathTimings{}, uint64(200+i))
		got, _, err := bondDownload(cli, 64<<10)
		if err != nil || got != 64<<10 {
			t.Fatalf("set %d: authorised client failed: %v", i, err)
		}
	}
}

// Real loopback sockets: udp + tcp pool bonded, bulk down and up, both carriers carry data.
func TestBondLoopbackUDPTCP(t *testing.T) {
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("bond-loop")
	srv := NewServer(Config{Key: key}, NewMultiRaw([]string{"udp", "tcp"}, []RawIO{us, ts}))
	t.Cleanup(srv.Close)
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
	uc, err := NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc, err := NewTCPPoolClient(ts.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBondIO([]PacketIO{uc, tc}, BondOptions{Names: []string{"udp", "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key}, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	time.Sleep(300 * time.Millisecond)
	got, _, err := bondDownload(cli, 24<<20)
	if err != nil || got != 24<<20 {
		t.Fatalf("download: %v (%d bytes)", err, got)
	}
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	up := pattern(8<<20, 3)
	st.Write([]byte{'U'})
	go func() { st.Write(up); st.CloseWrite() }()
	sum, err := readAll(st)
	want := sha256.Sum256(up)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("upload digest mismatch: %v", err)
	}
	cs := cli.CarrierStats()
	t.Logf("carriers %+v", cs)
	if cs[0].Acked == 0 || cs[1].Acked == 0 {
		t.Errorf("a carrier was never used: %+v", cs)
	}
}

// Two equal carriers carry clearly more than one (the point of bonding besides survival).
func TestBondAggregates(t *testing.T) {
	rate := func(links []*bondLink) float64 {
		rig := newBondRig(t, links, PathTimings{})
		t0 := time.Now()
		d, _, err := bondDownload(rig.cli, 24<<20)
		if err != nil || d != 24<<20 {
			t.Fatalf("download: %v (%d)", err, d)
		}
		return float64(d) / time.Since(t0).Seconds() / 1e6
	}
	one, two := rate(twoLinks(t)[:1]), rate(twoLinks(t))
	t.Logf("1 carrier %.1f MB/s, 2 carriers %.1f MB/s", one, two)
	if two < 1.3*one && !raceBuild {
		t.Errorf("bonding two carriers gave %.1f MB/s vs %.1f for one", two, one)
	}
}

// Unequal capacity at equal delay: the bond is at least as fast as its fast carrier alone and the fast one carries more.
func TestBondUnequalCapacity(t *testing.T) {
	mk := func(n int) []*bondLink {
		l := []*bondLink{newBondLink(t, 20*time.Millisecond, 8e6), newBondLink(t, 20*time.Millisecond, 2e6)}
		return l[:n]
	}
	run := func(links []*bondLink) (float64, []CarrierStat) {
		rig := newBondRig(t, links, PathTimings{})
		t0 := time.Now()
		d, _, err := bondDownload(rig.cli, 32<<20)
		if err != nil || d != 32<<20 {
			t.Fatalf("download: %v (%d)", err, d)
		}
		return float64(d) / time.Since(t0).Seconds() / 1e6, rig.srv.CarrierStats()
	}
	alone, _ := run(mk(1))
	both, cs := run(mk(2))
	t.Logf("fast carrier alone %.1f MB/s, bonded with a 4x slower one %.1f MB/s; server carriers %+v", alone, both, cs)
	if both < 1.05*alone && !raceBuild {
		t.Errorf("bond %.1f MB/s is not faster than the fast carrier alone (%.1f)", both, alone)
	}
	if cs[0].Sent < 2*cs[1].Sent {
		t.Errorf("the 8 MB/s carrier should carry well over the 2 MB/s one: %+v", cs)
	}
}

type mockRawWithProfile struct {
	RawIO
	prof Profile
}

func (m *mockRawWithProfile) Profile() Profile { return m.prof }
func (m *mockRawWithProfile) Recv() ([]byte, int, net.Addr, error) {
	select {}
}
func (m *mockRawWithProfile) SendTo([]byte, int, net.Addr) error { return nil }
func (m *mockRawWithProfile) Close() error                       { return nil }

func TestMultiRawProfilePreservation(t *testing.T) {
	icmpRaw := &mockRawWithProfile{prof: Profile{MTU: 640, MaxMTU: 1400, Reliable: false, InitBps: 1.5e6}}
	tcpRaw := &mockRawWithProfile{prof: Profile{MTU: 16384, MaxMTU: 16384, Reliable: true, InitBps: 2.5e6}}

	mr := NewMultiRaw([]string{"icmp", "tcp"}, []RawIO{icmpRaw, tcpRaw})
	defer mr.Close()

	if prof := mr.Profile(); prof.MTU != 640 || prof.Reliable {
		t.Fatalf("expected MultiRaw conservative profile (MTU 640, unreliable), got %+v", prof)
	}

	sub := newMultiSubIO(&subIO{done: make(chan struct{})}, mr, PathTimings{}, 1)
	if prof := sub.Profile(); prof.MTU != 16384 || !prof.Reliable {
		t.Fatalf("expected single-carrier TCP subIO profile (MTU 16384, reliable), got %+v", prof)
	}

	// Client sends traffic on ICMP as well -> multi-carrier bonding becomes active
	sub.SetPeer(&TaggedAddr{Idx: 0, Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, Lane: 0})
	sub.SetPeer(&TaggedAddr{Idx: 1, Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4443}, Lane: 0})
	if prof := sub.Profile(); prof.MTU != 640 || prof.Reliable {
		t.Fatalf("expected multi-carrier active profile to merge conservatively, got %+v", prof)
	}
}

type mockKidPacketIO struct {
	mu   sync.Mutex
	sent [][]byte
	prof Profile
	in   chan []byte
	done chan struct{}
	once sync.Once
}

func newMockKid(prof Profile) *mockKidPacketIO {
	return &mockKidPacketIO{
		prof: prof,
		in:   make(chan []byte, 16),
		done: make(chan struct{}),
	}
}

func (m *mockKidPacketIO) Send(p []byte, _ int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, append([]byte(nil), p...))
	return nil
}

func (m *mockKidPacketIO) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-m.in:
		return p, 0, nil, nil
	case <-m.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (m *mockKidPacketIO) SetPeer(net.Addr) {}
func (m *mockKidPacketIO) Close() error {
	m.once.Do(func() { close(m.done) })
	return nil
}
func (m *mockKidPacketIO) Profile() Profile { return m.prof }

func TestBondModes(t *testing.T) {
	// 1. active-backup mode
	ps := newPathSet([]string{"p0", "p1"}, true, PathTimings{Mode: "active-backup"}, false)
	if m := ps.Mode(); m != "active-backup" {
		t.Fatalf("expected mode active-backup, got %s", m)
	}
	if p := ps.choose(0, false); p != 0 {
		t.Fatalf("expected primary path 0, got %d", p)
	}
	if p := ps.choose(0, true); p != 0 {
		t.Fatalf("expected primary path 0 for interactive, got %d", p)
	}

	// Mute primary path -> immediate failover to backup
	ps.ToggleMute(0)
	if p := ps.choose(0, false); p != 1 {
		t.Fatalf("expected failover to path 1 when path 0 muted, got %d", p)
	}
	ps.ToggleMute(0) // unmute
	if p := ps.choose(0, false); p != 0 {
		t.Fatalf("expected failback to path 0 when unmuted, got %d", p)
	}

	// Primary path dies -> failover to path 1
	ps.mu.Lock()
	ps.p[0].state = pDead
	ps.mu.Unlock()
	if p := ps.choose(0, false); p != 1 {
		t.Fatalf("expected failover to path 1 when path 0 dead, got %d", p)
	}

	// Primary path revives with ack -> failback to path 0
	ps.onAck(0, 20*time.Millisecond)
	if p := ps.choose(0, false); p != 0 {
		t.Fatalf("expected failback to path 0 upon ack, got %d", p)
	}

	// 2. replicate mode
	k0 := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	k1 := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	defer k0.Close()
	defer k1.Close()

	bond, err := NewBondIO([]PacketIO{k0, k1}, BondOptions{
		Names: []string{"k0", "k1"},
		Mode:  "replicate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bond.Close()

	if bond.ps.Mode() != "replicate" {
		t.Fatalf("expected bond mode replicate, got %s", bond.ps.Mode())
	}

	testPayload := []byte("critical-replicated-datagram")
	if err := bond.Send(testPayload, 0); err != nil {
		t.Fatalf("bond Send failed: %v", err)
	}

	k0.mu.Lock()
	n0 := len(k0.sent)
	k0.mu.Unlock()
	k1.mu.Lock()
	n1 := len(k1.sent)
	k1.mu.Unlock()

	if n0 != 1 || n1 != 1 {
		t.Fatalf("expected packet sent to both kids in replicate mode, got k0=%d k1=%d", n0, n1)
	}
}

func TestBondMuting(t *testing.T) {
	k0 := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	k1 := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	defer k0.Close()
	defer k1.Close()

	bond, err := NewBondIO([]PacketIO{k0, k1}, BondOptions{
		Names: []string{"carrier0", "carrier1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bond.Close()

	stats := bond.PathStats()
	if len(stats) != 2 || stats[0].Muted || stats[1].Muted {
		t.Fatalf("expected both carriers unmuted, got %+v", stats)
	}

	// Toggle mute on carrier 0
	muted := bond.ToggleMute(0)
	if !muted {
		t.Fatalf("expected ToggleMute(0) to return true")
	}

	stats = bond.PathStats()
	if !stats[0].Muted || stats[0].Alive {
		t.Fatalf("expected carrier 0 muted and not alive, got %+v", stats[0])
	}
	if stats[1].Muted || !stats[1].Alive {
		t.Fatalf("expected carrier 1 unmuted and alive, got %+v", stats[1])
	}

	// Toggle mute off
	muted = bond.ToggleMute(0)
	if muted {
		t.Fatalf("expected ToggleMute(0) to return false (unmuted)")
	}
	stats = bond.PathStats()
	if stats[0].Muted {
		t.Fatalf("expected carrier 0 unmuted, got %+v", stats[0])
	}
}

func TestRetxFrameReslicing(t *testing.T) {
	st := &Stream{
		id:      1,
		sbase:   0,
		peerMax: 16384,
	}
	st.snd.write(bytes.Repeat([]byte("A"), 16384))

	// Simulate a lost 16KB frame
	st.retx = []frameRef{
		{sid: 1, off: 0, n: 16000, fin: true},
	}

	// Attempt emit with only 1000 bytes of room
	sp := &sentPkt{}
	p := make([]byte, 0, 2048)
	np, sent, fit := st.emit(p, sp, 1000)

	if !sent || !fit {
		t.Fatalf("expected frame to be sliced and emitted, got sent=%t fit=%t", sent, fit)
	}
	if len(sp.frames) != 1 {
		t.Fatalf("expected 1 frame recorded in sp, got %d", len(sp.frames))
	}
	firstSlice := sp.frames[0]
	if firstSlice.fin {
		t.Errorf("intermediate slice should have fin=false")
	}
	if len(np) > 1000 {
		t.Errorf("emitted frame size %d > room 1000", len(np))
	}

	// Check that remainder is preserved in st.retx[0] with fin=true
	if len(st.retx) != 1 {
		t.Fatalf("expected 1 frame remaining in retx queue, got %d", len(st.retx))
	}
	rem := st.retx[0]
	if rem.off != uint64(firstSlice.n) {
		t.Errorf("remainder offset %d != first slice len %d", rem.off, firstSlice.n)
	}
	if rem.n != 16000-firstSlice.n {
		t.Errorf("remainder len %d != 16000 - %d", rem.n, firstSlice.n)
	}
	if !rem.fin {
		t.Errorf("remainder frame should preserve fin=true")
	}
}

type mockBacklogKid struct {
	*mockKidPacketIO
	full   atomic.Bool
	deaths atomic.Uint64
}

func (m *mockBacklogKid) Backlogged() bool   { return m.full.Load() }
func (m *mockBacklogKid) ConnDeaths() uint64 { return m.deaths.Load() }

// 3.3.8: NextPath(false) must peek the next burst winner at burst boundaries instead of returning the previous 16 KB
// path, or Session.build sizes packet 25 to 16 KB and ChoosePath can never switch to a 1400 B / 4 KB path.
func TestBondNextPathBurstBoundary(t *testing.T) {
	ps := newPathSet([]string{"tcp", "udp"}, true, PathTimings{}, false)
	ps.setProfiles([]Profile{
		{Reliable: true, MTU: 4096, MaxMTU: 16384},
		{Reliable: false, MTU: 1400, MaxMTU: 1400},
	})
	var counts [2]int
	for range 200 {
		next := ps.nextPath(false)
		lim := ps.pathLimit(next)
		got := ps.choose(lim, false)
		if got != next {
			t.Fatalf("nextPath=%d (lim %d) disagreed with choose=%d", next, lim, got)
		}
		counts[got]++
	}
	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("expected both mixed-MTU paths to carry bursts, got tcp=%d udp=%d", counts[0], counts[1])
	}
}

// 3.3.8: BondIO propagates child Backlogger/DeathReporter, skips a backlogged leg while another has room, and holds
// the session only once every live leg is blocked.
func TestBondBackloggerAndMixedPacer(t *testing.T) {
	kICMP := newMockKid(Profile{})
	kTCP := &mockBacklogKid{mockKidPacketIO: newMockKid(Profile{Reliable: true, MTU: 4096, MaxMTU: 16384})}
	kWSS := &mockBacklogKid{mockKidPacketIO: newMockKid(Profile{Reliable: true, NoDirect: true, MTU: 4096, MaxMTU: 16384})}
	defer kICMP.Close()
	defer kTCP.Close()
	defer kWSS.Close()

	bond, err := NewBondIO([]PacketIO{kICMP, kTCP, kWSS}, BondOptions{Names: []string{"icmp", "tcp", "wss"}})
	if err != nil {
		t.Fatal(err)
	}
	defer bond.Close()

	s, err := NewSession(Config{Key: []byte("bond-338-key")}, bond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	rel, late, slack := s.cc.reliable, s.lateAck, s.winSlack
	s.mu.Unlock()
	if !rel {
		t.Fatalf("icmp+tcp+wss bond should run the reliable delivery-rate pacer while pool legs are live")
	}
	if !late {
		t.Fatalf("bonded session must enable lateAck to cover multipath reordering")
	}
	if slack < uint64(16384-overhead) {
		t.Fatalf("winSlack=%d, want >= %d for 16 KB pool leg", slack, 16384-overhead)
	}

	// Mark tcp backlogged: wss and icmp still have room, so BondIO is not backlogged and ChoosePath avoids tcp.
	kTCP.full.Store(true)
	if bond.Backlogged() {
		t.Fatalf("BondIO reported Backlogged while wss and icmp still have room")
	}
	for range 60 {
		if p := bond.ChoosePath(1000, false); p == 1 {
			t.Fatalf("ChoosePath picked backlogged tcp path 1 while wss/icmp had room")
		}
	}

	// Mark wss backlogged and mute icmp: no live path has room, so BondIO must hold the session.
	kWSS.full.Store(true)
	bond.ToggleMute(0)
	if !bond.Backlogged() {
		t.Fatalf("BondIO should report Backlogged when all unmuted paths are full")
	}

	kTCP.deaths.Store(3)
	kWSS.deaths.Store(2)
	if got := bond.ConnDeaths(); got != 5 {
		t.Fatalf("ConnDeaths=%d, want 5", got)
	}
}

// 3.3.8: relV2 cwnd covers pathRTT on multi-RTT bonds and suppresses false PROBE_RTT drains.
func TestBondMultiRTTCwnd(t *testing.T) {
	c := newCC(8e6, 8e6, 1e9, 8*time.Millisecond)
	c.reliable = true
	c.maxPlain = 4000
	c.maxBW = 20e6
	c.minRTT = 40 * time.Millisecond
	c.srtt = 110 * time.Millisecond
	c.pathRTT = 160 * time.Millisecond
	c.inflight = 1 << 20
	now := time.Now()
	c.probeAt = now.Add(-time.Second)

	wantMin := int(20e6 * 0.160 * relCwndBDP)
	if got := c.cwnd(); got < wantMin {
		t.Fatalf("multi-RTT bond cwnd=%d, want >= %d (covering 160 ms pathRTT)", got, wantMin)
	}
	c.probeRTT(now)
	if c.draining {
		t.Fatalf("probeRTT should not drain when srtt spread is explained by pathRTT")
	}
}

// 3.3.8 audit: tcp+wss MultiRaw server admitted on tcp must clamp wss frames to 4096-overhead (NoDirect),
// keep s.cc.direct=false once wss is active, propagate NoDirect in mergeProfiles, and copy noDirect in Clone().
func TestBondTCPWSSNoDirectServerAndClone(t *testing.T) {
	mp := mergeProfiles([]Profile{
		{Reliable: true, MTU: 4096, MaxMTU: 16384},
		{Reliable: true, NoDirect: true, MTU: 4096, MaxMTU: 16384},
	})
	if !mp.NoDirect {
		t.Fatalf("mergeProfiles dropped NoDirect: %+v", mp)
	}

	wsCli, err := NewWSPoolClient("127.0.0.1:1", 2, HTTPClientOptions{Path: "/wat"})
	if err != nil {
		t.Fatal(err)
	}
	defer wsCli.Close()
	if !wsCli.Profile().NoDirect {
		t.Fatalf("NewWSPoolClient missing NoDirect")
	}
	cloned, err := wsCli.Clone(2)
	if err != nil {
		t.Fatal(err)
	}
	defer cloned.Close()
	if !cloned.Profile().NoDirect {
		t.Fatalf("TCPPoolClient.Clone dropped NoDirect")
	}

	tcpRaw := &mockRawWithProfile{prof: Profile{Reliable: true, MTU: 4096, MaxMTU: 16384}}
	wssRaw := &mockRawWithProfile{prof: Profile{Reliable: true, NoDirect: true, MTU: 4096, MaxMTU: 16384}}
	mr := NewMultiRaw([]string{"tcp", "wss"}, []RawIO{tcpRaw, wssRaw})
	defer mr.Close()
	if !mr.Profile().NoDirect {
		t.Fatalf("MultiRaw.Profile dropped NoDirect")
	}

	base := &subIO{srv: &Server{raw: mr, sessions: map[uint64]*srvSess{}}, done: make(chan struct{})}
	sub := newMultiSubIO(base, mr, PathTimings{}, 0) // admitted on tcp
	s, err := NewSession(Config{Key: []byte("tcp-wss-338"), Direct: true}, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Both paths become active; tcp is muted so NextPath chooses wss.
	sub.SetPeer(&TaggedAddr{Idx: 0, Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1111}})
	sub.SetPeer(&TaggedAddr{Idx: 1, Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}})
	sub.ToggleMute(0)

	s.mu.Lock()
	s.syncBondPacer()
	if s.cc.direct {
		s.mu.Unlock()
		t.Fatalf("s.cc.direct remained true while NoDirect wss leg is active")
	}
	st := s.newStream(1)
	st.snd.write(bytes.Repeat([]byte("X"), 32<<10))
	s.cc.tokens = 1 << 20
	pkt, ok := s.build(time.Now())
	s.mu.Unlock()
	if !ok {
		t.Fatalf("expected build to emit packet on wss")
	}
	if len(pkt.p) > 4096-tagLen {
		t.Fatalf("wss packet plaintext+hdr=%d exceeds 4 KB NoDirect cap (%d)", len(pkt.p), 4096-tagLen)
	}
}

// 3.3.8 audit: udp+tcp bond must NOT clamp rate to ICMPPathBps when udp revives, while icmp+tcp must;
// false->true promotion clears stale bwRing/maxBW.
func TestBondUDPTCPNoICMPClampAndResetBW(t *testing.T) {
	kUDP := newMockKid(Profile{MTU: 1400, MaxMTU: 1400})
	kTCP := newMockKid(Profile{Reliable: true, MTU: 4096, MaxMTU: 16384})
	defer kUDP.Close()
	defer kTCP.Close()
	bond, err := NewBondIO([]PacketIO{kUDP, kTCP}, BondOptions{Names: []string{"udp", "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	defer bond.Close()
	s, err := NewSession(Config{Key: []byte("udp-tcp-338"), MaxBps: 200e6}, bond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Kill udp -> tcp only -> reliable=true, populate stale maxBW, then revive udp -> rate must stay 50e6.
	bond.ps.mu.Lock()
	bond.ps.p[0].state = pDead
	bond.ps.mu.Unlock()
	s.mu.Lock()
	s.syncBondPacer()
	if !s.cc.reliable {
		s.mu.Unlock()
		t.Fatalf("expected reliable=true while only tcp is live")
	}
	s.cc.maxBW, s.cc.bwSeen, s.cc.bwLen, s.cc.rate = 40e6, true, 1, 50e6
	s.mu.Unlock()

	bond.OnAck(0, 20*time.Millisecond, 100) // udp revives
	s.mu.Lock()
	s.syncBondPacer()
	gotRate, gotRel := s.cc.rate, s.cc.reliable
	s.mu.Unlock()
	if gotRel {
		t.Fatalf("expected reliable=false once udp is live alongside tcp")
	}
	if gotRate < 49e6 {
		t.Fatalf("udp+tcp slammed rate to %.0f after udp revival, want 50e6 preserved", gotRate)
	}

	// Kill udp again -> false->true promotion must clear stale maxBW/bwSeen.
	bond.ps.mu.Lock()
	bond.ps.p[0].state = pDead
	bond.ps.mu.Unlock()
	s.mu.Lock()
	s.syncBondPacer()
	if s.cc.maxBW != 0 || s.cc.bwSeen || s.cc.bwLen != 0 {
		s.mu.Unlock()
		t.Fatalf("stale BW not cleared on false->true promotion: maxBW=%v bwSeen=%v bwLen=%d", s.cc.maxBW, s.cc.bwSeen, s.cc.bwLen)
	}
	s.mu.Unlock()

	// icmp+tcp: when tcp dies, icmpOnly clamp to ICMPPathBps must apply.
	kICMP := newMockKid(Profile{})
	kTCP2 := newMockKid(Profile{Reliable: true, MTU: 4096, MaxMTU: 16384})
	defer kICMP.Close()
	defer kTCP2.Close()
	bond2, _ := NewBondIO([]PacketIO{kICMP, kTCP2}, BondOptions{Names: []string{"icmp", "tcp"}})
	defer bond2.Close()
	s2, _ := NewSession(Config{Key: []byte("icmp-tcp-338"), MaxBps: 200e6}, bond2)
	defer s2.Close()
	bond2.ps.mu.Lock()
	bond2.ps.p[1].state = pDead
	bond2.ps.mu.Unlock()
	s2.mu.Lock()
	s2.cc.rate = 50e6
	s2.syncBondPacer()
	rate2 := s2.cc.rate
	s2.mu.Unlock()
	if rate2 != ICMPPathBps {
		t.Fatalf("icmp+tcp with dead tcp should clamp to ICMPPathBps (%.0f), got %.0f", ICMPPathBps, rate2)
	}
}

// 3.3.8 audit: active-backup nextPath/choose parity on fullMask, eval parity, and credit clamp fairness.
func TestBondNextChooseParityAndCreditClamp(t *testing.T) {
	ps := newPathSet([]string{"udp", "tcp"}, true, PathTimings{Mode: "active-backup"}, false)
	ps.setProfiles([]Profile{
		{MTU: 1400, MaxMTU: 1400},
		{Reliable: true, MTU: 4096, MaxMTU: 16384},
	})
	ps.allBulkBlocked(1<<0, true) // primary udp full
	if next, got := ps.nextPath(false), ps.choose(16384, false); next != 1 || got != 1 {
		t.Fatalf("active-backup full primary: next=%d choose=%d, want 1/1", next, got)
	}

	// eval parity: silent tcp burstPath transitions to pDead in nextPath before sizing 16 KB.
	ps2 := newPathSet([]string{"tcp", "icmp"}, true, PathTimings{Silence: 50 * time.Millisecond}, false)
	ps2.setProfiles([]Profile{
		{Reliable: true, MTU: 4096, MaxMTU: 16384},
		{},
	})
	ps2.mu.Lock()
	ps2.burstPath, ps2.burstLeft = 0, 5
	ps2.p[0].firstUnacked = time.Now().Add(-500 * time.Millisecond)
	ps2.p[1].lastAck = time.Now()
	ps2.mu.Unlock()
	if next := ps2.nextPath(false); next != 1 {
		t.Fatalf("nextPath did not evaluate silent tcp path dead: got %d, want 1", next)
	}

	// Credit clamp must not squash an isFull peer's earned credit down to a low-weight active leg's 4*w.
	ps3 := newPathSet([]string{"icmp", "tcp"}, true, PathTimings{}, false)
	ps3.mu.Lock()
	ps3.p[0].w = 0.05
	ps3.p[1].w = 1.0
	ps3.p[1].credit = 0.9
	ps3.mu.Unlock()
	ps3.allBulkBlocked(1<<1, true)
	_ = ps3.choose(500, false)
	ps3.mu.Lock()
	tcpCred := ps3.p[1].credit
	ps3.mu.Unlock()
	if tcpCred < 0.89 {
		t.Fatalf("full tcp credit squashed to %v by low-weight active leg", tcpCred)
	}
}

// 3.3.8 audit: takeDgrams respects NextPath MTU, pathAcked tracks pathMinRTT separately from srtt,
// and bonded reliable sessions keep spurious-resend tracking in lostRing.
func TestBondDgramMTUMultiRTTAndSpurious(t *testing.T) {
	icmpRaw := &mockRawWithProfile{prof: Profile{}}
	tcpRaw := &mockRawWithProfile{prof: Profile{Reliable: true, MTU: 4096, MaxMTU: 16384}}
	mr := NewMultiRaw([]string{"icmp", "tcp"}, []RawIO{icmpRaw, tcpRaw})
	defer mr.Close()
	base := &subIO{srv: &Server{raw: mr, sessions: map[uint64]*srvSess{}}, done: make(chan struct{})}
	sub := newMultiSubIO(base, mr, PathTimings{}, 1) // admitted on tcp -> s.maxPlain=16352
	s, err := NewSession(Config{Key: []byte("dgram-mtu-338"), Direct: true}, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sub.SetPeer(&TaggedAddr{Idx: 0, Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}})
	sub.SetPeer(&TaggedAddr{Idx: 1, Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3333}})
	sub.ToggleMute(1) // force NextPath -> icmp (640 B)
	s.SendDatagram(1, 5000, bytes.Repeat([]byte("D"), 400))
	s.SendDatagram(1, 5000, bytes.Repeat([]byte("E"), 400))
	s.mu.Lock()
	s.cc.tokens = 1 << 20
	pkt, ok := s.build(time.Now())
	s.mu.Unlock()
	if !ok {
		t.Fatalf("expected datagram packet on icmp")
	}
	if len(pkt.p)+tagLen > MaxPayload {
		t.Fatalf("icmp datagram packet %d B exceeded MaxPayload %d", len(pkt.p)+tagLen, MaxPayload)
	}

	// pathAcked sets pathMinRTT from pc.minRTT (not queued srtt) and keeps lostRing spurious tracking.
	s.mu.Lock()
	now := time.Now()
	s.pcc[0].minRTT, s.pcc[0].srtt, s.pcc[0].at = 40*time.Millisecond, 40*time.Millisecond, now
	s.pcc[1].minRTT, s.pcc[1].srtt, s.pcc[1].at = 160*time.Millisecond, 400*time.Millisecond, now
	s.pcc[1].reliable = true
	s.cc.reliable = true
	s.cc.minRTT, s.cc.minRTTAt = 40*time.Millisecond, now
	s.pathAcked(nil, 0, 0, now, 0)
	if s.cc.pathMinRTT != 160*time.Millisecond || s.cc.pathRTT != 400*time.Millisecond {
		s.mu.Unlock()
		t.Fatalf("got pathMinRTT=%v pathRTT=%v, want 160ms/400ms", s.cc.pathMinRTT, s.cc.pathRTT)
	}
	sp := &sentPkt{pn: 99, at: now, size: 1000, lane: 1, ctrl: [][]byte{{frBoot, 1}}}
	s.lose(sp)
	if len(s.lostRing) != 1 {
		s.mu.Unlock()
		t.Fatalf("bonded reliable lose() did not record sp in lostRing")
	}
	s.matchLost(rangeSet{{lo: 99, hi: 100}}, 100, now.Add(10*time.Millisecond))
	if s.cc.spuriousN != 1 {
		s.mu.Unlock()
		t.Fatalf("matchLost spuriousN=%d, want 1", s.cc.spuriousN)
	}
	s.mu.Unlock()
}

// 3.3.8 audit: verify frBoot recovery when server clock stepped back > replayWin, reverse-merge untrusted skip,
// and datagram fragment expiry under fragPending.
func TestAuditEngineFixes(t *testing.T) {
	// 1. Server clock step-back frBoot recovery
	cli, srv := memPair(t, Config{})
	cli.mu.Lock()
	cli.peerBoot = 111
	cli.rxAny, cli.rxLargest = true, 50000
	cli.rxRing[50000%cli.replayWin] = 50001
	cli.rxRanges.add(50000, 50001)
	cli.rxAt = time.Now()
	cli.kexPriv = nil // exercise steady-state PSK/current-AEAD packet path directly
	aead := cli.aead
	sid := cli.sid
	cli.mu.Unlock()
	_ = srv

	var plain []byte
	plain = append(plain, frBoot)
	plain = appendUv(plain, 222)
	var pkt [128]byte
	const newPN = dirServerBit | 100 // well below 50000 & outside replayWin
	binary.BigEndian.PutUint64(pkt[:], sid)
	binary.BigEndian.PutUint64(pkt[8:], newPN)
	var nonce [12]byte
	copy(nonce[4:], pkt[8:16])
	sealed := aead.Seal(pkt[:hdrLen], nonce[:], plain, pkt[:8])
	if cli.hk != nil {
		maskHdr(cli.hk, sealed)
	}
	cli.handle(sealed, 0, nil)
	cli.mu.Lock()
	gotBoot, gotLargest := cli.peerBoot, cli.rxLargest
	cli.mu.Unlock()
	if gotBoot != 222 || gotLargest != newPN {
		t.Fatalf("frBoot clock step-back recovery failed: boot=%d largest=%x", gotBoot, gotLargest)
	}

	// 2. Fragment expiry below fragPending
	cli.mu.Lock()
	cli.onDgramFrag(1, 53, 7, 0, 2, bytes.Repeat([]byte("F"), 100), time.Now().Add(-2*fragKeep))
	if len(cli.reasm) != 1 {
		cli.mu.Unlock()
		t.Fatalf("expected 1 incomplete fragment")
	}
	cli.pruneReasm(time.Now())
	rem := len(cli.reasm)
	cli.mu.Unlock()
	if rem != 0 {
		t.Fatalf("pruneReasm left %d expired fragments", rem)
	}

	// 3. Reverse-merge pickConnTrusted skips untrusted connections once trusted IPs exist
	trusted := newPoolConn(&dummyConn{})
	trusted.ip = "198.51.100.1"
	trusted.qb.Store(4096)
	stranger := newPoolConn(&dummyConn{})
	stranger.ip = "203.0.113.9"
	stranger.qb.Store(0)
	defer trusted.fail()
	defer stranger.fail()
	ts := trustedIPs{"198.51.100.1"}
	picked := pickConnTrusted([]*poolConn{stranger, trusted}, 0, 0, &ts)
	if picked != trusted {
		t.Fatalf("pickConnTrusted chose untrusted stranger over trusted conn")
	}
	if full := backloggedTrusted([]*poolConn{stranger}, &ts); !full {
		t.Fatalf("backloggedTrusted should report full when only untrusted conns exist")
	}

	// 4. normPath("/") and ProbeName IPv6
	if normPath("/") != "/" || normPath("") != "/wat" {
		t.Fatalf("normPath(\"/\")=%q normPath(\"\")=%q", normPath("/"), normPath(""))
	}
	if got := ProbeName("tls", "", "", "[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("ProbeName IPv6=%q, want 2001:db8::1", got)
	}
}

type dummyConn struct{ net.Conn }

func (dummyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (dummyConn) Write(p []byte) (int, error)      { return len(p), nil }
func (dummyConn) Close() error                     { return nil }
func (dummyConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (dummyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (dummyConn) SetDeadline(time.Time) error      { return nil }
func (dummyConn) SetReadDeadline(time.Time) error  { return nil }
func (dummyConn) SetWriteDeadline(time.Time) error { return nil }
