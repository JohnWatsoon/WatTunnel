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
			return p, 0, strAddr("cli"), nil
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
	ps := newPathSet([]string{"p0", "p1"}, true, PathTimings{Mode: "active-backup"})
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
