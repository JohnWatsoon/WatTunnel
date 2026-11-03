package wat

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Bonding: one session over several carriers at once. Client side is BondIO (a PacketIO over child PacketIOs),
// server side is MultiRaw (a RawIO over child RawIOs) plus a per-session path scheduler in the Server. Both run
// the same pathSet: per-path delay/loss from the session's ACK feedback, health (live -> suspect -> dead), probes
// of dead paths with backoff, and a weighted split for bulk packets with the interactive ones on the fastest path.
// Duplicate or reordered packets across paths are harmless: the session already has a replay window and SACK.

const bondRecvQueue = 4096

// BondOptions configures NewBondIO. Names and Lanes are per child (Lanes: ICMP identifiers to stripe over, 1 for
// everything else).
type BondOptions struct {
	Names   []string
	Lanes   []int
	Timings PathTimings
	Mode    string
}

type bondPkt struct {
	p    []byte
	path int
	src  net.Addr
}

// BondIO is the client PacketIO over N child PacketIOs.
type BondIO struct {
	kids   []PacketIO
	lanes  []int
	laneRR []atomic.Uint32
	ps     *pathSet
	prof   Profile
	profs  []Profile
	in     chan bondPkt
	done   chan struct{}
	once   sync.Once
	prober atomic.Value // func(int)
	prev   []byte
}

func NewBondIO(kids []PacketIO, opt BondOptions) (*BondIO, error) {
	if len(kids) == 0 {
		return nil, errors.New("wat: bond needs at least one carrier")
	}
	names := make([]string, len(kids))
	lanes := make([]int, len(kids))
	b := &BondIO{kids: kids, lanes: lanes, laneRR: make([]atomic.Uint32, len(kids)),
		in: make(chan bondPkt, bondRecvQueue), done: make(chan struct{})}
	for i, k := range kids {
		names[i] = "carrier" + string(rune('0'+i%10))
		if i < len(opt.Names) && opt.Names[i] != "" {
			names[i] = opt.Names[i]
		}
		lanes[i] = 1
		if i < len(opt.Lanes) && opt.Lanes[i] > 0 {
			lanes[i] = opt.Lanes[i]
		}
		b.profs = append(b.profs, profileOf(k))
	}
	b.prof = mergeProfiles(b.profs)
	tm := opt.Timings
	if opt.Mode != "" {
		tm.Mode = opt.Mode
	}
	b.ps = newPathSet(names, true, tm)
	for i := range kids {
		go b.recvKid(i)
	}
	go b.tickLoop()
	return b, nil
}

func (b *BondIO) recvKid(i int) {
	backoff := time.Millisecond
	for {
		p, _, src, err := b.kids[i].Recv()
		if err != nil {
			select {
			case <-b.done:
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = time.Millisecond
		buf := getPkt(len(p))
		copy(buf, p)
		select {
		case b.in <- bondPkt{buf, i, src}:
		default: // overloaded: a dropped datagram is just loss
			putPkt(buf)
		}
	}
}

func (b *BondIO) tickLoop() {
	tk := time.NewTicker(50 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-tk.C:
		}
		list := b.ps.tick()
		if f, _ := b.prober.Load().(func(int)); f != nil {
			for _, i := range list {
				f(i)
			}
		}
	}
}

func (b *BondIO) Send(p []byte, path int) error {
	if path < 0 || path >= len(b.kids) {
		path = 0
	}
	b.ps.onSend(path, len(p))
	lane := 0
	if n := b.lanes[path]; n > 1 {
		lane = int(b.laneRR[path].Add(1) % uint32(n))
	}
	err := b.kids[path].Send(p, lane)
	if b.ps.Mode() == "replicate" {
		for i, kid := range b.kids {
			if i != path && b.ps.isLiveOrSuspect(i) {
				b.ps.onSend(i, len(p))
				l := 0
				if n := b.lanes[i]; n > 1 {
					l = int(b.laneRR[i].Add(1) % uint32(n))
				}
				_ = kid.Send(p, l)
			}
		}
	}
	return err
}

func (b *BondIO) Recv() ([]byte, int, net.Addr, error) {
	if b.prev != nil {
		putPkt(b.prev)
		b.prev = nil
	}
	select {
	case r := <-b.in:
		b.prev = r.p
		return r.p, r.path, r.src, nil
	case <-b.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (b *BondIO) SetPeer(net.Addr) {}

func (b *BondIO) Close() error {
	b.once.Do(func() {
		close(b.done)
		// b.prev stays: it belongs to the Recv goroutine, which may still be handling it (left to the GC)
		for {
			select {
			case r := <-b.in:
				putPkt(r.p)
			default:
				goto drained
			}
		}
	drained:
		for _, k := range b.kids {
			k.Close()
		}
	})
	return nil
}

func (b *BondIO) Profile() Profile                         { return b.prof }
func (b *BondIO) NumPaths() int                            { return len(b.kids) }
func (b *BondIO) PathProfile(i int) Profile                { return b.profs[i] }
func (b *BondIO) ChoosePath(_ int, inter bool) int         { return b.ps.choose(inter) }
func (b *BondIO) NextPath(inter bool) int                  { return b.ps.nextPath(inter) }
func (b *BondIO) ToggleMute(path int) bool                 { return b.ps.ToggleMute(path) }
func (b *BondIO) OnAck(path int, rtt time.Duration, _ int) { b.ps.onAck(path, rtt) }
func (b *BondIO) OnLoss(path int)                          { b.ps.onLoss(path) }
func (b *BondIO) SetProber(f func(int))                    { b.prober.Store(f) }
func (b *BondIO) PathStats() []CarrierStat                 { return b.ps.stats() }

// ---- server side

// TaggedAddr is the source address MultiRaw reports: which child raw the packet came in on, plus the child's own
// address and lane.
type TaggedAddr struct {
	Idx  int
	Addr net.Addr
	Lane int
}

func (a *TaggedAddr) Network() string { return "multi" }
func (a *TaggedAddr) String() string {
	return string(rune('a'+a.Idx%26)) + ":" + a.Addr.String()
}

type multiPkt struct {
	p    []byte
	lane int
	src  net.Addr
}

// MultiRaw is the server RawIO over several RawIOs (one per carrier). The Server detects it and gives every
// client session a path scheduler over the carriers that client has been heard on.
type MultiRaw struct {
	raws  []RawIO
	names []string
	in    chan multiPkt
	done  chan struct{}
	once  sync.Once
	prev  []byte
}

func NewMultiRaw(names []string, raws []RawIO) *MultiRaw {
	m := &MultiRaw{raws: raws, names: names, in: make(chan multiPkt, bondRecvQueue), done: make(chan struct{})}
	for len(m.names) < len(raws) {
		m.names = append(m.names, "carrier")
	}
	for i := range raws {
		go m.readLoop(i)
	}
	return m
}

func (m *MultiRaw) readLoop(i int) {
	backoff := time.Millisecond
	for {
		p, lane, src, err := m.raws[i].Recv()
		if err != nil {
			select {
			case <-m.done:
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = time.Millisecond
		buf := getPkt(len(p))
		copy(buf, p)
		select {
		case m.in <- multiPkt{buf, lane, &TaggedAddr{i, src, lane}}:
		default:
			putPkt(buf)
		}
	}
}

func (m *MultiRaw) Recv() ([]byte, int, net.Addr, error) {
	if m.prev != nil {
		putPkt(m.prev)
		m.prev = nil
	}
	select {
	case r := <-m.in:
		m.prev = r.p
		return r.p, r.lane, r.src, nil
	case <-m.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (m *MultiRaw) SendTo(p []byte, lane int, dst net.Addr) error {
	t, ok := dst.(*TaggedAddr)
	if !ok || t.Idx < 0 || t.Idx >= len(m.raws) {
		return net.ErrClosed
	}
	return m.raws[t.Idx].SendTo(p, lane, t.Addr)
}

func (m *MultiRaw) Close() error {
	m.once.Do(func() {
		close(m.done)
		// m.prev stays: it belongs to the Recv goroutine, which may still be handling it (left to the GC)
		for {
			select {
			case r := <-m.in:
				putPkt(r.p)
			default:
				goto drained
			}
		}
	drained:
		for _, r := range m.raws {
			r.Close()
		}
	})
	return nil
}

func (m *MultiRaw) Profile() Profile {
	ps := make([]Profile, len(m.raws))
	for i, r := range m.raws {
		ps[i] = profileOf(r)
	}
	return mergeProfiles(ps)
}

// multiSubIO is a server session's PacketIO when the Server runs on a MultiRaw: it remembers where the client was
// last heard on each carrier and replies on the best live one, so when the client's carrier dies and it carries on
// over another, the replies follow it (live migration) without any signalling.
type multiSubIO struct {
	*subIO
	mr              *MultiRaw
	ps              *pathSet
	mu              sync.Mutex
	slots           []peerSlot
	prober          atomic.Value // func(int)
	admittedCarrier int          // carrier slot index on which first packet arrived (-1 if unset)
}

type peerSlot struct {
	dst   *TaggedAddr // last authenticated source on this carrier
	lanes []int       // lanes (ICMP identifiers) the client used on it
	rr    int
}

func newMultiSubIO(base *subIO, mr *MultiRaw, tm PathTimings, admittingIdx int) *multiSubIO {
	m := &multiSubIO{subIO: base, mr: mr, slots: make([]peerSlot, len(mr.raws)), admittedCarrier: admittingIdx}
	m.ps = newPathSet(mr.names, false, tm)
	go func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-base.done:
				return
			case <-tk.C:
			}
			list := m.ps.tick()
			if f, _ := m.prober.Load().(func(int)); f != nil {
				for _, i := range list {
					f(i)
				}
			}
		}
	}()
	return m
}

// addrsEqual compares two peer addresses by value, without formatting or allocating for the common types.
func addrsEqual(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch x := a.(type) {
	case *net.UDPAddr:
		y, ok := b.(*net.UDPAddr)
		return ok && x.Port == y.Port && x.Zone == y.Zone && x.IP.Equal(y.IP)
	case *net.TCPAddr:
		y, ok := b.(*net.TCPAddr)
		return ok && x.Port == y.Port && x.Zone == y.Zone && x.IP.Equal(y.IP)
	case *net.IPAddr:
		y, ok := b.(*net.IPAddr)
		return ok && x.Zone == y.Zone && x.IP.Equal(y.IP)
	}
	return a.String() == b.String()
}

func (m *multiSubIO) SetPeer(a net.Addr) {
	t, ok := a.(*TaggedAddr)
	if !ok || t.Idx < 0 || t.Idx >= len(m.slots) {
		return
	}
	m.subIO.peer.Store(a) // newest source, for Server.Clients (Send is overridden here, so nothing else reads it)
	// Fast path: nothing changed. handle() calls this for every authenticated packet; this
	// goroutine is the only writer of dst/lanes, so the check needs no lock (Send only reads
	// them under m.mu). Compare the address by value: readLoop allocates a fresh *TaggedAddr per
	// datagram, so the old pointer comparison could never match (audit 2026-11-03).
	s := &m.slots[t.Idx]
	if s.dst != nil && s.dst.Idx == t.Idx && s.dst.Lane == t.Lane && addrsEqual(s.dst.Addr, t.Addr) &&
		(containsLane(s.lanes, t.Lane) || len(s.lanes) >= 8) {
		m.ps.markPresent(t.Idx)
		return
	}
	m.mu.Lock()
	s.dst = t
	if !containsLane(s.lanes, t.Lane) && len(s.lanes) < 8 {
		s.lanes = append(s.lanes, t.Lane)
	}
	m.mu.Unlock()
	m.ps.markPresent(t.Idx)
}

func containsLane(lanes []int, lane int) bool {
	for _, l := range lanes {
		if l == lane {
			return true
		}
	}
	return false
}

func (m *multiSubIO) Send(p []byte, path int) error {
	m.mu.Lock()
	if path < 0 || path >= len(m.slots) || m.slots[path].dst == nil {
		m.mu.Unlock()
		return errors.New("wat: no peer yet")
	}
	s := &m.slots[path]
	dst, lane := s.dst, 0
	if len(s.lanes) > 0 {
		s.rr++
		lane = s.lanes[s.rr%len(s.lanes)]
	}
	type dupItem struct {
		idx  int
		raw  RawIO
		lane int
		addr net.Addr
	}
	var dups []dupItem
	if m.ps.Mode() == "replicate" {
		for i := range m.slots {
			if i != path && m.slots[i].dst != nil && m.ps.isLiveOrSuspect(i) {
				ds := &m.slots[i]
				dl := 0
				if len(ds.lanes) > 0 {
					ds.rr++
					dl = ds.lanes[ds.rr%len(ds.lanes)]
				}
				dups = append(dups, dupItem{idx: i, raw: m.mr.raws[i], lane: dl, addr: ds.dst.Addr})
			}
		}
	}
	m.mu.Unlock()
	m.ps.onSend(path, len(p))
	err := m.mr.raws[path].SendTo(p, lane, dst.Addr)
	for _, d := range dups {
		m.ps.onSend(d.idx, len(p))
		_ = d.raw.SendTo(p, d.lane, d.addr)
	}
	return err
}

func (m *multiSubIO) NumPaths() int                            { return len(m.slots) }
func (m *multiSubIO) PathProfile(i int) Profile                { return profileOf(m.mr.raws[i]) }
func (m *multiSubIO) ChoosePath(_ int, inter bool) int         { return m.ps.choose(inter) }
func (m *multiSubIO) NextPath(inter bool) int                  { return m.ps.nextPath(inter) }
func (m *multiSubIO) ToggleMute(path int) bool                 { return m.ps.ToggleMute(path) }
func (m *multiSubIO) OnAck(path int, rtt time.Duration, _ int) { m.ps.onAck(path, rtt) }
func (m *multiSubIO) OnLoss(path int)                          { m.ps.onLoss(path) }
func (m *multiSubIO) SetProber(f func(int))                    { m.prober.Store(f) }
func (m *multiSubIO) PathStats() []CarrierStat                 { return m.ps.stats() }

// Profile reports the active carrier's native profile if the client connects on one carrier
// (e.g. TCP pool), or the conservative merged profile if multiple carriers are active.
// ponytail: single-active fast path avoids MTU collapse without dynamic renegotiation.
func (m *multiSubIO) Profile() Profile {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := -1
	for i, s := range m.slots {
		if s.dst != nil {
			if active == -1 {
				active = i
			} else {
				return m.mr.Profile()
			}
		}
	}
	if active >= 0 && active < len(m.mr.raws) {
		return profileOf(m.mr.raws[active])
	}
	if m.admittedCarrier >= 0 && m.admittedCarrier < len(m.mr.raws) {
		return profileOf(m.mr.raws[m.admittedCarrier])
	}
	return m.mr.Profile()
}
