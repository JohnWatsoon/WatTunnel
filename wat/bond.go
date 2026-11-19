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

// knockWait is how long a Bifrost NAT knock waits when it cannot fire yet: the first knock of a session
// (giving the session time to attach its prober) and each retry while the prober is still absent.
const knockWait = 250 * time.Millisecond

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

	// Bifrost NAT knock (found live 2026-11-19): the ":down" legs this client must knock for, when the next knock
	// is due on each (tickLoop-owned), the last packet received on each leg (recvKid-owned, unix ns) and how many
	// knocks went out. Server data arriving on a leg proves its NAT mapping works, so knocks pause while it flows.
	knockLegs []int
	knockAt   []time.Time
	lastRecv  []atomic.Int64
	knocks    []atomic.Uint64
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
	b.ps = newPathSet(names, true, tm, false)
	b.ps.setProfiles(b.profs)
	b.knockAt = make([]time.Time, len(kids))
	b.lastRecv = make([]atomic.Int64, len(kids))
	b.knocks = make([]atomic.Uint64, len(kids))
	for i := range kids {
		if b.ps.p[i].dir == DirDown { // Bifrost NAT knock: only a ":down" leg never sends otherwise
			b.knockLegs = append(b.knockLegs, i)
			// first knock at a fraction of the cadence, not after a full gap: a fresh session behind NAT gets
			// nothing on the leg until a mapping exists (found while re-verifying the 2026-11-20 knock: a
			// 25-35 s startup dead window); the knockWait floor gives the session a moment to attach its prober
			b.knockAt[i] = time.Now().Add(knockFirst(knockGap(b.ps.cfg.DownKnock)))
		}
	}
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
		b.lastRecv[i].Store(time.Now().UnixNano()) // Bifrost NAT knock: arrivals on a leg pause its knocks
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
		f, _ := b.prober.Load().(func(int))
		if f != nil {
			for _, i := range list {
				f(i)
			}
		}
		// Bifrost NAT knock (found live 2026-11-19, Kharej box): fire at most one knock per leg per jittered
		// cadence tick. The knock reuses the probe path — one tiny ack-eliciting PING on the leg — so it is a
		// normal authenticated packet, not a new wire surface, and its arrival on the server populates the leg's
		// destination through the same authenticated-source mechanism as any packet (SetPeer). Skipped while the
		// leg is delivering downlink (its mapping demonstrably works); knockAt is only touched here.
		now := time.Now()
		for _, i := range b.knockLegs {
			if now.Before(b.knockAt[i]) {
				continue
			}
			if f == nil {
				b.knockAt[i] = now.Add(knockWait) // no prober yet (session still starting): retry shortly,
				continue                          // don't burn a whole cadence gap on it
			}
			gap := knockGap(b.ps.cfg.DownKnock)
			b.knockAt[i] = now.Add(gap)
			if now.UnixNano()-b.lastRecv[i].Load() < int64(gap) {
				continue // server data arrived on the leg within the last cadence: no knock needed
			}
			b.knocks[i].Add(1)
			f(i)
		}
	}
}

func (b *BondIO) Send(p []byte, path int) error {
	if path < 0 || path >= len(b.kids) {
		path = 0
	}
	// Bifrost NAT knock: the only packets a client ever sends on a ":down" leg are knocks (probe PINGs the
	// tickLoop queues to refresh the NAT mapping) — the chooser never targets the leg. They bypass the scheduler
	// bookkeeping on purpose: a knock is control-plane, not assigned data, so Sent/replication must not count it.
	if b.ps.p[path].dir == DirDown {
		return b.kids[path].Send(p, 0)
	}
	b.ps.onSend(path, len(p))
	lane := 0
	if n := b.lanes[path]; n > 1 {
		lane = int(b.laneRR[path].Add(1) % uint32(n))
	}
	err := b.kids[path].Send(p, lane)
	if b.ps.Mode() == "replicate" {
		for i, kid := range b.kids {
			// Bifrost (3.3.9): replication copies to every live leg, but a direction-locked leg must still never
			// carry what this end may not send on it (a ":down" leg is receive-only for the client).
			if i != path && b.ps.isLiveOrSuspect(i) && b.ps.canSend(i) {
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

// PeerAuthenticated forwards a source address that proved it holds the session key to the child pools that can pin
// their peer (reverse pools). The session calls it for every authenticated packet on the client side.
func (b *BondIO) PeerAuthenticated(a net.Addr) {
	for _, k := range b.kids {
		if pa, ok := k.(interface{ PeerAuthenticated(net.Addr) }); ok {
			pa.PeerAuthenticated(a)
		}
	}
}

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
func (b *BondIO) ChoosePath(size int, inter bool) int      { return b.ps.choose(size, inter) }
func (b *BondIO) NextPath(inter bool) int                  { return b.ps.nextPath(inter) }
func (b *BondIO) ToggleMute(path int) bool                 { return b.ps.ToggleMute(path) }
func (b *BondIO) OnAck(path int, rtt time.Duration, _ int) { b.ps.onAck(path, rtt) }
func (b *BondIO) OnLoss(path int)                          { b.ps.onLoss(path) }
func (b *BondIO) SetProber(f func(int))                    { b.prober.Store(f) }
func (b *BondIO) PathStats() []CarrierStat {
	out := b.ps.stats()
	for _, i := range b.knockLegs { // Bifrost NAT knock: per-leg knock count for /stats (0 elsewhere)
		out[i].Knocks = b.knocks[i].Load()
	}
	return out
}
func (b *BondIO) PacerMode() (bool, bool, bool, bool) { return b.ps.pacerMode() }

// PathDirs reports each leg's direction lock (Bifrost, 3.3.9). The lock is parsed from the leg-name suffix once
// at NewBondIO and never changes, so the unsynchronized read is safe.
func (b *BondIO) PathDirs() []uint8 {
	out := make([]uint8, len(b.kids))
	for i := range out {
		out[i] = b.ps.p[i].dir
	}
	return out
}

// PathLocalPort reports the bound local port of leg i's kid socket (Bifrost frEndpoint announce, 3.3.9): a
// ":down" leg's kid is a quiet bound socket, and this is the port the server must send downlink to. 0 when the
// kid does not expose one (it is not a bound socket).
func (b *BondIO) PathLocalPort(leg int) int {
	if leg < 0 || leg >= len(b.kids) {
		return 0
	}
	if p, ok := b.kids[leg].(PathLocalPorter); ok {
		return p.PathLocalPort()
	}
	return 0
}

// OnLossSized is OnLoss with the packet's wire size, for the Hornet-MTU detector (-mtu-adapt, 3.3.9): the
// session calls the sized variant when the io implements PathLossSizer.
func (b *BondIO) OnLossSized(path, size int) { b.ps.onLossSized(path, size) }

// PathClamp reports the Hornet-MTU sender-side datagram clamp of path (3.3.9): hornetClampPayload while the
// detector's clamp holds, else 0. Session.build takes min(limit, clamp) when sizing packets.
func (b *BondIO) PathClamp(path int) int { return b.ps.clampOf(path) }

// Backlogged updates the per-path full mask and holds the session when no live path has room (3.3.8).
func (b *BondIO) Backlogged() bool {
	var mask uint64
	has := false
	for i, k := range b.kids {
		if i >= 64 {
			break
		}
		if bl, ok := k.(Backlogger); ok {
			has = true
			if bl.Backlogged() {
				mask |= uint64(1) << uint(i)
			}
		}
	}
	return b.ps.allBulkBlocked(mask, has)
}

func (b *BondIO) ConnDeaths() uint64 {
	var sum uint64
	for _, k := range b.kids {
		if dr, ok := k.(DeathReporter); ok {
			sum += dr.ConnDeaths()
		} else if _, ok := k.(*ReverseListenIO); ok {
			sum += poolConnDeaths.Load()
		}
	}
	return sum
}

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
	heard bool        // dst came from real traffic on this leg, not from an frEndpoint announce
	rr    int
}

func newMultiSubIO(base *subIO, mr *MultiRaw, tm PathTimings, admittingIdx int) *multiSubIO {
	m := &multiSubIO{subIO: base, mr: mr, slots: make([]peerSlot, len(mr.raws)), admittedCarrier: admittingIdx}
	m.ps = newPathSet(mr.names, false, tm, true)
	profs := make([]Profile, len(mr.raws))
	for i, r := range mr.raws {
		profs[i] = profileOf(r)
	}
	m.ps.setProfiles(profs)
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
	s.heard = true // traffic-observed source: ground truth for downlink (see SetPathEndpoint)
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

// SetPathEndpoint records where the client receives downlink on its ":down" leg (Bifrost frEndpoint 0x0e,
// 3.3.9; both ends need it for the suffixes to be honored). Security invariant: the IP comes ONLY from src, the
// packet's authenticated source address — the frame carries the announced port alone, so a hostile peer cannot
// aim the downlink anywhere but its own proven source (a peer that can seal frEndpoint already holds the session
// key, and its packets' source address is all the server will ever trust). The client never sends on a ":down"
// leg, so no ordinary packet populates this slot; until the announce arrives the leg stays absent (dst nil) and
// the server never sends down it. Replaces the slot wholesale: a ":down" leg is udp, so no ICMP lanes are kept.
func (m *multiSubIO) SetPathEndpoint(legIdx, port int, src net.Addr) {
	if legIdx < 0 || legIdx >= len(m.slots) || port <= 0 || port > 65535 {
		return
	}
	t, ok := src.(*TaggedAddr)
	if !ok || t.Idx < 0 || t.Idx >= len(m.slots) {
		return
	}
	var ip net.IP
	switch v := t.Addr.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return // no IP in the authenticated source (custom/test raw): nothing trustworthy to bind the endpoint to
	}
	if ip == nil {
		return
	}
	m.mu.Lock()
	if s := &m.slots[legIdx]; s.heard {
		// A packet has already arrived on this leg (a NAT knock or client data): its observed source is where
		// downlink demonstrably reaches. Behind a port-translating NAT the announced port is the client's
		// private one while the observed source carries the NAT's translation — an announce here would clobber
		// the working endpoint every endpointEvery and flap the downlink. Announces bootstrap only; a client
		// that rebinds its listen port is relearned from the new socket's next knock.
		m.mu.Unlock()
		return
	}
	m.slots[legIdx] = peerSlot{dst: &TaggedAddr{Idx: legIdx, Addr: &net.UDPAddr{IP: ip, Port: port}}}
	m.mu.Unlock()
	m.ps.markPresent(legIdx)
}

func (m *multiSubIO) Send(p []byte, path int) error {
	m.mu.Lock()
	// Bifrost (3.3.9): a ":down" leg is sendable only once its frEndpoint announce populated the slot (until then
	// dst is nil, the same gate as any never-heard-from carrier), and an ":up" leg is receive-only for the server
	// — the chooser already skips both, this is the belt-and-braces gate for direct sends.
	if path < 0 || path >= len(m.slots) || m.slots[path].dst == nil || !m.ps.canSend(path) {
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
			if i != path && m.slots[i].dst != nil && m.ps.isLiveOrSuspect(i) && m.ps.canSend(i) {
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
func (m *multiSubIO) ChoosePath(size int, inter bool) int      { return m.ps.choose(size, inter) }
func (m *multiSubIO) NextPath(inter bool) int                  { return m.ps.nextPath(inter) }
func (m *multiSubIO) ToggleMute(path int) bool                 { return m.ps.ToggleMute(path) }
func (m *multiSubIO) OnAck(path int, rtt time.Duration, _ int) { m.ps.onAck(path, rtt) }
func (m *multiSubIO) OnLoss(path int)                          { m.ps.onLoss(path) }
func (m *multiSubIO) SetProber(f func(int))                    { m.prober.Store(f) }
func (m *multiSubIO) PathStats() []CarrierStat                 { return m.ps.stats() }
func (m *multiSubIO) PacerMode() (bool, bool, bool, bool)      { return m.ps.pacerMode() }

// OnLossSized / PathClamp: the server end of the Hornet-MTU sender-side clamp (-mtu-adapt, 3.3.9) — each end
// watches its OWN send-path losses and clamps the payload it puts on that path, so both BondIO (client) and
// multiSubIO (server) implement the sized feedback and the clamp query.
func (m *multiSubIO) OnLossSized(path, size int) { m.ps.onLossSized(path, size) }
func (m *multiSubIO) PathClamp(path int) int     { return m.ps.clampOf(path) }

// Backlogged overrides subIO.Backlogged (srv.raw is MultiRaw, not RawBacklogger) so per-carrier pool backpressure
// works on bonded servers and un-narrowed Auto Kharej listeners (3.3.8).
func (m *multiSubIO) Backlogged() bool {
	var addrs [64]net.Addr
	n := min(len(m.slots), len(addrs))
	m.mu.Lock()
	for i := 0; i < n; i++ {
		if m.slots[i].dst != nil {
			addrs[i] = m.slots[i].dst.Addr
		}
	}
	m.mu.Unlock()
	var mask uint64
	has := false
	for i := 0; i < n; i++ {
		if addrs[i] == nil {
			continue
		}
		if rb, ok := m.mr.raws[i].(RawBacklogger); ok {
			has = true
			if rb.BackloggedTo(addrs[i]) {
				mask |= uint64(1) << uint(i)
			}
		}
	}
	return m.ps.allBulkBlocked(mask, has)
}

func (m *multiSubIO) ConnDeaths() uint64 {
	var sum uint64
	for _, r := range m.mr.raws {
		if dr, ok := r.(DeathReporter); ok {
			sum += dr.ConnDeaths()
		} else if _, ok := r.(*TCPPoolServer); ok {
			sum += poolConnDeaths.Load()
		}
	}
	return sum
}

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
