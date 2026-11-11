package wat

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// RawIO is the server's view of the wire: every client's datagrams arrive on one socket.
type RawIO interface {
	Recv() (p []byte, lane int, src net.Addr, err error)
	SendTo(p []byte, lane int, dst net.Addr) error
	Close() error
}

type rxPkt struct {
	p    []byte
	lane int
	src  net.Addr
}

// Server demultiplexes one raw socket into independent client Sessions, keyed by the session id each client
// process picks at start. Two clients on one key (the two slots of a handover, a restart loop) never touch each
// other, and a server instance that is draining accepts no new sessions while it finishes the ones it has.
type Server struct {
	cfg      Config
	raw      RawIO
	hk       []byte // header-mask key (nil: NoMask)
	mu       sync.Mutex
	sessions map[uint64]*srvSess
	New      chan *Session // freshly authenticated client sessions
	draining atomic.Bool
	stop     chan struct{}
	closed   bool
	free     chan []byte // receive buffers for the sessions' inboxes

	MaxSessions int
	IdleTimeout time.Duration
	muted       map[int]bool // bonded server: carriers muted by ToggleMute, applied to every session (guarded by mu)

	// Client allowlist (W10, Config.AllowClients): a new session is admitted only from a source inside allow.
	// deny is owned by run() (the single receive goroutine): one log line per rejected source per denyEvery, so a
	// source-address spray can neither grow the table without bound nor log per packet.
	allow     []netip.Prefix
	deny      map[netip.Addr]denyEntry
	denyEvery time.Duration
	// L8: a global token bucket on the deny log (lines/s, burst). A spoofed-source spray reaches the reject path
	// without a valid AEAD, so per-source throttling alone still allowed ~25 lines/s with 256 sources; this caps the
	// journald cost and counts what it suppressed. Owned by run(), like deny.
	denyLogRate    float64
	denyLogBurst   float64
	denyTokens     float64
	denyTokAt      time.Time
	denySuppressed int

	// retiredPN: highest packet number the session of a sid that left the table accepted, so a replay of one of its
	// packets cannot open a new session. retiredQ keeps insertion order for the bound.
	retiredPN map[uint64]uint64
	retiredQ  []uint64

	lastRx atomic.Int64 // unix nanoseconds of the newest authenticated packet of any session, kept after it closes

	statMu  sync.Mutex
	seen    map[*Session]Stats // each live session's counters at the last Stats call
	retired Stats              // counters of sessions that have closed, so the totals never go backwards
}

type srvSess struct {
	s       *Session
	io      *subIO
	created time.Time // janitor fallback until the first authenticated packet sets LastRecv
	pn      uint64    // packet number the session was admitted with (retire watermark)
}

// maxRetiredSIDs bounds the replay watermark map. An evicted id may be replayed once.
const maxRetiredSIDs = 4096

// Client allowlist deny log: one line per source per clientDenyEvery (never per packet), and a bounded source table.
const (
	clientDenyEvery = 10 * time.Second
	clientDenyMax   = 256
	// clientDenyLogPerSec/clientDenyLogBurst bound the deny log over the whole server (L8), not per source.
	clientDenyLogPerSec = 3.0
	clientDenyLogBurst  = 3.0
)

type denyEntry struct {
	at time.Time
	n  int // packets dropped since the last line
}

type subIO struct {
	srv   *Server
	prev  []byte // the datagram the last Recv returned: handed back to the server pool on the next call
	sid   uint64
	inbox chan rxPkt
	peer  atomic.Value // net.Addr
	done  chan struct{}
	once  sync.Once
}

func (b *subIO) Send(p []byte, lane int) error {
	v := b.peer.Load()
	if v == nil {
		return errors.New("wat: no peer yet")
	}
	return b.srv.raw.SendTo(p, lane, v.(net.Addr))
}

// Backlogged asks the server's RawIO whether this session's destination has its send queues full.
func (b *subIO) Backlogged() bool {
	rb, ok := b.srv.raw.(RawBacklogger)
	if !ok {
		return false
	}
	v := b.peer.Load()
	return v != nil && rb.BackloggedTo(v.(net.Addr))
}

func (b *subIO) Recv() ([]byte, int, net.Addr, error) {
	if b.prev != nil {
		b.srv.putBuf(b.prev)
		b.prev = nil
	}
	select {
	case r := <-b.inbox:
		b.prev = r.p
		return r.p, r.lane, r.src, nil
	case <-b.done:
		return nil, 0, nil, errors.New("wat: session closed")
	}
}

// CopiesOnSend: the session may reuse a datagram buffer after Send when the shared socket copies it (raw ICMP, UDP).
func (b *subIO) CopiesOnSend() bool { return copies(b.srv.raw) }

func (b *subIO) Profile() Profile { return profileOf(b.srv.raw) }

func (b *subIO) SetPeer(a net.Addr) {
	if a != nil {
		b.peer.Store(a)
	}
}

func (b *subIO) Close() error {
	b.once.Do(func() {
		close(b.done)
		b.srv.mu.Lock()
		ss := b.srv.sessions[b.sid]
		// Only retire the entry that is still this IO's own session. evictStaleLocked removes the victim under the
		// lock but closes it in a goroutine, and admit can insert a NEW session under the same sid before that
		// goroutine runs; deleting by sid alone would then orphan the live session (its streams and clients hang).
		// An absent entry means eviction already retired it.
		owned := ss != nil && ss.io == b
		if owned {
			delete(b.srv.sessions, b.sid)
			b.srv.retireLocked(b.sid, max(ss.pn, ss.s.LastPN()))
		}
		b.srv.mu.Unlock()
		if owned { // keep Server.LastRecv monotonic: the session no longer feeds it once it leaves the map
			b.srv.noteRecv(ss.s.LastRecv())
		}
	})
	return nil
}

// staleAfter: a session that heard nothing for this long gives its slot to a new client when the table is full
// (clients ping every ~2 s). Before 3.2.0 a restarted client with 16 sessions found the server full of its own dead
// sessions and could not connect until the idle timeout closed them.
var staleAfter = 10 * time.Second

// evictStaleLocked frees the slot of the longest-silent session if it is stale; the session closes outside the lock.
func (srv *Server) evictStaleLocked() bool {
	var victim *srvSess
	var vlast time.Time
	for _, ss := range srv.sessions {
		last := ss.s.LastRecv()
		if last.IsZero() {
			last = ss.created
		}
		if victim == nil || last.Before(vlast) {
			victim, vlast = ss, last
		}
	}
	if victim == nil || time.Since(vlast) < staleAfter {
		return false
	}
	sid := victim.io.sid
	delete(srv.sessions, sid)
	srv.retireLocked(sid, max(victim.pn, victim.s.LastPN()))
	if srv.cfg.Logf != nil {
		srv.cfg.Logf("server full: client session %016x silent for %s, closing it for a new one", sid, time.Since(vlast).Round(time.Second))
	}
	go victim.s.Close()
	return true
}

// retireLocked records the highest authenticated packet number of a session that left the table; admit refuses a
// packet at or below it, so the session's own captured packets cannot create a session again.
func (srv *Server) retireLocked(sid, pn uint64) {
	if old, ok := srv.retiredPN[sid]; ok {
		if pn > old {
			srv.retiredPN[sid] = pn
		}
		return
	}
	if len(srv.retiredQ) >= maxRetiredSIDs {
		delete(srv.retiredPN, srv.retiredQ[0])
		srv.retiredQ = srv.retiredQ[1:]
	}
	srv.retiredPN[sid] = pn
	srv.retiredQ = append(srv.retiredQ, sid)
}

func NewServer(cfg Config, raw RawIO) *Server {
	cfg.Server = true
	if cfg.PingEvery <= 0 {
		cfg.PingEvery = 2 * time.Second
	}
	if cfg.Boot == 0 {
		var b [8]byte
		crand.Read(b[:])
		cfg.Boot = binary.BigEndian.Uint64(b[:]) | 1
	}
	srv := &Server{cfg: cfg, raw: raw, sessions: map[uint64]*srvSess{}, New: make(chan *Session, 64),
		stop: make(chan struct{}), free: make(chan []byte, 1024), MaxSessions: 128, retiredPN: map[uint64]uint64{},
		// a raised -ping-every means longer silences between authenticated packets (see Alive)
		IdleTimeout: max(45*time.Second, 3*cfg.PingEvery)}
	if len(cfg.AllowClients) > 0 {
		srv.allow, srv.deny, srv.denyEvery = cfg.AllowClients, map[netip.Addr]denyEntry{}, clientDenyEvery
		srv.denyLogRate, srv.denyLogBurst = clientDenyLogPerSec, clientDenyLogBurst
	}
	if !cfg.NoMask {
		srv.hk = hdrMaskKey(cfg.Key)
	}
	go srv.run()
	go srv.janitor()
	return srv
}

// Drain stops accepting new sessions; existing ones continue until they end.
func (srv *Server) Drain() { srv.draining.Store(true) }

func (srv *Server) Draining() bool { return srv.draining.Load() }

func (srv *Server) Sessions() int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.sessions)
}

func (srv *Server) Stats() Stats {
	srv.mu.Lock()
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	srv.statMu.Lock()
	defer srv.statMu.Unlock()
	now := make(map[*Session]Stats, len(list))
	var t Stats
	t.FecState = "off" // no session, no parity: the aggregate is "on" while any client session sends it (F11)
	for _, s := range list {
		st := s.Stats()
		t.PktsOut += st.PktsOut
		t.PktsIn += st.PktsIn
		t.BytesOut += st.BytesOut
		t.BytesIn += st.BytesIn
		t.Retrans += st.Retrans
		t.Dropped += st.Dropped
		t.RateBps += st.RateBps
		t.Streams += st.Streams
		t.Inflight += st.Inflight
		t.FecSent += st.FecSent
		t.FecRecovered += st.FecRecovered
		if st.FecState == "on" {
			t.FecState = "on"
		}
		t.PadBytes += st.PadBytes
		t.NoiseSent += st.NoiseSent
		t.NoiseBytes += st.NoiseBytes
		t.CeilingBps += st.CeilingBps
		if st.LossPct > t.LossPct {
			t.LossPct = st.LossPct
		}
		if st.SRTT > t.SRTT {
			t.SRTT = st.SRTT
		}
		if t.MinRTT == 0 || (st.MinRTT > 0 && st.MinRTT < t.MinRTT) {
			t.MinRTT = st.MinRTT
		}
		t.CC.add(st.CC)
		t.FloorBps += st.FloorBps
		t.Cwnd += st.Cwnd
		t.WinBlocked += st.WinBlocked
		t.LossTime, t.PTO, t.RelLossMul = max(t.LossTime, st.LossTime), max(t.PTO, st.PTO), max(t.RelLossMul, st.RelLossMul)
		now[s] = st
	}
	// A closed session leaves the map; keep its last counters so the cumulative totals stay monotonic (callers
	// subtract the previous total, and a smaller total wrapped to ~1.8e19 in the stats log).
	for s, st := range srv.seen {
		if _, live := now[s]; !live {
			addCounters(&srv.retired, st)
		}
	}
	srv.seen = now
	addCounters(&t, srv.retired)
	return t
}

// ClientInfo describes one live client session.
type ClientInfo struct {
	IP      string // the session's current peer source IP, no port
	Carrier string // carrier it was last heard on (MultiRaw servers only, else empty)
	Age     time.Duration
}

// Clients lists the live client sessions. Cheap enough for a stats endpoint.
func (srv *Server) Clients() []ClientInfo {
	mr, _ := srv.raw.(*MultiRaw)
	now := time.Now()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	out := make([]ClientInfo, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		var ci ClientInfo
		if lr := ss.s.LastRecv(); !lr.IsZero() {
			ci.Age = max(now.Sub(lr), 0)
		} else {
			ci.Age = max(now.Sub(ss.created), 0)
		}
		a, _ := ss.io.peer.Load().(net.Addr)
		if t, ok := a.(*TaggedAddr); ok {
			a = t.Addr
			if mr != nil && t.Idx >= 0 && t.Idx < len(mr.names) {
				ci.Carrier = mr.names[t.Idx]
			}
		}
		ci.IP = addrIP(a)
		out = append(out, ci)
	}
	return out
}

// ToggleMute toggles mute on the given path of a bonded server once, and applies the result to every live session;
// sessions admitted later start with it too.
func (srv *Server) ToggleMute(idx int) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	mr, ok := srv.raw.(*MultiRaw)
	if !ok || idx < 0 || idx >= len(mr.raws) {
		return false
	}
	if srv.muted == nil {
		srv.muted = map[int]bool{}
	}
	srv.muted[idx] = !srv.muted[idx]
	for _, ss := range srv.sessions {
		if m, ok := ss.s.IO().(*multiSubIO); ok {
			m.ps.setMute(idx, srv.muted[idx])
		}
	}
	return srv.muted[idx]
}

func addrIP(a net.Addr) string {
	switch v := a.(type) {
	case nil:
		return ""
	case poolAddr:
		return v.ip
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

// LastRecv is when the newest authenticated packet from any client arrived, including sessions that have closed
// since the server started (zero: none yet).
func (srv *Server) LastRecv() time.Time {
	srv.mu.Lock()
	for _, ss := range srv.sessions {
		srv.noteRecv(ss.s.LastRecv())
	}
	srv.mu.Unlock()
	if n := srv.lastRx.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (srv *Server) noteRecv(t time.Time) {
	if t.IsZero() {
		return
	}
	for n := t.UnixNano(); ; {
		old := srv.lastRx.Load()
		if n <= old || srv.lastRx.CompareAndSwap(old, n) {
			return
		}
	}
}

// addCounters adds the cumulative counters of b to a (not the rates, RTTs or live gauges).
func addCounters(a *Stats, b Stats) {
	a.PktsOut += b.PktsOut
	a.PktsIn += b.PktsIn
	a.BytesOut += b.BytesOut
	a.BytesIn += b.BytesIn
	a.Retrans += b.Retrans
	a.Dropped += b.Dropped
	a.FecSent += b.FecSent
	a.FecRecovered += b.FecRecovered
	a.PadBytes += b.PadBytes
	a.NoiseSent += b.NoiseSent
	a.NoiseBytes += b.NoiseBytes
	a.CC.add(b.CC)
}

// CarrierStats sums the per-carrier numbers of every client session (nil unless the server runs on a MultiRaw).
func (srv *Server) CarrierStats() []CarrierStat {
	if _, ok := srv.raw.(*MultiRaw); !ok {
		return nil
	}
	srv.mu.Lock()
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	var out []CarrierStat
	n := make([]int, 0)
	for _, s := range list {
		for i, c := range s.CarrierStats() {
			for len(out) <= i {
				out = append(out, CarrierStat{})
				n = append(n, 0)
			}
			o := &out[i]
			o.Name, o.Sent, o.Acked, o.Lost = c.Name, o.Sent+c.Sent, o.Acked+c.Acked, o.Lost+c.Lost
			o.Alive = o.Alive || c.Alive
			if c.Present {
				n[i]++
				o.Share += c.Share
				if o.SRTTms == 0 || c.SRTTms > 0 && c.SRTTms < o.SRTTms {
					o.SRTTms = c.SRTTms
				}
			}
		}
	}
	for i := range out {
		if n[i] > 0 {
			out[i].Share /= float64(n[i])
		}
	}
	return out
}

func (srv *Server) Close() {
	srv.mu.Lock()
	if srv.closed {
		srv.mu.Unlock()
		return
	}
	srv.closed = true
	close(srv.stop)
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	for _, s := range list {
		s.Close()
	}
	srv.raw.Close()
}

func (srv *Server) run() {
	var bo recvBackoff
	for {
		p, lane, src, err := srv.raw.Recv()
		if err != nil {
			select {
			case <-srv.stop:
				return
			default:
				bo.fail(err, srv.cfg.Logf, "server receive")
				continue
			}
		}
		bo.ok()
		if len(p) < hdrLen+tagLen+1 { // also shorter than any knock (36 bytes and up)
			continue
		}
		// The header is plain (an older peer) or masked (hdrmask.go): a known plain session id decides, else the masked
		// reading is tried. The packet goes on as received; the session unmasks it itself.
		hdr := [hdrLen]byte(p)
		ss := srv.lookup(binary.BigEndian.Uint64(hdr[:]))
		if ss == nil && srv.hk != nil {
			mh := unmaskedHdr(srv.hk, p)
			if m := srv.lookup(binary.BigEndian.Uint64(mh[:])); m != nil {
				hdr, ss = mh, m
			}
		}
		if ss != nil {
			if binary.BigEndian.Uint64(hdr[8:])&dirServerBit != 0 {
				// Our own packet coming back: in reverse ICMP the client host's kernel answers every request with a copy.
				// It carries a live session id, so counting it as traffic would keep a dead client's session from ever
				// going idle. The session would drop it anyway (own direction).
				continue
			}
		} else {
			if srv.draining.Load() {
				continue
			}
			// W10: the client allowlist is checked before admit, on the unauthenticated packet: a valid packet from a
			// source that is not allowed must not create a session either. Existing sessions are not re-checked
			// (a NAT/roaming client keeps working; only admission is gated).
			if !srv.sourceAllowed(src) {
				srv.noteDenied(src)
				continue
			}
			if ss = srv.admit(hdr, p, src); ss == nil && srv.hk != nil {
				ss = srv.admit(unmaskedHdr(srv.hk, p), p, src)
			}
			if ss == nil {
				continue
			}
		}
		select {
		case ss.io.inbox <- rxPkt{srv.getBuf(p), lane, src}:
		default: // overloaded: a dropped datagram is just loss
		}
	}
}

func (srv *Server) lookup(sid uint64) *srvSess {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.sessions[sid]
}

// admit creates a session for an unknown id, but only if this very packet authenticates under that id's key.
func (srv *Server) admit(hdr [hdrLen]byte, p []byte, src net.Addr) *srvSess {
	sid := binary.BigEndian.Uint64(hdr[:])
	pn := binary.BigEndian.Uint64(hdr[8:])
	if pn&dirServerBit != 0 {
		return nil
	}
	aead, err := sessionAEAD(srv.cfg.Key, sid)
	if err != nil {
		return nil
	}
	var nonce [12]byte
	copy(nonce[4:], hdr[8:])
	if _, err := aead.Open(nil, nonce[:], p[hdrLen:], hdr[:8]); err != nil {
		return nil
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.closed || len(srv.sessions) >= srv.MaxSessions && !srv.evictStaleLocked() {
		return nil
	}
	if ss := srv.sessions[sid]; ss != nil {
		return ss
	}
	if wm, seen := srv.retiredPN[sid]; seen && pn <= wm {
		return nil // a replay of a packet this server already accepted for that session
	}
	io := &subIO{srv: srv, sid: sid, inbox: make(chan rxPkt, 8192), done: make(chan struct{})}
	cfg := srv.cfg
	cfg.SID = sid
	admittingIdx := -1
	if t, ok := src.(*TaggedAddr); ok {
		admittingIdx = t.Idx
	}
	var pio PacketIO = io
	if mr, ok := srv.raw.(*MultiRaw); ok { // bonded server: reply on the best live carrier of this client
		m := newMultiSubIO(io, mr, cfg.Bond, admittingIdx)
		for i, muted := range srv.muted {
			m.ps.setMute(i, muted)
		}
		pio = m
	}
	// Direct TCP auto-promotion: if admitted on TCP/TLS pool and reliable, activate directMTU (16384)
	if prof := profileOf(pio); prof.Reliable && prof.MaxMTU >= directMTU {
		cfg.Direct = true
	}
	s, err := NewSession(cfg, pio)
	if err != nil {
		return nil
	}
	ss := &srvSess{s: s, io: io, created: time.Now(), pn: pn}
	srv.sessions[sid] = ss
	go func() { // never blocks admit: a slow New consumer only delays the handoff (select on stop: no leak on Close)
		select {
		case srv.New <- s:
		case <-srv.stop:
			s.Close()
		}
	}()
	if srv.cfg.Logf != nil {
		srv.cfg.Logf("new client session %016x (%d active)", sid, len(srv.sessions))
	}
	return ss
}

// sourceIP resolves a RawIO source address to the client's IP. ok=false when the address carries no IP (a reverse
// pool's merged dialed connections, or a custom/test RawIO).
func sourceIP(a net.Addr) (netip.Addr, bool) {
	for {
		switch v := a.(type) {
		case nil:
			return netip.Addr{}, false
		case *TaggedAddr: // bonded server: the child raw's own source address
			a = v.Addr
			continue
		case poolAddr: // direct tcp/tls/ws pool: the accepted connection's remote IP
			ip, err := netip.ParseAddr(v.ip)
			if err != nil {
				return netip.Addr{}, false
			}
			return ip.Unmap(), true
		case *net.UDPAddr:
			return ipNetip(v.IP)
		case *net.TCPAddr:
			return ipNetip(v.IP)
		case *net.IPAddr:
			return ipNetip(v.IP)
		}
		if h, _, err := net.SplitHostPort(a.String()); err == nil {
			if ip, err := netip.ParseAddr(h); err == nil {
				return ip.Unmap(), true
			}
		}
		if ip, err := netip.ParseAddr(a.String()); err == nil {
			return ip.Unmap(), true
		}
		return netip.Addr{}, false
	}
}

// ipNetip converts a net.IP to a netip.Addr, unmapping a 4-in-6 address so IPv4 prefixes match it.
func ipNetip(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// sourceAllowed reports whether a new session may be admitted from src (run goroutine). With no allowlist every
// source is allowed; with one, a source that carries no IP fails closed: a source that cannot be checked must not
// create a session.
func (srv *Server) sourceAllowed(src net.Addr) bool {
	if len(srv.allow) == 0 {
		return true
	}
	ip, ok := sourceIP(src)
	if !ok {
		return false
	}
	for _, p := range srv.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// noteDenied logs a rejected source at most once per denyEvery (run goroutine). Drops between two lines are counted
// and reported with the next one; the source table is bounded, so an address spray is dropped silently once it is
// full. L8: a global token bucket caps the log over the whole server, and the suppressed count is reported with the
// next line that gets through.
func (srv *Server) noteDenied(src net.Addr) {
	ip, ok := sourceIP(src)
	if !ok || srv.cfg.Logf == nil {
		return
	}
	now := time.Now()
	e, seen := srv.deny[ip]
	if !seen && len(srv.deny) >= clientDenyMax {
		for k, v := range srv.deny {
			if now.Sub(v.at) >= srv.denyEvery {
				delete(srv.deny, k)
			}
		}
		if len(srv.deny) >= clientDenyMax {
			return
		}
	}
	if seen && now.Sub(e.at) < srv.denyEvery {
		e.n++
		srv.deny[ip] = e
		return
	}
	if !srv.denyAllow(now) {
		srv.denySuppressed++
		e.n++
		srv.deny[ip] = e
		return
	}
	if srv.denySuppressed > 0 {
		srv.cfg.Logf("client %s is not in -allow-clients: %d packet(s) dropped (%d more drops suppressed by the log throttle)", ip, e.n+1, srv.denySuppressed)
		srv.denySuppressed = 0
	} else {
		srv.cfg.Logf("client %s is not in -allow-clients: %d packet(s) dropped", ip, e.n+1)
	}
	srv.deny[ip] = denyEntry{at: now}
}

// denyAllow takes one token from the server-wide deny-log bucket (L8); false means this line is suppressed. A Server
// built directly rather than by NewServer has rate 0, which means unlimited (the pre-L8 behaviour).
func (srv *Server) denyAllow(now time.Time) bool {
	if srv.denyLogRate <= 0 {
		return true
	}
	if srv.denyTokAt.IsZero() {
		srv.denyTokAt, srv.denyTokens = now, srv.denyLogBurst
	}
	srv.denyTokens = min(srv.denyTokens+now.Sub(srv.denyTokAt).Seconds()*srv.denyLogRate, srv.denyLogBurst)
	srv.denyTokAt = now
	if srv.denyTokens < 1 {
		return false
	}
	srv.denyTokens--
	return true
}

func (srv *Server) janitor() {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-srv.stop:
			return
		case <-tk.C:
			var dead []*Session
			cut := time.Now().Add(-srv.IdleTimeout)
			srv.mu.Lock()
			for _, ss := range srv.sessions {
				// authenticated recency only: a replayed or forged packet with a live id refreshes nothing
				last := ss.s.LastRecv()
				if last.IsZero() {
					last = ss.created
				}
				if last.Before(cut) {
					dead = append(dead, ss.s)
				}
			}
			srv.mu.Unlock()
			for _, s := range dead {
				srv.noteRecv(s.LastRecv())
				if srv.cfg.Logf != nil {
					srv.cfg.Logf("client session %016x idle, closing", s.sid)
				}
				s.Close()
			}
		}
	}
}

// getBuf copies a received datagram into a pooled buffer (the raw socket reuses its own buffer on the next Recv).
func (srv *Server) getBuf(p []byte) []byte {
	select {
	case b := <-srv.free:
		if cap(b) >= len(p) {
			return append(b[:0], p...)
		}
		// Too small: hand it back without blocking. A blocking send here can find the freed slot refilled by a
		// concurrent putBuf and wedge the server's only receive loop (audit 2026-10-27).
		srv.putBuf(b)
	default:
	}
	return append(make([]byte, 0, max(len(p), 2048)), p...)
}

func (srv *Server) putBuf(b []byte) {
	select {
	case srv.free <- b:
	default:
	}
}

// SendBatch forwards a burst to the shared socket in one call when it can (sendmmsg), else datagram by datagram.
// (A bonded session's multiSubIO embeds subIO but is a PathChooser, so the session never batches it.)
func (b *subIO) SendBatch(ps [][]byte, lanes []int) error {
	v := b.peer.Load()
	if v == nil {
		return errors.New("wat: no peer yet")
	}
	dst := v.(net.Addr)
	if rb, ok := b.srv.raw.(RawBatchSender); ok {
		return rb.SendBatchTo(ps, lanes, dst)
	}
	var first error
	for i, p := range ps {
		if err := b.srv.raw.SendTo(p, lanes[i], dst); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// recvBackoff paces a receive loop whose Recv keeps failing: 1 ms doubling to 200 ms, reset by a good Recv. The
// first error of a streak is logged once. The no-error path costs one bool test.
type recvBackoff struct {
	d      time.Duration
	failed bool
}

func (b *recvBackoff) fail(err error, logf func(string, ...any), what string) {
	if !b.failed {
		b.failed = true
		if logf != nil {
			logf("%s error (retrying with backoff): %v", what, err)
		}
	}
	if b.d == 0 {
		b.d = time.Millisecond
	}
	time.Sleep(b.d)
	if b.d *= 2; b.d > 200*time.Millisecond {
		b.d = 200 * time.Millisecond
	}
}

func (b *recvBackoff) ok() {
	if b.failed {
		b.failed, b.d = false, 0
	}
}
