package wat

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
)

// The tcp pool carrier: N TCP connections between one client and the server, each datagram framed as
// uint16 length + bytes. No crypto and no retransmit here: the session authenticates every datagram and repairs
// loss, so every queue is bounded and a full queue DROPS (blocking would stall every stream). A dead connection is
// closed, its queued packets are lost (loss, repaired by the session) and the client redials it with backoff.
// The tls carrier (carrier_tls.go) is this same pool with a different dial func / listener.
//
// Server side a client is identified by a random 8-byte pool id it sends first on every connection, since the
// connections of one pool come from different source ports. The hello is unauthenticated on purpose: the Server only
// admits sids whose packets authenticate, so all a stranger can do here is occupy capped slots for a few seconds.

const (
	poolQueue     = 256      // packets queued per connection
	poolMaxFrame  = 32 << 10 // receive bound; datagrams are at most poolMaxMTU
	poolBufSize   = 64 << 10
	poolSlabMin   = 16 << 10 // a slab with less room than this left is replaced before the next read
	poolHelloWait = 5 * time.Second
	poolMaxPools  = 4096
	poolMaxConns  = 64 // per pool
	poolRxQueue   = 1024
	// DefaultPoolConns is the default connection count of a client pool.
	DefaultPoolConns = 8
)

// poolProfile: TCP carries every datagram, in order per connection, so the session relaxes its loss detection and
// delay judgement (see Profile.Reliable).
var poolDrops atomic.Int64

const poolMaxMTU = 16 << 10

// MTU 4096 and an 8 MB/s start are measured defaults (2026-10-09, bench link 40 ms / 0.2 % / 100 Mbit): 640 B datagrams
// cost 4x the CPU per MB and a 1.5 MB/s start spends a quarter of a 32 MB transfer ramping up.
var poolProfile = Profile{Reliable: true, MTU: 4096, MaxMTU: poolMaxMTU, InitBps: 8e6}

// poolAddr identifies a client pool on the server: it is the net.Addr handed to Server and back to SendTo.
type poolAddr struct {
	key string
	ip  string // remote IP of the connection the packet came in on (informational: Server.Clients)
}

func (poolAddr) Network() string  { return "pool" }
func (a poolAddr) String() string { return hex.EncodeToString([]byte(a.key)) }

// Send-side datagram buffers of the pool carriers are recycled (v2.3.0): Send copies into one and the connection's
// writer hands it back once bufio has taken the bytes. Two size classes cover the default 4096 MTU and -mtu 16384;
// anything else is allocated and left to the GC. Received datagrams are NOT recycled: doing so (handing the buffer
// back on the next Recv) cost 15-25 % of loopback wss download throughput in repeated A/B runs, with a channel free
// list and with sync.Pool alike, so readLoop keeps allocating a fresh slice per datagram.
const (
	pktSmall = 4096
	pktBig   = poolMaxMTU
)

var (
	pktPoolSmall = sync.Pool{New: func() any { return new([pktSmall]byte) }}
	pktPoolBig   = sync.Pool{New: func() any { return new([pktBig]byte) }}
)

// getPkt returns a buffer of length n, recycled when one of the size classes fits.
func getPkt(n int) []byte {
	switch {
	case n <= pktSmall:
		return pktPoolSmall.Get().(*[pktSmall]byte)[:n]
	case n <= pktBig:
		return pktPoolBig.Get().(*[pktBig]byte)[:n]
	}
	return make([]byte, n)
}

// putPkt hands a buffer from getPkt back; the caller must not touch it afterwards.
func putPkt(b []byte) {
	switch cap(b) {
	case pktSmall:
		pktPoolSmall.Put((*[pktSmall]byte)(b[:pktSmall]))
	case pktBig:
		pktPoolBig.Put((*[pktBig]byte)(b[:pktBig]))
	}
}

// poolConn is one framed connection with its own bounded send queue.
type poolConn struct {
	c      net.Conn
	q      chan []byte
	qb     atomic.Int64 // bytes in q (3.0.0: the backlog and the least-queued choice count bytes)
	done   chan struct{}
	once   sync.Once
	wbusy  atomic.Int64  // unix ns when the writer entered a socket write that has not returned yet, 0 when idle
	rx     atomic.Uint64 // datagrams received
	tx     atomic.Uint64 // datagrams handed to the socket
	lastRx atomic.Int64  // unix ns of the newest received datagram (idle reaper; 0 = none yet)
	lastTx atomic.Int64  // unix ns of the newest socket write (idle reaper; 0 = none yet)
	txSize atomic.Uint64 // bytes handed to the socket (churn byte axis)
	born   time.Time

	rxMark  uint64 // owned by the pool's health check (judgeSlow)
	lowWins int

	rot atomic.Pointer[rotateBudget] // churn budget (client SetRotate); nil on the server side

	ip string // remote IP of the accepted connection (reverse-pool trust)

	txm, rxm *chacha20.Cipher // hello v2 (tcp_mimic.go): length masks of what this end writes and reads; nil = plain lengths
}

// A pool connection whose socket write has been blocked this long is stalled: through a CDN, one edge connection can
// sit in TCP retransmit backoff for tens of seconds with megabytes queued while the others flow (field 2026-10-12:
// backoff 8, 5 MB Send-Q). Its own queue looks empty because the kernel holds the data, so leastQueued kept picking
// it and every packet sent there was lost for 400+ ms. Stalled conns are skipped while a healthy one exists, and
// closed (the client redials) once stuck for poolStallKill.
// PoolTCPCC is the TCP congestion control set on every pool socket (2.4.18, `tcp-cc`; "" keeps the kernel default).
// The kernel default (cubic) halves a connection's window on every loss, and on the Iran path random loss is not
// congestion. Field 2026-10-16 (reverse tcp, 8 conns, 40 ms): ~20 MB/s per tunnel, far below
// what one session moves on one core. BBR paces by measured bandwidth and RTT and does not back off on random loss.
// Local to each end: the sender of a direction decides, so set it on both.
var PoolTCPCC = "bbr"

var poolTCPCCInUse atomic.Pointer[string]

// PoolTCPCCInUse is the congestion control the last pool socket ended up with ("" = no pool socket yet / not Linux).
func PoolTCPCCInUse() string {
	if p := poolTCPCCInUse.Load(); p != nil {
		return *p
	}
	return ""
}

const (
	poolStall     = 300 * time.Millisecond
	poolStallKill = 5 * time.Second
)

// Anti-DoS bounds on the pool listener (audit 2026-11-03). A stranger can open a connection and send only the
// 8-byte pool id: before these bounds, 4096 such conns held every pool slot forever (a 64 KB read slab and a
// goroutine each means real memory), and every later conn from the real client failed add(). poolMaxPerIP bounds
// one source address; poolIdleNever closes a conn the server never wrote a byte on (no session ever answered it);
// poolIdleHard closes a conn silent in both directions long enough that a live session's keepalives must have
// reached it. Vars, not consts, so the tests can shrink them.
var (
	poolMaxPerIP  = 128
	poolIdleNever = 5 * time.Minute
	poolIdleHard  = 30 * time.Minute
)

// poolLowat caps the unsent data the kernel queues per pool socket (TCP_NOTSENT_LOWAT). WAT_POOL_LOWAT (bytes, 3.0.0)
// overrides the 128 KB default for an A/B: less is less queueing delay under load, if BBR still keeps the pipe full.
// poolUserTimeout is TCP_USER_TIMEOUT on every pool socket: data unacknowledged this long closes the connection, so a
// path that cuts established flows (an Iran ISP resetting nothing, just dropping) fails the pool over in ~30 s whatever
// the traffic. WAT_POOL_USER_TIMEOUT (seconds, 3.0.1; 0 turns it off).
var poolUserTimeout = func() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("WAT_POOL_USER_TIMEOUT")); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	return 30 * time.Second
}()

var poolLowat = func() int {
	if n, err := strconv.Atoi(os.Getenv("WAT_POOL_LOWAT")); err == nil && n >= 16<<10 {
		return n
	}
	return HostProfile().PoolLowat
}()

func newPoolConn(c net.Conn) *poolConn {
	if tc := rawTCP(c); tc != nil {
		tc.SetNoDelay(true)
		setNotsentLowat(tc, poolLowat) // a stalled conn must block its writer, not swallow megabytes
		if poolUserTimeout > 0 {
			setUserTimeout(tc, poolUserTimeout) // a blackholed conn dies in seconds, not after ~15 min of kernel retries
		}
		if cc := setCongestion(tc, PoolTCPCC); cc != "" {
			poolTCPCCInUse.Store(&cc)
		}
	}
	pc := &poolConn{c: c, q: make(chan []byte, poolQueue), done: make(chan struct{}), born: time.Now()}
	poolLive.Store(pc, struct{}{})
	return pc
}

// poolLive holds every open pool connection of the process, for PoolConnStats.
var poolLive sync.Map

// PoolConnInfo is one pool connection as /stats shows it: datagrams sent and received since it opened, its send
// queue, and how long its current socket write has been blocked.
type PoolConnInfo struct {
	AgeS      float64 `json:"age_s"`
	Tx        uint64  `json:"tx"`
	Rx        uint64  `json:"rx"`
	Queue     int     `json:"queue"`
	StalledMs int64   `json:"stalled_ms"`
}

// PoolConnStats lists the open pool connections, oldest first.
func PoolConnStats() []PoolConnInfo {
	var pcs []*poolConn
	poolLive.Range(func(k, _ any) bool { pcs = append(pcs, k.(*poolConn)); return true })
	slices.SortFunc(pcs, func(a, b *poolConn) int { return a.born.Compare(b.born) })
	now := time.Now()
	out := make([]PoolConnInfo, len(pcs))
	for i, pc := range pcs {
		out[i] = PoolConnInfo{now.Sub(pc.born).Seconds(), pc.tx.Load(), pc.rx.Load(), len(pc.q),
			pc.stalledFor(now.UnixNano()).Milliseconds()}
	}
	return out
}

// The sender spreads datagrams evenly over its pool connections, so each one should deliver about the same number.
// Through a CDN, one connection's far leg can slow down while the sender's own socket to the edge stays clean: the
// edge buffers, everything sent on that connection arrives seconds late, and the session resends it (field
// 2026-10-12, 2.4.6 after ~3 h: about half of all packets resent with zero real loss, and the tunnel fell to ~1 MB/s).
// The sender cannot see it, but the receiver can: once a second each end compares what every connection delivered,
// and closes one that delivered under half the typical (upper-quartile) count for poolSlowWins seconds in a row. The
// client redials it, through a fresh path. Works with any peer version: it only closes connections.
const (
	poolSlowEvery = time.Second
	poolSlowWins  = 3
	poolSlowMin   = 24 // datagrams per connection per window, on average, before anything is judged
	poolSlowAge   = 3 * time.Second
)

var poolSlowKills atomic.Int64

// PoolSlowKills is how many pool connections this process closed for delivering far below their share.
func PoolSlowKills() int64 { return poolSlowKills.Load() }

// poolRotates counts connections recycled by the churn budget (client pools, SetRotate).
var poolRotates atomic.Int64

// judgeSlow takes one window's delivery counts and returns the connection to close, if any. Only the pool's health
// check calls it, so rxMark and lowWins need no lock.
func judgeSlow(conns []*poolConn, now time.Time) *poolConn {
	type cnt struct {
		pc *poolConn
		d  uint64
	}
	var cs []cnt
	var total uint64
	for _, pc := range conns {
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
			continue
		default:
		}
		v := pc.rx.Load()
		d := v - pc.rxMark
		pc.rxMark = v
		if now.Sub(pc.born) < poolSlowAge {
			pc.lowWins = 0
			continue
		}
		cs = append(cs, cnt{pc, d})
		total += d
	}
	if len(cs) < 3 || total < uint64(poolSlowMin*len(cs)) {
		for _, c := range cs {
			c.pc.lowWins = 0
		}
		return nil
	}
	ds := make([]uint64, len(cs))
	for i, c := range cs {
		ds[i] = c.d
	}
	slices.Sort(ds)
	ref := ds[len(ds)*3/4]
	var worst *poolConn
	var wd uint64
	for _, c := range cs {
		if 2*c.d >= ref {
			c.pc.lowWins = 0
			continue
		}
		if c.pc.lowWins++; c.pc.lowWins >= poolSlowWins && (worst == nil || c.d < wd) {
			worst, wd = c.pc, c.d
		}
	}
	if worst != nil {
		worst.lowWins = 0
	}
	return worst
}

// rawTCP finds the TCP socket under the TLS / WebSocket / gRPC / fragmenting wrappers (nil for an HTTP/2 stream).
func rawTCP(c net.Conn) *net.TCPConn {
	for i := 0; i < 8 && c != nil; i++ {
		switch x := c.(type) {
		case *net.TCPConn:
			return x
		case *wsConn:
			c = x.Conn
		case *grpcConn:
			c = x.Conn
		case *fragConn:
			c = x.Conn
		case interface{ NetConn() net.Conn }:
			c = x.NetConn()
		default:
			return nil
		}
	}
	return nil
}

// stalledFor is how long the current socket write has been blocked (0 when the writer is not inside one).
func (pc *poolConn) stalledFor(now int64) time.Duration {
	if t := pc.wbusy.Load(); t != 0 {
		return time.Duration(now - t)
	}
	return 0
}

// timedWriter marks the poolConn busy for the duration of every socket write.
type timedWriter struct{ pc *poolConn }

func (w timedWriter) Write(b []byte) (int, error) {
	w.pc.wbusy.Store(time.Now().UnixNano())
	n, err := w.pc.c.Write(b)
	w.pc.wbusy.Store(0)
	return n, err
}

// poolConnDeaths counts pool connections that went down, process-wide. Whatever was queued on one or still in its
// socket is gone, so a session polls this and resends its old unacked packets at once (Session.timers) instead of
// waiting out the loss timer.
var poolConnDeaths atomic.Uint64

// PoolConnDeaths is how many pool connections closed or failed in this process.
func PoolConnDeaths() uint64 { return poolConnDeaths.Load() }

// ConnDeaths is this pool's own connection-death count (DeathReporter): a session over this pool
// repairs its in-flight packets only when one of ITS connections died, not on another pool's churn.
func (c *TCPPoolClient) ConnDeaths() uint64 { return c.deaths.Load() }

func (pc *poolConn) fail() {
	pc.once.Do(func() {
		poolConnDeaths.Add(1)
		close(pc.done)
		pc.c.Close()
		poolLive.Delete(pc)
	})
}

// enqueue never blocks: false means the queue is full (or the conn is dead) and the packet was dropped.
func (pc *poolConn) enqueue(p []byte) bool {
	select {
	case <-pc.done:
		putPkt(p)
		return false
	default:
	}
	select {
	case <-pc.done:
		putPkt(p)
		return false
	case pc.q <- p:
		pc.qb.Add(int64(len(p)))
		select {
		case <-pc.done:
			for {
				select {
				case dropped := <-pc.q:
					pc.qb.Add(-int64(len(dropped)))
					putPkt(dropped)
				default:
					return false
				}
			}
		default:
			return true
		}
	default:
		poolDrops.Add(1)
		putPkt(p)
		return false
	}
}

// serve runs the writer in a goroutine and the reader inline until the connection dies.
func (pc *poolConn) serve(wg *sync.WaitGroup, push func([]byte) bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		pc.writeLoop()
	}()
	pc.readLoop(push)
	pc.fail()
}

func (pc *poolConn) writeLoop() {
	bw := bufio.NewWriterSize(timedWriter{pc}, poolBufSize)
	var hdr [2]byte
	defer func() {
		for {
			select {
			case p := <-pc.q:
				pc.qb.Add(-int64(len(p)))
				putPkt(p)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-pc.done:
			return
		case p := <-pc.q:
			for { // batch: flush only when the queue runs dry
				pc.qb.Add(-int64(len(p)))
				binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
				if pc.txm != nil {
					pc.txm.XORKeyStream(hdr[:], hdr[:])
				}
				if _, err := bw.Write(hdr[:]); err != nil {
					pc.fail()
					return
				}
				_, err := bw.Write(p)
				putPkt(p) // bufio has copied it (or written it through)
				pc.tx.Add(1)
				pc.txSize.Add(uint64(len(p)))
				pc.lastTx.Store(time.Now().UnixNano())
				if err != nil {
					pc.fail()
					return
				}
				select {
				case p = <-pc.q:
					continue
				default:
				}
				break
			}
			if err := bw.Flush(); err != nil {
				pc.fail()
				return
			}
		}
	}
}

// readLoop reads the connection into 64 KB slabs and hands out the datagrams as sub-slices of them (v2.4.0): no
// bufio copy and no allocation per datagram (one slab per ~16 datagrams). A slab is never reused: Recv's slice stays
// valid for as long as the session holds it. The unread tail of a full slab moves to the next one.
func (pc *poolConn) readLoop(push func([]byte) bool) {
	buf := make([]byte, poolBufSize)
	r, w := 0, 0
	for {
		if w-r < 2 {
			if n, ok := pc.fill(&buf, &r, &w, 2); !ok {
				_ = n
				return
			}
		}
		n := int(binary.BigEndian.Uint16(buf[r:]))
		if pc.rxm != nil {
			h := [2]byte{buf[r], buf[r+1]}
			pc.rxm.XORKeyStream(h[:], h[:])
			n = int(binary.BigEndian.Uint16(h[:]))
		}
		if n == 0 || n > poolMaxFrame {
			return
		}
		if w-r < 2+n {
			if _, ok := pc.fill(&buf, &r, &w, 2+n); !ok {
				return
			}
		}
		p := buf[r+2 : r+2+n : r+2+n]
		r += 2 + n
		pc.rx.Add(1)
		pc.lastRx.Store(time.Now().UnixNano())
		if !push(p) {
			return
		}
	}
}

// fill reads until at least need bytes are buffered at buf[*r:*w], moving to a fresh slab when the current one has
// no room left for them (or is nearly full, so reads stay large).
func (pc *poolConn) fill(buf *[]byte, r, w *int, need int) (int, bool) {
	if len(*buf)-*r < need || len(*buf)-*w < poolSlabMin {
		nb := make([]byte, poolBufSize)
		*w = copy(nb, (*buf)[*r:*w])
		*buf, *r = nb, 0
	}
	for *w-*r < need {
		n, err := pc.c.Read((*buf)[*w:])
		*w += n
		if err != nil && *w-*r < need {
			return n, false
		}
	}
	return 0, true
}

// Stream pinning (2.4.18, direct pools). A session that sends with a lane of PinLaneBase or more asks the pool to
// put the packet on connection (lane-PinLaneBase) mod n, so each stream rides one TCP connection, the way separate
// TCP connections would. Striping every stream over every connection made each stream, and so the whole session,
// wait on whichever connection was stalled in a TCP retransmit: on the lossy Kharej -> Iran path a session moved
// ~20-25 MB/s whether 1, 4 or 8 streams ran, while 8 bare TCP connections moved 78 (field 2026-10-16). A pinned
// connection that is write-stalled or half full falls back to the least-queued one. Other lanes are ignored, as before.
const PinLaneBase = 1 << 24

// pinnedConn returns the pinned connection for lane, or nil when lane does not pin or that connection cannot take it.
func pinnedConn(conns []*poolConn, lane int) *poolConn {
	if lane < PinLaneBase || len(conns) == 0 {
		return nil
	}
	pc := conns[(lane-PinLaneBase)%len(conns)]
	if pc == nil || pc.full() || pc.stalledFor(time.Now().UnixNano()) > poolStall {
		return nil
	}
	select {
	case <-pc.done:
		return nil
	default:
	}
	return pc
}

// poolBacklog is the queue depth at which a pool counts as full (Backlogger) and a pinned connection as busy. It is
// short on purpose: the session's loss timer starts when a packet is built, so time spent in our own queue counts as
// flight time. With half of the 256-packet queue (2.4.18 first cut) a packet waited 512 KB per connection before
// even reaching its socket; at a few MB/s per connection that alone neared the 400 ms timer, and with the socket and
// TCP's own recovery on top ~45 % of a download was resent (field 2026-10-16, Kharej -> Iran, 8 streams: srtt
// 165-220 ms over a 38 ms base). 16 packets (64 KB at the default MTU) plus the socket's 128 KB unsent low-water mark
// keep every connection busy while the rest waits in the session, where no timer runs. WAT_POOL_BACKLOG overrides it.
var poolBacklog = func() int {
	if n, err := strconv.Atoi(os.Getenv("WAT_POOL_BACKLOG")); err == nil && n > 0 && n <= poolQueue {
		return n
	}
	return 16
}()

// poolBacklogBytes (3.0.0) bounds the same queue in bytes. Since direct and reverse pools carry 16 KB payloads, the
// 16 packets above meant 256 KB per connection, 4x the 64 KB they were sized as; at ~3 MB/s per connection that is
// ~85 ms of our own queue in front of every packet, interactive ones included. 64 KB keeps the old depth at the
// 4 KB MTU and caps the big-payload queue at the intended size. WAT_POOL_BACKLOG_BYTES overrides it; setting only
// WAT_POOL_BACKLOG keeps the pre-3.0.0 packet-only rule (for an A/B).
var poolBacklogBytes = func() int64 {
	if n, err := strconv.ParseInt(os.Getenv("WAT_POOL_BACKLOG_BYTES"), 10, 64); err == nil && n > 0 {
		return n
	}
	if os.Getenv("WAT_POOL_BACKLOG") != "" {
		return 1 << 62
	}
	return 64 << 10
}()

// full: the connection's queue holds poolBacklog packets or poolBacklogBytes bytes.
func (pc *poolConn) full() bool { return len(pc.q) >= poolBacklog || pc.qb.Load() >= poolBacklogBytes }

// Express lane (3.0.0). With 3 or more connections, bulk packets (pinned to a stream's connection) stay off the
// pool's first connection, so interactive packets, datagrams and ack-only packets, which take the least-queued
// connection, always find one with a short queue: under a bulk transfer every connection used to hold a full
// queue, and a ping or a game packet waited behind it. WAT_NO_EXPRESS=1 turns it off (A/B).
var poolExpress = os.Getenv("WAT_NO_EXPRESS") == ""

// expressSkip is how many leading connections bulk must avoid: 1 with the express lane on and 3+ connections.
func expressSkip(n int) int {
	if poolExpress && n >= 3 {
		return 1
	}
	return 0
}

// backlogged reports whether even the least-queued usable conn already holds poolBacklog packets. Over a lossy path
// the pool's TCP connections stall in their own retransmits, their sockets stop taking data, and the queues fill;
// before 2.4.18 the session kept sending, Send dropped the overflow, and each drop came back as a "loss" ~400 ms later
// (field 2026-10-16, Kharej -> Iran: 61k such losses in 4x200 MB, ~20 MB/s where bare TCP did 78). Holding new data
// while the queues are full turns those drops into backpressure. Since 3.0.0 no conn at all holds as well (see
// TCPPoolClient.Backlogged): the reverse listener and a server whose client is reconnecting no longer drop datagrams.
func backlogged(conns []*poolConn) bool {
	if k := expressSkip(len(conns)); k > 0 { // bulk cannot use the express lane, so its room does not count
		if full, live := backlogOf(conns[k:]); live {
			return full
		}
	}
	full, _ := backlogOf(conns)
	return full
}

// backlogOf: every live conn's queue is full (judged by the unstalled ones while any is), and whether any conn is live.
func backlogOf(conns []*poolConn) (full, live bool) {
	now := time.Now().UnixNano()
	n, unstalled, free, freeAny := 0, 0, false, false
	for _, pc := range conns {
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
			continue
		default:
		}
		n++
		room := !pc.full()
		freeAny = freeAny || room
		if pc.stalledFor(now) > poolStall {
			continue
		}
		unstalled++
		free = free || room
	}
	if n == 0 {
		return true, false
	}
	if unstalled == 0 { // every conn is stalled: judge by the shortest queue, as leastQueued does
		return !freeAny, true
	}
	return !free, true
}

// pickConn chooses the connection for one packet on the server side: a pinned (bulk) lane takes its stream's
// connection, or the least-queued one, both outside the express lane; everything else the least-queued of all.
func pickConn(conns []*poolConn, lane, start int) *poolConn {
	if lane >= PinLaneBase && len(conns) > 0 { // a stable order, so a stream keeps its connection
		bulk := conns[expressSkip(len(conns)):] // bulk keeps off the express lane (3.0.0)
		if pc := pinnedConn(bulk, lane); pc != nil {
			return pc
		}
		if pc := leastQueued(bulk, start); pc != nil {
			return pc
		}
	}
	return leastQueued(conns, start)
}

// leastQueued picks the live conn with the shortest queue; start rotates so ties spread.
func leastQueued(conns []*poolConn, start int) *poolConn {
	now := time.Now().UnixNano()
	var best, any *poolConn
	bl, al := int64(1<<62), int64(1<<62)
	var stuck []*poolConn
	for i := range conns {
		pc := conns[(start+i)%len(conns)]
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
			continue
		default:
		}
		l := pc.qb.Load() // bytes, not packets: an ack and a 16 KB payload do not weigh the same (3.0.0)
		if l < al {
			any, al = pc, l
		}
		if d := pc.stalledFor(now); d > poolStall {
			if d > poolStallKill {
				stuck = append(stuck, pc)
			}
			continue
		}
		if l < bl {
			best, bl = pc, l
		}
	}
	if best == nil { // every conn is stalled: the whole path is slow, not one edge
		// ...unless every one has made no progress for poolStallKill: then the sockets are dead, and the kernel would
		// keep retransmitting on them for ~15 min (tcp_retries2) while the session sits in a blackout (prod 2026-10-26).
		// Close the stuck ones so the client slots redial; a stalled conn below that age may still recover.
		for _, pc := range stuck {
			go pc.fail()
		}
		if any != nil && !slices.Contains(stuck, any) {
			return any
		}
		return nil
	}
	for _, pc := range stuck { // a healthy conn exists: drop the stuck ones so the client redials them
		go pc.fail()
	}
	return best
}

// ---------------------------------------------------------------- client

// PoolDialFunc opens one raw connection to the server (plain TCP or TLS).
type PoolDialFunc func(ctx context.Context) (net.Conn, error)

// TCPPoolClient is the client PacketIO over a pool of framed connections. The lane is ignored.
type TCPPoolClient struct {
	dial   func(ctx context.Context, slot int) (net.Conn, error)
	hook   atomic.Pointer[func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)] // SetDialHook, wraps dial (fake-SNI)
	tlsFn  func() (string, string, bool)                                                                                             // TLS fingerprint, mode and ECH state, nil for non-TLS carriers
	ps     *peerSet
	peer   poolAddr
	remIP  atomic.Value // string: remote IP of the newest connection
	id     [8]byte
	slots  []atomic.Pointer[poolConn]
	rx     chan []byte
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	rr     atomic.Uint32
	once   sync.Once

	keepSlow   atomic.Bool                // never close a connection for delivering below its share (SetKeepSlow)
	maxBackoff atomic.Int64               // cap of the redial backoff in ns (0: poolBackoffMax)
	rotate     atomic.Int64               // churn: recycle a healthy connection after this many ns (0: off, SetRotate)
	rotBytes   atomic.Int64               // churn: also recycle after this many bytes handed to the sockets (0: off)
	logf       atomic.Pointer[dialLogger] // optional, see SetDialLog
	logMu      sync.Mutex
	lastLog    time.Time     // last failure line
	failing    bool          // a failure was logged and no connection came up since
	deaths     atomic.Uint64 // this pool's own connection deaths (ConnDeaths)

	obf    atomic.Pointer[obfsCfg] // SetObfs: hello v2 parameters (nil: the plain 8-byte pool id)
	v2     atomic.Bool             // the next connections open with hello v2 (flipped by mimicWatch against an older listener)
	lastRx atomic.Int64            // unix ns of the last packet received (mimicWatch)
	upAt   atomic.Int64            // unix ns of the last connection that came up
}

// obfsCfg is the hello v2 setup, published as one pointer so the slot goroutines started by the constructor never
// read a half-written value.
type obfsCfg struct {
	key []byte
	sni string
}

// SetObfs makes every new connection open with the TLS-shaped hello v2 and mask its frame lengths (see tcp_mimic.go),
// keyed by psk and naming sni (empty: www.cloudflare.com). Call it right after the pool is built, before traffic.
func (c *TCPPoolClient) SetObfs(psk []byte, sni string) {
	c.setObfs(&obfsCfg{key: psk, sni: sni})
}

func (c *TCPPoolClient) setObfs(o *obfsCfg) {
	c.obf.Store(o)
	c.v2.Store(true)
	c.wg.Add(1)
	go c.mimicWatch()
}

// mimicWatch falls back to the 8-byte pool id when connections come up but the listener never answers (an older
// version reads the long hello as garbage and stays silent), and tries hello v2 again if the plain one is not answered
// either, so a listener that is simply down or upgraded later is found again.
func (c *TCPPoolClient) mimicWatch() {
	defer c.wg.Done()
	t := time.NewTicker(max(mimicFallback/4, 50*time.Millisecond))
	defer t.Stop()
	since := time.Now()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			if c.upAt.Load() < since.UnixNano() {
				continue // nothing connected in this mode yet: not the hello's fault
			}
			ref, limit := since, mimicFallback
			if last := c.lastRx.Load(); last > since.UnixNano() {
				ref, limit = time.Unix(0, last), mimicLater
			}
			if now.Sub(ref) <= limit {
				continue
			}
			c.v2.Store(!c.v2.Load())
			since = now
			for i := range c.slots {
				if pc := c.slots[i].Load(); pc != nil {
					pc.fail() // the slot redials with the other hello
				}
			}
		}
	}
}

// SetDialHook wraps the pool's dial function (from the next redial on): the fake-SNI layer of the tcp and tls
// carriers uses it to inject its packet into every connection the pool opens. Safe at any time.
func (c *TCPPoolClient) SetDialHook(hook func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)) {
	p := hook
	c.hook.Store(&p)
}

// dialer returns the dial function the slots use: the hook, if set, wrapped around dial.
func (c *TCPPoolClient) dialer() func(ctx context.Context, slot int) (net.Conn, error) {
	if h := c.hook.Load(); h != nil {
		return func(ctx context.Context, slot int) (net.Conn, error) { return (*h)(ctx, slot, c.dial) }
	}
	return c.dial
}

// TCPClientOptions configures client dial parameters (source IP binding, dial hook).
type TCPClientOptions struct {
	LocalAddr net.Addr
	DialHook  func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)
}

// NewTCPPoolClient dials conns (0 = DefaultPoolConns) TCP connections to host:port in the background; Send drops
// until the first one is up, which the session treats as loss.
//
// peer may hold several comma-separated addresses: slot i dials address i%n (see peerSet).
func NewTCPPoolClient(peer string, conns int) (*TCPPoolClient, error) {
	return NewTCPPoolClientOptions(peer, conns, TCPClientOptions{})
}

// NewTCPPoolClientOptions is NewTCPPoolClient with custom TCPClientOptions (e.g. LocalAddr for multi-WAN bonding).
func NewTCPPoolClientOptions(peer string, conns int, opt TCPClientOptions) (*TCPPoolClient, error) {
	addrs, err := SplitPeers(peer)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: opt.LocalAddr}
	return newSlotClient(addrs, conns, func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}, opt.DialHook)
}

// newSlotClient is a pool client whose slots spread over addrs; dial opens one connection to one address. A slot
// tries its home address first, then the others at once, and the pool's redial backoff only applies when all failed.
func newSlotClient(addrs []string, conns int, dial func(ctx context.Context, addr string) (net.Conn, error), hook ...func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)) (*TCPPoolClient, error) {
	ps := newPeerSet(addrs)
	var h func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)
	if len(hook) > 0 {
		h = hook[0]
	}
	c, err := newSlotPoolClient(func(ctx context.Context, slot int) (net.Conn, error) {
		var last error
		for _, i := range ps.order(slot) {
			if ctx.Err() != nil {
				break
			}
			conn, err := dial(ctx, addrs[i])
			ps.mark(i, err == nil)
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = ctx.Err()
		}
		return nil, last
	}, conns, h)
	if c != nil {
		c.ps = ps
	}
	return c, err
}

// TLSInfo reports the TLS fingerprint in use and whether the newest connection used ECH (ok false: not a TLS carrier).
func (c *TCPPoolClient) TLSInfo() (fp, mode string, ech bool, ok bool) {
	if c.tlsFn == nil {
		return "", "", false, false
	}
	fp, mode, ech = c.tlsFn()
	return fp, mode, ech, true
}

// Edges reports the health of each peer address (nil for a client built without addresses).
func (c *TCPPoolClient) Edges() []EdgeStat {
	if c.ps == nil {
		return nil
	}
	return c.ps.edges()
}

func newSlotPoolClient(dial func(ctx context.Context, slot int) (net.Conn, error), conns int, hook ...func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error)) (*TCPPoolClient, error) {
	if conns <= 0 {
		conns = HostProfile().DefaultPoolConns
	}
	if conns > poolMaxConns {
		conns = poolMaxConns
	}
	c := &TCPPoolClient{dial: dial, slots: make([]atomic.Pointer[poolConn], conns),
		rx: make(chan []byte, poolRxQueue), done: make(chan struct{})}
	if len(hook) > 0 && hook[0] != nil {
		c.SetDialHook(hook[0])
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if _, err := crand.Read(c.id[:]); err != nil {
		return nil, err
	}
	c.peer = poolAddr{key: "server"}
	for i := range c.slots {
		c.wg.Add(1)
		go c.slotLoop(i)
	}
	c.wg.Add(1)
	go c.healthLoop()
	return c, nil
}

// healthLoop closes a connection that delivers far below its share (see judgeSlow); its slot redials it.
func (c *TCPPoolClient) healthLoop() {
	defer c.wg.Done()
	t := time.NewTicker(poolSlowEvery)
	defer t.Stop()
	conns := make([]*poolConn, len(c.slots))
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			// A socket whose write has made no progress for poolStallKill is dead for our purposes. leastQueued closes
			// such a conn only when a packet is sent, and a backlogged session sends nothing: when every conn stalls
			// at once (prod 2026-10-26) this sweep is what frees the slots to redial (3.0.1).
			for i := range c.slots {
				if pc := c.slots[i].Load(); pc != nil && pc.stalledFor(now.UnixNano()) > poolStallKill {
					pc.fail()
				}
			}
			// churn (2.8.0): recycle the connections that hit their budget. At most one per tick, oldest first,
			// so a recycle never lands in the same tick as a slow-connection kill (two closures in one tick halve
			// the judged traffic at once and read as one coordinated event) and the per-connection share the
			// slow check judges against stays honest while a slot redials.
			if rd := time.Duration(c.rotate.Load()); rd > 0 || c.rotBytes.Load() > 0 {
				if pc := c.rotatePick(now); pc != nil {
					poolRotates.Add(1)
					pc.fail() // the slot redials it; in-flight datagrams are resent like any death
					continue  // one closure per tick: the guarantee above covers the slow kill too
				}
			}
			if c.keepSlow.Load() {
				continue
			}
			for i := range c.slots {
				conns[i] = c.slots[i].Load()
			}
			if pc := judgeSlow(conns, now); pc != nil {
				poolSlowKills.Add(1)
				pc.fail()
			}
		}
	}
}

const (
	poolBackoffMax = 3 * time.Second
	poolLogEvery   = 5 * time.Minute
)

type dialLogger struct {
	name string
	f    func(string, ...any)
}

// SetDialLog makes the client report failed dials: the first one, then at most one per few minutes (all slots
// together), and a line when a connection comes up again. name tags the lines (the carrier). Safe at any time.
func (c *TCPPoolClient) SetDialLog(name string, f func(string, ...any)) {
	if f != nil {
		c.logf.Store(&dialLogger{name, f})
	}
}

// SetMaxBackoff caps the redial backoff (default 3 s); a dialer whose far end may simply not be listening wants
// longer, so it neither hammers the peer nor fills the log.
func (c *TCPPoolClient) SetMaxBackoff(d time.Duration) { c.maxBackoff.Store(int64(d)) }

func (c *TCPPoolClient) backoffCap() time.Duration {
	if n := c.maxBackoff.Load(); n > 0 {
		return time.Duration(n)
	}
	return poolBackoffMax
}

func (c *TCPPoolClient) noteFail(err error) {
	l := c.logf.Load()
	if l == nil {
		return
	}
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if now := time.Now(); !c.failing || now.Sub(c.lastLog) >= poolLogEvery {
		c.lastLog = now
		c.failing = true
		l.f("%s: cannot connect (%v); retrying with backoff, next report in %v", l.name, err, poolLogEvery)
	}
}

func (c *TCPPoolClient) noteUp() {
	l := c.logf.Load()
	if l == nil {
		return
	}
	c.logMu.Lock()
	was := c.failing
	c.failing = false
	c.logMu.Unlock()
	if was {
		l.f("%s: connected", l.name)
	}
}

func (c *TCPPoolClient) peerAddr() poolAddr {
	a := c.peer
	a.ip, _ = c.remIP.Load().(string)
	return a
}

func (c *TCPPoolClient) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.done:
		return false
	}
}

func (c *TCPPoolClient) push(p []byte) bool {
	if c.obf.Load() != nil {
		c.lastRx.Store(time.Now().UnixNano())
	}
	select {
	case c.rx <- p:
		return true
	case <-c.done:
		return false
	}
}

func (c *TCPPoolClient) slotLoop(i int) {
	defer c.wg.Done()
	backoff := 100 * time.Millisecond
	// 3.0.0: the first dial of every slot but slot 0 waits 50-250 ms, so a pool does not open N connections in the
	// same millisecond (a burst of identical handshakes is easy to fingerprint); slot 0 keeps startup fast.
	if i > 0 && !c.sleep(time.Duration(50+mrand.IntN(201))*time.Millisecond) {
		return
	}
	for {
		select {
		case <-c.done:
			return
		default:
		}
		conn, err := c.dialer()(c.ctx, i)
		var txm, rxm *chacha20.Cipher
		if err == nil {
			hello := c.id[:]
			if o := c.obf.Load(); o != nil && c.v2.Load() {
				if h, t, r, herr := buildMimicHello(o.key, o.sni, c.id); herr == nil {
					hello, txm, rxm = h, t, r
				}
			}
			conn.SetWriteDeadline(time.Now().Add(poolHelloWait))
			_, err = conn.Write(hello)
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				conn.Close()
			}
		}
		if err != nil {
			c.noteFail(err)
			if !c.sleep(backoff) {
				return
			}
			backoff = min(backoff*2, c.backoffCap())
			continue
		}
		c.noteUp()
		if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			c.remIP.Store(ra.IP.String())
		} else if conn.RemoteAddr() != nil {
			c.remIP.Store(addrIP(conn.RemoteAddr()))
		}
		pc := newPoolConn(conn)
		pc.txm, pc.rxm = txm, rxm
		c.upAt.Store(time.Now().UnixNano())
		if rd := time.Duration(c.rotate.Load()); rd > 0 || c.rotBytes.Load() > 0 {
			b := rollRotate(rd, c.rotBytes.Load())
			pc.rot.Store(&b)
		}
		c.slots[i].Store(pc)
		select { // Close may have swept the slots just before the Store
		case <-c.done:
			pc.fail()
		default:
		}
		t0 := time.Now()
		pc.serve(&c.wg, c.push)
		c.slots[i].Store(nil)
		c.deaths.Add(1) // this pool's own death counter (DeathReporter), for repairAfterDeath
		if time.Since(t0) > time.Second {
			backoff = 100 * time.Millisecond
		}
		if !c.sleep(backoff) {
			return
		}
		backoff = min(backoff*2, c.backoffCap())
	}
}

// Send copies p, but the pool carriers deliberately do not declare CopiesOnSend: letting the session recycle its
// sealed buffers saved ~7 % of the pump's CPU yet cost about a third of single-session wss download throughput on
// loopback in repeated A/B runs (2.3.0 measurements), so the session keeps allocating them.
func (c *TCPPoolClient) Send(p []byte, path int) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	// inline the snapshot: the pump calls this thousands of times a second and the old
	// make()+copy per packet was pure GC pressure (audit 2026-10-22, transport #4).
	// pinnedConn and leastQueued keep their slice form for the server/tests; here the
	// selection is written out against c.slots directly.
	now := time.Now().UnixNano()
	var pc *poolConn
	skip := 0
	if path >= PinLaneBase {
		skip = expressSkip(len(c.slots)) // bulk keeps off the express lane
	}
	if path >= PinLaneBase && len(c.slots) > skip { // pinned first, exactly like pinnedConn
		if cand := c.slots[skip+(path-PinLaneBase)%(len(c.slots)-skip)].Load(); cand != nil &&
			!cand.full() && cand.stalledFor(now) <= poolStall {
			select {
			case <-cand.done:
			default:
				pc = cand
			}
		}
	}
	// leastQueued: rotate start, prefer unstalled, then shortest queue. Bulk first looks outside the express lane,
	// then at every conn, so it still has a way out while the other slots dial (as pickConn on the server).
	for from := skip; pc == nil && from >= 0; from-- {
		start := int(c.rr.Add(1))
		var best, any *poolConn
		bl, al := int64(1<<62), int64(1<<62)
		for i := range c.slots {
			k := (start + i) % len(c.slots)
			if k < from {
				continue
			}
			cand := c.slots[k].Load()
			if cand == nil {
				continue
			}
			select {
			case <-cand.done:
				continue
			default:
			}
			l := cand.qb.Load()
			if cand.stalledFor(now) <= poolStall && l < bl {
				best, bl = cand, l
			}
			if l < al {
				any, al = cand, l
			}
		}
		if best == nil {
			pc = any // every conn stalled: judge by the shortest queue, as leastQueued does
		} else {
			pc = best
		}
	}
	if pc != nil {
		pc.enqueue(append(getPkt(len(p))[:0], p...)) // full queue: drop, the session repairs it
	}
	return nil
}

// rotateBudget is the jittered lifetime/byte budget of one pool connection (SetRotate). Every recycle rolls a
// fresh one, so no two connections share a period.
type rotateBudget struct {
	at    time.Time
	bytes int64
}

// rollRotate jitters the base budget: ±40 % on time, ±25 % on bytes (RESEARCH.md part 3 §2: a fixed reconnect period
// is itself a fingerprint). Floors: 10 s / 1 MB, so a bad roll cannot hot-loop the redialer.
func rollRotate(base time.Duration, baseBytes int64) rotateBudget {
	b := rotateBudget{}
	if base > 0 {
		j := time.Duration(float64(base) * (0.6 + 0.8*jitter01()))
		if j < 10*time.Second {
			j = 10 * time.Second
		}
		b.at = time.Now().Add(j)
	}
	if baseBytes > 0 {
		j := int64(float64(baseBytes) * (0.75 + 0.5*jitter01()))
		if j < 1<<20 {
			j = 1 << 20
		}
		b.bytes = j
	}
	return b
}

// jitter01 is a uniform [0,1) jitter source (spread, not secrecy: crypto strength is not needed).
func jitter01() float64 {
	var b [8]byte
	_, _ = crand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

// rotateDue reports whether the connection hit its churn budget. bytes is a byte budget compared against the
// bytes handed to the socket (2.8.1: it was datagram count, which at the default 4096-byte MTU ran the byte
// axis ~256x late and under a larger -mtu far too early — the budget's unit is bytes and so is the counter's).
func (pc *poolConn) rotateDue(now time.Time) bool {
	b := pc.rot.Load()
	if b == nil {
		return false
	}
	if !b.at.IsZero() && now.After(b.at) {
		return true
	}
	return b.bytes > 0 && int64(pc.txSize.Load()) >= b.bytes
}

// SetKeepSlow turns off the slow-connection check for a direct path (see TCPPoolServer.SetKeepSlow).
func (c *TCPPoolClient) SetKeepSlow(v bool) { c.keepSlow.Store(v) }

// rotatePick returns the oldest live connection that is due for its churn recycle (nil when none is, or when the
// recycle would strip the pool's last usable connection). At most one per health tick: a redial gap is invisible
// to the session (it resends like any connection death) but two closures in one tick halve the pool at once, and
// the slow check's per-connection share judgement reads better on a pool that loses one connection at a time.
func (c *TCPPoolClient) rotatePick(now time.Time) *poolConn {
	usable := 0
	for i := range c.slots {
		if pc := c.slots[i].Load(); pc != nil && !pc.full() && pc.stalledFor(now.UnixNano()) <= poolStall {
			select {
			case <-pc.done:
			default:
				usable++
			}
		}
	}
	if usable <= 1 { // never strip the last usable conn: on a 1-slot pool every recycle is a full outage
		return nil
	}
	var best *poolConn
	for i := range c.slots {
		pc := c.slots[i].Load()
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
			continue
		default:
		}
		if pc.rotateDue(now) && (best == nil || pc.born.Before(best.born)) {
			best = pc
		}
	}
	return best
}

// SetRotate turns on connection churn (2.8.0): a healthy pool connection is recycled after d, or after bytes
// handed to its socket (whichever comes first), so no long-lived flow presents a months-stable
// lifetime x volume profile to a behavioral classifier (RESEARCH.md part 3, bbs #649: lifetime is the strongest
// real-world tell). Each connection's budget is jittered ±40 % in time and ±25 % in count and re-rolled on every recycle,
// so the redials do not line up into a synchronized, fingerprintable period. Recycling closes one connection at
// a moment the pool picks itself: the session treats it like any connection death (in-flight datagrams are
// resent), and the slot redials immediately. d <= 0 and bytes <= 0 disable their axis. Client side only.
func (c *TCPPoolClient) SetRotate(d time.Duration, bytes int64) {
	c.rotate.Store(int64(d))
	c.rotBytes.Store(bytes)
}

// Backlogged reports whether the pool's send queues are full (Backlogger).
// Since 3.0.0 a client pool with no live connection counts as backlogged too: Send would drop the packet, and a
// datagram (UDP forwarding) is never repaired, so every datagram sent while the pool (re)connected was lost (the first
// datagram of each new session on loopback; HTTP carriers in the field, whose connections churn). Holding is safe:
// acks and pings still go out (and are dropped), stream data waits in the session where no loss timer runs.
func (c *TCPPoolClient) Backlogged() bool {
	if k := expressSkip(len(c.slots)); k > 0 { // as backlogged(): bulk's room is outside the express lane
		if full, live := c.backlogFrom(k); live {
			return full
		}
	}
	full, _ := c.backlogFrom(0)
	return full
}

// backlogFrom is backlogOf over c.slots[from:], inline: no per-tick allocation on the 1 kHz pump path (audit 2026-10-22).
func (c *TCPPoolClient) backlogFrom(from int) (full, live bool) {
	now := time.Now().UnixNano()
	n, unstalled, free, freeAny := 0, 0, false, false
	for i := from; i < len(c.slots); i++ {
		pc := c.slots[i].Load()
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
			continue
		default:
		}
		n++
		room := !pc.full()
		freeAny = freeAny || room
		if pc.stalledFor(now) > poolStall {
			continue
		}
		unstalled++
		free = free || room
	}
	if n == 0 {
		return true, false
	}
	if unstalled == 0 {
		return !freeAny, true
	}
	return !free, true
}

// Clone returns a new pool client to the same peer(s) with the same dial function, and with it the same TLS engine
// (fingerprint, ECH state and cache) and the same per-address health, but its own connections and its own random
// pool id, so the server sees an independent pool. The clone's slot i dials as slot i+slotOffset of the original
// would, which moves its starting edge on a multi-address -peer. (-sessions N, client only, 2.3.0.)
func (c *TCPPoolClient) Clone(slotOffset int) (*TCPPoolClient, error) {
	n, err := newSlotPoolClient(func(ctx context.Context, slot int) (net.Conn, error) {
		return c.dial(ctx, slot+slotOffset)
	}, len(c.slots))
	if err != nil {
		return nil, err
	}
	n.ps, n.tlsFn = c.ps, c.tlsFn
	n.hook.Store(c.hook.Load()) // the fake-SNI wrapper rides along, like every other dial-path setting
	if o := c.obf.Load(); o != nil {
		n.setObfs(o) // -tcp-mimic: the clone's connections must look like TLS too
	}
	n.keepSlow.Store(c.keepSlow.Load())
	n.maxBackoff.Store(c.maxBackoff.Load())
	n.rotate.Store(c.rotate.Load())
	n.rotBytes.Store(c.rotBytes.Load())
	if l := c.logf.Load(); l != nil {
		n.logf.Store(l)
	}
	return n, nil
}

func (c *TCPPoolClient) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-c.rx:
		return p, 0, c.peerAddr(), nil
	case <-c.done:
		return nil, 0, nil, net.ErrClosed
	}
}

// Conns reports how many pool connections are currently up.
func (c *TCPPoolClient) Conns() int {
	n := 0
	for i := range c.slots {
		if c.slots[i].Load() != nil {
			n++
		}
	}
	return n
}

func (c *TCPPoolClient) SetPeer(net.Addr) {}

func (c *TCPPoolClient) Profile() Profile { return poolProfile }

func (c *TCPPoolClient) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.cancel()
		for i := range c.slots {
			if pc := c.slots[i].Load(); pc != nil {
				pc.fail()
			}
		}
		c.wg.Wait()
	})
	return nil
}

// ---------------------------------------------------------------- server

// TCPPoolServer is the server RawIO: one listener, many pools. Recv's src and SendTo's dst are poolAddr values.
type TCPPoolServer struct {
	ln      net.Listener
	rx      chan rxPkt
	done    chan struct{}
	wg      sync.WaitGroup
	rr      atomic.Uint32
	once    sync.Once
	mu      sync.RWMutex
	pools   map[string]map[*poolConn]struct{}
	ordered map[string][]*poolConn // the same pools in born order, kept under mu by add/remove for the hot SendTo
	all     map[net.Conn]struct{}  // every accepted conn, so Close also reaches ones still in their hello
	perIP   map[string]int         // accepted conns per remote IP (anti-DoS cap; owned by mu)
	merge   atomic.Bool            // reverse mode: every conn joins one pool whatever its hello id says
	keep    atomic.Bool            // never close a connection for delivering below its share (SetKeepSlow)
	obfKey  atomic.Pointer[[]byte] // SetObfs: PSK that lets the listener recognise hello v2 (nil: only the plain pool id)

	// Reverse merge mode: source IPs whose connections delivered a packet the session authenticated. SendTo only
	// writes to those, so an unauthenticated dialer can neither receive the tunnel's packets nor hold it hostage.
	trustMu sync.Mutex
	trusted atomic.Pointer[trustedIPs]
}

type trustedIPs []string

const (
	maxTrustedIPs  = 8
	poolTrustGrace = 5 * time.Second // a new conn gets this long to deliver an authenticated packet before it is reaped
)

// SetObfs lets the listener accept hello v2 (tcp_mimic.go) next to the plain 8-byte pool id, which it tells apart by the
// first five bytes. A connection that starts like a hello v2 but does not verify is closed without an answer.
func (s *TCPPoolServer) SetObfs(psk []byte) { s.obfKey.Store(&psk) }

// addTrustedIP pins one source address that delivered an authenticated session packet (reverse merge mode only). The
// list is small and FIFO-bounded so a peer whose egress address changes keeps working.
func (s *TCPPoolServer) addTrustedIP(ip string) {
	if ip == "" {
		return
	}
	if cur := s.trusted.Load(); cur != nil && trustedHas(cur, ip) {
		return
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	cur := s.trusted.Load()
	if cur != nil && trustedHas(cur, ip) {
		return
	}
	var ips trustedIPs
	if cur != nil {
		ips = *cur
	}
	if len(ips) >= maxTrustedIPs {
		ips = ips[1:]
	}
	list := make(trustedIPs, 0, len(ips)+1) // a fresh slice: ipTrusted reads the stored one without a lock
	list = append(list, ips...)
	list = append(list, ip)
	s.trusted.Store(&list)
}

// ipTrusted reports whether ip is allowed to receive tunnel packets on a merged reverse pool. Before any address has
// authenticated, every connection is allowed (the pool has nothing to protect yet); afterwards only authenticated ones.
func (s *TCPPoolServer) ipTrusted(ip string) bool {
	cur := s.trusted.Load()
	return cur == nil || trustedHas(cur, ip)
}

func trustedHas(list *trustedIPs, ip string) bool {
	if list == nil {
		return false
	}
	for _, x := range *list {
		if x == ip {
			return true
		}
	}
	return false
}

// SetKeepSlow turns off the slow-connection check (2.4.7) for a direct path (2.4.18). It exists for a CDN edge whose
// far leg slows down; on a direct but lossy path every connection's delivery swings with its own TCP retransmits
// (field 2026-10-16, Kharej -> Iran: 2 to 209 Mbit/s per connection in one sample), and closing one throws away
// everything queued on it.
func (s *TCPPoolServer) SetKeepSlow(v bool) { s.keep.Store(v) }

// NewTCPPoolServer listens on addr (":4443").
func NewTCPPoolServer(addr string) (*TCPPoolServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newPoolServer(ln), nil
}

func newPoolServer(ln net.Listener) *TCPPoolServer {
	s := &TCPPoolServer{ln: ln, rx: make(chan rxPkt, poolRxQueue), done: make(chan struct{}),
		pools: map[string]map[*poolConn]struct{}{}, ordered: map[string][]*poolConn{}, all: map[net.Conn]struct{}{},
		perIP: map[string]int{}}
	s.wg.Add(2)
	go s.acceptLoop()
	go s.healthLoop()
	return s
}

// healthLoop closes, per pool, a connection that delivers far below its share (see judgeSlow); the client redials.
func (s *TCPPoolServer) healthLoop() {
	defer s.wg.Done()
	t := time.NewTicker(poolSlowEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			pools := make([][]*poolConn, 0, len(s.pools))
			for _, set := range s.pools {
				conns := make([]*poolConn, 0, len(set))
				for pc := range set {
					conns = append(conns, pc)
				}
				pools = append(pools, conns)
			}
			s.mu.Unlock()
			for _, cs := range pools { // a write blocked for poolStallKill is a dead socket, whatever keep-slow says (3.0.1)
				for _, pc := range cs {
					if pc.stalledFor(now.UnixNano()) > poolStallKill {
						pc.fail()
					}
				}
			}
			nowNano := now.UnixNano()
			for _, cs := range pools { // idle conns: a stranger can hold a slot only for a bounded time (audit 2026-11-03)
				for _, pc := range cs {
					if pc.tx.Load() == 0 && now.Sub(pc.born) > poolIdleNever {
						pc.fail() // no session ever sent on it: a handshake that never completed, or a slot squatter
						continue
					}
					if last := max(pc.lastRx.Load(), pc.lastTx.Load(), pc.born.UnixNano()); nowNano-last > int64(poolIdleHard) {
						pc.fail()
					}
				}
			}
			if s.merge.Load() { // reverse pool: after the first authenticated packet, strangers lose their slots
				if ts := s.trusted.Load(); ts != nil {
					for _, cs := range pools {
						for _, pc := range cs {
							if !trustedHas(ts, pc.ip) && now.Sub(pc.born) > poolTrustGrace {
								pc.fail()
							}
						}
					}
				}
			}
			for _, cs := range pools {
				if s.keep.Load() {
					break
				}
				if pc := judgeSlow(cs, now); pc != nil {
					poolSlowKills.Add(1)
					pc.fail()
				}
			}
		}
	}
}

// Addr is the bound address (useful with port 0).
func (s *TCPPoolServer) Addr() net.Addr { return s.ln.Addr() }

func (s *TCPPoolServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(50 * time.Millisecond) // transient (EMFILE...): do not spin
			continue
		}
		ip := addrIP(c.RemoteAddr())
		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			c.Close()
			return
		default:
		}
		if s.perIP[ip] >= poolMaxPerIP {
			s.mu.Unlock()
			c.Close() // one source cannot hold every pool slot (audit 2026-11-03); the real client just redials
			continue
		}
		s.perIP[ip]++
		s.all[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *TCPPoolServer) handle(c net.Conn) {
	defer s.wg.Done()
	ip := addrIP(c.RemoteAddr())
	defer func() {
		s.mu.Lock()
		delete(s.all, c)
		if n := s.perIP[ip]; n <= 1 {
			delete(s.perIP, ip)
		} else {
			s.perIP[ip] = n - 1
		}
		s.mu.Unlock()
	}()
	c.SetReadDeadline(time.Now().Add(poolHelloWait)) // also bounds a TLS handshake
	var id [8]byte
	if _, err := io.ReadFull(c, id[:]); err != nil {
		c.Close()
		return
	}
	var txm, rxm *chacha20.Cipher
	if k := s.obfKey.Load(); k != nil && isMimicPrefix(id[:]) {
		hello := make([]byte, mimicHelloLen)
		copy(hello, id[:])
		var ok bool
		if _, err := io.ReadFull(c, hello[len(id):]); err == nil {
			id, txm, rxm, ok = parseMimicHello(*k, hello)
		}
		if !ok {
			c.Close()
			return
		}
	}
	c.SetReadDeadline(time.Time{})
	pc := newPoolConn(c)
	pc.ip = ip
	pc.txm, pc.rxm = txm, rxm
	key := string(id[:])
	if s.merge.Load() {
		key = reverseKey
	}
	if !s.add(key, pc) {
		pc.fail()
		return
	}
	src := poolAddr{key: key, ip: addrIP(c.RemoteAddr())}
	pc.serve(&s.wg, func(p []byte) bool {
		select {
		case s.rx <- rxPkt{p: p, src: src}:
			return true
		case <-s.done:
			return false
		}
	})
	s.remove(key, pc)
}

func (s *TCPPoolServer) add(key string, pc *poolConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	set := s.pools[key]
	if set == nil {
		if len(s.pools) >= poolMaxPools {
			return false
		}
		set = map[*poolConn]struct{}{}
		s.pools[key] = set
	}
	if len(set) >= poolMaxConns {
		if !s.merge.Load() {
			return false
		}
		// Reverse mode has ONE pool, so a stranger must never be able to lock the dialing side out of it: evict the
		// oldest connection (preferring one that never delivered an authenticated packet) and let the new dialer in.
		// SendTo only writes to trusted source IPs, so an evicted stranger loses nothing it was entitled to.
		o := s.ordered[key]
		if len(o) == 0 {
			return false
		}
		victim := o[0]
		if ts := s.trusted.Load(); ts != nil {
			for _, c := range o {
				if !trustedHas(ts, c.ip) {
					victim = c
					break
				}
			}
		}
		delete(set, victim)
		next := make([]*poolConn, 0, len(o))
		for _, c := range o {
			if c != victim {
				next = append(next, c)
			}
		}
		s.ordered[key] = next
		go victim.fail()
	}
	set[pc] = struct{}{}
	s.ordered[key] = append(s.ordered[key], pc) // born order kept on change: SendTo must not sort per packet
	return true
}

func (s *TCPPoolServer) remove(key string, pc *poolConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.pools[key]; set != nil {
		delete(set, pc)
		if len(set) == 0 {
			delete(s.pools, key)
			delete(s.ordered, key)
		} else if o := s.ordered[key]; o != nil {
			for i, x := range o {
				if x == pc {
					// fresh array, never shift in place: SendTo reads the old slice without s.mu,
					// and append(o[:i], ...) would move entries under its feet (race, audit 2026-10-22)
					no := append([]*poolConn(nil), o[:i]...)
					s.ordered[key] = append(no, o[i+1:]...)
					break
				}
			}
		}
	}
}

func (s *TCPPoolServer) Recv() ([]byte, int, net.Addr, error) {
	select {
	case r := <-s.rx:
		return r.p, 0, r.src, nil
	case <-s.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (s *TCPPoolServer) SendTo(p []byte, lane int, dst net.Addr) error {
	a, ok := dst.(poolAddr)
	if !ok {
		return net.ErrClosed
	}
	s.mu.RLock()
	conns := s.ordered[a.key] // born-ordered copy kept by add/remove: read-locked without writer contention
	s.mu.RUnlock()
	pc := pickConn(conns, lane, int(s.rr.Add(1)))
	if pc != nil {
		if s.merge.Load() && !s.ipTrusted(pc.ip) {
			// A dialer that never delivered a packet the session could authenticate must not receive the tunnel's
			// packets. A young connection keeps its grace window to authenticate (a peer may use another egress
			// address); an older one is closed so the sender can pick a real one.
			if time.Since(pc.born) > poolTrustGrace {
				pc.fail()
			}
			return nil
		}
		pc.enqueue(append(getPkt(len(p))[:0], p...))
	}
	return nil // no live conn or full queue: dropped, the session repairs it
}

// BackloggedTo reports whether the pool behind dst has its send queues full (RawBacklogger).
func (s *TCPPoolServer) BackloggedTo(dst net.Addr) bool {
	a, ok := dst.(poolAddr)
	if !ok {
		return false
	}
	s.mu.RLock()
	conns := s.ordered[a.key]
	s.mu.RUnlock()
	return backlogged(conns)
}

// PoolDrops counts packets dropped because every pool queue was full (process-wide).
func PoolDrops() int64 { return poolDrops.Load() }

func (s *TCPPoolServer) Profile() Profile { return poolProfile }

// Pools and Conns report the live pool and connection counts.
func (s *TCPPoolServer) Pools() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pools)
}

func (s *TCPPoolServer) Conns() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, set := range s.pools {
		n += len(set)
	}
	return n
}

func (s *TCPPoolServer) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		close(s.done)
		s.mu.Unlock()
		s.ln.Close()
		s.mu.Lock()
		for c := range s.all {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}
