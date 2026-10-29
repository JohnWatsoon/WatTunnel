// Package wat is WatTunnel: a multiplexed, encrypted, paced transport for paths that only pass ICMP echo.
package wat

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	MaxPayload    = 640 // default datagram size: ICMP echo payload cap, stays under the 680 route MTU after IP+ICMP headers
	MinPayload    = 256 // bounds of Config.MaxPayload
	MaxPayloadHi  = 1400
	hdrLen        = 16 // session id (8) + explicit packet number (8); nonce = 4 zero bytes + pn
	tagLen        = 16
	overhead      = hdrLen + tagLen
	streamWindow  = 4 << 20
	sendBufMax    = 4 << 20
	maxStreamWin  = 16 << 20  // default auto-tuned window cap per stream; Config.WinMax lowers it (stream.go tuneWindow)
	maxSessionWin = 64 << 20  // total window growth beyond the 4 MB bases, per session
	sendStage     = 256 << 10 // Write may buffer this much beyond the peer's window (stream.go writeCap)
	slowWinMin    = 256 << 10 // a lagging reader's window floor (stream.go tuneSlow)
	slowWinRTTs   = 2
	// keepBuf is the largest drained send buffer a stream keeps for reuse (the receive side uses pooled chunks). Field 2026-10-12: at 1 MB, 220
	// mostly idle streams pinned ~190 MB on the receiving end.
	keepBuf      = 256 << 10
	prioBytes    = 64 << 10 // streams that sent less than this recently go first (interactive traffic; Stream.bulky)
	dirServerBit = uint64(1) << 63
	replayWin    = 1024
	// A pool of TCP connections reorders by a whole head-of-line stall (60-100 ms of packets, ~1900 at 640 B and
	// 12 MB/s); a window of 1024 turned every late packet after a stall into a "replay" and dropped it (measured).
	// 16384 was ~0.3-0.7 s at 30-70 MB/s: a connection in a few rounds of TCP loss recovery outlasted it, and the data
	// it then delivered was dropped as a replay and resent (field 2026-10-16, 32 connections: 2005 such packets per
	// 200 MB). 131072 (a 1 MB ring) covers ~4 s at 125 MB/s with 4 KB packets.
	reliableReplayWin = 131072
	directMTU         = 16 << 10 // default datagram size on a direct pool (2.5.0)
	maxStreams        = 8192
	ipIcmpHdr         = 28
)

// PathNextChooser queries the next scheduled path before packet serialization.
type PathNextChooser interface {
	NextPath(interactive bool) int
}

var ErrSessionDead = errors.New("wat: session closed")

type Config struct {
	Server     bool
	Key        []byte
	SID        uint64        // session id (client: random if 0; server sessions get the client's)
	Paths      int           // client: lanes (ICMP identifiers) to stripe over
	InitBps    float64       // starting pace, bytes/s (default 1.5 MB/s)
	MaxBps     float64       // pace ceiling, bytes/s (default 16 MB/s)
	MinBps     float64       // pace floor (default 200 KB/s)
	Slack      time.Duration // extra RTT over the minimum tolerated before slowing down (default 8 ms)
	Boot       uint64        // server process id (random per run); clients reset their streams when it changes
	MaxPayload int           // datagram size cap incl. header and tag; 0 = MaxPayload (640), bounded to [256, 1400]
	Hedge      bool          // send young packets twice on different lanes (costs ~8% extra packets)
	FEC        bool          // adaptive XOR parity after bursts of small packets (both ends must enable it; see fec.go)
	NoKex      bool          // skip the forward-secrecy key exchange on this session (same as WAT_NO_KEX, but per session)
	Bond       PathTimings   // multipath health/probe timings (server side; zero = production values)
	// Direct: the reliable carrier runs straight between the two servers (reverse mode, or tcp/tls), with no CDN that
	// could buffer in between. The only queues are our pool's and the sockets', which push back (Backlogger), so the
	// session lets TCP set the pace: a window of about a second of delivery and a long loss timer (2.4.18, see cc.go).
	Direct bool
	// PingEvery: idle keepalive interval (default 2 s). Raise it on paths whose filter rate-limits steady
	// periodic packets into a penalty box (observed live 2026-10-22: 30 ICMP echo req/min to one host
	// collapsed to 95% loss until a ~5 min cooldown). Both ends need it only if BOTH are idle-quiet;
	// a single-sided raise already halves the rate.
	PingEvery time.Duration
	// NoMask sends and expects the plain packet header (session id and packet number in clear). The default masks
	// both (hdrmask.go) and falls back to the plain form against a peer older than 3.0.0.
	NoMask bool
	// NoShape turns off the random padding of small packets and the jitter on the idle keepalive (hdrmask.go).
	NoShape bool
	// WinMax caps the receive window this end advertises per stream, so it also caps what the peer's sender may
	// buffer for that stream (stream.go sendCap/writeCap). Clamped to 4-64 MB; 0 = the
	// host profile's cap (hardware.go: 4 MB lean, 16 MB standard, 32 MB highperf; a fixed 16 MB before 3.0.3). 4 MB pins the window at the base, i.e. no auto-tuning. Set it on
	// a small VPS to bound memory: with the default, N concurrent bulk streams let the sender hold up to N x 16 MB,
	// measured 2026-10-27 as 148-214 MB of live heap for 8 streams on a 894 MB box. Windows are receiver-driven, so
	// each end bounds the direction it receives; set it on both ends to bound both.
	WinMax uint64
	Logf   func(string, ...any)
}

type Stats struct {
	PktsOut, PktsIn, BytesOut, BytesIn uint64
	Retrans, Dropped                   uint64
	AckLate                            uint64 // packets acked only by a late-ACK frame (older than the newest 64 ranges)
	RxDup, RxTooOld                    uint64 // packets dropped as already received / older than the replay window
	RateBps                            float64
	SRTT, MinRTT                       time.Duration
	Streams                            int
	Inflight                           int
	// datagrams (UDP forwarding)
	DgramSent, DgramRecv                       uint64
	DgramDropQueue, DgramDropSize, DgramDropRx uint64
	DgramFragmented, DgramReassembled          uint64 // datagrams sent in pieces / rebuilt from pieces (2.5.0)
	FecSent, FecRecovered                      uint64
	CeilingBps, LossPct                        float64 // loss-aware soft ceiling (0 = none); last judged interval loss in percent

	// pacer diagnostics (2.4.10)
	CC            CCDiag
	FloorBps      float64
	Cwnd          int
	LossTime, PTO time.Duration
	RelLossMul    float64
	WinBlocked    int // streams with data waiting but no window from the peer
}

type sentPkt struct {
	pn     uint64
	at     time.Time
	size   int
	frames []frameRef
	ctrl   [][]byte
	dgram  bool // carries datagrams: tracked for pacing/inflight only, never retransmitted
	lane   int  // path it was sent on (the ICMP lane, or the bond path)
	done   bool // acked or declared lost
	lost   bool // declared lost (bond: a late ack still proves the path alive)
	rtx    bool // carries resent stream data (a pinned pool sends it on any connection, not the stream's own)
}

type outPkt struct {
	p       []byte
	lane    int
	dupLane int // >=0: send the identical datagram again on this lane (hedge against random loss)
}

type Session struct {
	cfg  Config
	sid  uint64
	io   PacketIO
	aead cipher.AEAD
	// forward-secrecy key exchange (2.10.0, both ends; see onKex): the client offers an ephemeral X25519 key until
	// the server's reply switches it, the server answers offers until a packet sealed with the fresh key arrives.
	oldAead      cipher.AEAD // the key before the switch: still opens in-flight packets for kexGrace, then dropped
	pskAead      cipher.AEAD // the original PSK key: seals the restart probes (never dropped; a restarted peer's only way in)
	probeUntil   time.Time   // client: while set, send PSK-sealed kex offers and accept PSK packets — the peer may have restarted and lost the fresh key
	kexPriv      []byte      // this side's ephemeral X25519 private key (nil: no exchange — WAT_NO_KEX, an old peer, or a bad peer key)
	kexPub       []byte      // the matching public key, sent as the frKex frame
	kexAead      cipher.AEAD // server: the fresh key, tried first on receive until the client proves it switched
	kexPeerPub   []byte      // server: the client's ephemeral public key
	kexOfferAt   time.Time   // server: last offer received (kexAead expires kexGrace after the offers stop)
	kexReplyPend bool        // server: answer the offer with our own key in the next packet
	kexSentAt    time.Time   // client: last offer sent (re-offered a second later if the reply is lost)
	kexStart     time.Time   // client: when the current offer round began (10 s without a reply re-arms with fresh keys)
	kexAt        time.Time   // when the fresh key took over in both directions
	kexDone      bool
	rxKeys       atomic.Pointer[[2]cipher.AEAD] // {aead, oldAead} while kexDone, else nil: handle's lock-free open (pubRxKeys)
	kexGrace     time.Duration                  // old-key grace / stale-exchange expiry (a copy of the kexGrace default; a field so tests can shrink it per session without racing other sessions' pumps)
	kexGiveUp    time.Duration                  // client: how long to keep offering before re-arming with fresh keys (same reasoning)
	probeAfter   time.Duration                  // client: copies of kexProbeAfter/kexProbeFor (same reasoning)
	probeFor     time.Duration
	mu           sync.Mutex
	now          time.Time

	closed   bool
	stop     chan struct{}
	nextPN   uint64
	laneRR   int
	laneSeen map[int]time.Time
	lanes    []int

	// receive state
	rxAny     bool
	rxLargest uint64
	rxRing    []uint64 // replay window: 1024 packets, or reliableReplayWin for a Profile.Reliable carrier
	replayWin uint64
	ackMax    int // SACK ranges per ACK frame (the wire format allows 64)
	rxKeep    int // received ranges remembered
	ackEvery  int // ack after this many ack-eliciting packets (or 2 ms)
	rxRanges  rangeSet
	rxSince   []uint64 // reliable: packet numbers received since the last ACK (lateAck reports the ones it leaves out)
	rxLate    rangeSet // reliable: received packets no ACK has reported yet, below the newest ackMax ranges
	lateAck   bool
	rxAt      time.Time
	ackPend   int
	ackSince  time.Time
	lastRecv  time.Time // cleared after 30 s of silence (the session then counts as dead)
	lastAuth  time.Time // same, never cleared: what LastRecv reports

	streams       map[uint64]*Stream
	tomb          map[uint64]time.Time
	lastTombPrune time.Time
	nextSID       uint64
	acceptQ       []*Stream
	acceptC       *sync.Cond
	prio          streamQ // interactive streams (sent < prioBytes), FIFO
	bulk          fairQ   // bulk streams: fair between groups (public ports), round-robin inside a group
	ctrl          [][]byte
	sent          []*sentPkt
	sentHead      int
	inflight      int
	cc            cc
	lastSend      time.Time
	wantPing      bool
	pingGap       time.Duration // idle time before the next keepalive: PingEvery, re-rolled after each ping (nextPingGap)
	hk            []byte        // header-mask key (nil: NoMask)
	masked        atomic.Bool   // seal outgoing packets with a masked header: the client's guess, the server's echo of what it received
	maskFlip      time.Time     // client: when the masked/plain guess last changed while no packet had authenticated
	peerMaskOK    atomic.Bool   // the peer's padding carried the "I read masked headers" byte (hdrmask.go): a client that guessed plain then switches to masked for good
	stats         Stats
	openBuf       []byte
	noWinTune     bool     // tests: behave like a peer that never advertises more than the implicit window
	winCap        uint64   // per-stream window ceiling this end advertises: cfg.WinMax, or auto-tuned from host profile (stream.go)
	maxSessionWin uint64   // total window growth beyond base windows per session: auto-tuned from host profile (stream.go)
	winExtra      uint64   // sum over streams of (win - streamWindow): the auto-tuned growth in use
	winSlack      uint64   // bytes a peer's largest datagram may overshoot the advertised stream window
	maxPlain      int      // plaintext bytes per datagram: cfg.MaxPayload - header - tag
	plainBuf      []byte   // reused packet assembly buffer (nextPacket runs under s.mu)
	txNonce       [12]byte // seal runs under s.mu; kept here because an array passed to the AEAD interface escapes to the heap
	rxNonce       [12]byte // handle runs on the receive goroutine only
	copier        bool     // the carrier copies a datagram inside Send, so the buffer may be reused as soon as Send returns
	outFree       chan []byte
	outStack      [][]byte      // fast L1-cached buffer recycler for pump goroutine
	batcher       BatchSender   // nil: send one datagram at a time
	backlog       Backlogger    // nil: the carrier has no send queues of its own to report
	deathIO       DeathReporter // the carrier's own connection-death counter, when it has one (pool carriers)
	held          bool          // this pump round: the carrier's send queues are full, no new data
	pin           bool          // direct pool: send each packet on its first stream's own connection (PinLaneBase+slot)
	pinNext       int           // next stream's connection slot: round-robin, so 8 streams over 8 connections use all 8
	deaths        uint64        // connection deaths already handled (per-IO when the carrier reports, else global)
	bp            [][]byte
	bl            []int
	spFree        []*sentPkt
	ackRs         []rng // parsed ACK ranges, valid for one parse

	fec      *fecState // nil unless Config.FEC
	hedgeTok float64   // bytes of hedging allowed: ~8% of what was sent
	bootAt   time.Time
	peerBoot uint64
	wake     chan struct{}

	dq      [][]byte // encoded frDgram frames waiting to go out (unreliable, bounded)
	dqBytes int
	dgIn    chan Datagram
	fragID  uint64               // next id for a fragmented datagram
	reasm   map[fragKey]*fragBuf // datagrams being rebuilt from pieces
	dbuf    []byte               // scratch: datagram frames chosen for the packet being built

	// multipath (nil/empty for every single-carrier PacketIO)
	chooser  PathChooser
	fb       PathFeedback
	pcc      []pathCC
	probeQ   []int
	ackBuf   []*sentPkt
	lostRing []lostRec // reliable single carrier: recently declared lost, for spurious-resend detection
	smpBuf   []*sentPkt
}

// pathCC is the session's own per-path delay/ordering state, used only with a PathChooser: loss detection must
// compare a packet with later packets of ITS path (paths of different delay reorder against each other), and the
// pacer must see queueing growth on a path, not the difference between two paths.
type pathCC struct {
	srtt, minRTT time.Duration
	minAt, at    time.Time
	largest      uint64
	have         bool
	reliable     bool
	ackOnly      int // ack-only packets since the last PING on this path
}

func NewSession(cfg Config, pio PacketIO) (*Session, error) {
	if cfg.Paths <= 0 {
		cfg.Paths = 1
	}
	prof := profileOf(pio)
	if cfg.InitBps == 0 {
		cfg.InitBps = 1.5e6
		if prof.InitBps > 0 {
			cfg.InitBps = prof.InitBps
		}
	}
	if cfg.MaxBps == 0 {
		cfg.MaxBps = 16e6
	}
	if cfg.MinBps == 0 {
		cfg.MinBps = 2e5
	}
	if cfg.Slack == 0 {
		cfg.Slack = 8 * time.Millisecond
	}
	if cfg.PingEvery <= 0 {
		cfg.PingEvery = 2 * time.Second
	}
	hi := MaxPayloadHi
	if prof.MaxMTU > hi {
		hi = prof.MaxMTU
	}
	if cfg.MaxPayload == 0 {
		cfg.MaxPayload = MaxPayload
		if prof.MTU > 0 {
			cfg.MaxPayload = prof.MTU
		}
		if cfg.Direct && prof.Reliable && prof.MaxMTU >= directMTU {
			// A direct pool has no CDN or middlebox to fit: 16 KB datagrams cut the packets, acks and seals per byte
			// by 4 against the 4 KB default (2.5.0). Any peer version reads them (the pool frame takes up to 64 KB).
			cfg.MaxPayload = directMTU
		}
	}
	cfg.MaxPayload = min(max(cfg.MaxPayload, MinPayload), hi)
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.SID == 0 {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			return nil, err
		}
		cfg.SID = binary.BigEndian.Uint64(b[:]) | 1
	}
	aead, err := sessionAEAD(cfg.Key, cfg.SID)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg: cfg, sid: cfg.SID, io: pio, aead: aead, pskAead: aead, stop: make(chan struct{}),
		kexGrace: kexGrace, kexGiveUp: kexGiveUp, probeAfter: kexProbeAfter, probeFor: kexProbeFor,
		laneSeen: map[int]time.Time{}, streams: map[uint64]*Stream{}, tomb: map[uint64]time.Time{},
		nextSID: 1, now: time.Now(), wake: make(chan struct{}, 1),
		cc:       newCC(cfg.InitBps, cfg.MinBps, cfg.MaxBps, cfg.Slack),
		maxPlain: cfg.MaxPayload - overhead,
		winSlack: uint64(hi - overhead),
	}
	s.pingGap, s.maskFlip = cfg.PingEvery, time.Now()
	hp := HostProfile()
	s.winCap = hp.WinCap
	s.maxSessionWin = hp.MaxSessionWin
	if cfg.WinMax > 0 {
		s.winCap = min(max(cfg.WinMax, uint64(streamWindow)), 64<<20)
	}
	if !cfg.NoMask {
		s.hk = hdrMaskKey(cfg.Key)
		s.masked.Store(!cfg.Server)
	}
	s.cc.reliable = prof.Reliable
	s.cc.direct = prof.Reliable && cfg.Direct && !noDirect
	s.pin = s.cc.direct && !noPin && !isChooser(pio) // a chooser routes by its own lanes; PinLaneBase means another path there
	if prof.Reliable && cfg.MinBps == 2e5 && cfg.InitBps > s.cc.minRate { // default floor: never pace a TCP pool below its start rate
		s.cc.minRate = min(cfg.InitBps, cfg.MaxBps)
	}
	s.replayWin, s.ackMax, s.rxKeep, s.ackEvery = replayWin, 20, 64, 6
	if prof.Reliable { // pool reordering leaves a hole per stalled connection's packets: track and report more of them
		s.replayWin, s.ackMax, s.rxKeep = reliableReplayWin, 64, 512
		s.lateAck = !noLateAck
		s.ackEvery = 16 // TCP below never loses a datagram: fewer acks, less work for both ends (2.5.0); 2 ms still bounds it
	}
	if ch, ok := pio.(PathChooser); ok && ch.NumPaths() > 0 {
		s.replayWin = reliableReplayWin // paths of different delay put packets thousands of numbers behind each other
	}
	s.rxRing = make([]uint64, s.replayWin)
	if b, ok := pio.(Backlogger); ok && !noBacklog {
		s.backlog = b
	}
	s.deathIO, _ = pio.(DeathReporter) // per-IO death counter: repairs only after THIS carrier lost a conn
	if b, ok := pio.(BatchSender); ok && !isChooser(pio) && batchWanted(pio) {
		s.batcher = b // the multipath chooser has its own Send and never implements BatchSender
	}
	if copies(pio) {
		s.copier = true
		s.outFree = make(chan []byte, 512)
	}
	s.plainBuf = make([]byte, 0, s.maxPlain)
	s.dgIn = make(chan Datagram, dgramRxCap)
	if ch, ok := pio.(PathChooser); ok && ch.NumPaths() > 0 {
		s.chooser = ch
		s.pcc = make([]pathCC, ch.NumPaths())
		s.smpBuf = make([]*sentPkt, ch.NumPaths())
		for i := range s.pcc {
			s.pcc[i].reliable = ch.PathProfile(i).Reliable
		}
		s.ackMax, s.rxKeep = 64, 512 // two paths reorder and double the holes: report as many ranges as the wire allows
		s.fb, _ = pio.(PathFeedback)
		if pr, ok := pio.(PathProber); ok {
			pr.SetProber(s.probePath)
		}
	}
	s.cc.maxPlain = s.maxPlain
	if cfg.FEC {
		s.fec = newFec()
	}
	// A client run has its own random session id and with it its own key, so its packet numbers can start at 0 and two
	// clients on one key (two slots) are independent sessions. A restarted SERVER meets the same session id again, so
	// its packet numbers start at the wall clock in microseconds: a new run always continues above the old one (no
	// nonce reuse, and the client does not mistake the new packets for replays of the old ones).
	if cfg.Server {
		s.nextPN = dirServerBit | uint64(time.Now().UnixMicro())&(1<<62-1)
	}
	s.acceptC = sync.NewCond(&s.mu)
	if !cfg.Server {
		for i := 0; i < cfg.Paths; i++ {
			s.lanes = append(s.lanes, i)
		}
	}
	if !noKex && !cfg.NoKex { // both ends generate an ephemeral X25519 key; onKex turns the exchange into a key switch (2.10.0)
		priv := make([]byte, 32)
		if _, err := crand.Read(priv); err != nil {
			return nil, err
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		s.kexPriv, s.kexPub, s.kexStart = priv, pub, s.now
	}
	go s.recvLoop()
	go s.pump()
	return s, nil
}

// sessionAEAD derives the per-session key: the same PSK with another session id is a different key.
func sessionAEAD(key []byte, sid uint64) (cipher.AEAD, error) {
	h := sha256.New()
	h.Write([]byte("github.com/JohnWatsoon/WatTunnel/v2:"))
	h.Write(key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sid)
	h.Write(b[:])
	return chacha20poly1305.New(h.Sum(nil))
}

// sessionAEADEx derives the fresh key after the X25519 exchange (2.10.0, both ends): PSK, session id, both ephemeral
// public keys (client's first) and the shared secret all go into the hash. Everything sealed after the switch stays
// confidential even if the PSK leaks later (forward secrecy); the packets of the first RTT remain PSK-only.
func sessionAEADEx(key []byte, sid uint64, shared, clientPub, serverPub []byte) (cipher.AEAD, error) {
	h := sha256.New()
	h.Write([]byte("github.com/JohnWatsoon/WatTunnel/v2:"))
	h.Write(key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sid)
	h.Write(b[:])
	h.Write(clientPub)
	h.Write(serverPub)
	h.Write(shared)
	return chacha20poly1305.New(h.Sum(nil))
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// kexGrace is how long the key before the switch still authenticates in-flight packets. Every session copies it
// into its kexGrace field (timers reads the field), so a test can shrink one session's grace without racing other
// sessions' pumps. kexGiveUp is how long a client keeps offering before re-arming with fresh keys.
// kexProbeAfter/kexProbeFor bound the restart probe: a client that has switched keys but heard nothing for
// kexProbeAfter while it keeps sending suspects the peer restarted (a restarted peer cannot open the fresh
// key), and sends lone PSK-sealed kex offers for kexProbeFor so a restarted peer can authenticate it again.
var kexGrace = 30 * time.Second

var kexGiveUp = 10 * time.Second

var (
	kexProbeAfter = 4 * time.Second // a send this long after the last received packet starts the probe
	kexProbeFor   = 10 * time.Second
)

// onKex handles a peer frKex frame (s.mu held). The client offers on every packet (a second apart when the reply is
// lost) until the reply switches its key; the server answers every offer until a packet only the fresh key opens
// proves the client has switched. A peer key that yields the all-zero shared secret (a low-order point) ends the
// exchange: the session stays on the PSK key, exactly like talking to an older peer.
func (s *Session) onKex(pub []byte, now time.Time) {
	if noKex || s.kexPriv == nil || (s.kexDone && s.probeUntil.IsZero()) || len(pub) != 32 {
		return
	}
	if !s.cfg.Server {
		if s.oldAead != nil {
			return // an earlier reply already switched the key (nil again while probing, so a restarted peer's reply lands)
		}
		shared, err := curve25519.X25519(s.kexPriv, pub)
		if err != nil || allZero(shared) {
			s.kexPriv = nil
			return
		}
		fresh, err := sessionAEADEx(s.cfg.Key, s.sid, shared, s.kexPub, pub)
		if err != nil {
			s.kexPriv = nil
			return
		}
		s.oldAead, s.aead, s.kexAt, s.kexDone = s.aead, fresh, now, true
		s.probeUntil = time.Time{}
		s.pubRxKeys()
		return
	}
	if s.kexPeerPub != nil && s.kexAead != nil && bytes.Equal(s.kexPeerPub, pub) {
		s.kexReplyPend = true // our reply was lost: the client is still offering
		s.kexOfferAt = now
		return
	}
	// a different pub (the client re-armed with fresh keys after our reply was lost) or a stale
	// exchange (the old kexAead expired): start over with the offered key. Only the PSK-authenticated
	// peer reaches here, so substitution fails closed at the AEAD either way.
	shared, err := curve25519.X25519(s.kexPriv, pub)
	if err != nil || allZero(shared) {
		s.kexPriv = nil
		return
	}
	s.kexPeerPub = append([]byte(nil), pub...)
	s.kexOfferAt = now
	fresh, err := sessionAEADEx(s.cfg.Key, s.sid, shared, pub, s.kexPub) // the client's public key first, as on the client side
	if err != nil {
		s.kexPriv = nil
		return
	}
	s.kexAead = fresh
	s.kexReplyPend = true
}

// kexPending: this side has a frKex frame to send (the guards in build let such a packet out even when it is empty).
func (s *Session) kexPending() bool {
	if s.cfg.Server {
		return s.kexReplyPend && s.kexAead != nil
	}
	return s.kexPriv != nil && !s.kexDone
}

// appendKex adds this side's frKex frame as the LAST frame of the packet (an older peer stops parsing there, which
// is why nothing may follow it). The client offers when the first packet goes out and again a second later; the
// server answers every offer it receives.
func (s *Session) appendKex(p []byte, now time.Time) []byte {
	if !s.kexPending() || len(p)+1+len(s.kexPub) > s.maxPlain {
		return p
	}
	if !s.cfg.Server {
		if !s.kexSentAt.IsZero() && now.Sub(s.kexSentAt) < time.Second {
			return p
		}
		s.kexSentAt = now
	} else {
		s.kexReplyPend = false
	}
	return append(append(p, frKex), s.kexPub...)
}

func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stop)
	for _, st := range s.streams {
		s.killStream(st, ErrSessionDead)
	}
	s.acceptC.Broadcast()
	s.mu.Unlock()
	s.io.Close()
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.RateBps, st.SRTT, st.MinRTT = s.cc.rate, s.cc.srtt, s.cc.minRTT
	st.CeilingBps, st.LossPct = s.cc.ceiling, s.cc.lossPct*100
	st.Streams, st.Inflight = len(s.streams), s.inflight
	st.CC, st.FloorBps, st.Cwnd = s.cc.diag, s.cc.floor(), s.cc.cwnd()
	st.LossTime, st.PTO, st.RelLossMul = s.cc.lossTime(), s.cc.pto(), s.cc.relLossMul
	for _, x := range s.streams {
		if len(x.retx) == 0 && x.snext < x.sbase+uint64(len(x.sbuf)) && x.snext >= x.peerMax {
			st.WinBlocked++
		}
	}
	return st
}

// Load reports the open streams and the bytes in flight: what a client running several sessions (-sessions N)
// balances new streams on. Cheaper than Stats.
func (s *Session) Load() (streams, inflight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams), s.inflight
}

// OpenStream starts a new stream (client side).
func (s *Session) OpenStream() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionDead
	}
	if len(s.streams) >= maxStreams {
		return nil, ErrTooManyConns
	}
	id := s.nextSID
	s.nextSID++
	return s.newStream(id), nil
}

// Accept waits for a stream opened by the peer (server side).
func (s *Session) Accept() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.acceptQ) == 0 && !s.closed {
		s.acceptC.Wait()
	}
	if len(s.acceptQ) == 0 {
		return nil, ErrSessionDead
	}
	st := s.acceptQ[0]
	s.acceptQ = s.acceptQ[1:]
	return st, nil
}

func (s *Session) activate(st *Stream) {
	if st.inActive || st.dead || !st.sendable() {
		return
	}
	st.inActive = true
	s.enqueue(st)
	s.kick()
}

func (s *Session) enqueue(st *Stream) {
	if !st.bulky(s.now) {
		s.prio.push(st)
	} else {
		s.bulk.push(st)
	}
}

func (s *Session) pick() *Stream {
	for s.prio.len() > 0 {
		st := s.prio.pop()
		if st.dead || !st.sendable() {
			st.inActive = false
			continue
		}
		if st.bulky(s.now) {
			s.bulk.push(st)
			continue
		}
		return st
	}
	for s.bulk.n > 0 {
		st := s.bulk.pop()
		if st.dead || !st.sendable() {
			st.inActive = false
			continue
		}
		return st
	}
	return nil
}

func (s *Session) requeue(st *Stream) {
	if st.dead || !st.sendable() {
		st.inActive = false
		return
	}
	s.enqueue(st)
}

func (s *Session) hasWork() bool {
	return len(s.dq) > 0 || s.hasStreamWork()
}

func (s *Session) hasStreamWork() bool {
	work := func(st *Stream) bool { return !st.dead && st.sendable() }
	return s.prio.any(work) || s.bulk.any(work)
}

// ---- sending ----

// kick wakes the pump now: new data, a window update, or an ack-eliciting packet arrived.
func (s *Session) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// busy: anything the pump must act on soon. Idle sessions tick slowly (keepalives need ~2 s precision).
func (s *Session) busy() bool {
	return s.ackPend > 0 || len(s.ctrl) > 0 || s.wantPing || len(s.probeQ) > 0 || s.sentHead < len(s.sent) || s.prio.len() > 0 || s.bulk.n > 0 || len(s.dq) > 0 || (s.fec != nil && s.fec.txN > 0)
}

func (s *Session) pump() {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	last := time.Now()
	var batch []outPkt
	for {
		select {
		case <-s.stop:
			return
		case <-timer.C:
		case <-s.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		now := time.Now()
		dt := now.Sub(last)
		last = now
		held := s.backlog != nil && s.backlog.Backlogged() // the carrier's own lock: asked outside ours
		s.mu.Lock()
		s.held = held
		s.now = now
		s.cc.refill(dt)
		s.timers(now)
		batch = batch[:0]
		for len(batch) < 160 {
			o, ok := s.build(now)
			if !ok {
				break
			}
			batch = append(batch, o)
		}
		if s.fec != nil {
			if o, ok := s.fecDue(now); ok {
				batch = append(batch, o)
			}
		}
		next := 100 * time.Millisecond
		if s.busy() || len(batch) > 0 {
			next = time.Millisecond
		}
		s.mu.Unlock()
		if s.masked.Load() {
			for _, o := range batch {
				maskHdr(s.hk, o.p)
			}
		}
		if s.batcher != nil && len(batch) > 1 {
			s.sendBatch(batch)
		} else {
			s.sendEach(batch)
		}
		timer.Reset(next)
	}
}

func (s *Session) sendEach(batch []outPkt) {
	for _, o := range batch {
		if err := s.io.Send(o.p, o.lane); err != nil {
			s.mu.Lock()
			s.stats.Dropped++
			s.mu.Unlock()
		}
		if o.dupLane >= 0 {
			if err := s.io.Send(o.p, o.dupLane); err != nil { // both lanes' drops must be visible in /stats
				s.mu.Lock()
				s.stats.Dropped++
				s.mu.Unlock()
			}
		}
		s.putOut(o.p)
	}
}

// sendBatch hands everything the pacer released to the carrier in one call (sendmmsg on Linux).
func (s *Session) sendBatch(batch []outPkt) {
	ps, ls := s.bp[:0], s.bl[:0]
	for _, o := range batch {
		ps, ls = append(ps, o.p), append(ls, o.lane)
		if o.dupLane >= 0 {
			ps, ls = append(ps, o.p), append(ls, o.dupLane)
		}
	}
	if err := s.batcher.SendBatch(ps, ls); err != nil {
		s.mu.Lock()
		s.stats.Dropped++
		s.mu.Unlock()
	}
	for i, o := range batch {
		s.putOut(o.p)
		ps[i] = nil
	}
	clear(ps)
	s.bp, s.bl = ps[:0], ls[:0]
}

func (s *Session) nextLane() int {
	if len(s.lanes) == 0 {
		return -1
	}
	s.laneRR++
	return s.lanes[s.laneRR%len(s.lanes)]
}

// repairAfterDeath resends, at once, every unacked packet older than twice the smoothed RTT: when a pool connection
// dies, whatever was queued on it or still in its socket never arrives, and the stream behind each hole would stall
// for the whole loss timer (2 s on a direct carrier). Packets that were on healthy connections are usually acked by
// then; the few still in flight are sent twice, once per death.
func (s *Session) repairAfterDeath(now time.Time) {
	age := 2 * s.cc.srtt
	if age < 150*time.Millisecond {
		age = 150 * time.Millisecond
	}
	for i := s.sentHead; i < len(s.sent); i++ {
		sp := s.sent[i]
		if sp.done {
			continue
		}
		if now.Sub(sp.at) < age {
			break
		}
		s.lose(sp)
	}
	s.compact()
}

// noPin (WAT_NO_PIN=1) stripes direct pools' stream data over every connection again, for an A/B.
var noPin = os.Getenv("WAT_NO_PIN") != ""

// noDirect (WAT_NO_DIRECT=1) ignores Config.Direct, for an A/B.
var noDirect = os.Getenv("WAT_NO_DIRECT") != ""

// noBacklog (WAT_NO_BACKLOG=1) ignores the carrier's Backlogger, the pre-2.4.18 behaviour, for an A/B.
var noBacklog = os.Getenv("WAT_NO_BACKLOG") != ""

// Late ACKs. A reliable pool reorders across its connections: while one connection stalls, every packet it carries
// is a hole between the other connections' packets, and an ACK frame names only the newest 64 ranges (the receiver
// remembers 512). The stalled packets arrive later, below that window, so before this no ACK ever reported them and
// the sender's loss timer resent them all, and the more connections the more resends. Now each ACK first carries a
// frame with the received packets the main frame leaves out. Its delay is lateAckDelay, so a sender of any version
// takes no RTT sample from it and declares nothing lost by it (loss needs age > lossTime + delay); it only marks
// those packets delivered. Needs only the receiving end updated. WAT_NO_LATEACK=1 turns it off for an A/B.
const (
	lateAckDelay = 3600e6 // µs
	lateSinceMax = 16384  // received packet numbers kept between two ACKs
	lateKeep     = 4096   // late ranges waiting for an ACK
)

var noLateAck = os.Getenv("WAT_NO_LATEACK") != ""

// noKex (WAT_NO_KEX=1) turns the forward-secrecy key exchange off, for an A/B (2.10.0).
var noKex = os.Getenv("WAT_NO_KEX") != ""

// appendLateAck moves the packets received since the last ACK that the main frame will not cover into rxLate and
// encodes the newest of them as a late-ACK frame; what does not fit goes out with the next ACK.
func (s *Session) appendLateAck(p []byte, now time.Time) []byte {
	var cut uint64
	if n := len(s.rxRanges); n > s.ackMax {
		cut = s.rxRanges[n-s.ackMax].lo
	}
	for _, pn := range s.rxSince {
		if pn < cut {
			s.rxLate.add(pn, pn+1)
		}
	}
	s.rxSince = s.rxSince[:0]
	if len(s.rxLate) == 0 {
		return p
	}
	s.rxLate.trim(lateKeep)
	n := min(s.ackMax, len(s.rxLate), max(1, (s.maxPlain/4-24)/8))
	p = appendAck(p, s.rxLate, lateAckDelay, n)
	for _, r := range s.rxLate[len(s.rxLate)-n:] {
		s.stats.AckLate += r.hi - r.lo
	}
	s.rxLate = s.rxLate[:len(s.rxLate)-n]
	return p
}

func (s *Session) build(now time.Time) (outPkt, bool) {
	const none = -1
	if len(s.probeQ) > 0 {
		return s.buildProbe(now), true
	}
	if !s.probeUntil.IsZero() && s.kexPriv != nil && now.Sub(s.kexSentAt) >= time.Second {
		if o, ok := s.buildKexProbe(now); ok {
			return o, true
		}
	}
	needAck := s.ackPend > 0 && (s.ackPend >= s.ackEvery || now.Sub(s.ackSince) >= 2*time.Millisecond)
	canData := s.cc.tokens > 0 && s.inflight < s.cc.cwnd() && !s.held
	// The boot id lets a client notice a server restart; that needs the same cadence as the keepalive, not 1 Hz.
	// At the old fixed 1 s it was over half the idle cost of an otherwise silent tunnel on a billed link
	// (measured 2026-10-29: 8.2 of 15.5 MB/day). A shorter -ping-every keeps the old detection latency.
	bootEvery := max(s.cfg.PingEvery, time.Second)
	needBoot := s.cfg.Server && s.cfg.Boot != 0 && now.Sub(s.bootAt) >= bootEvery
	if !canData && !needAck && !s.wantPing && len(s.ctrl) == 0 && !needBoot && !s.kexPending() {
		if s.hasWork() {
			s.cc.limited = true
			s.noteLimit()
		}
		return outPkt{}, false
	}
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	}
	prioSeen, bulkSeen := false, false
	pinSlot, pinned := 0, false
	p := s.plainBuf[:0]
	sp := s.newSent()
	if needBoot {
		p = append(p, frBoot)
		p = appendUv(p, s.cfg.Boot)
		s.bootAt = now
	}
	if needAck {
		if s.lateAck {
			p = s.appendLateAck(p, now)
		}
		delay := uint64(now.Sub(s.rxAt) / time.Microsecond)
		p = appendAck(p, s.rxRanges, delay, s.ackMax)
		s.ackPend = 0
		if len(s.rxLate) > 0 { // more than one frame's worth left: the next ACK goes out within 2 ms
			s.ackPend, s.ackSince = 1, now
		}
	}
	for len(s.ctrl) > 0 && len(p)+len(s.ctrl[0]) <= s.maxPlain {
		p = append(p, s.ctrl[0]...)
		sp.ctrl = append(sp.ctrl, s.ctrl[0])
		s.ctrl = s.ctrl[1:]
	}
	if s.wantPing {
		p = append(p, frPing)
		s.wantPing = false
		s.pingGap = s.nextPingGap()
		sp.ctrl = append(sp.ctrl, pingFrame)
	}
	if canData {
		// Datagrams go before stream data (they are interactive), but as the LAST frames of the packet so an old
		// peer that stops at the unknown type still sees everything before it. While streams have work, datagrams
		// take at most half of what is left, so a datagram flood cannot starve a bulk transfer.
		dbuf := s.dbuf[:0]
		if len(s.dq) > 0 {
			dbuf = s.takeDgrams(dbuf, s.maxPlain-len(p), s.hasStreamWork())
			s.dbuf = dbuf[:0]
		}
		pathMTU := s.maxPlain
		if nc, ok := s.chooser.(PathNextChooser); ok {
			p := nc.NextPath(false)
			prof := s.chooser.PathProfile(p)
			if prof.MaxMTU > 0 {
				limit := prof.MaxMTU - overhead
				if prof.MTU > 0 && prof.MTU-overhead > pathMTU {
					pathMTU = prof.MTU - overhead
				}
				if prof.Reliable && limit >= directMTU-overhead {
					pathMTU = directMTU - overhead
				}
				if pathMTU > limit {
					pathMTU = limit
				}
			}
		}
		room := pathMTU - len(dbuf)
		for room-len(p) > 40 {
			st := s.pick()
			if st == nil {
				break
			}
			isBulk := st.bulky(now)
			if isBulk {
				bulkSeen = true
			} else {
				prioSeen = true
			}
			np, sent, fit := st.emit(p, sp, room-len(p))
			if sent && !pinned {
				pinSlot, pinned = st.pin, true
			}
			if isBulk {
				s.bulk.charge(st, len(np)-len(p))
			}
			p = np
			s.requeue(st)
			if !sent {
				if !fit {
					break
				}
				continue
			}
		}
		if len(dbuf) > 0 {
			p = append(p, dbuf...)
			sp.dgram = true
		}
		if len(sp.frames) == 0 && len(p) == 0 && !s.kexPending() {
			s.freeSent(sp)
			return outPkt{}, false
		}
		if s.cc.tokens <= 0 || s.inflight >= s.cc.cwnd() {
			if s.hasWork() {
				s.cc.limited = true
				s.noteLimit()
			}
		}
	}
	if len(p) == 0 && !s.kexPending() {
		s.freeSent(sp)
		return outPkt{}, false
	}
	if s.chooser != nil { // bond: packets that carry young streams, datagrams, acks or are small want the fastest path
		lane = s.chooser.ChoosePath(len(p)+overhead, prioSeen || !bulkSeen || len(p)+overhead <= 330)
		// An ack-only packet is never acked, so a path used only for acks (a download's return path) would give no
		// feedback and a dead one would go unnoticed: every 16th such packet on a path carries a PING.
		if len(sp.frames) == 0 && len(sp.ctrl) == 0 && !sp.dgram && lane >= 0 && lane < len(s.pcc) {
			pc := &s.pcc[lane]
			if pc.ackOnly++; pc.ackOnly >= 16 {
				pc.ackOnly = 0
				p = append(p, frPing)
				sp.ctrl = append(sp.ctrl, pingFrame)
			}
		}
	}
	if s.pin && pinned && !sp.rtx && !prioSeen { // interactive data takes the least queued connection, not a bulk one's
		lane = PinLaneBase + pinSlot
	}
	p = s.appendKex(p, now)
	if len(p) == 0 {
		s.freeSent(sp)
		return outPkt{}, false
	}
	if (!s.cfg.NoShape || s.hk != nil) && len(sp.frames) == 0 && !sp.dgram {
		p = s.pad(p)
	}
	out, pn := s.seal(p)
	size := len(out) + ipIcmpHdr
	if len(sp.frames) > 0 || len(sp.ctrl) > 0 || sp.dgram {
		if s.fec != nil && (len(sp.frames) > 0 || sp.dgram) {
			s.fecNoteSent(pn, p)
		}
		sp.pn, sp.at, sp.size, sp.lane = pn, now, size, lane
		s.sent = append(s.sent, sp)
		s.cc.sentN++
		s.inflight += size
		s.cc.tokens -= float64(size)
	} else {
		s.freeSent(sp) // ack-only: nothing to track
	}
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	dup := none
	s.hedgeTok += 0.08 * float64(len(out))
	if s.hedgeTok > 20000 {
		s.hedgeTok = 20000
	}
	if s.cfg.Hedge && len(sp.frames) > 0 && s.hedgeTok >= float64(len(out)) && s.young(sp) && len(s.lanes) > 1 && s.chooser == nil {
		if l := s.nextLane(); l != lane {
			dup = l
			s.hedgeTok -= float64(len(out))
			s.cc.tokens -= float64(size)
			s.stats.PktsOut++
			s.stats.BytesOut += uint64(len(out))
		}
	}
	return outPkt{out, lane, dup}, true
}

// noteLimit records what held the sender back this tick (diagnostics).
func (s *Session) noteLimit() {
	if s.held {
		s.cc.heldLim = true
	} else if s.inflight >= s.cc.cwnd() {
		s.cc.cwndLim = true
	} else if s.cc.tokens <= 0 {
		s.cc.tokLim = true
	}
}

func (s *Session) seal(p []byte) ([]byte, uint64) { return s.sealWith(s.aead, p) }

func (s *Session) sealWith(a cipher.AEAD, p []byte) ([]byte, uint64) {
	pn := s.nextPN
	s.nextPN++
	out := s.getOut(hdrLen + len(p) + tagLen)
	binary.BigEndian.PutUint64(out, s.sid)
	binary.BigEndian.PutUint64(out[8:], pn)
	copy(s.txNonce[4:], out[8:16])
	return a.Seal(out, s.txNonce[:], p, out[:8]), pn
}

// buildKexProbe sends the restart probe (client, while probeUntil is set): a lone frKex offer sealed with the PSK
// key, at most once a second. Only a restarted peer opens it; a live one drops it and keeps opening the data, which
// stays on the fresh key. Untracked: a live peer never acks it, and that must not count as loss.
func (s *Session) buildKexProbe(now time.Time) (outPkt, bool) {
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	}
	s.kexSentAt = now // not lastSend: fresh-key pings must keep eliciting a live peer's answer
	out, _ := s.sealWith(s.pskAead, append(append(s.plainBuf[:0], frKex), s.kexPub...))
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	return outPkt{out, lane, -1}, true
}

// probePath asks for a tiny ack-eliciting packet on one path (how the bond finds a dead carrier alive again).
func (s *Session) probePath(path int) {
	s.mu.Lock()
	if !s.closed && len(s.probeQ) < 16 {
		s.probeQ = append(s.probeQ, path)
	}
	s.mu.Unlock()
	s.kick()
}

// buildProbe sends one PING on the oldest requested path. It is not paced (a handful of bytes) but is tracked, so
// its ack revives the path and its loss is just counted.
func (s *Session) buildProbe(now time.Time) outPkt {
	lane := s.probeQ[0]
	s.probeQ = s.probeQ[1:]
	out, pn := s.seal([]byte{frPing})
	size := len(out) + ipIcmpHdr
	s.sent = append(s.sent, &sentPkt{pn: pn, at: now, size: size, ctrl: [][]byte{pingFrame}, lane: lane})
	s.inflight += size
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	return outPkt{out, lane, -1}
}

// pathPTO: a tail packet on a slow path is not lost just because the fast path's timeout passed.
func (s *Session) pathPTO(lane int, pto time.Duration) time.Duration {
	if lane < 0 || lane >= len(s.pcc) {
		return pto
	}
	pc := &s.pcc[lane]
	if x := 3 * pc.srtt; x > pto {
		pto = x
	}
	if pc.srtt == 0 && pto < unsampledRTT {
		pto = unsampledRTT
	}
	if pc.reliable && pto < reliablePTO {
		pto = reliablePTO
	}
	return pto
}

// pathLost is the multipath loss rule: a packet is lost when later packets OF ITS OWN PATH were acked (count),
// or when it is older than that path's own loss time.
func (s *Session) pathLost(sp *sentPkt, delay, lt time.Duration, now time.Time) bool {
	if sp.lane < 0 || sp.lane >= len(s.pcc) {
		return now.Sub(sp.at) > lt+delay
	}
	pc := &s.pcc[sp.lane]
	if !pc.have || sp.pn > pc.largest {
		// Nothing later on ITS OWN path has been acked, so there is no evidence about this packet: the ack that
		// triggered this check came over another path, which may simply be faster. Leave it to the path's PTO.
		return false
	}
	if !pc.reliable && pc.largest-sp.pn >= 4 {
		return true
	}
	if pc.srtt == 0 && lt < unsampledRTT {
		lt = unsampledRTT
	}
	if pc.srtt > 0 {
		x := pc.srtt + pc.srtt/4 + 3*time.Millisecond
		if pc.reliable && x < reliableLossTime {
			x = reliableLossTime
		}
		if x > lt {
			lt = x
		}
	}
	return now.Sub(sp.at) > lt+delay
}

func (s *Session) pathSample(lane int, r time.Duration, now time.Time) {
	if lane < 0 || lane >= len(s.pcc) || r <= 0 {
		return
	}
	pc := &s.pcc[lane]
	if pc.srtt == 0 {
		pc.srtt = r
	} else {
		pc.srtt = (7*pc.srtt + r) / 8
	}
	if pc.minRTT == 0 || r < pc.minRTT || now.Sub(pc.minAt) > 10*time.Second {
		pc.minRTT, pc.minAt = r, now
	}
	pc.at = now
}

// unsampledRTT is assumed for a path that has not answered yet: far above any sane carrier, so its first packets
// are not declared lost (and the path killed) before the first ack can possibly arrive.
const unsampledRTT = time.Second

// pathAcked updates the per-path state from a batch of newly acked packets (ascending pn) and returns the rtt
// sample for the pacer, normalised so that it measures queueing, not which path the packet happened to take.
func (s *Session) pathAcked(acked []*sentPkt, largest uint64, delay time.Duration, now time.Time, rtt time.Duration) time.Duration {
	for i := range s.smpBuf {
		s.smpBuf[i] = nil
	}
	for _, sp := range acked {
		if sp.lane < 0 || sp.lane >= len(s.pcc) {
			continue
		}
		if pc := &s.pcc[sp.lane]; !pc.have || sp.pn > pc.largest {
			pc.largest, pc.have = sp.pn, true
		}
		s.smpBuf[sp.lane] = sp
	}
	var norm time.Duration
	for _, sp := range acked {
		var r time.Duration
		if sp.lane >= 0 && sp.lane < len(s.pcc) && s.smpBuf[sp.lane] == sp {
			if r = now.Sub(sp.at); sp.pn == largest || delay >= lateAckDelay*time.Microsecond/2 { // a late ACK: no sample
				r -= delay
			}
			if r > 0 {
				s.pathSample(sp.lane, r, now)
			} else {
				r = 0
			}
		}
		if s.fb != nil {
			s.fb.OnAck(sp.lane, r, sp.size)
		}
	}
	if rtt > 0 {
		var floor, ref time.Duration
		for _, sp := range acked {
			if sp.pn == largest && sp.lane >= 0 && sp.lane < len(s.pcc) {
				floor = s.pcc[sp.lane].minRTT
			}
		}
		for i := range s.pcc {
			if m := s.pcc[i].minRTT; m > 0 && (ref == 0 || m < ref) {
				ref = m
			}
		}
		if floor > 0 && ref > 0 {
			norm = max(rtt-floor+ref, time.Microsecond)
		} else {
			norm = rtt
		}
	}
	var hi time.Duration
	for i := range s.pcc {
		if pc := &s.pcc[i]; pc.srtt > hi && now.Sub(pc.at) < 5*time.Second {
			hi = pc.srtt
		}
	}
	s.cc.pathRTT = hi
	return norm
}

// timers: loss on tail packets, keepalive, pacing adjustments, tombstone pruning.
func (s *Session) timers(now time.Time) {
	s.cc.inflight = s.inflight // PROBE_RTT drains until this reaches its floor
	s.cc.tick(now)
	if s.backlog != nil && s.cc.reliable { // a pool connection died: what it held is gone, resend old packets now
		var d uint64
		if s.deathIO != nil {
			d = s.deathIO.ConnDeaths() // only this carrier's churn wakes the repair
		} else {
			d = poolConnDeaths.Load()
		}
		if d != s.deaths {
			s.deaths = d
			s.repairAfterDeath(now)
		}
	}
	if s.sentHead < len(s.sent) {
		pto := s.cc.pto()
		for i := s.sentHead; i < len(s.sent); i++ {
			sp := s.sent[i]
			if sp.done {
				continue
			}
			age := now.Sub(sp.at)
			if age < pto {
				break
			}
			if s.chooser != nil && age < s.pathPTO(sp.lane, pto) {
				continue
			}
			s.lose(sp)
		}
		s.compact()
	}
	if now.Sub(s.lastSend) > s.pingGap {
		s.wantPing = true
	}
	if s.hk != nil && !s.cfg.Server && s.lastAuth.IsZero() && now.Sub(s.maskFlip) > 3*time.Second {
		s.masked.Store(!s.masked.Load()) // nothing answered yet: the peer may speak only the other header form
		s.maskFlip = now
	}
	// Silence this long means the session is dead: reset it and let it rebuild. A raised -ping-every means longer
	// legitimate silences (both ends ping on their own value), so scale with it like Server.IdleTimeout does -
	// otherwise -ping-every 40/60 killed every open stream every 30 s (2026-10-29).
	if !s.lastRecv.IsZero() && now.Sub(s.lastRecv) > max(30*time.Second, 3*s.cfg.PingEvery) {
		if s.hk != nil && !s.cfg.Server {
			s.masked.Store(!s.masked.Load()) // a peer downgraded or upgraded while we were silent
			s.peerMaskOK.Store(false)
			s.maskFlip = now
		}
		s.resetAll(ErrSessionDead)
		// Re-arm with now, not zero: zeroing lastRecv disarmed the watchdog permanently (audit
		// 2026-10-22), so a client session that never recovered kept streams opened after the
		// reset blocked forever. Alive() now blips true for <=10 s per 30 s cycle; LastRecv()
		// and monitors read lastAuth, which stays honest.
		s.lastRecv = now
	}
	if len(s.tomb) > 0 && now.Sub(s.lastTombPrune) >= 5*time.Second {
		s.lastTombPrune = now
		for id, t := range s.tomb {
			if now.Sub(t) > 2*time.Minute {
				delete(s.tomb, id)
			}
		}
	}
	for l, t := range s.laneSeen {
		if now.Sub(t) > 20*time.Second {
			delete(s.laneSeen, l)
			s.rebuildLanes()
		}
	}
	if s.oldAead != nil && now.Sub(s.kexAt) > s.kexGrace {
		s.oldAead = nil // long past the switch: in-flight old-key packets are gone, and the PSK must not authenticate anything again
		s.pubRxKeys()
	}
	if !s.cfg.Server && s.kexPriv != nil && !s.kexDone && now.Sub(s.kexStart) > s.kexGiveUp {
		// no reply within the window: re-arm with FRESH keys instead of giving up forever, so an
		// exchange whose replies were lost still completes once the path recovers (a new pub makes the
		// server re-engage). An older peer just keeps ignoring the frame; the offer rides existing
		// packets at most once a second (audit 2026-10-21).
		priv := make([]byte, 32)
		if _, err := crand.Read(priv); err != nil {
			s.kexPriv = nil
			return
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			s.kexPriv = nil
			return
		}
		s.kexPriv, s.kexPub, s.kexStart = priv, pub, now
	}
	if !s.probeUntil.IsZero() && now.After(s.probeUntil) {
		s.probeUntil = time.Time{} // no restarted peer answered: back to the fresh key alone (re-probes if still silent)
		s.pubRxKeys()
	}
	if !s.cfg.Server && s.kexDone && s.probeUntil.IsZero() && !s.lastRecv.IsZero() && s.lastSend.Sub(s.lastRecv) > s.probeAfter {
		// we switched keys but the peer went silent while we keep sending: either the path died, or
		// the peer RESTARTED and can no longer open the fresh key (2.10.0 regression the frBoot frame
		// used to cover: a restarted server could never authenticate the switched client, so the boot
		// id never reached it and every stream hung). Probe: send lone PSK-sealed offers (buildKexProbe)
		// and accept PSK packets for a while, so a restarted peer re-authenticates us and re-runs the kex.
		// "Silent" means we sent probeAfter past the last packet we heard: an idle session whose keepalives
		// are rarer than probeAfter (-ping-every) is not probed forever.
		// Data stays on the fresh key: a peer that is alive, only cut off, keeps opening it (sealing the
		// data with the PSK blackholed it at a live peer past kexGrace and gave it no forward secrecy),
		// and kexDone stays set so a later real restart is still detected.
		s.probeUntil = now.Add(s.probeFor)
		s.oldAead = nil // the PSK key takes over as the receive fallback while probing
		s.pubRxKeys()
	}
	if s.cfg.Server && !s.kexDone && s.kexAead != nil && now.Sub(s.kexOfferAt) > s.kexGrace {
		// the client never switched: stop paying one failed fresh-key open per packet for the rest of
		// the session. A live client offers until its reply lands, refreshing kexOfferAt (audit 2026-10-21).
		s.kexAead, s.kexPeerPub = nil, nil
	}
}

func (s *Session) rebuildLanes() {
	if !s.cfg.Server {
		return
	}
	// Keep the last known set when every lane has aged out. A client quiet for longer than the laneSeen prune
	// (20 s, see timers) used to leave a server with no lane at all, and build() then sent nothing - not even the
	// boot frame - until the client spoke again. Never observed at the default 2 s ping, but it muted a server
	// whose -ping-every was raised (2026-10-29).
	if len(s.laneSeen) == 0 && len(s.lanes) > 0 {
		return
	}
	s.lanes = s.lanes[:0]
	for l := range s.laneSeen {
		s.lanes = append(s.lanes, l)
	}
}

func (s *Session) resetAll(err error) {
	for _, st := range s.streams {
		s.killStream(st, err)
	}
	s.prio, s.ctrl = streamQ{}, nil
	s.bulk.reset()
	s.sent, s.sentHead, s.inflight = nil, 0, 0
}

func (s *Session) lose(sp *sentPkt) {
	sp.done, sp.lost = true, true
	s.cc.lostN++
	s.cc.diag.Lost++
	if s.cc.reliable && s.chooser == nil && (len(sp.frames) > 0 || len(sp.ctrl) > 0) {
		// Remember it: the packet is the oldest in flight, so compact frees it at once, and a late ack (TCP delivered
		// it after all) could otherwise never be matched (2.4.9 missed most of them).
		if len(s.lostRing) >= lostRingMax {
			s.lostRing = append(s.lostRing[:0], s.lostRing[len(s.lostRing)-lostRingMax/2:]...)
		}
		s.lostRing = append(s.lostRing, lostRec{sp.pn, sp.at})
	}
	s.inflight -= sp.size
	if s.fb != nil {
		s.fb.OnLoss(sp.lane)
	}
	if s.fec != nil && len(sp.frames) > 0 {
		s.fec.onLoss()
	}
	if len(sp.frames) > 0 || len(sp.ctrl) > 0 { // a lost datagram-only packet repairs nothing: it only frees its bytes
		s.stats.Retrans++
	}
	for _, f := range sp.frames {
		if st := s.streams[f.sid]; st != nil {
			st.onLost(f)
		}
	}
	s.ctrl = append(s.ctrl, sp.ctrl...)
	// a lost PING needs no resend: the next keepalive tick covers it
	if len(s.ctrl) > 0 {
		keep := s.ctrl[:0]
		for _, c := range s.ctrl {
			if len(c) == 1 && c[0] == frPing {
				continue
			}
			keep = append(keep, c)
		}
		s.ctrl = keep
	}
}

func (s *Session) compact() {
	for s.sentHead < len(s.sent) && s.sent[s.sentHead].done {
		s.freeSent(s.sent[s.sentHead])
		s.sent[s.sentHead] = nil
		s.sentHead++
	}
	if s.sentHead > 2048 {
		s.sent = append(s.sent[:0], s.sent[s.sentHead:]...)
		s.sentHead = 0
	}
}

// ---- receiving ----

func (s *Session) recvLoop() {
	var bo recvBackoff
	for {
		raw, lane, src, err := s.io.Recv()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				bo.fail(err, s.cfg.Logf, "session receive")
				continue
			}
		}
		bo.ok()
		s.handle(raw, lane, src)
	}
}

func (s *Session) handle(raw []byte, lane int, src net.Addr) {
	if len(raw) < hdrLen+tagLen+1 {
		return
	}
	peerMasked := false
	if binary.BigEndian.Uint64(raw) != s.sid {
		if s.hk == nil {
			return
		}
		maskHdr(s.hk, raw)
		if binary.BigEndian.Uint64(raw) != s.sid {
			return
		}
		peerMasked = true
	}
	pn := binary.BigEndian.Uint64(raw[8:])
	if (pn&dirServerBit != 0) == s.cfg.Server { // our own direction: reflected or foreign
		return
	}
	dup := s.rxDup(pn) // fast path: rxRing and rxLargest are owned by recvLoop; checked with 0 locks
	if dup {
		return // not counted: unauthenticated junk with a known sid/pn must not pollute the loss stats
	}
	var first, fall cipher.AEAD
	var freshRx cipher.AEAD
	if k := s.rxKeys.Load(); k != nil {
		// steady state: the kex is done; timers() (pump goroutine) changes these keys under s.mu, so they are
		// published atomically instead of read as plain fields here
		first, fall = k[0], k[1]
	} else {
		// Handshake phase: snapshot under lock
		s.mu.Lock()
		first, fall = s.aead, s.oldAead
		freshRx = s.kexAead
		if freshRx != nil {
			first, fall = freshRx, s.aead
		}
		s.mu.Unlock()
	}
	copy(s.rxNonce[4:], raw[8:16])
	plain, err := first.Open(s.openBuf[:0], s.rxNonce[:], raw[hdrLen:], raw[:8])
	if err != nil && fall != nil {
		plain, err = fall.Open(s.openBuf[:0], s.rxNonce[:], raw[hdrLen:], raw[:8])
		freshRx = nil
	}
	if err != nil {
		return // not ours: stay silent
	}
	if s.hk != nil && s.masked.Load() != peerMasked && (s.cfg.Server || !s.peerMaskOK.Load()) { // answer in the header form the peer spoke
		s.masked.Store(peerMasked)
	}
	s.openBuf = plain[:0]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	if freshRx != nil { // a packet only the fresh key opens: the peer has switched, so we seal our own packets with it too
		s.oldAead, s.aead, s.kexAead, s.kexAt, s.kexDone = fall, first, nil, now, true
		s.pubRxKeys()
	}
	if s.rxDup(pn) { // re-check under the lock: only authenticated duplicates count (audit 2026-10-22)
		if s.rxLargest-pn >= s.replayWin {
			s.stats.RxTooOld++
		} else {
			s.stats.RxDup++
		}
		return
	}
	if !s.rxAny || pn > s.rxLargest {
		s.rxLargest, s.rxAny, s.rxAt = pn, true, now
	}
	s.rxRing[pn%s.replayWin] = pn + 1
	s.rxRanges.add(pn, pn+1)
	s.rxRanges.trim(s.rxKeep)
	if s.lateAck && len(s.rxSince) < lateSinceMax {
		s.rxSince = append(s.rxSince, pn)
	}
	if s.fec != nil {
		s.fecKeep(pn, plain)
	}
	s.lastRecv, s.lastAuth = now, now
	s.stats.PktsIn++
	s.stats.BytesIn += uint64(len(raw))
	if s.cfg.Server {
		s.io.SetPeer(src)
		if _, ok := s.laneSeen[lane]; !ok {
			s.laneSeen[lane] = now
			s.rebuildLanes()
		}
		s.laneSeen[lane] = now
	}
	eliciting := s.parse(plain, now)
	if eliciting {
		if s.ackPend == 0 {
			s.ackSince = now
		}
		s.ackPend++
		s.kick()
	}
}

// pubRxKeys publishes the receive keys for handle's lock-free path (s.mu held); call after every change to
// aead, oldAead or kexDone.
func (s *Session) pubRxKeys() {
	if s.kexDone {
		fall := s.oldAead
		if !s.probeUntil.IsZero() {
			fall = s.pskAead // restart probe: a restarted peer answers with the PSK key (oldAead is nil while probing)
		}
		s.rxKeys.Store(&[2]cipher.AEAD{s.aead, fall})
	} else {
		s.rxKeys.Store(nil)
	}
}

func (s *Session) rxDup(pn uint64) bool {
	if !s.rxAny || pn > s.rxLargest {
		return false
	}
	if s.rxLargest-pn >= s.replayWin {
		return true
	}
	return s.rxRing[pn%s.replayWin] == pn+1
}

func (s *Session) parse(b []byte, now time.Time) (eliciting bool) {
	r := &reader{b: b}
	for len(r.b) > 0 && r.err == nil {
		switch t := r.byte(); t {
		case frStream, frStreamFin:
			sid, off, n := r.uv(), r.uv(), r.uv()
			data := r.take(n)
			if r.err != nil {
				return
			}
			eliciting = true
			s.onStream(sid, off, data, t == frStreamFin)
		case frAck:
			largest, delayUs, rs := parseAckInto(r, s.ackRs)
			if r.err != nil {
				return
			}
			if s.fec == nil || !s.fec.inRec { // a rebuilt packet's ack is stale: it would skew the RTT sample
				s.onAck(largest, time.Duration(delayUs)*time.Microsecond, rangeSet(rs), now)
			}
			s.ackRs = rs[:0]
		case frWindow:
			sid, max := r.uv(), r.uv()
			if r.err != nil {
				return
			}
			eliciting = true
			if st := s.streams[sid]; st != nil && max > st.peerMax {
				st.peerMax = max
				st.wc.Broadcast() // Write may buffer more now
				s.activate(st)
			}
		case frRst:
			sid := r.uv()
			if r.err != nil {
				return
			}
			eliciting = true
			if st := s.streams[sid]; st != nil {
				s.killStream(st, ErrReset)
			} else {
				s.tomb[sid] = now
			}
		case frBoot:
			boot := r.uv()
			if r.err != nil {
				return
			}
			if s.peerBoot != 0 && boot != s.peerBoot { // the server restarted: our streams exist only on our side now
				s.cfg.Logf("server restarted, resetting %d streams", len(s.streams))
				s.resetAll(ErrReset)
			}
			s.peerBoot = boot
		case frPing:
			eliciting = true
		case frDgram:
			flow, port, n := r.uv(), r.uv(), r.uv()
			data := r.take(n)
			if r.err != nil || port > 65535 {
				return
			}
			eliciting = true // acked, so the sender's pacing/inflight accounting releases the packet
			s.onDgram(flow, int(port), data)
		case frDgramFrag:
			flow, port, id, idx, cnt, n := r.uv(), r.uv(), r.uv(), r.uv(), r.uv(), r.uv()
			data := r.take(n)
			if r.err != nil || port > 65535 || cnt < 2 || cnt > dgramFragMax || idx >= cnt {
				return
			}
			eliciting = true
			s.onDgramFrag(flow, int(port), id, int(idx), int(cnt), data, now)
		case frFec:
			if s.onFec(r, now) {
				eliciting = true
			}
		case frKex:
			pub := r.take(32)
			if r.err != nil {
				return
			}
			eliciting = true
			s.onKex(pub, now)
		case frPad:
			if b := r.take(r.uv()); len(b) > 0 && b[0] == padCapMask && s.hk != nil && !s.cfg.Server {
				s.peerMaskOK.Store(true)
				s.masked.Store(true) // the first exchange may have settled on plain only because the server was not up yet
			}
		default:
			return
		}
	}
	return
}

func (s *Session) onStream(sid, off uint64, data []byte, fin bool) {
	st := s.streams[sid]
	if st == nil {
		if !s.cfg.Server || len(s.streams) >= maxStreams {
			return
		}
		if _, gone := s.tomb[sid]; gone {
			return
		}
		st = s.newStream(sid)
		s.acceptQ = append(s.acceptQ, st)
		s.acceptC.Signal()
	}
	end := off + uint64(len(data))
	if end < off { // offset+len wrapped: an authenticated but hostile peer must not bypass the window check
		return
	}
	if end > max(st.advMax, st.consumed+streamWindow)+s.winSlack { // slack for the largest datagram any peer may send
		return // beyond the advertised window
	}
	if fin {
		st.peerFin, st.peerFinO = true, end
	}
	st.insert(off, data)
}

func (s *Session) onAck(largest uint64, delay time.Duration, rs rangeSet, now time.Time) {
	var newly int
	var rtt time.Duration
	acked := s.ackBuf[:0]
	// Visit only the packets the ack covers: s.sent is in packet-number order, so each range is a binary search and a
	// short walk. Walking everything in flight on every ack cost O(inflight) per ack, which at a second of delivery
	// in flight (a direct pool) capped one session near 50-60 MB/s on one core while 4 sessions together moved 140+
	// (field 2026-10-16).
	live := s.sent[s.sentHead:]
	for _, r := range rs {
		j := sort.Search(len(live), func(k int) bool { return live[k].pn >= r.lo })
		for ; j < len(live) && live[j].pn < r.hi; j++ {
			s.ackOne(live[j], largest, delay, now, &newly, &rtt, &acked)
		}
	}
	if len(s.lostRing) > 0 {
		s.matchLost(rs, largest, now)
	}
	if s.chooser != nil {
		rtt = s.pathAcked(acked, largest, delay, now, rtt)
		for i := range acked {
			acked[i] = nil
		}
		s.ackBuf = acked[:0]
	}
	s.afterAck(largest, delay, newly, rtt, now)
}

// ackOne marks one packet an ack covers as delivered.
func (s *Session) ackOne(sp *sentPkt, largest uint64, delay time.Duration, now time.Time, newly *int, rtt *time.Duration, acked *[]*sentPkt) {
	{
		if sp.done && sp.lost && s.chooser != nil {
			sp.lost = false // declared lost too early (a slow path): the ack still tells the path is alive and how slow
			s.pathSample(sp.lane, now.Sub(sp.at), now)
			if s.fb != nil {
				s.fb.OnAck(sp.lane, now.Sub(sp.at), 0)
			}
			return
		}
		if sp.done {
			return
		}
		sp.done = true
		if s.fec != nil && len(sp.frames) > 0 {
			s.fec.onAck()
		}
		if s.chooser != nil {
			*acked = append(*acked, sp)
		}
		s.inflight -= sp.size
		*newly += sp.size
		for _, f := range sp.frames {
			if st := s.streams[f.sid]; st != nil {
				st.onAcked(f)
			}
		}
		if sp.pn == largest {
			*rtt = now.Sub(sp.at) - delay
		}
	}
}

// afterAck feeds the pacer and declares losses once an ack's packets are marked.
func (s *Session) afterAck(largest uint64, delay time.Duration, newly int, rtt time.Duration, now time.Time) {
	s.cc.inflight = s.inflight // post-ack, so the PROBE_RTT drain-floor guard in sample() sees the current queue
	s.cc.onDelivered(newly)
	if rtt > 0 {
		s.cc.sample(rtt, now)
	}
	// loss: a packet three or more behind the largest acked, or older than one RTT plus a quarter
	lt := s.cc.lossTime()
	for i := s.sentHead; i < len(s.sent); i++ {
		sp := s.sent[i]
		if sp.pn >= largest {
			break
		}
		if sp.done {
			continue
		}
		if s.chooser != nil {
			if s.pathLost(sp, delay, lt, now) {
				s.lose(sp)
			}
			continue
		}
		if (largest-sp.pn >= 4 && !s.cc.reliable) || now.Sub(sp.at) > lt+delay {
			s.lose(sp)
		} else if s.cc.reliable {
			break // reliable loss is by age only, and s.sent is in send order: everything after is younger
		}
	}
	s.compact()
}

// lostRec is a packet a reliable single-carrier session declared lost, kept so a late ack can prove it spurious.
type lostRec struct {
	pn uint64
	at time.Time
}

const (
	lostRingMax = 8192
	lostKeep    = 5 * time.Second
)

// matchLost finds packets declared lost that this ack covers after all: TCP delivered them late, so the resend was
// spurious. Each is counted once (the pacer discounts it from congestion loss and stretches its loss timer), and
// records older than lostKeep are dropped.
func (s *Session) matchLost(rs rangeSet, largest uint64, now time.Time) {
	keep := s.lostRing[:0]
	for _, r := range s.lostRing {
		if now.Sub(r.at) > lostKeep {
			continue
		}
		if r.pn <= largest && rs.contains(r.pn) {
			s.cc.spuriousN++
			s.cc.diag.Spurious++
			continue
		}
		keep = append(keep, r)
	}
	s.lostRing = keep
}

// Alive reports whether authenticated packets arrived from the peer in the last 10 seconds.
// CarrierStats is the per-carrier view of a bonded session (nil for a single-carrier one).
func (s *Session) CarrierStats() []CarrierStat {
	if ps, ok := s.io.(PathStatser); ok {
		return ps.PathStats()
	}
	return nil
}

// IO returns the underlying PacketIO of the session.
func (s *Session) IO() PacketIO { return s.io }

// Alive reports whether an authenticated packet from the peer arrived recently. A keepalive gap is 0.6-1.4x
// PingEvery (nextPingGap) and each ping is acked at once, so 3x PingEvery covers a raised -ping-every.
func (s *Session) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastAuth.IsZero() && time.Since(s.lastAuth) < max(10*time.Second, 3*s.cfg.PingEvery)
}

// LastRecv is when the last authenticated packet from the peer arrived (zero: none yet). Unlike Alive's clock it is
// never reset, so a monitor can see how long the link has been silent.
func (s *Session) LastRecv() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuth
}

// LastPN is the highest packet number this session authenticated, used as the replay watermark when it closes.
func (s *Session) LastPN() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rxLargest
}

// young: the packet is small, or carries only the first bytes of its streams (handshakes, requests, replies):
// those are the ones a single random loss would hurt most, so they are sent twice on different lanes.
func (s *Session) young(sp *sentPkt) bool {
	n := 0
	for _, f := range sp.frames {
		n += f.n
		st := s.streams[f.sid]
		if st == nil || f.off > 32<<10 {
			return false
		}
	}
	return n <= 330 || len(sp.frames) > 0
}
