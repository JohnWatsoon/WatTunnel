package wat

import (
	"math"
	mrand "math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Multipath (bonding). One session can run over several carriers at once; a "path" is one carrier. A PacketIO
// opts in by implementing the interfaces below, so every single-carrier setup (icmp, udp, tcp, ...) keeps the exact
// behaviour it had before: the session only looks at these when its PacketIO provides them.

// PathFeedback is told by the session how each path performs. OnAck is called for every newly acknowledged
// packet (rtt is a round-trip sample, or 0 when this packet is not the freshest acked packet of its path in this
// ACK, so it would be inflated by waiting); OnLoss when a packet sent on the path is declared lost. Both run
// under the session lock: implementations must be quick and must not call back into the session.
type PathFeedback interface {
	OnAck(path int, rtt time.Duration, bytes int)
	OnLoss(path int)
}

// PathChooser lets the PacketIO decide the path of every packet (called under the session lock, so cheap). The
// returned value is passed to Send as the `path` argument and reported back through PathFeedback. interactive is
// true for packets that carry young streams, datagrams, acks or are small: latency matters more than throughput.
type PathChooser interface {
	NumPaths() int
	PathProfile(path int) Profile
	ChoosePath(size int, interactive bool) int
}

// PathProber is implemented by a PacketIO that wants the session to emit a tiny ack-eliciting packet (PING) on a
// given path from time to time: how a dead path is found alive again. The function may be called from any goroutine.
type PathProber interface{ SetProber(func(path int)) }

// PathStatser exposes per-carrier numbers for /stats.
type PathStatser interface{ PathStats() []CarrierStat }

// PathMuter allows live path muting/unmuting without session restart.
type PathMuter interface{ ToggleMute(path int) bool }

// Bifrost directional bond legs (3.3.9, frEndpoint 0x0e; BOTH ends need this release for the suffixes to be
// honored): a bond leg name may carry an ":up" or ":down" suffix — ":up" carries uplink (client→server) only,
// ":down" downlink (server→client) only, no suffix both ways. The SAME suffix appears in both ends' configs;
// each end applies its own side's meaning: the client never sends on a ":down" leg (it is the leg the server
// pushes downlink to) and the server never replies on an ":up" one. A mixed-version pair degrades gracefully:
// an older server ignores frEndpoint and never sends down the ":down" leg, while uplink on ":up" and
// bidirectional legs still works. In this release ":down" is restricted to the udp carrier: its client socket
// is a quiet bound socket whose receive port is announced with frEndpoint (0x0e).
const (
	DirBoth uint8 = 0 // unsuffixed leg: today's bidirectional behaviour (the zero value)
	DirUp   uint8 = 1 // client→server only
	DirDown uint8 = 2 // server→client only
)

// LegDirection splits a bond leg name into its carrier name and its direction suffix (Bifrost, 3.3.9):
// "udp:down" → ("udp", DirDown), "icmp" → ("icmp", DirBoth), "ws:weird" → ("ws:weird", DirBoth) — anything
// after the last ':' that is not up/down is part of the carrier name, so the split never invents a carrier.
func LegDirection(leg string) (carrier string, dir uint8) {
	if i := strings.LastIndexByte(leg, ':'); i > 0 {
		switch leg[i+1:] {
		case "up":
			return leg[:i], DirUp
		case "down":
			return leg[:i], DirDown
		}
	}
	return leg, DirBoth
}

// ValidateBondLegs checks a '+'-split bond carrier list against the directional-leg rules (Bifrost, 3.3.9) and
// returns "" when the list is acceptable, else a refusal reason for the operator. Carrier-name validity and
// duplicates stay the caller's checks (they depend on the process's carrier table). Only the udp carrier takes
// ":down" in this release (frEndpoint signaling), a single carrier cannot be directional, and the bond must keep
// at least one leg able to carry each direction.
func ValidateBondLegs(legs []string) string {
	if len(legs) == 0 {
		return ""
	}
	if len(legs) == 1 {
		if _, d := LegDirection(legs[0]); d != DirBoth {
			return ":up/:down are directional BOND legs; a single carrier is always bidirectional (drop the suffix)"
		}
		return ""
	}
	up, down := 0, 0
	for _, leg := range legs {
		base, d := LegDirection(leg)
		switch d {
		case DirUp:
			up++
		case DirDown:
			if base != "udp" {
				return "only the udp carrier supports :down legs in this release — its receive endpoint is announced with frEndpoint (0x0e), which only a quiet bound udp socket has"
			}
			down++
		}
	}
	if down == len(legs) {
		return "every bond leg is :down — no leg could carry uplink; keep at least one bidirectional or :up leg"
	}
	if up == len(legs) {
		return "every bond leg is :up — no leg could carry downlink; keep at least one bidirectional or :down leg"
	}
	return ""
}

// PathDirs is implemented by a chooser PacketIO whose paths carry a direction lock (Bifrost, 3.3.9): the session
// reads it once at start to learn which of the bond's legs are ":down" and need frEndpoint announces.
type PathDirs interface{ PathDirs() []uint8 }

// PathEndpoints is implemented by a bond PacketIO that can report the bound local port of one leg's socket
// (Bifrost, 3.3.9): the client announces it with frEndpoint so the server knows where to send downlink.
type PathEndpoints interface{ PathLocalPort(leg int) int }

// PathLocalPorter is implemented by a single-carrier PacketIO over a socket with a local port (the udp client):
// the per-leg query of PathEndpoints delegates to it. 0 = no port (not bound yet).
type PathLocalPorter interface{ PathLocalPort() int }

// PathEndpointSignaler is the server-side receiver of frEndpoint (Bifrost ":down" legs, 3.3.9): the session
// parses the frame and hands over the announced leg index and port plus the packet's AUTHENTICATED source
// address. The implementation must take the IP from src only — the frame carries no IP, so a hostile peer
// cannot aim the downlink anywhere but its own proven source.
type PathEndpointSignaler interface {
	SetPathEndpoint(legIdx, port int, src net.Addr)
}

// PathLossSizer is the optional richer loss feedback (Hornet-MTU, 3.3.9, -mtu-adapt): OnLossSized carries the
// lost packet's wire size (sentPkt.size: datagram + tag + IP/ICMP headers) so the io can tell big-packet loss
// (the ICMP-clamp signature) from small-packet loss. The session calls it instead of PathFeedback.OnLoss when
// the io implements it, and only for paths it actually sent on — plain OnLoss stays for the other ios.
type PathLossSizer interface{ OnLossSized(path, size int) }

// PathClamp is the Hornet-MTU sender-side payload clamp (3.3.9, -mtu-adapt): Session.build takes
// min(limit, PathClamp(next path)) when the chooser provides it, so a path whose big packets a filter drops
// puts out smaller packets while its clamp holds. The value is a datagram size (header and tag incl), 0 =
// unclamped. Sender-side only: no wire signal, each end clamps its own sending, mixed versions are safe.
type PathClamp interface{ PathClamp(path int) int }

// CarrierStat is one carrier of a bond, as seen from this end.
type CarrierStat struct {
	Name    string  `json:"name"`
	Alive   bool    `json:"alive"`
	Muted   bool    `json:"muted"`
	SRTTms  float64 `json:"srtt_ms"`
	Share   float64 `json:"share"`
	Sent    uint64  `json:"sent"`
	Acked   uint64  `json:"acked"`
	Lost    uint64  `json:"lost"`
	Knocks  uint64  `json:"knocks,omitempty"` // Bifrost NAT knocks sent on this leg (":down" legs, client side only)
	Present bool    `json:"-"`
}

// PathTimings tunes health and probing; the zero value is the production setting.
type PathTimings struct {
	Silence    time.Duration // floor of "no acks while sending" before a path is suspect (default 1 s)
	ProbeFirst time.Duration // first probe of a dead path (default 2 s); the gap doubles ...
	ProbeMax   time.Duration // ... up to this (default 30 s)
	Ramp       time.Duration // a revived path goes from a 10 % to a full share over this (default 3 s)
	IdleProbe  time.Duration // a live path with nothing sent for this long gets a PING (default 5 s)
	Mode       string        // "balanced" (default), "active-backup", "replicate"
	// DownKnock is the base cadence of the Bifrost NAT knock (found live 2026-11-19, Kharej box: a client behind
	// NAT whose bond has a ":down" leg never sends from that leg's socket, so the NAT holds no mapping for it and
	// the server's downlink is dropped). The client periodically sends ONE normal authenticated packet (a probe
	// PING) from the ":down" leg's own socket to refresh the mapping; the interval is the base plus uniform jitter
	// of up to 40 % (default 25 s → 25-35 s), comfortably inside typical 30-60 s UDP NAT timeouts. Automatic for
	// ":down" legs only — without it they are unusable behind NAT. Unconditional at the cadence: a NAT UDP mapping
	// is refreshed by outbound traffic only, so arriving downlink does not prove the mapping's idle budget
	// (2026-11-20 review defect 1: the old skip let the mapping lapse mid-flow).
	DownKnock time.Duration
	// MtuAdapt turns on the Hornet-MTU sender-side clamp (3.3.9, -mtu-adapt; default off, dead code when off):
	// after hornetLosses consecutive losses of packets bigger than hornetBigPkt the path's datagrams are capped
	// at hornetClampPayload for hornetClampHold, then retried at full size (the detector re-fires while the
	// pattern persists). Sender-side only — no wire signal, each end watches its own send-path losses, so a
	// single end may enable it and mixed versions are safe. Bond paths only: the detector rides PathFeedback,
	// which only the bond ios implement.
	MtuAdapt bool
}

// Hornet-MTU sender-side clamp constants (3.3.9, -mtu-adapt). The measured signature (live Iran paths, 2026-10:
// ICMP payloads above ~668 B vanish while small pings pass; see the R3 hornet experiment) is a path that silently
// drops every large packet; a detector keyed on CONSECUTIVE big losses sits clearly above the ordinary loss the
// delay-based CC already absorbs (the design-review bar: ≥ 8 consecutive full-size losses). The clamp value
// matches the experiment's proven 640 B ceiling; the hold auto-expires so the path re-probes full size and the
// detector re-clamps if the signature persists — no canary machinery.
const (
	hornetBigPkt       = 512              // a lost packet bigger than this wire size counts as "big" (datagram + tag + IP/ICMP headers)
	hornetLosses       = 8                // consecutive big losses before the clamp engages
	hornetClampPayload = 640              // clamped datagram size incl. header and tag (the experiment's proven ceiling)
	hornetClampHold    = 30 * time.Second // clamp hold; expires by itself and re-fires if the losses persist
)

func (t PathTimings) norm() PathTimings {
	if t.Silence <= 0 {
		t.Silence = time.Second
	}
	if t.ProbeFirst <= 0 {
		t.ProbeFirst = 2 * time.Second
	}
	if t.ProbeMax <= 0 {
		t.ProbeMax = 30 * time.Second
	}
	if t.ProbeFirst > t.ProbeMax {
		t.ProbeFirst = t.ProbeMax
	}
	if t.Ramp <= 0 {
		t.Ramp = 3 * time.Second
	}
	if t.IdleProbe <= 0 {
		t.IdleProbe = 5 * time.Second
	}
	if t.DownKnock <= 0 {
		t.DownKnock = 25 * time.Second
	}
	if t.Mode == "" {
		t.Mode = "balanced"
	}
	return t
}

// bulkBurst: consecutive bulk packets sent on the same path.
const bulkBurst = 24

// knockGap is one Bifrost NAT-knock interval (found live 2026-11-19): the DownKnock base plus uniform jitter of up
// to 40 % of it (default 25-35 s). Jittered on purpose — a fixed period would let a NAT (or a watcher) learn the
// knock schedule — and bounded well inside typical 30-60 s UDP NAT timeouts, so one knock always lands before a
// mapping could expire.
func knockGap(base time.Duration) time.Duration {
	return base + time.Duration(mrand.Float64()*float64(base)*0.4)
}

// knockFirst is when a Bifrost NAT-knock sequence begins: an eighth of the (jittered) cadence, floored at
// knockWait (defined in bond.go). A fresh session behind NAT has neither a mapping nor a server-side endpoint
// yet, so waiting a full 25-35 s gap would be a startup dead window (found re-verifying the knock, 2026-11-20);
// an eighth keeps the same ratio for the fast test cadences and still defers an hour-cadence control test far
// past its window.
func knockFirst(gap time.Duration) time.Duration {
	if f := gap / 8; f > knockWait {
		return f
	}
	return knockWait
}

// ICMPPathBps caps the bulk bytes/s a bond sends on its icmp path (Iran reroutes ICMP above ~30 MB/s); the other
// carriers of the bond are not held to it (3.2.0, before: the whole session was capped at 16 MB/s whenever icmp was
// among the carriers).
var ICMPPathBps = 16e6

const (
	pLive = iota
	pSuspect
	pDead
)

type pathState struct {
	name    string
	present bool
	state   int
	muted   bool
	dir     uint8 // direction lock from the leg-name suffix (Bifrost, 3.3.9): DirBoth/DirUp/DirDown; fixed at creation

	srtt, minRTT time.Duration
	minAt        time.Time
	loss         float64 // EWMA of the loss indicator
	w            float64 // adaptive weight (AIMD on queueing delay): capacity share, 0.05..1
	credit       float64
	icredit      float64
	adjAt        time.Time
	revived      time.Time // when a dead path came back: its share ramps up from here

	lastAck, firstUnacked, lastSend time.Time
	lossRun                         int
	gap                             time.Duration
	nextProbe                       time.Time

	sent, acked, lost uint64

	capBps, tokens float64 // >0: byte cap of this path (token bucket, 50 ms burst)
	tokAt          time.Time

	// Hornet-MTU sender-side detector (-mtu-adapt, 3.3.9): consecutive lost packets bigger than hornetBigPkt,
	// and the deadline until which this path's datagrams are clamped to hornetClampPayload (zero = unclamped).
	lostBig    int
	clampUntil time.Time
}

func (p *pathState) refill(now time.Time) {
	if p.capBps <= 0 {
		return
	}
	p.tokens = min(p.capBps/20, p.tokens+p.capBps*now.Sub(p.tokAt).Seconds())
	p.tokAt = now
}

// overCap: the path spent its byte budget; bulk goes elsewhere until it refills.
func (p *pathState) overCap(now time.Time) bool {
	p.refill(now)
	return p.capBps > 0 && p.tokens < 0
}

// pathSet is the scoring and health state of the paths of one session end. It is shared by BondIO (client) and
// the per-session send side of a MultiRaw server.
type pathSet struct {
	mu       sync.Mutex
	cfg      PathTimings
	mode     string
	srv      bool // this end is the server: an ":up" leg is receive-only here; a client end refuses ":down" legs (Bifrost, 3.3.9)
	p        []pathState
	profs    []Profile     // per-path profile: a packet is never sent on a carrier that cannot frame it (set before traffic)
	fullMask atomic.Uint64 // 3.3.8: bit i set while path i's pool send queues are full (refreshed per pump round)

	burstPath, burstLeft int
}

func newPathSet(names []string, present bool, cfg PathTimings, srv bool) *pathSet {
	norm := cfg.norm()
	ps := &pathSet{cfg: norm, mode: norm.Mode, srv: srv, p: make([]pathState, len(names))}
	now := time.Now()
	for i, n := range names {
		base, dir := LegDirection(n)
		ps.p[i] = pathState{name: n, present: present, w: 1, gap: ps.cfg.ProbeFirst, dir: dir, tokAt: now}
		if base == "icmp" && len(names) > 1 {
			ps.p[i].capBps, ps.p[i].tokens = ICMPPathBps, ICMPPathBps/20
		}
	}
	return ps
}

// canSendLocked reports whether THIS end may send on path i (Bifrost directional legs, 3.3.9): the client sends
// uplink, so a ":down" leg is receive-only for it; the server sends downlink, so an ":up" leg is receive-only
// for it. With no suffix anywhere (dir == DirBoth everywhere) every path passes, so the zero value keeps today's
// behaviour exactly. Caller holds ps.mu and passes a valid index.
func (ps *pathSet) canSendLocked(i int) bool {
	switch ps.p[i].dir {
	case DirUp:
		return !ps.srv
	case DirDown:
		return ps.srv
	}
	return true
}

// canSend is canSendLocked with its own locking, for callers outside the choose/tick critical sections.
func (ps *pathSet) canSend(i int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i < 0 || i >= len(ps.p) {
		return false
	}
	return ps.canSendLocked(i)
}

// setProfiles records the profile of every path (BondIO or MultiRaw builds it). Call it before traffic starts.
func (ps *pathSet) setProfiles(profs []Profile) {
	ps.mu.Lock()
	ps.profs = profs
	ps.mu.Unlock()
}

// pathLimit is the largest datagram the carrier at path i can frame. A carrier without a Profiled hint (icmp) is
// bounded by the ICMP-safe default.
func (ps *pathSet) pathLimit(i int) int {
	var prof Profile
	if i >= 0 && i < len(ps.profs) {
		prof = ps.profs[i]
	}
	lim := prof.MaxMTU
	if lim == 0 {
		lim = prof.MTU
	}
	if lim == 0 {
		lim = MaxPayload
	}
	return lim
}

// fits reports whether a packet of size bytes (datagram size, header and tag included) may be sent on path i.
func (ps *pathSet) fits(i, size int) bool { return size <= 0 || ps.pathLimit(i) >= size }

func (ps *pathSet) Mode() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.mode
}

func (ps *pathSet) ToggleMute(i int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i >= 0 && i < len(ps.p) {
		ps.p[i].muted = !ps.p[i].muted
		return ps.p[i].muted
	}
	return false
}

// setMute sets the mute state of path i (the server applies its one muted set to every session's paths).
func (ps *pathSet) setMute(i int, muted bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i >= 0 && i < len(ps.p) {
		ps.p[i].muted = muted
	}
}

func (ps *pathSet) isLiveOrSuspect(i int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i >= 0 && i < len(ps.p) {
		return ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted
	}
	return false
}

func (ps *pathSet) isFull(i int) bool {
	return i >= 0 && i < 64 && ps.fullMask.Load()&(uint64(1)<<uint(i)) != 0
}

// allBulkBlocked records the per-path pool backlog mask and reports whether no present path can take bulk right now
// without overflowing a full pool queue or exceeding a path byte cap (3.3.8).
func (ps *pathSet) allBulkBlocked(fullMask uint64, hasBacklogger bool) bool {
	ps.fullMask.Store(fullMask)
	if !hasBacklogger || fullMask == 0 {
		return false
	}
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	anyPresent := false
	for i := range ps.p {
		p := &ps.p[i]
		if !p.present || p.muted {
			continue
		}
		if !ps.canSendLocked(i) {
			continue // a direction-locked leg is never bulk capacity on this end (2026-11-20 review defect 2):
		} // counting it made the pump build into a full pool queue and drop, never setting held
		anyPresent = true
		full := i < 64 && fullMask&(uint64(1)<<uint(i)) != 0
		if !full && p.state != pDead && !p.overCap(now) {
			return false
		}
	}
	return anyPresent
}

// pacerMode reports whether the currently live path set should run the reliable delivery-rate pacer (3.3.8): true when
// at least one reliable pool path is live and no uncapped datagram path (udp) is live beside it (an icmp leg is
// already bounded by its own 16 MB/s token bucket and per-path queue-delay weight). icmpClamp is true when only
// capped datagram paths (icmp) remain live and no reliable or uncapped datagram path is live.
func (ps *pathSet) pacerMode() (reliable, direct, anyRel, icmpClamp bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	direct = true
	anyUncappedUnrel := false
	anyCappedUnrel := false
	for i := range ps.p {
		p := &ps.p[i]
		if !p.present || p.muted || p.state == pDead {
			continue
		}
		if !ps.canSendLocked(i) {
			continue // a direction-locked leg must not sway the pacer on this end (2026-11-20 review suspect 4):
		} // a client's ":down" leg counted as a live uncapped udp path and downgraded the CC the
		// reliable pool leg alone would run
		var prof Profile
		if i < len(ps.profs) {
			prof = ps.profs[i]
		}
		if prof.Reliable {
			anyRel = true
			if prof.NoDirect {
				direct = false
			}
		} else if p.capBps <= 0 {
			anyUncappedUnrel = true
		} else {
			anyCappedUnrel = true
		}
	}
	reliable = anyRel && !anyUncappedUnrel
	icmpClamp = !reliable && anyCappedUnrel && !anyUncappedUnrel
	return reliable, reliable && direct, anyRel, icmpClamp
}

func (ps *pathSet) nextPath(interactive bool) int {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.eval(now)
	if ps.mode == "active-backup" {
		if len(ps.p) > 0 && ps.p[0].present && ps.p[0].state != pDead && !ps.p[0].muted && !ps.isFull(0) && ps.canSendLocked(0) {
			return 0
		}
		for i := 1; i < len(ps.p); i++ {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted && !ps.isFull(i) && ps.canSendLocked(i) {
				return i
			}
		}
		for i := range ps.p {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted && ps.canSendLocked(i) {
				return i
			}
		}
		return 0
	}
	if interactive {
		bs := time.Duration(math.MaxInt64)
		for i := range ps.p {
			if p := &ps.p[i]; p.present && p.state == pLive && !p.muted && !ps.isFull(i) && p.ramped(now, ps.cfg.Ramp) && ps.canSendLocked(i) {
				if sc := p.score(); sc < bs {
					bs = sc
				}
			}
		}
		best, bestCred := -1, -1e18
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.state != pLive || p.muted || ps.isFull(i) || !p.ramped(now, ps.cfg.Ramp) || p.score() > bs+bs/4+5*time.Millisecond || !ps.canSendLocked(i) {
				continue
			}
			if c := p.icredit + p.w; best < 0 || c > bestCred {
				best, bestCred = i, c
			}
		}
		if best >= 0 {
			return best
		}
	}
	// 3.3.8: peek the actual next bulk winner when burstLeft == 0 or the current burst path is full/capped/dead, so
	// Session.build sizes packet 25 for the path ChoosePath will pick instead of locking smaller-MTU paths out.
	if !interactive && ps.burstLeft > 0 {
		if p := &ps.p[ps.burstPath]; p.present && p.state != pDead && !p.muted && !ps.isFull(ps.burstPath) && !p.overCap(now) && ps.canSendLocked(ps.burstPath) {
			return ps.burstPath
		}
	}
	for pass := 0; pass < 2; pass++ {
		best, bestCred := -1, -1e18
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.muted || pass == 0 && (p.state == pDead || ps.isFull(i) || p.overCap(now)) || !ps.canSendLocked(i) {
				continue
			}
			w := 1.0
			if pass == 0 {
				w = p.weight(now, ps.cfg.Ramp)
			}
			if c := p.credit + w; best < 0 || c > bestCred {
				best, bestCred = i, c
			}
		}
		if best >= 0 {
			return best
		}
	}
	return ps.burstPath
}

func (ps *pathSet) markPresent(i int) {
	ps.mu.Lock()
	if i >= 0 && i < len(ps.p) {
		ps.p[i].present = true
	}
	ps.mu.Unlock()
}

func (ps *pathSet) onSend(i, n int) {
	now := time.Now()
	ps.mu.Lock()
	if i >= 0 && i < len(ps.p) {
		p := &ps.p[i]
		p.refill(now)
		p.tokens -= float64(n)
		p.sent++
		p.lastSend = now
		if p.firstUnacked.IsZero() {
			p.firstUnacked = now
		}
	}
	ps.mu.Unlock()
}

func (ps *pathSet) onAck(i int, rtt time.Duration) {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i < 0 || i >= len(ps.p) {
		return
	}
	p := &ps.p[i]
	p.acked++
	p.lastAck, p.firstUnacked, p.lossRun = now, time.Time{}, 0
	p.loss -= p.loss * 0.02
	if ps.cfg.MtuAdapt {
		p.lostBig = 0 // Hornet-MTU: an ack proves big packets get through again; only consecutive big losses count
	}
	if p.state != pLive {
		if p.state == pDead {
			p.revived = now
		}
		p.state, p.gap = pLive, ps.cfg.ProbeFirst
	}
	if rtt <= 0 {
		return
	}
	if p.srtt == 0 {
		p.srtt = rtt
	} else {
		p.srtt = (7*p.srtt + rtt) / 8
	}
	if p.minRTT == 0 || rtt < p.minRTT || now.Sub(p.minAt) > 10*time.Second {
		p.minRTT, p.minAt = rtt, now
	}
	// capacity share: the session paces globally, so a path that cannot take its share shows it as queueing delay
	if now.Sub(p.adjAt) >= 100*time.Millisecond {
		p.adjAt = now
		// compared with the least-queued path, so a queue every path shares (the global pacer overshooting) does not
		// punish anyone; only a path that cannot take its share stands out
		qmin := p.srtt - p.minRTT
		for j := range ps.p {
			if q := &ps.p[j]; j != i && q.present && q.state == pLive && q.srtt > 0 && q.srtt-q.minRTT < qmin {
				qmin = q.srtt - q.minRTT
			}
		}
		if p.srtt-p.minRTT > qmin+max(15*time.Millisecond, p.minRTT/4) {
			p.w = math.Max(0.05, p.w*0.9)
		} else {
			p.w = math.Min(1, p.w*1.05+0.01)
		}
	}
}

func (ps *pathSet) onLoss(i int) {
	ps.mu.Lock()
	if i >= 0 && i < len(ps.p) {
		p := &ps.p[i]
		p.lost++
		p.lossRun++
		p.loss += (1 - p.loss) * 0.02
	}
	ps.mu.Unlock()
}

// onLossSized is onLoss with the lost packet's wire size (datagram + tag + IP/ICMP headers, sentPkt.size): the
// Hornet-MTU detector (-mtu-adapt, 3.3.9) counts CONSECUTIVE losses of packets bigger than hornetBigPkt — the
// measured ICMP-clamp signature drops exactly those while small packets pass — and clamps the path's datagrams
// to hornetClampPayload for hornetClampHold when the run reaches hornetLosses. An ack or any small loss resets
// the run; the clamp itself persists to its deadline and the detector re-fires if the losses persist past it.
// Without -mtu-adapt only the plain counters run (the sized bookkeeping is dead code, same as onLoss).
func (ps *pathSet) onLossSized(i, size int) {
	now := time.Now()
	ps.mu.Lock()
	if i >= 0 && i < len(ps.p) {
		p := &ps.p[i]
		p.lost++
		p.lossRun++
		p.loss += (1 - p.loss) * 0.02
		if ps.cfg.MtuAdapt {
			if size > hornetBigPkt {
				p.lostBig++
				if p.lostBig >= hornetLosses && (p.clampUntil.IsZero() || !now.Before(p.clampUntil)) {
					p.clampUntil = now.Add(hornetClampHold)
					p.lostBig = 0 // one clamp per signature: count afresh so the expiry+persist case can re-fire
				}
			} else {
				p.lostBig = 0
			}
		}
	}
	ps.mu.Unlock()
}

// clampOf reports path i's sender-side datagram ceiling while the Hornet-MTU clamp holds (hornetClampPayload),
// else 0. Session.build takes min(limit, clamp) when the chooser implements PathClamp; without -mtu-adapt this
// is a plain bool check and returns 0 without touching the lock.
func (ps *pathSet) clampOf(i int) int {
	if !ps.cfg.MtuAdapt {
		return 0
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i < 0 || i >= len(ps.p) {
		return 0
	}
	if p := &ps.p[i]; !p.clampUntil.IsZero() && time.Now().Before(p.clampUntil) {
		return hornetClampPayload
	}
	return 0
}

// eval moves paths between live, suspect and dead. Caller holds ps.mu.
func (ps *pathSet) eval(now time.Time) {
	for i := range ps.p {
		p := &ps.p[i]
		if !p.present || p.state == pDead {
			continue
		}
		// Bifrost (3.3.9): this end never sends on a direction-locked leg, so its silence proves nothing —
		// a receive-only client leg legitimately never sends uplink (and the server never sends down an ":up"
		// leg). Skip the silence transitions; the leg stays eligible for the direction it does carry.
		if !ps.canSendLocked(i) {
			continue
		}
		thr := max(3*p.srtt, ps.cfg.Silence)
		var silent time.Duration
		if !p.firstUnacked.IsZero() {
			silent = now.Sub(maxTime(p.lastAck, p.firstUnacked))
		}
		// A path is only blamed when the ack channel demonstrably works: if NO path got an ack since this one went
		// quiet, the return direction is what broke (e.g. the peer still acks over its dead carrier) and every path
		// would look dead at once. A lone path is never declared dead either.
		if !ps.witness(i, p.firstUnacked) {
			continue
		}
		if ps.mode == "active-backup" && i == 0 && (silent > 100*time.Millisecond || p.lossRun >= 3) {
			p.state, p.gap, p.nextProbe = pDead, ps.cfg.ProbeFirst, now.Add(ps.cfg.ProbeFirst)
			continue
		}
		switch {
		case silent > 2*thr || p.lossRun >= 12 && silent > 400*time.Millisecond:
			p.state, p.gap, p.nextProbe = pDead, ps.cfg.ProbeFirst, now.Add(ps.cfg.ProbeFirst)
		case (silent > thr || p.lossRun >= 5 && silent > 200*time.Millisecond) && p.state == pLive:
			p.state, p.nextProbe = pSuspect, now.Add(250*time.Millisecond)
		}
	}
}

func (ps *pathSet) witness(i int, since time.Time) bool {
	for j := range ps.p {
		if j != i && ps.p[j].present && ps.p[j].lastAck.After(since) {
			return true
		}
	}
	return false
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (p *pathState) weight(now time.Time, ramp time.Duration) float64 {
	// (1-loss)^4: a carrier losing 10 % keeps 66 % of its share, 20 % keeps 41 %, 30 % keeps 24 %. With (1-loss) a
	// 10 %-loss carrier kept 90 % and fed retransmits (3.2.0).
	w := p.w * math.Pow(1-math.Min(p.loss, 0.9), 4)
	if !p.revived.IsZero() {
		w *= math.Min(1, 0.1+0.9*float64(now.Sub(p.revived))/float64(ramp))
	}
	if p.state == pSuspect {
		w *= 0.2
	}
	return math.Max(w, 0.001)
}

// score is the expected one-way-ish cost of an interactive packet: delay, inflated by loss.
func (p *pathState) score() time.Duration {
	rtt := p.srtt
	if rtt == 0 {
		rtt = 100 * time.Millisecond
	}
	return time.Duration(float64(rtt) * (1 + 5*p.loss))
}

func (p *pathState) ramped(now time.Time, ramp time.Duration) bool {
	return p.revived.IsZero() || now.Sub(p.revived) >= ramp
}

// choose picks the path for one packet of size bytes (datagram size incl header and tag; 0 = unknown). Interactive
// packets go to the live path with the lowest delay; the rest is split by smooth weighted round robin over every
// path that is not dead. A path whose carrier cannot frame a packet this size is skipped while another one fits, so a
// packet sized for a 16 KB direct pool is never handed to the 2 KB-buffered ICMP leg.
func (ps *pathSet) choose(size int, interactive bool) int {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.eval(now)
	if ps.mode == "active-backup" {
		if len(ps.p) > 0 && ps.p[0].present && ps.p[0].state != pDead && !ps.p[0].muted && !ps.isFull(0) && ps.canSendLocked(0) {
			return 0
		}
		for i := 1; i < len(ps.p); i++ {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted && !ps.isFull(i) && ps.canSendLocked(i) {
				return i
			}
		}
		for i := range ps.p {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted && ps.canSendLocked(i) {
				return i
			}
		}
		return 0
	}
	if interactive {
		// the live paths whose delay is within 25 % (+5 ms) of the best share the interactive packets: acks and
		// requests must not all ride one carrier, or its silent death would also starve every other path of acks
		bs := time.Duration(math.MaxInt64)
		for i := range ps.p {
			if p := &ps.p[i]; p.present && p.state == pLive && !p.muted && p.ramped(now, ps.cfg.Ramp) && ps.fits(i, size) && ps.canSendLocked(i) {
				if sc := p.score(); sc < bs {
					bs = sc
				}
			}
		}
		best, sum := -1, 0.0
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.state != pLive || p.muted || !p.ramped(now, ps.cfg.Ramp) || p.score() > bs+bs/4+5*time.Millisecond || !ps.fits(i, size) || !ps.canSendLocked(i) {
				continue
			}
			p.icredit += p.w
			sum += p.w
			if best < 0 || p.icredit > ps.p[best].icredit {
				best = i
			}
		}
		if best >= 0 {
			ps.p[best].icredit -= sum
			return best
		}
	}
	// Bulk goes in bursts: the receiver reports only its newest ACK ranges, and per-packet alternation between paths
	// of different delay leaves a hole after every packet that is still in flight on the slow one, which pushes
	// the slow path's packets out of the reported ranges (they were then retransmitted although they arrived: 23 %
	// of all packets on a 40 ms + 150 ms bond, measured).
	if ps.burstLeft > 0 {
		if p := &ps.p[ps.burstPath]; p.present && p.state != pDead && !p.muted && !ps.isFull(ps.burstPath) && !p.overCap(now) && ps.fits(ps.burstPath, size) && ps.canSendLocked(ps.burstPath) {
			ps.burstLeft--
			return ps.burstPath
		}
		ps.burstLeft = 0
	}
	// shortcut: when only capped paths are left, the second pass sends on them past the cap; the pacer is the only
	// brake then. Upgrade to holding the packet if a bond whose other carriers all died trips the ICMP reroute.
	for pass := 0; pass < 2; pass++ { // second pass (nothing healthy): spread over every path so one of them answers
		bestFit, bestAny, sum := -1, -1, 0.0
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.muted || (p.state == pDead || ps.isFull(i) || p.overCap(now)) && pass == 0 || !ps.canSendLocked(i) {
				continue
			}
			w := 1.0
			if pass == 0 {
				w = p.weight(now, ps.cfg.Ramp)
			}
			// 3.3.8: every healthy path earns credit even when this packet was sized for a larger-MTU peer path, so
			// nextPath switches to the smaller-MTU path at the next burst boundary instead of starving it forever.
			p.credit += w
			sum += w
			if ps.fits(i, size) && (bestFit < 0 || p.credit > ps.p[bestFit].credit) {
				bestFit = i
			}
			if bestAny < 0 || p.credit > ps.p[bestAny].credit {
				bestAny = i
			}
		}
		best := bestFit
		if best < 0 && pass > 0 {
			best = bestAny
		}
		if best >= 0 {
			ps.p[best].credit -= sum
			totalW := sum
			for i := range ps.p {
				if p := &ps.p[i]; p.present && !p.muted && pass == 0 && (p.state == pDead || ps.isFull(i) || p.overCap(now)) {
					totalW += p.weight(now, ps.cfg.Ramp)
				}
			}
			lim := 4 * max(sum, totalW)
			for i := range ps.p {
				if ps.p[i].credit > lim {
					ps.p[i].credit = lim
				} else if ps.p[i].credit < -lim {
					ps.p[i].credit = -lim
				}
			}
			ps.burstPath, ps.burstLeft = best, bulkBurst-1
			return best
		}
		// No healthy path could frame size (e.g. only capped/dead paths fit): undo pass-0 credit before pass 1
		// — the same canSendLocked guard its earning counterpart has, so a direction-locked leg does not accrue
		// unbounded negative credit (2026-11-20 review nit 5; harmless to selection, a trap to read).
		for i := range ps.p {
			p := &ps.p[i]
			if p.present && !p.muted && p.state != pDead && !ps.isFull(i) && !p.overCap(now) && ps.canSendLocked(i) {
				p.credit -= p.weight(now, ps.cfg.Ramp)
			}
		}
	}
	return 0
}

// tick re-evaluates health and returns the paths that should get a probe now.
func (ps *pathSet) tick() []int {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.eval(now)
	var out []int
	for i := range ps.p {
		p := &ps.p[i]
		if !p.present || p.muted {
			continue
		}
		if !ps.canSendLocked(i) {
			continue // Bifrost (3.3.9): a probe IS a send — never probe a leg this end must not send on
		}
		if ps.mode == "active-backup" && i > 0 && p.state == pLive {
			if now.Sub(p.lastSend) >= 50*time.Millisecond {
				p.lastSend = now
				out = append(out, i)
				continue
			}
		}
		switch {
		case p.state == pSuspect && !now.Before(p.nextProbe):
			p.nextProbe = now.Add(500 * time.Millisecond)
			out = append(out, i)
		case p.state == pDead && !now.Before(p.nextProbe):
			p.gap = min(p.gap*2, ps.cfg.ProbeMax)
			p.nextProbe = now.Add(p.gap)
			out = append(out, i)
		case p.state == pLive && now.Sub(p.lastSend) > ps.cfg.IdleProbe:
			p.lastSend = now
			out = append(out, i)
		}
	}
	return out
}

func (ps *pathSet) stats() []CarrierStat {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	sum := 0.0
	for i := range ps.p {
		if p := &ps.p[i]; p.present && p.state != pDead && !p.muted {
			sum += p.weight(now, ps.cfg.Ramp)
		}
	}
	out := make([]CarrierStat, len(ps.p))
	for i := range ps.p {
		p := &ps.p[i]
		cs := CarrierStat{Name: p.name, Alive: p.present && p.state == pLive && !p.muted, Muted: p.muted, SRTTms: float64(p.srtt) / 1e6,
			Sent: p.sent, Acked: p.acked, Lost: p.lost, Present: p.present}
		if p.present && p.state != pDead && !p.muted && sum > 0 {
			cs.Share = p.weight(now, ps.cfg.Ramp) / sum
		}
		out[i] = cs
	}
	return out
}

// mergeProfiles is the most conservative of the carriers: the smallest datagram, reliable only if all are, the
// slowest start. The MTU must not change during a session, so it is fixed from the whole configured set.
func mergeProfiles(ps []Profile) Profile {
	if len(ps) == 0 {
		return Profile{MTU: MaxPayload, MaxMTU: MaxPayloadHi, InitBps: 1.5e6}
	}
	if len(ps) == 1 {
		return ps[0]
	}
	out := Profile{Reliable: len(ps) > 0}
	for i, p := range ps {
		mtu := p.MTU
		if mtu == 0 {
			mtu = MaxPayload
		}
		bps := p.InitBps
		if bps == 0 {
			bps = 1.5e6
		}
		if i == 0 || mtu < out.MTU {
			out.MTU = mtu
		}
		if i == 0 || bps < out.InitBps {
			out.InitBps = bps
		}
		mm := p.MaxMTU
		if mm == 0 {
			mm = MaxPayloadHi
		}
		if i == 0 || mm < out.MaxMTU {
			out.MaxMTU = mm
		}
		out.Reliable = out.Reliable && p.Reliable
		out.NoDirect = out.NoDirect || p.NoDirect
	}
	return out
}
