package wat

import (
	"math"
	"sync"
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
}

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
	if t.Mode == "" {
		t.Mode = "balanced"
	}
	return t
}

// bulkBurst: consecutive bulk packets sent on the same path.
const bulkBurst = 24

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
	mu   sync.Mutex
	cfg  PathTimings
	mode string
	p    []pathState

	burstPath, burstLeft int
}

func newPathSet(names []string, present bool, cfg PathTimings) *pathSet {
	norm := cfg.norm()
	ps := &pathSet{cfg: norm, mode: norm.Mode, p: make([]pathState, len(names))}
	now := time.Now()
	for i, n := range names {
		ps.p[i] = pathState{name: n, present: present, w: 1, gap: ps.cfg.ProbeFirst, tokAt: now}
		if n == "icmp" && len(names) > 1 {
			ps.p[i].capBps, ps.p[i].tokens = ICMPPathBps, ICMPPathBps/20
		}
	}
	return ps
}

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

func (ps *pathSet) isLiveOrSuspect(i int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i >= 0 && i < len(ps.p) {
		return ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted
	}
	return false
}

func (ps *pathSet) nextPath(interactive bool) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.mode == "active-backup" {
		if len(ps.p) > 0 && ps.p[0].present && ps.p[0].state != pDead && !ps.p[0].muted {
			return 0
		}
		for i := 1; i < len(ps.p); i++ {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted {
				return i
			}
		}
		return 0
	}
	if !interactive && ps.burstLeft > 0 {
		if p := &ps.p[ps.burstPath]; p.present && p.state != pDead && !p.muted {
			return ps.burstPath
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

// eval moves paths between live, suspect and dead. Caller holds ps.mu.
func (ps *pathSet) eval(now time.Time) {
	for i := range ps.p {
		p := &ps.p[i]
		if !p.present || p.state == pDead {
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

// choose picks the path for one packet. Interactive packets go to the live path with the lowest delay; the rest
// is split by smooth weighted round robin over every path that is not dead.
func (ps *pathSet) choose(interactive bool) int {
	now := time.Now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.eval(now)
	if ps.mode == "active-backup" {
		if len(ps.p) > 0 && ps.p[0].present && ps.p[0].state != pDead && !ps.p[0].muted {
			return 0
		}
		for i := 1; i < len(ps.p); i++ {
			if ps.p[i].present && ps.p[i].state != pDead && !ps.p[i].muted {
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
			if p := &ps.p[i]; p.present && p.state == pLive && !p.muted && p.ramped(now, ps.cfg.Ramp) {
				if sc := p.score(); sc < bs {
					bs = sc
				}
			}
		}
		best, sum := -1, 0.0
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.state != pLive || p.muted || !p.ramped(now, ps.cfg.Ramp) || p.score() > bs+bs/4+5*time.Millisecond {
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
		if p := &ps.p[ps.burstPath]; p.present && p.state != pDead && !p.muted && !p.overCap(now) {
			ps.burstLeft--
			return ps.burstPath
		}
		ps.burstLeft = 0
	}
	// shortcut: when only capped paths are left, the second pass sends on them past the cap; the pacer is the only
	// brake then. Upgrade to holding the packet if a bond whose other carriers all died trips the ICMP reroute.
	for pass := 0; pass < 2; pass++ { // second pass (nothing healthy): spread over every path so one of them answers
		best, sum := -1, 0.0
		for i := range ps.p {
			p := &ps.p[i]
			if !p.present || p.muted || (p.state == pDead || p.overCap(now)) && pass == 0 {
				continue
			}
			w := 1.0
			if pass == 0 {
				w = p.weight(now, ps.cfg.Ramp)
			}
			p.credit += w
			sum += w
			if best < 0 || p.credit > ps.p[best].credit {
				best = i
			}
		}
		if best >= 0 {
			ps.p[best].credit -= sum
			ps.burstPath, ps.burstLeft = best, bulkBurst-1
			return best
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
	}
	return out
}
