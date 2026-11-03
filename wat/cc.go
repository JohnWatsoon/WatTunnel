package wat

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// lossAwareOn enables the loss-aware ceiling (opt-in, -loss-ceiling). Off by default: judged per 50 ms tick it also
// reacts to a local datagram flood's own drops and to CPU-starved receivers, which the delay rule handles better.
var lossAwareOn atomic.Bool

// SetLossCeiling switches the loss-aware ceiling on or off for every session of this process.
func SetLossCeiling(on bool) { lossAwareOn.Store(on) }

// cc is a delay-based pacer. Random loss on this path is ~0.2-2% and says nothing about congestion, so loss
// never changes the rate; only a growing RTT (a queue building somewhere) slows it down.
type cc struct {
	rate, maxRate, minRate float64 // bytes per second
	tokens                 float64
	slack                  time.Duration

	minRTT   time.Duration
	minRTTAt time.Time
	srtt     time.Duration
	rttvar   time.Duration
	latest   time.Duration

	tickAt   time.Time
	rttSum   time.Duration
	rttN     int
	limited  bool
	maxPlain int // plaintext bytes per datagram (cwnd floor is 40 of them)
	backoff  int // consecutive inflated intervals (for stats)

	// reliable: the carrier is TCP based (Profile.Reliable). It never loses a datagram by itself, but a lost TCP
	// segment stalls one connection for 1-2 RTT (head-of-line), so a few samples per interval are late while the
	// rest are on time. Judging delay by the interval's floor instead of its mean, and giving loss detection the
	// time a TCP retransmit takes, keeps the pacer and the repair logic from reacting to that (measured 2026-10-09
	// on the bench link: 56 % of all packets were spurious retransmits).
	reliable bool
	tickMin  time.Duration

	pathRTT time.Duration // bond: the slowest recently used path's RTT, so the window covers every path

	// Loss-aware soft ceiling (v1.8.0). Loss alone is not congestion here (~0.2 % random), but a loss rate far above
	// the learned baseline means the path is dropping our packets at a bottleneck (measured 2026-10-10: past ~50k
	// pps a deep queue fills and 30 % of the wire was retransmissions). Then the rate is cut and may not climb past a
	// ceiling that itself only creeps up while no loss is seen.
	sentN, lostN int     // tracked packets sent / declared lost in the current tick
	spuriousN    int     // reliable: declared lost this tick, then acked after all (TCP delivered it late)
	relLossMul   float64 // reliable: adaptive multiplier on the loss timer, grows while retransmits are spurious
	hardMin      float64 // the configured floor; minRate may sit above it (reliable: the start rate)
	lowTicks     int     // reliable: ticks left during which overload may cut below minRate, down to hardMin
	stuckTicks   int     // reliable: loss cuts while already at the floor (reset once the rate climbs)
	lossOff      int     // reliable: ticks left during which loss is not treated as overload
	baseLoss     float64 // learned quiet-interval loss (EWMA, floor minBaseLoss)
	lossPct      float64 // last judged interval's loss, 0..1 (stats)
	ceiling      float64 // bytes per second; 0 = none

	// ICMP ceiling governor (2.9.0, -governor): learns the rate ceiling under the reroute signature
	gov govState

	// diagnostics (2.4.10, /stats "cc"): what held the sender back, per tick, and why the rate was cut
	tokLim, cwndLim bool // set by build during the current tick
	heldLim         bool // set by build: the carrier's send queues were full (Backlogger)
	direct          bool // reliable carrier with no CDN in between (Config.Direct): TCP paces, see cwnd/lossTime
	diag            CCDiag

	// delivery-rate pacer for reliable carriers (2.4.11). TCP underneath does its own congestion control and injects
	// RTT jitter from its retransmits, so delay is a false signal here; instead pace a little above the measured
	// delivery rate (bytes acked per second, windowed max over busy ticks) and bound inflight to a few BDP.
	delivered uint64    // cumulative acked bytes (reliable)
	delLast   uint64    // delivered at the last tick
	bwAt      time.Time // last delivery-rate tick
	bwRing    [bwWin]float64
	bwPos     int
	bwLen     int
	bwBusy    bool    // the current measurement interval had at least one busy tick
	maxBW     float64 // windowed-max delivery rate (bytes/s); 0 until the first sample
	bwSeen    bool    // a delivery rate was ever measured: a later 0 means a dead path, not "no estimate yet"
	grown     bool    // direct startup over: the estimate stopped growing (BBR's full-pipe check)
	growBW    float64 // estimate at the last 25 % step
	growAt    time.Time

	// PROBE_RTT (reliable): a single deeply-queued connection never delivers a drained RTT sample, so minRTT would
	// climb with its own queue and the BDP window with it (field 2026-10-13: minRTT rose to 550 ms from a real 108,
	// inflight ran away). Every probeRTTEvery the pacer briefly caps inflight low to drain the queue and re-measure.
	probeAt    time.Time // when to next enter PROBE_RTT
	draining   bool      // currently draining inflight to re-measure the base RTT
	probeStart time.Time // when the current drain began (bounds its length)
	probeLowAt time.Time // when inflight first reached the drain floor; zero until the queue has emptied
	inflight   int       // bytes in flight, mirrored from the session so the drain knows when the queue is empty
}

const bwWin = 10 // delivery-rate window, samples of >= 1 RTT each (~1 s): its max is the capacity estimate

const (
	// relBWGain: pace this far above the estimate, to keep probing for more. 1.5 since 2.4.18 (was 1.2): on a lossy
	// path each TCP connection's retransmit stalls make delivery lumpy, and 1.2 climbed too slowly to ever fill it.
	relBWGain = 1.5
	// relStartGain: a direct carrier paces this far above the estimate until the estimate stops growing by 25 % within
	// relStartWait (at least 3 srtt). Each step waits a whole srtt for its delivery sample, and with TCP's retransmit
	// stalls srtt is 150-250 ms, so at 1.5x a fresh tunnel took seconds to fill: a first 200 MB download ran at 42-45
	// MB/s and the next on the same tunnel at 53-71 (field 2026-10-16, reverse tcp, 8-16 connections). The pool's own
	// backpressure (Backlogger) holds the session once its queues fill, so the higher gain cannot flood a connection.
	relStartGain = 2.5
	relStartWait = 500 * time.Millisecond
	relCwndBDP   = 3 // inflight ceiling, in bandwidth-delay products
)

// Direct reliable carriers (Config.Direct): window in seconds of delivery, and the loss timer / PTO floors. A datagram
// there is lost only when its connection dies; anything sooner is TCP recovering, and resending it only duplicates
// (field 2026-10-16: 6-70k resends per 200 MB, most never proven spurious).
const relDirectWin = time.Second

// WAT_DIRECT_LOSS_MS sets a loss timer floor for direct carriers (the PTO floor 500 ms above it), for field A/Bs. Off
// by default: a 2 s floor was measured slower than the normal timer (field 2026-10-16, Kharej -> Iran: 2 s ~12 MB/s,
// 500 ms ~20, normal ~25), because a hole behind a stalled connection is repaired faster by an early resend on
// another connection than by waiting for TCP's own recovery.
var relDirectLossTime, relDirectPTO = directLossTimes()

func directLossTimes() (time.Duration, time.Duration) {
	if n, err := strconv.Atoi(os.Getenv("WAT_DIRECT_LOSS_MS")); err == nil && n > 0 {
		lt := time.Duration(n) * time.Millisecond
		return lt, lt + 500*time.Millisecond
	}
	return 0, 0
}

// relCwndStall bounds how far above the base RTT srtt may size the reliable window (2.4.18); WAT_CWND_MINRTT=1 sizes
// it from minRTT only, as before, for an A/B.
const relCwndStall = 500 * time.Millisecond

var relCwndMinRTT = os.Getenv("WAT_CWND_MINRTT") != ""

// relLossCuts: whether a direct reliable carrier still cuts its rate on timed-out packets (WAT_REL_LOSSCUT=1; off since
// 2.4.18). TCP does the congestion control on these carriers and never drops a datagram, so a "loss" is a datagram
// held up behind a TCP retransmit, a dead connection or a full local queue, and the delivery-rate pace plus the BDP
// window already bound what we put in flight. The cut is also judged too early: a late ack proves a loss spurious only
// after the tick that cut. On the Kharej->Iran path (heavy random loss, BBR underneath) the cuts held a session at
// ~20 MB/s while bare TCP on the same 8 connections did 78 (field 2026-10-16); on the emulated version of that path
// removing them took 16 parallel downloads from 8-15 to 35-45 MB/s.
var relLossCuts = os.Getenv("WAT_REL_LOSSCUT") != ""

const (
	probeRTTEvery = 8 * time.Second        // enter PROBE_RTT this often (< the 10 s minRTT window, so minRTT never goes stale-high)
	probeRTTHold  = 200 * time.Millisecond // once inflight reaches the floor, hold there this long (or 1x minRTT) to sample
	probeRTTMax   = 4 * time.Second        // give up a drain that never reaches the floor (e.g. a wedged connection)
)

// onDelivered adds newly acked bytes to the reliable delivery-rate estimate.
func (c *cc) onDelivered(n int) {
	if c.reliable && n > 0 {
		c.delivered += uint64(n)
	}
}

// updateBW turns the bytes acked since the last tick into a delivery-rate sample. A tick where the sender had nothing
// to send (app-limited) under-measures the path, so it never lowers the estimate; a busy tick enters the window and
// the windowed maximum is the capacity estimate.
func (c *cc) updateBW(now time.Time, busy bool) {
	c.bwBusy = c.bwBusy || busy
	if c.bwAt.IsZero() {
		c.bwAt, c.delLast = now, c.delivered
		return
	}
	// measure over at least one RTT: a stall releasing many packets in one tick is an ack burst, not real bandwidth,
	// and a per-tick rate would read it as capacity. Averaging over >= 1 RTT smooths that.
	span := c.minRTT
	if span < 40*time.Millisecond {
		span = 40 * time.Millisecond
	}
	if now.Sub(c.bwAt) < span {
		return
	}
	dt := now.Sub(c.bwAt).Seconds()
	c.bwAt = now
	if dt <= 0 {
		return
	}
	bw := float64(c.delivered-c.delLast) / dt
	c.delLast = c.delivered
	busyInterval := c.bwBusy
	c.bwBusy = false
	if !busyInterval { // app-limited: let a high sample raise the estimate, never let a low one lower it
		if bw > c.maxBW {
			c.maxBW = bw
			c.bwSeen = true
		}
		return
	}
	c.bwRing[c.bwPos] = bw
	c.bwPos = (c.bwPos + 1) % bwWin
	if c.bwLen < bwWin {
		c.bwLen++
	}
	c.maxBW = 0
	for i := 0; i < c.bwLen; i++ {
		if c.bwRing[i] > c.maxBW {
			c.maxBW = c.bwRing[i]
		}
	}
	if c.maxBW > 0 {
		c.bwSeen = true
	}
}

// CCDiag counts, since start, the pacer's ticks by what limited the sender and its rate cuts by cause.
type CCDiag struct {
	Ticks, TokLimited, CwndLimited, AppLimited uint64 // ticks; app-limited: nothing waiting to be sent
	LossCuts, DelayCuts, DeepTrips             uint64 // DeepTrips: the delay rule let the rate fall below the start rate
	Lost, Spurious                             uint64 // declared lost; of those, acked later after all
	PoolFull                                   uint64 // ticks held back by the carrier's full send queues (2.4.18)
}

func (d *CCDiag) add(o CCDiag) {
	d.Ticks += o.Ticks
	d.TokLimited += o.TokLimited
	d.CwndLimited += o.CwndLimited
	d.AppLimited += o.AppLimited
	d.LossCuts += o.LossCuts
	d.DelayCuts += o.DelayCuts
	d.DeepTrips += o.DeepTrips
	d.Lost += o.Lost
	d.Spurious += o.Spurious
	d.PoolFull += o.PoolFull
}

// AddPacer folds b's pacer diagnostics into a: counters and gauges (floor, window) add up across sessions, and the
// timers take the largest. For a client running several sessions.
func AddPacer(a *Stats, b Stats) {
	a.CC.add(b.CC)
	a.FloorBps += b.FloorBps
	a.Cwnd += b.Cwnd
	a.WinBlocked += b.WinBlocked
	a.LossTime, a.PTO, a.RelLossMul = max(a.LossTime, b.LossTime), max(a.PTO, b.PTO), max(a.RelLossMul, b.RelLossMul)
}

const (
	minBaseLoss   = 0.005
	lossFloor     = 0.03
	lossMinSent   = 50
	lossCut       = 0.85
	ceilingHead   = 1.05
	ceilingGrowth = 1.02
)

// lossLimit is the interval loss above which the path counts as dropping our packets.
func (c *cc) lossLimit() float64 {
	b := c.baseLoss
	if b < minBaseLoss {
		b = minBaseLoss
	}
	return max(lossFloor, 4*b)
}

// lossStep judges one tick's loss; true when the rate was just cut.
func (c *cc) lossStep() bool {
	sent, lost := c.sentN, c.lostN
	c.sentN, c.lostN = 0, 0
	if c.reliable {
		return c.reliableLoss(sent, lost)
	}
	if sent < lossMinSent || !lossAwareOn.Load() {
		return false
	}
	loss := float64(lost) / float64(sent)
	c.lossPct = loss
	if loss > c.lossLimit() {
		c.rate *= lossCut
		if c.rate < c.minRate {
			c.rate = c.minRate
		}
		c.ceiling = c.rate * ceilingHead
		return true
	}
	c.baseLoss += (loss - c.baseLoss) / 64
	if c.baseLoss < minBaseLoss {
		c.baseLoss = minBaseLoss
	}
	if c.ceiling > 0 {
		c.ceiling *= ceilingGrowth
		if c.ceiling >= c.maxRate {
			c.ceiling = 0
		}
	}
	return false
}

// A reliable carrier loses a datagram only when it sat in some queue past reliableLossTime, or its connection died.
// Many of those in one tick mean the path is far slower than our pace: a CDN edge buffering for a slow last leg
// (field 2026-10-12, wss via Cloudflare: four sessions held at the 8 MB/s floor into a ~10 MB/s path, 10 MB in
// flight, sustained download collapsed from 40-50 to 10 MB/s with ~500 ms stalls). Retransmitted packets give no RTT
// sample, so the delay rule cannot see that queue. Cut, and for a while let the rate fall below the start-rate floor.
const (
	relLossMin  = 4  // lost packets in one tick
	relLossFrac = 20 // and at least 1/20 of the tick's sent packets
	relLossCut  = 0.8
	relLowTicks = 600 // ~30 s at 50 ms per tick, renewed by every cut

	// Loss that goes on while the rate sits at the floor was not caused by our rate (field 2026-10-12, 2.4.6 after
	// ~3 h: a few CDN connections delivered seconds late, half of all packets were resent, and every session sat at
	// the 0.2 MB/s floor for good because each tick at the floor still saw losses). After relStuckTicks such cuts
	// the loss rule stands down for relLossOff ticks and the delay rule alone sets the pace.
	relStuckTicks = 40  // >= 2 s of cuts at the floor
	relLossOff    = 600 // ~30 s

	relLossMulMax = 8   // the loss timer may stretch to 8x its base while retransmits keep turning out spurious
	relSpurHigh   = 0.5 // a tick is "mostly spurious" when >= half its declared losses were later acked
)

// relV2 is the 2.4.9 reliable-carrier congestion rule: separate genuine wire loss from TCP's own late delivery
// (spurious retransmits), adapt the loss timer so the session stops resending what TCP will deliver, and respond to
// real loss with gentle AIMD and a creeping ceiling instead of slamming to the floor. Gated for an A/B on the
// emulator and the field; default on.
var relV2 = os.Getenv("WAT_REL_V1") == ""

func (c *cc) reliableLoss(sent, lost int) bool {
	if relV2 {
		return c.reliableLossV2(sent, lost)
	}
	if c.lowTicks > 0 {
		c.lowTicks--
	}
	if sent+lost >= lossMinSent { // judged intervals only, like the datagram rule (2.4.2 kept a stale value)
		c.lossPct = float64(lost) / float64(max(sent, lost))
	}
	atFloor := c.rate <= 1.5*c.hardMin
	if !atFloor {
		c.stuckTicks = 0
	}
	if c.lossOff > 0 {
		c.lossOff--
		return false
	}
	if lost < relLossMin || lost*relLossFrac < sent {
		return false
	}
	if atFloor {
		if c.stuckTicks++; c.stuckTicks >= relStuckTicks {
			c.stuckTicks, c.lossOff, c.lowTicks = 0, relLossOff, 0
			return false
		}
	}
	c.rate *= relLossCut
	if c.rate < c.hardMin {
		c.rate = c.hardMin
	}
	c.lowTicks = relLowTicks
	return true
}

// reliableLossV2 judges one tick after removing spurious retransmits. A CDN edge buffers shallowly, so an overfilled
// path drops rather than delays and the delay rule is blind; but TCP's own fast-retransmit also delays a datagram
// past our loss timer, and the session then resends a packet TCP is about to deliver (field 2026-10-12: ~12-50 % of
// the wire was such duplicates, and the old rule read them as congestion and slammed to the floor). Here a
// declared-lost packet that is later acked is counted spurious and removed from the congestion signal; while losses
// keep turning out spurious the loss timer stretches (relLossMul), so the session waits for TCP instead of resending;
// genuine wire loss gets a gentle multiplicative cut and a ceiling that creeps back up, not a slam to the floor.
func (c *cc) reliableLossV2(sent, lost int) bool {
	spur := c.spuriousN
	c.spuriousN = 0
	if c.lowTicks > 0 {
		c.lowTicks--
	}
	if lost > 0 { // steer the loss timer by how many of this tick's "losses" TCP actually delivered late
		if float64(spur) >= relSpurHigh*float64(lost) {
			c.relLossMul = min(c.relLossMul*1.25, relLossMulMax)
		} else {
			c.relLossMul = max(c.relLossMul*0.97, 1)
		}
	}
	real := lost - spur // genuine wire drops: the congestion signal
	if real < 0 {
		real = 0
	}
	if sent+real >= lossMinSent {
		c.lossPct = float64(real) / float64(max(sent, real))
	}
	if (c.direct && !relLossCuts) || real < relLossMin || real*relLossFrac < sent {
		if c.ceiling > 0 { // quiet tick: let the ceiling creep up, then release it at the max
			c.ceiling *= ceilingGrowth
			if c.ceiling >= c.maxRate {
				c.ceiling = 0
			}
		}
		return false
	}
	c.rate *= relLossCut
	if c.rate < c.hardMin {
		c.rate = c.hardMin
	}
	c.ceiling = c.rate * ceilingHead // AIMD: grow only back toward where loss began
	return true
}

// floor is the lowest rate the delay rule may cut to.
func (c *cc) floor() float64 {
	if c.lowTicks > 0 {
		return c.hardMin
	}
	return c.minRate
}

func newCC(initRate, minRate, maxRate float64, slack time.Duration) cc {
	return cc{rate: initRate, minRate: minRate, hardMin: minRate, maxRate: maxRate, slack: slack, relLossMul: 1}
}

func (c *cc) refill(dt time.Duration) {
	c.tokens += c.rate * dt.Seconds()
	burst := c.rate*0.005 + 64<<10
	if c.direct {
		// Direct TCP carriers rely on kernel socket buffers and BBR pacing. Allow sufficient
		// token burst headroom (50 ms or 512 KB) so the userspace pacer does not starve socket buffers.
		burst = max(c.rate*0.05, 512<<10)
	}
	if c.tokens > burst {
		c.tokens = burst
	}
}

func (c *cc) sample(rtt time.Duration, now time.Time) {
	if rtt <= 0 {
		return
	}
	c.latest = rtt
	if c.srtt == 0 {
		c.srtt, c.rttvar = rtt, rtt/2
	} else {
		d := c.srtt - rtt
		if d < 0 {
			d = -d
		}
		c.rttvar = (3*c.rttvar + d) / 4
		c.srtt = (7*c.srtt + rtt) / 8
	}
	stale := now.Sub(c.minRTTAt) > 10*time.Second
	if c.reliable && relV2 {
		// never raise minRTT to a queued sample: PROBE_RTT supplies a drained one. Only a sample taken with inflight
		// actually at the drain floor (the queue is empty) may move minRTT up, to follow a genuine path change.
		stale = stale && c.draining && c.inflight <= c.drainFloor()
	}
	if c.minRTT == 0 || rtt < c.minRTT || stale {
		c.minRTT, c.minRTTAt = rtt, now
	}
	c.gov.govSample(rtt, c.rate, now) // the governor watches base-RTT jumps (2.9.0)
	c.rttSum += rtt
	if c.rttN == 0 || rtt < c.tickMin {
		c.tickMin = rtt
	}
	c.rttN++
}

// tick runs every ~50 ms.
func (c *cc) tick(now time.Time) {
	if now.Sub(c.tickAt) < 50*time.Millisecond {
		return
	}
	c.tickAt = now
	c.diag.Ticks++
	switch {
	case c.heldLim:
		c.diag.PoolFull++
	case c.cwndLim:
		c.diag.CwndLimited++
	case c.tokLim:
		c.diag.TokLimited++
	case !c.limited:
		c.diag.AppLimited++
	}
	busy := c.cwndLim || c.tokLim || c.heldLim
	c.tokLim, c.cwndLim, c.heldLim = false, false, false
	cut := c.lossStep()
	if cut {
		c.diag.LossCuts++
	}
	if c.reliable && relV2 {
		c.tickReliable(now, cut, busy)
		c.rttSum, c.rttN, c.limited = 0, 0, false
		return
	}
	if c.rttN > 0 && c.minRTT > 0 {
		avg := c.rttSum / time.Duration(c.rttN)
		if c.reliable {
			avg = c.tickMin
		}
		slack := c.slack
		if s := c.minRTT / 8; s > slack {
			slack = s
		}
		// reliable (TCP pool, e.g. through a CDN): delay spread across edges and TCP buffering inflates the RTT
		// without any queue of ours, and real congestion is already handled by TCP. Allow a third of the RTT and cut
		// only while we fill the window ourselves: in production (2.4.0, ~500 bursty web streams) the old rule cut
		// app-limited sessions down to the 0.2 MB/s floor and they never climbed back.
		if c.reliable {
			if s := c.minRTT / 3; s > slack {
				slack = s
			}
		}
		// reliable: even the interval's fastest sample at twice the base RTT is our own queue, not edge spread, so the
		// cut may go under the start-rate floor (field 2026-10-12: a ~10 MB/s CDN leg under a 4 x 8 MB/s floor queued
		// until packets timed out).
		if c.reliable && c.limited && avg > 2*c.minRTT && avg-c.minRTT > 40*time.Millisecond {
			c.lowTicks = relLowTicks
			c.diag.DeepTrips++
		}
		if avg > c.minRTT+slack && (!c.reliable || c.limited) {
			c.diag.DelayCuts++
			c.rate *= 0.93
			if f := c.floor(); c.rate < f {
				c.rate = min(f, c.rate/0.93) // clamp to the floor, but never raise a rate already below it
			}
			c.backoff++
		} else {
			c.backoff = 0
			if c.limited && !cut {
				c.rate *= 1.10
				if c.ceiling > 0 && c.rate > c.ceiling {
					c.rate = max(c.ceiling, c.rate/1.10) // never raise past the ceiling
				}
				if g := c.gov.ceiling; g > 0 && c.rate > g { // the reroute governor's learned ceiling (2.9.0)
					c.rate = g
				}
				if c.rate > c.maxRate {
					c.rate = c.maxRate
				}
			}
		}
	}
	c.rttSum, c.rttN, c.limited = 0, 0, false
}

// tickReliable paces a reliable carrier by delivery rate, not delay. The target is relBWGain above the windowed-max
// delivery rate; cwnd (reliableBDP) bounds inflight, so over-pacing turns into token/cwnd-limited headroom that probes
// for more without inflating latency. Real wire loss (after spurious removal) still cuts via reliableLossV2's ceiling;
// delay never cuts here, because TCP's retransmit jitter is not our queue (field 2026-10-13: a single CDN stream sat
// at 1 MB/s with 641 delay cuts to 1 loss cut while TCP below it was idle).
func (c *cc) tickReliable(now time.Time, cut, busy bool) {
	c.updateBW(now, busy)
	c.probeRTT(now)
	if c.maxBW <= 0 {
		if c.bwSeen { // the estimate fell to zero over busy windows: nothing is delivered. Hold; ramping to the maximum on a dead path (3.0.1)
			return
		}
		if c.limited && !cut { // no estimate yet: ramp like slow start
			c.rate = min(c.rate*1.10, c.maxRate)
			if c.ceiling > 0 && c.rate > c.ceiling { // the ramp honours the same ceilings as the probe above
				c.rate = max(c.ceiling, c.rate/1.10)
			}
			if g := c.gov.ceiling; g > 0 && c.rate > g {
				c.rate = g
			}
		}
		return
	}
	gain := relBWGain
	if c.direct && !c.grown {
		gain = relStartGain
		if c.maxBW >= 1.25*c.growBW || !busy { // idle time does not count: a tunnel sits idle before its first transfer
			c.growBW, c.growAt = max(c.growBW, c.maxBW), now
		} else if now.Sub(c.growAt) > max(relStartWait, 3*c.srtt) {
			c.grown = true
		}
	}
	target := gain * c.maxBW
	if c.ceiling > 0 && target > c.ceiling { // a recent real-loss cut caps the probe until the ceiling creeps back up
		target = c.ceiling
	}
	if g := c.gov.ceiling; g > 0 && target > g { // learned governor ceiling on reliable carriers (2.9.0)
		target = g
	}
	if target > c.maxRate {
		target = c.maxRate
	}
	if target < c.hardMin {
		target = c.hardMin
	}
	// the windowed-max already smooths single samples, so track the target directly: climb fast to fill the pipe,
	// drop at once when the estimate falls (loss or a slower path)
	c.rate = target
}

// probeRTT runs the drain schedule (BBR PROBE_RTT). Every probeRTTEvery it caps inflight to a few packets (via cwnd),
// waits for the queue to actually empty, then holds there ~1 RTT so sample() can read the true base RTT. Draining to a
// fixed low floor — not to a fraction of the (possibly already polluted) BDP — is what makes the measured minRTT
// reflect an empty pipe: a shallow drain leaves a standing queue and re-measures the queue, not the base (field
// 2026-10-13: a half-BDP drain left minRTT at 314 ms over a real 105, and the window ran away with it).
func (c *cc) probeRTT(now time.Time) {
	if c.probeAt.IsZero() {
		c.probeAt = now.Add(probeRTTEvery)
		return
	}
	if c.draining {
		if c.inflight <= c.drainFloor() && c.probeLowAt.IsZero() {
			c.probeLowAt = now // queue emptied: start the sampling hold
		}
		hold := probeRTTHold
		if c.minRTT > hold {
			hold = c.minRTT
		}
		drained := !c.probeLowAt.IsZero() && now.Sub(c.probeLowAt) >= hold
		if drained || now.Sub(c.probeStart) >= probeRTTMax {
			c.draining, c.probeLowAt = false, time.Time{}
			c.probeAt = now.Add(probeRTTEvery)
		}
		return
	}
	if now.After(c.probeAt) {
		c.probeAt = now.Add(probeRTTEvery) // re-arm whether or not we drain this time
		// Drain only when a standing queue of our own could be hiding the base RTT. Two conditions, both needed:
		//   - inflight above twice the floor: this sender is holding a real queue. An app-limited sender -- the receive
		//     side of a transfer, or an idle session -- sits at the floor, builds no queue, and its delayed samples are
		//     reverse-path or scheduling noise, not a base to re-measure from. Draining there once raised a client's
		//     minRTT from 107 to 545 ms while it was only downloading and wrecked its next upload (field 2026-10-13).
		//   - srtt well above minRTT: there is actually a queue to clear. The pool runs at srtt ~ minRTT (its many
		//     connections keep the per-connection queue shallow and minRTT fresh), so it skips the drain and its
		//     throughput dip; a single queued connection sits far above and drains every cycle.
		// Requiring inflight above the floor also means the minRTT raise in sample() fires only after a genuine drain.
		// A direct carrier's window does not hang on minRTT (cwnd), so it has nothing to re-measure.
		if !c.direct && c.inflight > 2*c.drainFloor() && c.srtt > c.minRTT+c.minRTT/2 {
			c.draining, c.probeStart, c.probeLowAt = true, now, time.Time{}
		}
	}
}

func (c *cc) probing() bool   { return c.draining }
func (c *cc) drainFloor() int { return 4 * c.maxPlain }

func (c *cc) cwnd() int {
	if c.reliable && relV2 && c.maxBW > 0 && c.minRTT > 0 {
		// bandwidth-delay product bound: keep a few BDP in flight to fill the pipe and survive one RTT of jitter,
		// but no more, so our own queue (and the measured RTT) stays bounded.
		bdp := c.maxBW * c.minRTT.Seconds()
		if c.draining { // PROBE_RTT: hold inflight to a few packets so the queue drains and the base RTT can be read
			return c.drainFloor()
		}
		w := bdp * relCwndBDP
		if c.direct {
			// Direct TCP between the servers: a datagram also waits behind its connection's own retransmits, so its
			// real time in flight is far above minRTT, and a BDP window capped the whole session at ~22 MB/s on the
			// lossy Kharej -> Iran path (field 2026-10-16: cwnd-limited whether 1 or 4 streams ran, bare TCP on the
			// same 8 connections 78 MB/s). With no CDN buffer to fill, our only queues are the pool's and the
			// sockets', and those push back, so allow about a second of delivery and let TCP set the pace.
			w = max(w, c.maxBW*relDirectWin.Seconds())
		}
		if c.direct && !relCwndMinRTT && c.srtt > c.minRTT { // CDN tunnels keep the 2.4.17 window (not field-tested there)
			// Packets also wait behind TCP's own retransmits: a pool connection stalled in recovery holds everything
			// queued on it, so a datagram's real time in flight is srtt, not minRTT. A window of 3x maxBW x minRTT then
			// caps delivery at 3 x minRTT / srtt of the path, and maxBW (measured through that cap) can never grow
			// (field 2026-10-16, Kharej -> Iran, 6-14 % TCP retransmits: ~22 MB/s per session whether 1 or 4 streams
			// ran, cwnd-limited, where bare TCP on the same 8 connections did 78). Cover 2 x srtt as well, with srtt
			// counted at most relCwndStall above the base so a queue of our own cannot inflate the window without
			// bound (the 2.4.12 runaway; backpressure from the pool also bounds that queue now).
			if w2 := 2 * c.maxBW * min(c.srtt, c.minRTT+relCwndStall).Seconds(); w2 > w {
				w = w2
			}
		}
		return int(w) + 40*c.maxPlain
	}
	rtt := c.srtt
	// reliable: srtt includes our own queue in the TCP buffers, so a window sized from it grows with the queue it
	// creates and the sender is never window-limited. Size it from the base RTT instead.
	if c.reliable && c.minRTT > 0 {
		if lim := c.minRTT + c.minRTT/2; rtt > lim {
			rtt = lim
		}
	}
	if c.pathRTT > rtt {
		rtt = c.pathRTT
	}
	if rtt == 0 {
		rtt = 100 * time.Millisecond
	}
	return int(c.rate*rtt.Seconds()*2) + 40*c.maxPlain
}

// pto is how long an unacknowledged packet may stay out before it is presumed lost.
func (c *cc) pto() time.Duration {
	d := 3*c.srtt + 4*c.rttvar
	if d < 120*time.Millisecond {
		d = 120 * time.Millisecond
	}
	if c.reliable {
		if m := time.Duration(float64(reliablePTO) * c.relLossMul); d < m {
			d = m
		}
		if c.direct && d < relDirectPTO {
			d = relDirectPTO
		}
	}
	return d
}

func (c *cc) lossTime() time.Duration {
	rtt := c.srtt
	if c.latest > rtt {
		rtt = c.latest
	}
	d := rtt + rtt/4 + 3*time.Millisecond
	if c.reliable {
		if m := time.Duration(float64(reliableLossTime) * c.relLossMul); d < m {
			d = m
		}
		if c.direct && d < relDirectLossTime {
			d = relDirectLossTime
		}
	}
	return d
}

// A reliable carrier's datagram is late, not lost: TCP's own retransmit timer is at least 200 ms. These floors
// only matter when a connection died (its queue is gone) or a bounded queue overflowed.
const (
	reliablePTO      = 500 * time.Millisecond
	reliableLossTime = 400 * time.Millisecond
)
