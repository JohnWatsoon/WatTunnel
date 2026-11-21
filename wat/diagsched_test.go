//go:build diag

// The speed-swarm diagnostics (2026-11-21): measurement tools, NOT regression pins — they add ~7 min to
// the suite, so they build only under the diag tag:  go test -tags diag -run Diag ./wat/
package wat

// Diagnostic harness for the interactive tail during bulk (P4, 2026-11-21). Decomposes one echo sample
// next to a bulk download into: client queue/pacer wait, uplink wire, server receive+handle, server
// queue/pacer wait, downlink wire (incl. the link's own standing queue), client deliver. All runs at 0%
// loss so nothing loss-related can appear. Runs on a purpose-built link that can be shared by two
// sessions (cross-session isolation probe) and records the per-packet queueing delay it imposed, keyed
// by packet number (cfg.NoMask keeps the header plain so the pn is readable on the wire).

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// ---- link ----

type diagQd struct {
	sid, pn uint64
	qd      time.Duration
	n       int
}

// diagLink is one direction of a rate-limited, delayed link that fans every packet out to all attached
// receivers (a shared bottleneck for the cross-session probe), like simDir in sim_test.go but with the
// per-packet queueing delay recorded under the packet number.
type diagLink struct {
	mu       sync.Mutex
	loss     float64
	bps      float64
	delay    time.Duration
	maxQueue time.Duration
	capBytes int
	free     time.Time
	q        chan time.Time
	pend     map[time.Time][][]byte
	order    []time.Time
	outs     []chan []byte
	rnd      *rand.Rand
	rec      []diagQd
	dropped  int
	sent     int
}

func newDiagLink(loss float64, bps float64, delay time.Duration, maxQueue time.Duration, capBytes int, seed int64) *diagLink {
	l := &diagLink{loss: loss, bps: bps, delay: delay, maxQueue: maxQueue, capBytes: capBytes,
		q: make(chan time.Time, 1<<16), pend: map[time.Time][][]byte{}, rnd: rand.New(rand.NewSource(seed))}
	go func() {
		for at := range l.q {
			if w := time.Until(at); w > 0 {
				time.Sleep(w)
			}
			l.mu.Lock()
			ps := l.pend[at]
			delete(l.pend, at)
			l.mu.Unlock()
			for _, p := range ps {
				for _, o := range l.outs {
					c := append([]byte(nil), p...)
					select {
					case o <- c:
					default:
					}
				}
			}
		}
	}()
	return l
}

func (l *diagLink) send(p []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent++
	now := time.Now()
	if len(p) > l.capBytes {
		l.dropped++
		return
	}
	start := l.free
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > l.maxQueue {
		l.dropped++
		return
	}
	l.rec = append(l.rec, diagQd{sid: binary.BigEndian.Uint64(p[0:8]), pn: binary.BigEndian.Uint64(p[8:16]), qd: start.Sub(now), n: len(p)})
	l.free = start.Add(time.Duration(float64(len(p)+28) / l.bps * float64(time.Second)))
	if l.rnd.Float64() < l.loss {
		l.dropped++
		return
	}
	at := l.free.Add(l.delay)
	l.pend[at] = append(l.pend[at], append([]byte(nil), p...))
	l.q <- at
}

// qdFor returns the recorded queueing delay of pn (found flag when absent).
func (l *diagLink) qdFor(sid, pn uint64) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.rec) - 1; i >= 0; i-- { // newest first: pn repeats only on a hedge dup or a retransmit
		if l.rec[i].sid == sid && l.rec[i].pn == pn {
			return l.rec[i].qd, true
		}
	}
	return 0, false
}

func (l *diagLink) qdAll() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	q := make([]time.Duration, 0, len(l.rec))
	for _, r := range l.rec {
		q = append(q, r.qd)
	}
	return q
}

// ---- io ----

type diagPkt struct {
	sid, pn uint64
	at      time.Time
	n       int
}

// diagBusIO is one session's attachment to the shared links, recording Send and Recv with the pn. With a
// masked config the wire header is unreadable, so a copy is unmasked with the PSK's mask key before parsing
// (maskHdr is an XOR involution).
type diagBusIO struct {
	tx    *diagLink
	simTx *simDir
	sim   bool
	inner *simIO // set: delegate to a bare simIO with no recording (the killLatency pair, verbatim)
	rx    chan []byte
	done  chan struct{}
	once  sync.Once
	hk    []byte
	mu    sync.Mutex
	snds  []diagPkt
	rcvs  []diagPkt
}

func (d *diagBusIO) hdr(p []byte) (sid, pn uint64, n int) {
	q := p
	if d.hk != nil {
		c := append([]byte(nil), p[:hdrLen+12]...)
		maskHdr(d.hk, c)
		q = c
	}
	return binary.BigEndian.Uint64(q[0:8]), binary.BigEndian.Uint64(q[8:16]), len(p)
}

func (d *diagBusIO) Send(p []byte, lane int) error {
	if d.inner != nil {
		return d.inner.Send(p, lane)
	}
	if d.sim {
		d.simTx.send(p)
	} else {
		d.tx.send(p)
	}
	sid, pn, n := d.hdr(p)
	d.mu.Lock()
	d.snds = append(d.snds, diagPkt{sid: sid, pn: pn, at: time.Now(), n: n})
	d.mu.Unlock()
	return nil
}

func (d *diagBusIO) Recv() ([]byte, int, net.Addr, error) {
	if d.inner != nil {
		return d.inner.Recv()
	}
	select {
	case p := <-d.rx:
		sid, pn, n := d.hdr(p)
		d.mu.Lock()
		d.rcvs = append(d.rcvs, diagPkt{sid: sid, pn: pn, at: time.Now(), n: n})
		d.mu.Unlock()
		return p, 0, nil, nil
	case <-d.done:
		return nil, 0, nil, io.EOF
	}
}

func (d *diagBusIO) SetPeer(net.Addr) {}
func (d *diagBusIO) Close() error     { d.once.Do(func() { close(d.done) }); return nil }

func (d *diagBusIO) snd(sid, pn uint64) (time.Time, int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.snds {
		if r.sid == sid && r.pn == pn {
			return r.at, r.n, true
		}
	}
	return time.Time{}, 0, false
}

func (d *diagBusIO) rcv(sid, pn uint64) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.rcvs {
		if r.sid == sid && r.pn == pn {
			return r.at, true
		}
	}
	return time.Time{}, false
}

// sndMin/rcvMin return the earliest Send/Recv of any of pns (a retransmit series: the first that moved
// the frame forward is the one that matters for latency stage boundaries).
func (d *diagBusIO) sndMin(sid uint64, pns []uint64) (time.Time, int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best time.Time
	n := 0
	for _, r := range d.snds {
		if r.sid != sid {
			continue
		}
		for _, pn := range pns {
			if r.pn == pn && (best.IsZero() || r.at.Before(best)) {
				best, n = r.at, r.n
			}
		}
	}
	return best, n, !best.IsZero()
}

func (d *diagBusIO) rcvMin(sid uint64, pns []uint64) (time.Time, uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best time.Time
	var pn uint64
	for _, r := range d.rcvs {
		if r.sid != sid {
			continue
		}
		for _, q := range pns {
			if r.pn == q && (best.IsZero() || r.at.Before(best)) {
				best, pn = r.at, r.pn
			}
		}
	}
	return best, pn, !best.IsZero()
}

// sizes between lo (inclusive) and hi (exclusive), sends in [a, b]
func (d *diagBusIO) sndBetween(a, b time.Time, min int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, r := range d.snds {
		if !r.at.Before(a) && r.at.Before(b) && r.n >= min {
			n++
		}
	}
	return n
}

// ---- harness ----

type diagEchoSrv struct {
	tD, tE, tF time.Time // request read by handler / response written / response frame built (pump)
	pnR        uint64
	pns        *pnSet // every pn that carried the response frame (retransmits included)
}

// pnSet collects the packet numbers that carried a given stream frame; a retransmit rides a new pn, so a
// lost request or response must be matched by frame, not by the pn it first left in.
type pnSet struct {
	mu sync.Mutex
	m  map[uint64]bool
}

func (p *pnSet) add(pn uint64) {
	if pn == 0 {
		return
	}
	p.mu.Lock()
	p.m[pn] = true
	p.mu.Unlock()
}

func (p *pnSet) snapshot() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]uint64, 0, len(p.m))
	for pn := range p.m {
		out = append(out, pn)
	}
	return out
}

// collectPNs polls s.sent for every packet that carried the (sid, off) frame until the deadline. Entries
// are freed once acked, so polling is what catches them while live.
func collectPNs(s *Session, sid, off uint64, p *pnSet, deadline time.Time) {
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for i := s.sentHead; i < len(s.sent); i++ {
			for _, f := range s.sent[i].frames {
				if f.sid == sid && f.off == off && f.n > 0 {
					p.add(s.sent[i].pn)
				}
			}
		}
		s.mu.Unlock()
		time.Sleep(300 * time.Microsecond)
	}
}

type diagStage struct {
	total, cliQ, wireUp, srvRx, srvHandle, srvQ, srvSeal, wireDown, cliRx, qdDown time.Duration
	bulkBefore, rspN                                                              int
	rspFull                                                                       bool
}

// waitFrame polls until the pump has put the stream frame (sid, off) into a packet, and returns that
// packet's number and build time from s.sent. Polling only observes: the timestamps come from sentPkt.at.
func waitFrame(s *Session, sid, off uint64) (uint64, time.Time) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if st := s.streams[sid]; st != nil && st.snext > off {
			for i := s.sentHead; i < len(s.sent); i++ {
				for _, f := range s.sent[i].frames {
					if f.sid == sid && f.off == off && f.n > 0 {
						pn, at := s.sent[i].pn, s.sent[i].at
						s.mu.Unlock()
						return pn, at
					}
				}
			}
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Microsecond)
	}
	return 0, time.Time{}
}

type diagRun struct {
	cli, srv  *Session
	cliIO     *diagBusIO
	srvIO     *diagBusIO
	up, down  *diagLink
	payload   int
	pollOn    bool
	bare      bool
	simUp     *simDir
	simDown   *simDir
	srvEcho   map[uint64]diagEchoSrv
	srvEchoMu sync.Mutex
}

// newDiagRun builds the shared links and one echo session (plus optionally a second bulk-only session
// sharing the same bottleneck for the cross-session probe).
func newDiagRun(t testing.TB, loss float64, mtu int, cfg Config, crossBulk bool) *diagRun {
	return newDiagRunPoll(t, loss, mtu, cfg, crossBulk, true)
}

func newDiagRunPoll(t testing.TB, loss float64, mtu int, cfg Config, crossBulk bool, pollOn bool) *diagRun {
	return newDiagRunPoll2(t, loss, mtu, cfg, crossBulk, pollOn, false, false)
}

// newDiagRunPoll2: useSim swaps my diagLink for the harness's own simDir links, to bisect the
// clean-p50 difference between this decomposition harness and killLatency (coded_test.go).
func newDiagRunPoll2(t testing.TB, loss float64, mtu int, cfg Config, crossBulk bool, pollOn bool, useSim bool, bare bool) *diagRun {
	r := &diagRun{srvEcho: map[uint64]diagEchoSrv{}, payload: mtu, pollOn: pollOn, bare: bare}
	if useSim {
		r.simUp = newSimDirCap(loss, 20*time.Millisecond, 10e6, 100*time.Millisecond, 11, mtu)
		r.simDown = newSimDirCap(loss, 20*time.Millisecond, 10e6, 100*time.Millisecond, 12, mtu)
	} else {
		r.up = newDiagLink(loss, 10e6, 20*time.Millisecond, 100*time.Millisecond, mtu, 11)
		r.down = newDiagLink(loss, 10e6, 20*time.Millisecond, 100*time.Millisecond, mtu, 12)
	}
	key := []byte("test-key")
	mk := func(server bool, sid uint64) (*Session, *diagBusIO) {
		t.Helper()
		c := cfg
		c.Key, c.Server, c.SID = key, server, sid
		c.MaxPayload = mtu
		if c.Paths == 0 {
			c.Paths = 4
		}
		var tx *diagLink
		rx := make(chan []byte, 1<<14)
		var simTx *simDir
		if useSim {
			if server {
				rx, simTx = r.simUp.out, r.simDown
			} else {
				rx, simTx = r.simDown.out, r.simUp
			}
		} else if server {
			tx = r.down
			r.up.outs = append(r.up.outs, rx)
		} else {
			tx = r.up
			r.down.outs = append(r.down.outs, rx)
		}
		dio := &diagBusIO{tx: tx, simTx: simTx, rx: rx, done: make(chan struct{}), sim: useSim}
		if bare { // no recording at all: exactly the pair killLatency builds
			if server {
				dio.inner = &simIO{r.simDown, r.simUp, dio.done, sync.Once{}}
			} else {
				dio.inner = &simIO{r.simUp, r.simDown, dio.done, sync.Once{}}
			}
		} else if !c.NoMask {
			dio.hk = hdrMaskKey(key)
		}
		s, err := NewSession(c, dio)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s, dio
	}
	r.cli, r.cliIO = mk(false, 0x1234567)
	r.srv, r.srvIO = mk(true, 0x1234567)
	go func() { // echo+bulk server
		for {
			st, err := r.srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(pattern(96<<20, 5))
					st.CloseWrite()
					return
				}
				e := diagEchoSrv{tD: time.Now(), pns: &pnSet{m: map[uint64]bool{}}}
				st.Write(hdr)
				e.tE = time.Now()
				if r.pollOn {
					go collectPNs(r.srv, st.id, 0, e.pns, time.Now().Add(700*time.Millisecond))
				}
				e.pnR, e.tF = waitFrame(r.srv, st.id, 0)
				e.pns.add(e.pnR)
				st.CloseWrite()
				r.srvEchoMu.Lock()
				r.srvEcho[st.id] = e
				r.srvEchoMu.Unlock()
			}()
		}
	}()
	if crossBulk {
		cb, _ := mk(false, 0x7654321)
		sb, _ := mk(true, 0x7654321)
		go func() {
			for {
				st, err := sb.Accept()
				if err != nil {
					return
				}
				go func() {
					hdr := make([]byte, 1)
					if _, err := io.ReadFull(st, hdr); err != nil {
						return
					}
					st.Write(pattern(96<<20, 6))
					st.CloseWrite()
				}()
			}
		}()
		bs, _ := cb.OpenStream()
		bs.Write([]byte{'B'})
		bs.CloseWrite()
		go io.Copy(io.Discard, bs)
	}
	return r
}

func (r *diagRun) startBulk(t testing.TB) {
	bs, _ := r.cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
}

func (r *diagRun) echo(t testing.TB) diagStage {
	var sg diagStage
	t0 := time.Now()
	st, err := r.cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte{'x'})
	qp := &pnSet{m: map[uint64]bool{}}
	st.CloseWrite()
	if r.pollOn {
		go collectPNs(r.cli, st.id, 0, qp, time.Now().Add(700*time.Millisecond))
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(st, b); err != nil {
		t.Fatal(err)
	}
	sg.total = time.Since(t0)
	if !r.pollOn || r.bare { // no wrapper: the total is the only valid measurement
		return sg
	}
	time.Sleep(5 * time.Millisecond) // let the collectors see the retransmit pns before records age out
	sid := r.cli.sid
	tB, _, ok := r.cliIO.sndMin(sid, qp.snapshot())
	if !ok {
		t.Fatal("client never sent the request frame")
	}
	tC, _, ok := r.srvIO.rcvMin(sid, qp.snapshot())
	if !ok {
		t.Fatal("server never received the request frame")
	}
	var e diagEchoSrv
	for i := 0; i < 100; i++ { // the handler may still be finishing its waitFrame poll
		r.srvEchoMu.Lock()
		e, ok = r.srvEcho[st.id]
		r.srvEchoMu.Unlock()
		if ok && e.tF.IsZero() == false {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !ok || e.tF.IsZero() {
		t.Fatalf("no server echo record for sid=%d", st.id)
	}
	tG, rspN, ok := r.srvIO.sndMin(r.srv.sid, e.pns.snapshot())
	if !ok {
		t.Fatal("server never sent the response frame")
	}
	tH, _, ok := r.cliIO.rcvMin(r.srv.sid, e.pns.snapshot())
	if !ok {
		t.Fatal("client never received the response frame")
	}
	sg.cliQ = tB.Sub(t0)
	sg.wireUp = tC.Sub(tB)
	sg.srvRx = e.tD.Sub(tC)
	sg.srvHandle = e.tE.Sub(e.tD)
	sg.srvQ = e.tF.Sub(e.tE)
	sg.srvSeal = tG.Sub(e.tF)
	sg.wireDown = tH.Sub(tG)
	sg.cliRx = sg.total - tH.Sub(t0)
	for _, pn := range e.pns.snapshot() {
		if r.down == nil {
			break
		}
		if qd, ok := r.down.qdFor(r.srv.sid, pn); ok && qd > sg.qdDown {
			sg.qdDown = qd // the queueing the (possibly retransmitted) response actually met
		}
	}
	full := r.payload * 9 / 10
	sg.bulkBefore = r.srvIO.sndBetween(e.tD, tG, full)
	sg.rspN = rspN
	sg.rspFull = rspN >= full
	return sg
}

func diagMed(v []time.Duration) time.Duration {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}

func diagPct(v []time.Duration, p float64) time.Duration {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[int(float64(len(v)-1)*p)]
}

// TestDiagSchedEchoTail decomposes the echo tail during bulk at 0% loss across configs. It asserts only
// that every sample completes and the decomposition accounts for the total; the numbers are logged for
// the report.
func TestDiagSchedEchoTail(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	const samples = 150
	_ = samples
	base := Config{NoMask: true, NoShape: true}
	gap := 25 * time.Millisecond
	warm := 2500 * time.Millisecond
	samp := samples
	poll := true
	simio := false
	tokProbe := true
	bare := false
	run := func(name string, loss float64, cfg Config, mtu int, bulk, cross bool) {
		t.Run(name, func(t *testing.T) {
			r := newDiagRunPoll2(t, loss, mtu, cfg, cross, poll, simio, bare)
			if bulk && !cross {
				r.startBulk(t)
			}
			// token probe: sample the server pacer's bucket while the bulk runs
			tokLo, tokPkt, n := 0, 0, 0
			stop := make(chan struct{})
			goTok := tokProbe
			if !goTok { // none: the sampler goroutine is part of the measurement, keep it out of A/B runs
				close(stop)
			}
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					r.srv.mu.Lock()
					tok := r.srv.cc.tokens
					pend := r.srv.prio.len() + r.srv.bulk.n
					r.srv.mu.Unlock()
					if pend > 0 {
						n++
						if tok < float64(mtu) {
							tokPkt++
						}
						if tok < 200 {
							tokLo++
						}
					}
					time.Sleep(time.Millisecond)
				}
			}()
			time.Sleep(warm) // bulk warmup
			var sgs []diagStage
			var cls []killClass
			for i := 0; i < samp; i++ {
				c0, s0 := r.cli.Stats(), r.srv.Stats()
				sgs = append(sgs, r.echo(t))
				c1, s1 := r.cli.Stats(), r.srv.Stats()
				cls = append(cls, classifyKill(
					c1.Retrans > c0.Retrans,
					s1.Retrans > s0.Retrans || c1.RepairRecovered > c0.RepairRecovered))
				time.Sleep(gap)
			}
			if goTok {
				close(stop)
			}
			var cnt [4]int
			for _, c := range cls {
				cnt[c]++
			}
			var tot, cliQ, wireUp, srvRx, srvH, srvQ, srvSeal, wireD, cliRx, qdD, totC []time.Duration
			var bulkBef, rspN, rspFull, r120 []int
			for i, s := range sgs {
				if cls[i] == kcClean {
					totC = append(totC, s.total)
				}
				tot = append(tot, s.total)
				cliQ = append(cliQ, s.cliQ)
				wireUp = append(wireUp, s.wireUp)
				srvRx = append(srvRx, s.srvRx)
				srvH = append(srvH, s.srvHandle)
				srvQ = append(srvQ, s.srvQ)
				srvSeal = append(srvSeal, s.srvSeal)
				wireD = append(wireD, s.wireDown)
				cliRx = append(cliRx, s.cliRx)
				qdD = append(qdD, s.qdDown)
				bulkBef = append(bulkBef, s.bulkBefore)
				if s.rspFull {
					rspFull = append(rspFull, 1)
				}
				rspN = append(rspN, s.rspN)
				if s.total > 120*time.Millisecond {
					r120 = append(r120, 1)
				}
			}
			var allQd []time.Duration
			if r.down != nil {
				allQd = r.down.qdAll()
			}
			tokStr := "n/a"
			if n > 0 {
				tokStr = fmt.Sprintf("%.0f%%<1pkt %.0f%%<200B of %d busy samples",
					100*float64(tokPkt)/float64(n), 100*float64(tokLo)/float64(n), n)
			}
			t.Logf("DIAG %s: total p50=%v p99=%v cleanP50=%v(n=%d) | cliQ=%v wireUp=%v srvRx=%v srvHandle=%v srvQ=%v srvSeal=%v wireDown med=%v p99=%v(qd med=%v p99=%v) cliRx=%v | sum=%v | bulkPktsBeforeRsp med=%d rspFull=%d/%d rspSizeMed=%d over120ms=%d/%d | linkQdAll med=%v p99=%v | tok: %s | srtt=%v min=%v rate=%.2fMB/s retrans=%d classes clean=%d down=%d up=%d other=%d",
				name, diagMed(tot), diagPct(tot, 0.99), diagMed(totC), len(totC), diagMed(cliQ), diagMed(wireUp), diagMed(srvRx), diagMed(srvH),
				diagMed(srvQ), diagMed(srvSeal), diagMed(wireD), diagPct(wireD, 0.99), diagMed(qdD), diagPct(qdD, 0.99), diagMed(cliRx),
				diagMed(cliQ)+diagMed(wireUp)+diagMed(srvRx)+diagMed(srvH)+diagMed(srvQ)+diagMed(srvSeal)+diagMed(wireD)+diagMed(cliRx),
				diagMed(int64s(bulkBef)), len(rspFull), samp, diagMed(int64s(rspN)), len(r120), samp,
				diagMed(allQd), diagPct(allQd, 0.99), tokStr, r.srv.Stats().SRTT, r.srv.Stats().MinRTT, r.srv.Stats().RateBps/1e6, r.srv.Stats().Retrans,
				cnt[kcClean], cnt[kcDown], cnt[kcUp], cnt[kcOther])
			if diagMed(tot) <= 0 {
				t.Fatal("no samples")
			}
		})
	}
	run("base0-1400", 0, base, 1400, true, false)
	run("loss1-1400", 0.01, base, 1400, true, false)
	run("loss1-640", 0.01, base, 640, true, false)
	h := base
	h.Hedge = true
	run("hedge-loss1-1400", 0.01, h, 1400, true, false)
	mb := base
	mb.MaxBps = 100e6
	run("maxbps100-loss1-1400", 0.01, mb, 1400, true, false)
	run("nobulk-1400", 0, base, 1400, false, false)
	run("cross0-1400", 0, base, 1400, true, true)
	// replication runs: the kill harness's exact shape (default config, 50 ms gap, 3 s warmup) to
	// reconcile the clean-p50 87 ms fact with the decomposition above.
	samp, warm, gap = 120, 3*time.Second, 50*time.Millisecond
	run("repl-kill1400", 0.01, Config{}, 1400, true, false)
	// same, but with the pn collectors off: isolates whether the polling itself is what keeps the
	// pump tick punctual (and the echo fast) on this Windows host
	poll = false
	run("repl-kill1400-nopoll", 0.01, Config{}, 1400, true, false)
	poll = true
	run("repl-kill1400-nomask", 0.01, Config{NoMask: true}, 1400, true, false)
	run("repl-kill1400-gap50", 0.01, base, 1400, true, false)
	// and with the harness's own simDir links under my wrapper: pins whether the difference lives in
	// the link model or in the surrounding harness
	simio = true
	run("repl-kill1400-simio", 0.01, Config{}, 1400, true, false)
	// their links AND their bare simIO: only the run loop remains as a difference
	bare = true
	poll = false
	tokProbe = false
	run("repl-kill1400-bare", 0.01, Config{}, 1400, true, false)
	bare, poll, tokProbe = false, true, true
	// sampler off: isolates the 1 ms token-sampling goroutine as the pacing smoothing agent
	tokProbe = false
	run("repl-kill1400-notok", 0.01, Config{}, 1400, true, false)
	tokProbe = true
	simio = false
}

// TestDiagSchedKillRepl is killLatency (coded_test.go) re-implemented without its trailing sort, plus
// the aligned-vs-ghost accounting that pinned the clean-p50 ~87 ms fact on the sort's destroyed
// cls[i]<->lat[i] pairing (GHOST = what the sorted array reports, ALIGNED = the truth). killLatency
// was fixed on 2026-11-21 (classes now sort WITH the latencies); this test and the ~87 ms numbers
// below remain as the historical record of the bug.
func TestDiagSchedKillRepl(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, tc := range []struct {
		name      string
		warm, gap time.Duration
		samp      int
		seed      int64
	}{{"warm3-gap50", 3 * time.Second, 50 * time.Millisecond, 120, 96},
		{"warm2.5-gap50", 2500 * time.Millisecond, 50 * time.Millisecond, 120, 96}} {
		t.Run(tc.name, func(t *testing.T) {
			lat, cls, st := killLatencySeed(t, 0.01, 1400, tc.samp, tc.warm, tc.gap, Config{}, tc.seed)
			var cnt [4]int
			var clean []time.Duration
			var clsLat [4][]time.Duration
			var cleanIdx []int
			for i, c := range cls {
				cnt[c]++
				clsLat[c] = append(clsLat[c], lat[i])
				if c == kcClean {
					clean = append(clean, lat[i])
					cleanIdx = append(cleanIdx, i)
				}
			}
			sort.Slice(clean, func(i, j int) bool { return clean[i] < clean[j] })
			// what the sorted-array misalignment reports: killLatency sorts lat in place after cls was
			// appended, so its caller reads the values at the chronological clean positions of the
			// SORTED array. Reproduce exactly: sort a copy, then index by the chronological positions.
			sorted := append([]time.Duration(nil), lat...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			var ghost []time.Duration
			for _, i := range cleanIdx {
				ghost = append(ghost, sorted[i])
			}
			sort.Slice(ghost, func(i, j int) bool { return ghost[i] < ghost[j] })
			t.Logf("DIAG repl-%s: p50=%v p99=%v cleanP50=%v(n=%d) classes clean=%d down=%d up=%d other=%d retrans=%d rate=%.2f | ALIGNED clean p50=%v p99=%v max=%v down p50=%v p99=%v | cleanIdx first=%d last=%d | GHOST(sorted-position) p50=%v",
				tc.name, diagPct(lat, 0.5), diagPct(lat, 0.99), diagPct(clean, 0.5), len(clean),
				cnt[kcClean], cnt[kcDown], cnt[kcUp], cnt[kcOther], st.Retrans, st.RateBps/1e6,
				diagPct(clsLat[kcClean], 0.5), diagPct(clsLat[kcClean], 0.99), clsLat[kcClean][len(clsLat[kcClean])-1],
				diagPct(clsLat[kcDown], 0.5), diagPct(clsLat[kcDown], 0.99),
				cleanIdx[0], cleanIdx[len(cleanIdx)-1], diagPct(ghost, 0.5))
		})
	}
}

// TestDiagSchedKillTRun: killLatency vs byte-identical copies of it, interleaved in one process. The
// copies without the trailing sort.Slice report the aligned clean p50 (~41 ms, the no-bulk floor);
// every variant that sorts lat in place reports ~85 ms — the sort destroyed the cls[i]<->lat[i]
// pairing, and TestKillInteractiveP99 then read the slow (loss-recovery) half of the sorted array
// through chronologically-clean labels. That is the whole "clean p50 ~87 ms during bulk" fact.
// THE DISCOVERY of the harness bug (2026-11-21): after the fix killLatency sorts classes with
// latencies and the "theirs" rows moved to ~41 ms, agreeing with "exact"; only the deliberately
// buggy "exactsort" copy still reproduces the old ~87 ms mispairing.
func TestDiagSchedKillTRun(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, round := range []string{"exact0", "exactsort", "theirs0", "exact0b", "exactsortb", "theirs0b", "mine0"} {
		t.Run(round, func(t *testing.T) {
			var lat []time.Duration
			var cls []killClass
			var st Stats
			switch round {
			case "theirs0", "theirs0b":
				lat, cls, st = killLatency(t, 0.01, 640, 120, 3*time.Second, 50*time.Millisecond, Config{})
			case "exact0", "exact0b":
				lat, cls, st = killLatencyExact(t, 0.01, 640, 120, 3*time.Second, 50*time.Millisecond, Config{})
			case "exactsort", "exactsortb":
				lat, cls, st = killLatencyExactSort(t, 0.01, 640, 120, 3*time.Second, 50*time.Millisecond, Config{})
			default:
				lat, cls, st = killLatencySeed(t, 0.01, 640, 120, 3*time.Second, 50*time.Millisecond, Config{}, 96)
			}
			var cnt [4]int
			var clean []time.Duration
			for i, c := range cls {
				cnt[c]++
				if c == kcClean {
					clean = append(clean, lat[i])
				}
			}
			sort.Slice(clean, func(i, j int) bool { return clean[i] < clean[j] })
			t.Logf("DIAG killtrun-%s: p50=%v p99=%v cleanP50=%v(n=%d) classes clean=%d down=%d up=%d other=%d retrans=%d",
				round, diagPct(lat, 0.5), diagPct(lat, 0.99), diagPct(clean, 0.5), len(clean),
				cnt[kcClean], cnt[kcDown], cnt[kcUp], cnt[kcOther], st.Retrans)
		})
	}
}

func killLatencyExact(t testing.TB, loss float64, mtu int, samples int, warmup, gap time.Duration, cfg Config) (lat []time.Duration, cls []killClass, st Stats) {
	t.Helper()
	cli, srv := newPairCap(t, loss, 20*time.Millisecond, 10e6, mtu, cfg)
	bulkData := pattern(96<<20, 5)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulkData)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(warmup)
	for i := 0; i < samples; i++ {
		c0, s0 := cli.Stats(), srv.Stats()
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		c1, s1 := cli.Stats(), srv.Stats()
		cls = append(cls, classifyKill(
			c1.Retrans > c0.Retrans,
			s1.Retrans > s0.Retrans || c1.RepairRecovered > c0.RepairRecovered))
		time.Sleep(gap)
	}
	return lat, cls, srv.Stats()
}

func killLatencyExactSort(t testing.TB, loss float64, mtu int, samples int, warmup, gap time.Duration, cfg Config) (lat []time.Duration, cls []killClass, st Stats) {
	t.Helper()
	cli, srv := newPairCap(t, loss, 20*time.Millisecond, 10e6, mtu, cfg)
	bulkData := pattern(96<<20, 5)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulkData)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(warmup)
	for i := 0; i < samples; i++ {
		c0, s0 := cli.Stats(), srv.Stats()
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		c1, s1 := cli.Stats(), srv.Stats()
		cls = append(cls, classifyKill(
			c1.Retrans > c0.Retrans,
			s1.Retrans > s0.Retrans || c1.RepairRecovered > c0.RepairRecovered))
		time.Sleep(gap)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat, cls, srv.Stats()
}

// killLatencySeed is killLatency with a variable pattern seed (its own is fixed at 5).
func killLatencySeed(t testing.TB, loss float64, mtu int, samples int, warmup, gap time.Duration, cfg Config, seed int64) ([]time.Duration, []killClass, Stats) {
	t.Helper()
	cli, srv := newPairCap(t, loss, 20*time.Millisecond, 10e6, mtu, cfg)
	bulkData := pattern(int(seed)<<20, 5)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulkData)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(warmup)
	var lat []time.Duration
	var cls []killClass
	for i := 0; i < samples; i++ {
		c0, s0 := cli.Stats(), srv.Stats()
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		c1, s1 := cli.Stats(), srv.Stats()
		cls = append(cls, classifyKill(
			c1.Retrans > c0.Retrans,
			s1.Retrans > s0.Retrans || c1.RepairRecovered > c0.RepairRecovered))
		time.Sleep(gap)
	}
	return lat, cls, srv.Stats()
}

func int64s(v []int) []time.Duration {
	w := make([]time.Duration, len(v))
	for i, x := range v {
		w[i] = time.Duration(x)
	}
	return w
}
