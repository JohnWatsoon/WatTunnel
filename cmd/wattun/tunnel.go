package main

// The client's set of sessions (-sessions N, client only, 2.3.0; server unchanged).
//
// One wat.Session is one encrypted connection with one pacer, one receive goroutine and one send goroutine, and every
// stream inside it is limited by its own flow-control window. -sessions N runs N fully independent sessions to the
// same server (each with its own carrier pool, pacer and random session id); the server needs no change, since it
// already demultiplexes by session id. New TCP streams go to the least loaded live session, UDP flows stick to one
// session chosen by a hash of the flow id, and the built-in speed test runs one stream on every session at once.
// With N = 1 (the default) every path below is the single session of earlier versions.

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

const maxSessions = 16 // the server admits 32 sessions per process; a handover runs two clients at once

type tunnel struct {
	list []*wat.Session
	rr   atomic.Uint32
	done chan struct{} // closed once every session is closed
}

func newTunnel(list []*wat.Session) *tunnel {
	t := &tunnel{list: list, done: make(chan struct{})}
	go func() {
		for _, s := range list {
			<-s.Done()
		}
		close(t.done)
	}()
	return t
}

// Done is closed when all sessions are closed.
func (t *tunnel) Done() <-chan struct{} { return t.done }

func (t *tunnel) Close() {
	for _, s := range t.list {
		s.Close()
	}
}

// alive: the tunnel works while any of its sessions does.
func (t *tunnel) alive() bool {
	for _, s := range t.list {
		if s.Alive() {
			return true
		}
	}
	return false
}

// up counts the live sessions.
func (t *tunnel) up() int {
	n := 0
	for _, s := range t.list {
		if s.Alive() {
			n++
		}
	}
	return n
}

// pick chooses the session for a new stream: a live one if any is live, among those the one with the fewest open
// streams, then the fewest bytes in flight; exact ties rotate (round robin).
func (t *tunnel) pick() *wat.Session {
	if len(t.list) == 1 {
		return t.list[0]
	}
	start := int(t.rr.Add(1))
	var best *wat.Session
	bestAlive, bs, bi := false, 0, 0
	for i := range t.list {
		s := t.list[(start+i)%len(t.list)]
		alive := s.Alive()
		st, in := s.Load()
		if best == nil || alive && !bestAlive || alive == bestAlive && (st < bs || st == bs && in < bi) {
			best, bestAlive, bs, bi = s, alive, st, in
		}
	}
	return best
}

// forFlow picks the session of a new UDP flow: fixed by a hash of the flow id, skipping sessions that are down. The
// flow remembers the result (cflow.session) and stays there while the flow lives, so a recovering session does not
// pull it back and reorder its datagrams.
func (t *tunnel) forFlow(id uint64) *wat.Session {
	n := len(t.list)
	if n == 1 {
		return t.list[0]
	}
	h := int(((id * 0x9E3779B97F4A7C15) >> 33) % uint64(n)) // flow ids are odd: mix before taking the modulus
	for i := 0; i < n; i++ {
		if s := t.list[(h+i)%n]; s.Alive() {
			return s
		}
	}
	return t.list[h]
}

// lastRecv is the newest authenticated packet over all sessions.
func (t *tunnel) lastRecv() time.Time {
	var last time.Time
	for _, s := range t.list {
		if r := s.LastRecv(); r.After(last) {
			last = r
		}
	}
	return last
}

// stats sums the sessions: counters, rates, streams and in-flight bytes add up; srtt is the median of the live
// sessions' smoothed RTTs (all sessions when none is live), min_rtt the smallest, loss the highest.
func (t *tunnel) stats() wat.Stats {
	if len(t.list) == 1 {
		return t.list[0].Stats()
	}
	var tot wat.Stats
	tot.FecState = "off" // F11: "on" while any session's loss gate is open
	var srtts, all []time.Duration
	for _, s := range t.list {
		st := s.Stats()
		tot.PktsOut += st.PktsOut
		tot.PktsIn += st.PktsIn
		tot.BytesOut += st.BytesOut
		tot.BytesIn += st.BytesIn
		tot.Retrans += st.Retrans
		tot.Dropped += st.Dropped
		tot.RateBps += st.RateBps
		tot.Streams += st.Streams
		tot.Inflight += st.Inflight
		tot.DgramSent += st.DgramSent
		tot.DgramRecv += st.DgramRecv
		tot.DgramDropQueue += st.DgramDropQueue
		tot.DgramDropSize += st.DgramDropSize
		tot.DgramDropRx += st.DgramDropRx
		tot.FecSent += st.FecSent
		tot.FecRecovered += st.FecRecovered
		if st.FecState == "on" {
			tot.FecState = "on"
		}
		tot.PadBytes += st.PadBytes
		tot.NoiseSent += st.NoiseSent
		tot.NoiseBytes += st.NoiseBytes
		tot.CeilingBps += st.CeilingBps
		wat.AddPacer(&tot, st)
		tot.LossPct = max(tot.LossPct, st.LossPct)
		if st.MinRTT > 0 && (tot.MinRTT == 0 || st.MinRTT < tot.MinRTT) {
			tot.MinRTT = st.MinRTT
		}
		if st.SRTT > 0 {
			all = append(all, st.SRTT)
			if s.Alive() {
				srtts = append(srtts, st.SRTT)
			}
		}
	}
	if len(srtts) == 0 {
		srtts = all
	}
	if len(srtts) > 0 {
		sort.Slice(srtts, func(i, j int) bool { return srtts[i] < srtts[j] })
		tot.SRTT = srtts[len(srtts)/2]
	}
	return tot
}

// sessionJSON is one row of the /stats "session_list" (clients with -sessions > 1).
type sessionJSON struct {
	Alive   bool    `json:"alive"`
	SRTTms  float64 `json:"srtt_ms"`
	RateBps float64 `json:"rate_bps"`
	Streams int     `json:"streams"`
}

func (t *tunnel) sessionList() []sessionJSON {
	out := make([]sessionJSON, 0, len(t.list))
	for _, s := range t.list {
		st := s.Stats()
		out = append(out, sessionJSON{s.Alive(), float64(st.SRTT) / 1e6, st.RateBps, st.Streams})
	}
	return out
}

// live lists the sessions that are up (for the speed test).
func (t *tunnel) live() []*wat.Session {
	var out []*wat.Session
	for _, s := range t.list {
		if s.Alive() {
			out = append(out, s)
		}
	}
	return out
}

// eachDatagram runs f for every datagram received on any session until all sessions are closed.
func (t *tunnel) eachDatagram(f func(wat.Datagram)) {
	var wg sync.WaitGroup
	for _, s := range t.list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case d := <-s.Datagrams():
					f(d)
				case <-s.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
}
