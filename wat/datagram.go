package wat

import (
	"sync/atomic"
	"time"
)

// Unreliable datagrams (UDP forwarding). A datagram rides in a frDgram frame inside an ordinary encrypted packet, so
// it is paced and counted in flight like everything else, but it is never retransmitted, never tracked per frame
// and has no flow control. When the peer is too slow or the queue is full the datagram is dropped, like UDP would.
//
// Compatibility: a peer older than 1.2.0 stops parsing a packet at the unknown frame type (parse's default case) and
// carries on; the session survives. Datagrams are put LAST in a packet so the stream frames before them still land.
// Nothing is sent unless SendDatagram is called, so existing deployments see no wire change; but both ends must be
// upgraded before any udp port is configured, or the old end silently discards every datagram.
//
// Fragments (2.5.0). A datagram bigger than one packet used to be dropped (dgram_dropped_size): WireGuard's default
// 1420 MTU makes ~1450-byte UDP packets, more than the udp carrier's ~1350 and the default icmp's ~590, so a VPN
// over the tunnel opened small things (Telegram) but no web page. Now such a datagram goes out as up to dgramFragMax
// frDgramFrag pieces, each the last frame of its packet, and the receiver rebuilds it; one lost piece loses the
// datagram, like IP fragmentation. A peer older than 2.5.0 drops the pieces, exactly as it dropped the datagram
// before, so mixed versions lose nothing they had; both ends need 2.5.0 for big datagrams to pass.

const (
	dgramQueueMax   = 512     // datagrams waiting to be sent
	dgramQueueBytes = 1 << 20 // and their total size
	// Received datagrams waiting for the consumer. Each can be up to MaxDatagram bytes once reassembled, so a deep
	// queue of large VPN frames would pin hundreds of MB; this only buffers the burst between the UDP consumer's reads.
	dgramRxCap   = 64
	dgramFragMax = 64 // pieces per datagram
	fragHdrMax   = 1 + 10 + 3 + 10 + 1 + 1 + 3
	fragKeep     = 2 * time.Second // an incomplete datagram is dropped after this
	fragPending  = 256             // datagrams being rebuilt at once
)

// reasmMaxBytes caps the bytes held by datagrams being reassembled across every session: pieces arrive before any
// stream-level gate sees them. It is a var, not a const, so tests can shrink the cap.
var reasmMaxBytes int64 = 32 << 20

// reasmHeld is the bytes currently stored in incomplete fragment buffers (every session's s.mu guards its own map,
// so the process-wide total is atomic).
var reasmHeld atomic.Int64

type fragKey struct{ flow, id uint64 }

type fragBuf struct {
	port  int
	parts [][]byte
	bytes int // bytes stored in parts, subtracted from reasmHeld when the buffer completes or expires
	have  int
	at    time.Time
}

// Datagram is one received unreliable datagram. Data is owned by the receiver.
type Datagram struct {
	Flow uint64
	Port int
	Data []byte
}

// SendDatagram queues p on flow (port is the server-side target; send it on every datagram). It returns false and
// counts a drop when the queue is full, the session is closed, or p is bigger than MaxDatagram. A datagram that
// does not fit one packet goes out in pieces (see Fragments above).
func (s *Session) SendDatagram(flow uint64, port int, p []byte) bool {
	f := make([]byte, 0, len(p)+24)
	f = append(f, frDgram)
	f = appendUv(f, flow)
	f = appendUv(f, uint64(port))
	f = appendUv(f, uint64(len(p)))
	f = append(f, p...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	var frames [][]byte
	if len(f) <= s.maxPlain {
		frames = [][]byte{f}
	} else {
		piece := s.maxPlain - fragHdrMax
		cnt := (len(p) + piece - 1) / piece
		if piece <= 0 || cnt > dgramFragMax {
			s.stats.DgramDropSize++
			s.mu.Unlock()
			return false
		}
		id := s.fragID
		s.fragID++
		for i := 0; i < cnt; i++ {
			d := p[i*piece : min(len(p), (i+1)*piece)]
			g := make([]byte, 0, len(d)+fragHdrMax)
			g = append(g, frDgramFrag)
			g = appendUv(g, flow)
			g = appendUv(g, uint64(port))
			g = appendUv(g, id)
			g = appendUv(g, uint64(i))
			g = appendUv(g, uint64(cnt))
			g = appendUv(g, uint64(len(d)))
			frames = append(frames, append(g, d...))
		}
	}
	n := 0
	for _, g := range frames {
		n += len(g)
	}
	if len(s.dq)+len(frames) > dgramQueueMax || s.dqBytes+n > dgramQueueBytes {
		s.stats.DgramDropQueue++
		s.mu.Unlock()
		return false
	}
	if len(frames) > 1 {
		s.stats.DgramFragmented++
	}
	s.dq = append(s.dq, frames...)
	s.dqBytes += n
	s.mu.Unlock()
	s.kick()
	return true
}

// MaxDatagram is the largest payload SendDatagram accepts (conservative: 10-byte flow id).
func (s *Session) MaxDatagram() int { return dgramFragMax * (s.maxPlain - fragHdrMax) }

// Datagrams delivers received datagrams. It never closes; select on Done() as well.
func (s *Session) Datagrams() <-chan Datagram { return s.dgIn }

// Done is closed when the session is closed.
func (s *Session) Done() <-chan struct{} { return s.stop }

// takeDgrams appends queued frames to dst while they fit in room. With shared set (streams also want this packet)
// the first datagram may use all of room but further ones only the first half, so streams keep progressing.
func (s *Session) takeDgrams(dst []byte, room int, shared bool) []byte {
	limit := room
	for len(s.dq) > 0 {
		f := s.dq[0]
		if len(dst)+len(f) > limit {
			break
		}
		dst = append(dst, f...)
		s.dq[0] = nil
		s.dq = s.dq[1:]
		s.dqBytes -= len(f)
		s.stats.DgramSent++ // a fragmented piece counts too: a dropped /stats undercounted UDP (audit 2026-10-22)
		if f[0] == frDgramFrag {
			break // a piece is always the last frame: an older peer stops parsing at it
		}
		if shared {
			limit = room / 2
		}
	}
	if len(s.dq) == 0 {
		s.dq, s.dqBytes = nil, 0
	}
	return dst
}

// onDgram runs under s.mu: copy and hand over without blocking.
func (s *Session) onDgram(flow uint64, port int, data []byte) {
	d := Datagram{flow, port, append([]byte(nil), data...)}
	select {
	case s.dgIn <- d:
		s.stats.DgramRecv++
	default:
		s.stats.DgramDropRx++
	}
}

// onDgramFrag runs under s.mu: store one piece and hand the datagram over once every piece is in.
func (s *Session) onDgramFrag(flow uint64, port int, id uint64, idx, cnt int, data []byte, now time.Time) {
	if s.closed { // Close returned the buffered fragments; a late piece must not start a new buffer (and leak its cap)
		return
	}
	if s.reasm == nil {
		s.reasm = make(map[fragKey]*fragBuf)
	}
	k := fragKey{flow, id}
	b := s.reasm[k]
	if b == nil {
		if len(s.reasm) >= fragPending {
			for kk, bb := range s.reasm {
				if now.Sub(bb.at) > fragKeep {
					reasmHeld.Add(-int64(bb.bytes))
					delete(s.reasm, kk)
				}
			}
			if len(s.reasm) >= fragPending {
				s.stats.DgramDropRx++
				return
			}
		}
		b = &fragBuf{port: port, parts: make([][]byte, cnt), at: now}
		s.reasm[k] = b
	}
	if len(b.parts) != cnt || b.parts[idx] != nil {
		return
	}
	// A key-holding peer can keep fragment sets incomplete, so the bytes they hold are charged to their own cap
	// instead of growing with the number of peer-chosen ids.
	if reasmHeld.Load()+int64(len(data)) > reasmMaxBytes {
		s.stats.DgramDropRx++
		return
	}
	b.parts[idx] = append([]byte(nil), data...)
	b.bytes += len(data)
	reasmHeld.Add(int64(len(data)))
	b.have++
	if b.have < cnt {
		return
	}
	delete(s.reasm, k)
	reasmHeld.Add(-int64(b.bytes))
	var full []byte
	for _, x := range b.parts {
		full = append(full, x...)
	}
	s.stats.DgramReassembled++
	select {
	case s.dgIn <- Datagram{flow, b.port, full}:
		s.stats.DgramRecv++
	default:
		s.stats.DgramDropRx++
	}
}
