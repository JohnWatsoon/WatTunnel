//go:build linux

package wat

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// recvmmsg / sendmmsg through x/net/ipv4. Off unless WAT_BATCH=1 (plain ReadFrom / WriteTo, the
// behaviour before v1.6.0).

const (
	rxBatch = 32   // datagrams per recvmmsg
	rxBufSz = 2048 // fits the largest datagram of the raw-socket and UDP carriers (1400 + headers)
)

// WAT_BATCH: unset = on for the ICMP carrier, off for the others; "0" = off everywhere; anything else = on.
// ICMP default on since v1.8.0: on the real Iran<->Kharej path (2026-10-10) it raised one flow 15 -> 25 MB/s and cut
// CPU/MB from 0.043 to 0.026 (it had looked neutral on the veth bench, which has no per-packet path cost).
func batchDisabled() bool { return os.Getenv("WAT_BATCH") == "" || os.Getenv("WAT_BATCH") == "0" }

func icmpBatchDisabled() bool { return os.Getenv("WAT_BATCH") == "0" }

type batchPacketConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// mmsgRx reads up to rxBatch datagrams per system call and hands them out one by one.
type mmsgRx struct {
	pc   batchPacketConn
	msgs []ipv4.Message
	n, i int

	gro  bool     // UDP_GRO on: a message may hold several datagrams of seg bytes each (the last may be shorter)
	rest []byte   // the coalesced datagrams of the current message not handed out yet
	seg  int      // their size
	from net.Addr // and their source
}

func newMmsgRx(pc batchPacketConn) *mmsgRx {
	r := &mmsgRx{pc: pc, msgs: make([]ipv4.Message, rxBatch)}
	for i := range r.msgs {
		r.msgs[i].Buffers = [][]byte{make([]byte, rxBufSz)}
	}
	return r
}

// next returns the next datagram; it is valid until the next call that refills the batch.
// A datagram larger than rxBufSz arrives truncated (MSG_TRUNC in m.Flags): drop it here rather
// than hand out a cut packet that fails AEAD downstream with no explanation (audit 2026-10-22).
func (r *mmsgRx) next() ([]byte, net.Addr, error) {
	if len(r.rest) > 0 { // GRO: the next datagram of a coalesced message
		k := min(r.seg, len(r.rest))
		p := r.rest[:k]
		r.rest = r.rest[k:]
		return p, r.from, nil
	}
	for r.i >= r.n {
		n, err := r.pc.ReadBatch(r.msgs, 0)
		if err != nil {
			return nil, nil, err
		}
		r.n, r.i = n, 0
	}
	m := &r.msgs[r.i]
	r.i++
	if m.Flags&unix.MSG_TRUNC != 0 {
		return nil, m.Addr, errTrunc
	}
	p := m.Buffers[0][:m.N]
	if r.gro {
		if seg := groSegment(m.OOB[:m.NN]); seg > 0 && seg < len(p) {
			r.rest, r.seg, r.from = p[seg:], seg, m.Addr
			p = p[:seg]
		}
	}
	return p, m.Addr, nil
}

// groSegment reads the UDP_GRO control message (the size of each coalesced datagram); 0 = none.
func groSegment(oob []byte) int {
	cms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, c := range cms {
		if c.Header.Level == unix.SOL_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 4 {
			return int(binary.NativeEndian.Uint32(c.Data))
		}
	}
	return 0
}

// errTrunc: the receive buffer was smaller than the datagram. Callers skip it like any junk packet;
// the AEAD would reject the cut bytes anyway, but a named error keeps a -mtu misconfiguration diagnosable.
var errTrunc = errors.New("wat: datagram truncated (receive buffer too small; lower -mtu)")

// mmsgTx sends a burst with sendmmsg. Shared by every session of a server, hence the lock.
type mmsgTx struct {
	pc   batchPacketConn
	mu   sync.Mutex
	msgs []ipv4.Message
}

// write sends the messages built by fill (called under the lock with the reusable message slice).
func (t *mmsgTx) write(n int, dst net.Addr, set func(i int, m *ipv4.Message)) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.msgs) < n {
		t.msgs = append(t.msgs, ipv4.Message{Buffers: make([][]byte, 1)})
	}
	ms := t.msgs[:n]
	for i := range ms {
		ms[i].Addr = dst
		set(i, &ms[i])
	}
	var err error
	for len(ms) > 0 {
		var k int
		if k, err = t.pc.WriteBatch(ms, 0); err != nil || k <= 0 {
			break
		}
		ms = ms[k:]
	}
	for i := 0; i < n; i++ {
		t.msgs[i].Buffers[0] = nil
	}
	return err
}

// ---- UDP

type udpBatch struct {
	rx *mmsgRx
	tx mmsgTx

	c    *net.UDPConn
	gso  atomic.Bool // UDP_SEGMENT sends (WAT_GSO=1) until the kernel refuses one
	gbuf []byte      // GSO assembly buffer, under tx.mu
	oob  []byte      // the UDP_SEGMENT control message, under tx.mu
}

// WAT_GSO=1 (3.0.0, opt-in, needs batching on): UDP generic segmentation and receive offload. A run of equal-size
// datagrams to one peer leaves in one sendmsg with UDP_SEGMENT, and the kernel splits it (in the NIC when it can);
// with UDP_GRO the kernel hands several received datagrams over in one buffer. Fewer system calls than
// sendmmsg/recvmmsg for the same burst. Datagrams of mixed sizes (the DNS shape's random names) fall back to sendmmsg
// run by run. A kernel or NIC that refuses UDP_SEGMENT turns it off for the socket, logged once.
var gsoWanted = os.Getenv("WAT_GSO") == "1"

const (
	gsoMaxSegs  = 64    // the kernel's UDP_MAX_SEGMENTS
	gsoMaxBytes = 65000 // one UDP datagram (65507) with room for the headers
	groBufSz    = 65536
)

func newUDPBatch(c *net.UDPConn) *udpBatch {
	if batchDisabled() {
		return nil
	}
	var pc batchPacketConn = ipv4.NewPacketConn(c)
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok && la.IP != nil && la.IP.To4() == nil {
		pc = ipv6.NewPacketConn(c)
	}
	b := &udpBatch{rx: newMmsgRx(pc), tx: mmsgTx{pc: pc}, c: c}
	if gsoWanted {
		b.gso.Store(true)
		if setUDPOpt(c, unix.UDP_GRO, 1) == nil {
			b.rx.gro = true
			for i := range b.rx.msgs {
				b.rx.msgs[i].Buffers = [][]byte{make([]byte, groBufSz)}
				b.rx.msgs[i].OOB = make([]byte, unix.CmsgSpace(4))
			}
		}
	}
	return b
}

func setUDPOpt(c *net.UDPConn, opt, v int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, opt, v) }); err != nil {
		return err
	}
	return serr
}

func (b *udpBatch) recv() ([]byte, net.Addr, error) { return b.rx.next() }

// send writes the datagrams; dst is nil on a connected socket.
func (b *udpBatch) send(ps [][]byte, dst net.Addr) error {
	if b.gso.Load() && len(ps) > 1 {
		return b.sendGSO(ps, dst)
	}
	return b.sendMMsg(ps, dst)
}

func (b *udpBatch) sendMMsg(ps [][]byte, dst net.Addr) error {
	if len(ps) == 0 {
		return nil
	}
	return b.tx.write(len(ps), dst, func(i int, m *ipv4.Message) { m.Buffers[0] = ps[i] })
}

// sendGSO sends every run of 2+ equal-size datagrams (plus one shorter tail) as one UDP_SEGMENT write and the
// datagrams in between with sendmmsg, in order.
func (b *udpBatch) sendGSO(ps [][]byte, dst net.Addr) error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	single := 0 // ps[single:i] are waiting for sendmmsg
	for i := 0; i < len(ps); {
		seg, total, j := len(ps[i]), len(ps[i]), i+1
		for j < len(ps) && j-i < gsoMaxSegs && len(ps[j]) == seg && total+seg <= gsoMaxBytes {
			total += seg
			j++
		}
		if j < len(ps) && j-i < gsoMaxSegs && len(ps[j]) < seg && total+len(ps[j]) <= gsoMaxBytes {
			total += len(ps[j])
			j++
		}
		if j-i < 2 || !b.gso.Load() {
			i = j
			continue
		}
		keep(b.sendMMsg(ps[single:i], dst))
		if err := b.writeGSO(ps[i:j], seg, total, dst); err != nil {
			if !b.gso.Load() { // refused: this run goes the old way
				keep(b.sendMMsg(ps[i:j], dst))
			} else {
				keep(err)
			}
		}
		i, single = j, j
	}
	keep(b.sendMMsg(ps[single:], dst))
	return first
}

func (b *udpBatch) writeGSO(ps [][]byte, seg, total int, dst net.Addr) error {
	b.tx.mu.Lock()
	defer b.tx.mu.Unlock()
	if cap(b.gbuf) < total {
		b.gbuf = make([]byte, 0, gsoMaxBytes)
	}
	buf := b.gbuf[:0]
	for _, p := range ps {
		buf = append(buf, p...)
	}
	if b.oob == nil {
		b.oob = make([]byte, unix.CmsgSpace(2))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b.oob[0]))
		h.Level, h.Type = unix.SOL_UDP, unix.UDP_SEGMENT
		h.SetLen(unix.CmsgLen(2))
	}
	binary.NativeEndian.PutUint16(b.oob[unix.CmsgLen(0):], uint16(seg))
	ua, _ := dst.(*net.UDPAddr)
	_, _, err := b.c.WriteMsgUDP(buf, b.oob, ua)
	if err != nil && (errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP)) {
		if b.gso.Swap(false) {
			note("wat: udp GSO refused by the kernel or NIC (%v); this socket falls back to sendmmsg", err)
		}
	}
	return err
}
