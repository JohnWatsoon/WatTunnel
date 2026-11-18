//go:build linux

package wat

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// ICMPIO carries datagrams as ICMP echo payloads. The client sends echo requests and the server sends echo
// replies (the Iran filter does not tie replies to requests: measured with icmp_tunnel/wattun/cmd/wprobe).
// A classic-BPF filter on the raw socket hands the process only echo packets of its own type whose identifier
// is inside this tunnel's range, so unrelated ping traffic never reaches user space.
type ICMPIO struct {
	c         *net.IPConn
	server    bool
	sendsReq  bool  // this end sends requests: the client, or the server in reverse mode
	reqType   uint8 // ICMP type the requesting end sends
	repType   uint8 // ICMP type the answering end sends
	identBase uint16
	dst       net.Addr // client: fixed peer
	seq       [256]uint32
	rbuf      []byte
	rx        *mmsgRx // recvmmsg (nil: plain ReadFrom)
	tx        *mmsgTx
}

const identLanes = 256

// icmpBufs: packet assembly buffers for SendTo (the kernel copies the datagram, so a buffer is free again as soon as WriteTo returns).
var icmpBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// IdentBase derives the first ICMP identifier of the tunnel from the key; both ends compute the same one.
func IdentBase(key []byte) uint16 {
	h := sha256.Sum256(append([]byte("github.com/JohnWatsoon/WatTunnel/ident:"), key...))
	return 0x4000 + binary.BigEndian.Uint16(h[:2])%0xA000
}

// NewICMPIO is the echo carrier (what every deployment before v1.8.0 runs).
func NewICMPIO(server bool, peerIP string, key []byte) (*ICMPIO, error) {
	return NewICMPIOType(server, peerIP, key, "echo")
}

// NewICMPIOType carries datagrams in the given ICMP request/reply pair: echo, timestamp, info or mask. Both ends
// must use the same kind. The BPF filter matches only that pair, so other ICMP software never sees our packets.
func NewICMPIOType(server bool, peerIP string, key []byte, kind string) (*ICMPIO, error) {
	return NewICMPIOReverse(server, false, peerIP, key, kind)
}

// NewICMPIOReverse is NewICMPIOType with the ICMP direction optionally swapped (reverse, wattun >= 2.0.0 on both
// ends): the server sends the requests and the client answers with replies. The session roles do not change. It is
// for routes where Iran's own requests are dropped but requests from Kharej reach Iran and Iran's replies get back.
// In reverse mode peerIP on the server is the client's IP, used only for Knock; the server still answers whatever
// address a session authenticates from.
func NewICMPIOReverse(server, reverse bool, peerIP string, key []byte, kind string) (*ICMPIO, error) {
	return NewICMPIOSource(server, reverse, peerIP, "", key, kind)
}

// NewICMPIOSource is NewICMPIOReverse binding the raw ICMP socket to an optional local source IP address for multi-homing.
func NewICMPIOSource(server, reverse bool, peerIP, srcIP string, key []byte, kind string) (*ICMPIO, error) {
	req, rep, ok := ICMPTypes(kind)
	if !ok {
		return nil, errors.New("wat: -icmp-type must be echo, timestamp, info or mask")
	}
	bindIP := net.IPv4zero
	if srcIP != "" {
		ip := net.ParseIP(srcIP)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("wat: icmp requires an IPv4 source ip")
		}
		bindIP = ip.To4()
	}
	if !server || reverse && peerIP != "" {
		ip := net.ParseIP(peerIP)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("wat: icmp requires an IPv4 peer ip")
		}
	}
	c, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: bindIP})
	if err != nil {
		return nil, err
	}
	io := &ICMPIO{c: c, server: server, sendsReq: server == reverse, reqType: req, repType: rep, identBase: IdentBase(key), rbuf: make([]byte, 2048)}
	if !server || reverse && peerIP != "" {
		io.dst = &net.IPAddr{IP: net.ParseIP(peerIP).To4()}
	}
	c.SetReadBuffer(8 << 20)
	c.SetWriteBuffer(8 << 20)
	want := io.repType // what we receive: the requesting end gets replies, the answering end gets requests
	if !io.sendsReq {
		want = io.reqType
	}
	prog, err := bpf.Assemble(icmpFilter(want, io.identBase))
	if err != nil {
		c.Close()
		return nil, err
	}
	fl := make([]unix.SockFilter, len(prog))
	for i, r := range prog {
		fl[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	sc, err := c.SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	var serr error
	if err := sc.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(fl)), Filter: &fl[0]})
	}); err != nil {
		c.Close()
		return nil, err
	}
	if serr != nil {
		c.Close()
		return nil, serr
	}
	if !icmpBatchDisabled() {
		pc := ipv4.NewPacketConn(c)
		io.rx, io.tx = newMmsgRx(pc), &mmsgTx{pc: pc}
	}
	return io, nil
}

// icmpFilter is the classic-BPF program: ICMP type == want and identifier in [identBase, identBase+identLanes).
func icmpFilter(want uint8, identBase uint16) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadMemShift{Off: 0},
		bpf.LoadIndirect{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(want), SkipTrue: 0, SkipFalse: 4},
		bpf.LoadIndirect{Off: 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpLessThan, Val: uint32(identBase), SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: uint32(identBase) + identLanes, SkipTrue: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	}
}

// csum lives in desync.go (portable, shared with the fake-SNI injector).

// Send is the client's path to its fixed peer.
func (i *ICMPIO) Send(p []byte, lane int) error {
	if i.dst == nil {
		return errors.New("wat: no peer")
	}
	return i.SendTo(p, lane, i.dst)
}

// SendTo writes one datagram to dst (the server uses it for every client).
func (i *ICMPIO) SendTo(p []byte, lane int, dst net.Addr) error {
	lane &= identLanes - 1
	bp := icmpBufs.Get().(*[]byte)
	defer icmpBufs.Put(bp)
	b := append((*bp)[:0], 0, 0, 0, 0, 0, 0, 0, 0)
	b = append(b, p...)
	*bp = b
	b[0] = i.sendType()
	binary.BigEndian.PutUint16(b[4:], i.identBase+uint16(lane))
	binary.BigEndian.PutUint16(b[6:], uint16(atomic.AddUint32(&i.seq[lane], 1)))
	binary.BigEndian.PutUint16(b[2:], csum(b))
	_, err := i.c.WriteTo(b, dst)
	return err
}

// sendType: the requesting end (the client, or the server in reverse mode) sends requests, the other end replies.
func (i *ICMPIO) sendType() uint8 {
	if i.sendsReq {
		return i.reqType
	}
	return i.repType
}

// Knock sends one empty request on each of the first lanes identifiers to the fixed peer, then again every
// interval until the socket closes. Used by a reverse-mode server: a stateful firewall on either end (or on the
// route) then sees the client's replies as answers to requests it has seen. Conntrack keys ICMP on the identifier,
// not the sequence, so one knock per lane is enough. An empty payload is dropped by Recv on the other end, and
// the kernel's own echo of it comes back empty and is dropped here too.
func (i *ICMPIO) Knock(lanes int, interval time.Duration) {
	if i.dst == nil || !i.sendsReq {
		return
	}
	if lanes < 1 || lanes > identLanes {
		lanes = identLanes
	}
	go func() {
		for {
			for l := 0; l < lanes; l++ {
				if err := i.SendTo(nil, l, i.dst); errors.Is(err, net.ErrClosed) {
					return
				}
			}
			time.Sleep(interval)
		}
	}()
}

func (i *ICMPIO) Recv() ([]byte, int, net.Addr, error) {
	if i.rx != nil {
		return i.recvBatch()
	}
	for {
		n, src, err := i.c.ReadFrom(i.rbuf)
		if err != nil {
			return nil, 0, nil, err
		}
		if n == len(i.rbuf) { // datagram cut to the buffer: an AEAD check would fail downstream with no clue
			return nil, 0, src, errTrunc
		}
		if n < 9 {
			continue
		}
		id := binary.BigEndian.Uint16(i.rbuf[4:])
		if id < i.identBase || id >= i.identBase+identLanes {
			continue
		}
		return i.rbuf[8:n], int(id - i.identBase), src, nil
	}
}

// CopiesOnSend: WriteTo hands the datagram to the kernel, which copies it.
func (i *ICMPIO) CopiesOnSend() bool { return true }

func (i *ICMPIO) SetPeer(net.Addr) {}

func (i *ICMPIO) Close() error { return i.c.Close() }

// recvBatch is Recv over recvmmsg. A raw socket delivers the IP header too (IPConn.ReadFrom strips it for the
// single-datagram path), so skip it here.
func (i *ICMPIO) recvBatch() ([]byte, int, net.Addr, error) {
	for {
		b, src, err := i.rx.next()
		if err != nil {
			return nil, 0, nil, err
		}
		if len(b) < 20 {
			continue
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+9 {
			continue
		}
		b = b[ihl:]
		id := binary.BigEndian.Uint16(b[4:])
		if id < i.identBase || id >= i.identBase+identLanes {
			continue
		}
		return b[8:], int(id - i.identBase), src, nil
	}
}

// SendBatch is the client's burst path to its fixed peer.
func (i *ICMPIO) SendBatch(ps [][]byte, lanes []int) error {
	if i.dst == nil {
		return errors.New("wat: no peer")
	}
	return i.SendBatchTo(ps, lanes, i.dst)
}

// SendBatchTo writes a burst of echo packets to dst with one sendmmsg.
func (i *ICMPIO) SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error {
	if i.tx == nil {
		var first error
		for k, p := range ps {
			if err := i.SendTo(p, lanes[k], dst); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	bufs := make([]*[]byte, len(ps)) // pooled assembly buffers, returned once the kernel has copied them
	for k := range bufs {
		bufs[k] = icmpBufs.Get().(*[]byte)
	}
	err := i.tx.write(len(ps), dst, func(k int, m *ipv4.Message) {
		lane := lanes[k] & (identLanes - 1)
		b := append((*bufs[k])[:0], 0, 0, 0, 0, 0, 0, 0, 0)
		b = append(b, ps[k]...)
		*bufs[k] = b
		b[0] = i.sendType()
		binary.BigEndian.PutUint16(b[4:], i.identBase+uint16(lane))
		binary.BigEndian.PutUint16(b[6:], uint16(atomic.AddUint32(&i.seq[lane], 1)))
		binary.BigEndian.PutUint16(b[2:], csum(b))
		m.Buffers[0] = b
	})
	for _, bp := range bufs {
		icmpBufs.Put(bp)
	}
	return err
}
