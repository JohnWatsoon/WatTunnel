//go:build linux

package wat

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// RawIPIO carries datagrams as GRE (IP protocol 47) or IP-in-IP (protocol 4) packets (3.2.0). Each one looks like a
// tunnelled IPv4/UDP packet: [GRE header with key, for gre] inner IPv4 header, UDP header, then the sealed datagram.
// The inner addresses, ports and the GRE key come from the PSK, so both ends build the same ones, and a BPF filter
// hands this process only packets addressed to its own end of the tunnel. A user's route test showed every UDP
// method dead while gre/ipip passed at ~1.1 Gbit/s. Needs root and Linux, like icmp; both ends must be 3.2.0+.
type RawIPIO struct {
	c        *net.IPConn
	gre      bool
	server   bool
	key      uint32    // GRE key
	in       [2]uint32 // inner IPv4 addresses: [0] the client's, [1] the server's
	sport    [2]uint16 // inner UDP source port per side
	dst      net.Addr
	rbuf     []byte
	ipid     atomic.Uint32
	rx       *mmsgRx
	tx       *mmsgTx
	hdrBytes int
}

// rawIPProfile: 1400 on the wire like udp, minus the GRE/inner headers this carrier adds (outer IP and the inner
// IPv4+UDP are 28 bytes, GRE with a key 8 more).
func rawIPProfile(gre bool) Profile {
	if gre {
		return Profile{MTU: 1400 - 36, InitBps: 8e6}
	}
	return Profile{MTU: 1400 - 28, InitBps: 8e6}
}

func (r *RawIPIO) Profile() Profile { return rawIPProfile(r.gre) }

var rawIPBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// rawIPIdent derives the GRE key, the inner addresses (100.64.0.0/10, the shared address space) and ports.
func rawIPIdent(key []byte) (gk uint32, in [2]uint32, sport [2]uint16) {
	h := sha256.Sum256(append([]byte("github.com/JohnWatsoon/WatTunnel/rawip:"), key...))
	gk = binary.BigEndian.Uint32(h[0:])
	base := uint32(100)<<24 | uint32(64)<<16
	in[0] = base | binary.BigEndian.Uint32(h[4:])&0x3fffff
	in[1] = base | binary.BigEndian.Uint32(h[8:])&0x3fffff
	if in[1] == in[0] {
		in[1] ^= 1
	}
	sport[0] = 32768 + binary.BigEndian.Uint16(h[12:])%28000
	sport[1] = 32768 + binary.BigEndian.Uint16(h[14:])%28000
	return
}

// NewRawIPIO opens the gre (gre=true) or ipip carrier. peerIP is the fixed peer of a client; a server answers
// whatever address a session authenticates from.
func NewRawIPIO(gre, server bool, peerIP, srcIP string, key []byte) (*RawIPIO, error) {
	proto := "ip4:4"
	if gre {
		proto = "ip4:47"
	}
	bindIP := net.IPv4zero
	if srcIP != "" {
		if bindIP = net.ParseIP(srcIP); bindIP == nil {
			return nil, errors.New("wat: bad source ip")
		}
	}
	c, err := net.ListenIP(proto, &net.IPAddr{IP: bindIP})
	if err != nil {
		return nil, err
	}
	r := &RawIPIO{c: c, gre: gre, server: server, rbuf: make([]byte, 2048), hdrBytes: 28}
	if gre {
		r.hdrBytes = 36
	}
	r.key, r.in, r.sport = rawIPIdent(key)
	if !server {
		ip := net.ParseIP(peerIP)
		if ip == nil {
			c.Close()
			return nil, errors.New("wat: bad peer ip")
		}
		r.dst = &net.IPAddr{IP: ip}
	}
	c.SetReadBuffer(8 << 20)
	c.SetWriteBuffer(8 << 20)
	if err := attachFilter(c, rawIPFilter(gre, r.key, r.in[r.me()])); err != nil {
		c.Close()
		return nil, err
	}
	if !icmpBatchDisabled() {
		pc := ipv4.NewPacketConn(c)
		r.rx, r.tx = newMmsgRx(pc), &mmsgTx{pc: pc}
	}
	return r, nil
}

func (r *RawIPIO) me() int {
	if r.server {
		return 1
	}
	return 0
}

func attachFilter(c *net.IPConn, ins []bpf.Instruction) error {
	prog, err := bpf.Assemble(ins)
	if err != nil {
		return err
	}
	fl := make([]unix.SockFilter, len(prog))
	for i, p := range prog {
		fl[i] = unix.SockFilter{Code: p.Op, Jt: p.Jt, Jf: p.Jf, K: p.K}
	}
	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := sc.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(fl)), Filter: &fl[0]})
	}); err != nil {
		return err
	}
	return serr
}

// rawIPFilter accepts gre packets with our key and flags, or ipip packets, whose inner destination is this end.
func rawIPFilter(gre bool, key, myInner uint32) []bpf.Instruction {
	if gre {
		return []bpf.Instruction{
			bpf.LoadMemShift{Off: 0},
			bpf.LoadIndirect{Off: 0, Size: 4}, // flags (K bit) + protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x20000800, SkipFalse: 4},
			bpf.LoadIndirect{Off: 4, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: key, SkipFalse: 2},
			bpf.LoadIndirect{Off: 8 + 16, Size: 4}, // inner IPv4 destination
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: myInner, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 0xffff},
		}
	}
	return []bpf.Instruction{
		bpf.LoadMemShift{Off: 0},
		bpf.LoadIndirect{Off: 16, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: myInner, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 0xffff},
	}
}

// frame builds [gre] + inner IPv4 + UDP + p into b.
func (r *RawIPIO) frame(b, p []byte) []byte {
	me, peer := r.me(), 1-r.me()
	if r.gre {
		b = binary.BigEndian.AppendUint32(b, 0x20000800)
		b = binary.BigEndian.AppendUint32(b, r.key)
	}
	ih := len(b)
	tot := 28 + len(p)
	b = append(b, 0x45, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(tot))
	b = binary.BigEndian.AppendUint16(b, uint16(r.ipid.Add(1)))
	b = append(b, 0x40, 0, 64, 17, 0, 0) // DF, ttl 64, udp, checksum below
	b = binary.BigEndian.AppendUint32(b, r.in[me])
	b = binary.BigEndian.AppendUint32(b, r.in[peer])
	binary.BigEndian.PutUint16(b[ih+10:], csum(b[ih:ih+20]))
	b = binary.BigEndian.AppendUint16(b, r.sport[me])
	b = binary.BigEndian.AppendUint16(b, 443)
	b = binary.BigEndian.AppendUint16(b, uint16(8+len(p)))
	b = append(b, 0, 0) // no UDP checksum (legal on IPv4)
	return append(b, p...)
}

// unframe returns the datagram inside a packet that starts after the outer IP header.
func (r *RawIPIO) unframe(b []byte) ([]byte, bool) {
	if len(b) < r.hdrBytes+1 {
		return nil, false
	}
	return b[r.hdrBytes:], true
}

func (r *RawIPIO) Send(p []byte, lane int) error {
	if r.dst == nil {
		return errors.New("wat: no peer")
	}
	return r.SendTo(p, lane, r.dst)
}

func (r *RawIPIO) SendTo(p []byte, _ int, dst net.Addr) error {
	bp := rawIPBufs.Get().(*[]byte)
	defer rawIPBufs.Put(bp)
	*bp = r.frame((*bp)[:0], p)
	_, err := r.c.WriteTo(*bp, dst)
	return err
}

func (r *RawIPIO) SendBatch(ps [][]byte, lanes []int) error {
	if r.dst == nil {
		return errors.New("wat: no peer")
	}
	return r.SendBatchTo(ps, lanes, r.dst)
}

func (r *RawIPIO) SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error {
	if r.tx == nil {
		var first error
		for k, p := range ps {
			if err := r.SendTo(p, lanes[k], dst); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	bufs := make([]*[]byte, len(ps))
	for k := range bufs {
		bufs[k] = rawIPBufs.Get().(*[]byte)
	}
	err := r.tx.write(len(ps), dst, func(k int, m *ipv4.Message) {
		*bufs[k] = r.frame((*bufs[k])[:0], ps[k])
		m.Buffers[0] = *bufs[k]
	})
	for _, bp := range bufs {
		rawIPBufs.Put(bp)
	}
	return err
}

func (r *RawIPIO) Recv() ([]byte, int, net.Addr, error) {
	for {
		if r.rx != nil { // recvmmsg hands over the outer IP header too
			b, src, err := r.rx.next()
			if err != nil {
				return nil, 0, nil, err
			}
			if len(b) < 20 || len(b) < int(b[0]&0x0f)*4 {
				continue
			}
			if p, ok := r.unframe(b[int(b[0]&0x0f)*4:]); ok {
				return p, 0, src, nil
			}
			continue
		}
		n, src, err := r.c.ReadFrom(r.rbuf) // strips the outer IP header
		if err != nil {
			return nil, 0, nil, err
		}
		if n == len(r.rbuf) {
			return nil, 0, src, errTrunc
		}
		if p, ok := r.unframe(r.rbuf[:n]); ok {
			return p, 0, src, nil
		}
	}
}

// CopiesOnSend: WriteTo hands the datagram to the kernel, which copies it.
func (r *RawIPIO) CopiesOnSend() bool { return true }
func (r *RawIPIO) SetPeer(net.Addr)   {}
func (r *RawIPIO) Close() error       { return r.c.Close() }
