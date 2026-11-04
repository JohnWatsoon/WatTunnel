//go:build linux

package wat

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
)

// ShapedRawIO is the RawIO of an F19 raw-tier shaped carrier (3.3.0): sit, 6to4, xfrm-ipsec, etherip or l2tpv3. One
// raw socket per IP protocol (root, CAP_NET_RAW, Linux only), each datagram gets the shape's fixed keyed outer header
// (rawshape.go) and the sealed session datagram after it. Both ends must run 3.3.0 and use the same carrier name; the
// shapes are wattun-internal, not real 6in4/IPsec/EtherIP/L2TPv3.
type ShapedRawIO struct {
	c      *net.IPConn
	shape  rawShape
	server bool
	k      rawShapeKey
	dst    net.Addr
	rbuf   []byte
	seq    atomic.Uint32 // ESP sequence counter (the other shapes ignore it)
	rx     *mmsgRx
	tx     *mmsgTx
}

var shapedRawBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// NewShapedRaw opens one raw-tier shaped carrier. peerIP is the fixed peer of a client (a bare IP, like icmp/gre); a
// server answers the source address a session authenticated from. srcIP optionally pins the local address.
func NewShapedRaw(name string, server bool, peerIP, srcIP string, key []byte) (*ShapedRawIO, error) {
	s, ok := rawShapeByName(name)
	if !ok {
		return nil, errors.New("wat: unknown raw shape " + name)
	}
	bindIP := net.IPv4zero
	if srcIP != "" {
		if bindIP = net.ParseIP(srcIP); bindIP == nil {
			return nil, errors.New("wat: bad source ip")
		}
	}
	proto := rawShapeSpecs[s].proto
	c, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: bindIP})
	if err != nil {
		return nil, err
	}
	r := &ShapedRawIO{c: c, shape: s, server: server, rbuf: make([]byte, 2048), k: newRawShapeKey(s, key)}
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
	// M15: drop every packet of this protocol that is not addressed to this receiver in the kernel, before the Go loop.
	// H9: the strip repeats the direction check, so filter and userspace agree.
	if err := attachFilter(c, rawShapeFilter(s, r.k, server)); err != nil {
		c.Close()
		return nil, err
	}
	if !icmpBatchDisabled() {
		pc := ipv4.NewPacketConn(c)
		r.rx, r.tx = newMmsgRx(pc), &mmsgTx{pc: pc}
	}
	return r, nil
}

// Profile: like the other raw-IP carriers, 1400 B on the wire minus this shape's header (M1/M15: NewSession also
// clamps an explicit -mtu to this ceiling).
func (r *ShapedRawIO) Profile() Profile {
	return Profile{MTU: rawShapeMTU(r.shape), InitBps: 8e6}
}

func (r *ShapedRawIO) frame(b, p []byte) []byte {
	return rawShapeFrame(r.shape, r.k, r.server, r.seq.Add(1), b, p)
}

func (r *ShapedRawIO) Send(p []byte, lane int) error {
	if r.dst == nil {
		return errors.New("wat: no peer")
	}
	return r.SendTo(p, lane, r.dst)
}

func (r *ShapedRawIO) SendTo(p []byte, _ int, dst net.Addr) error {
	bp := shapedRawBufs.Get().(*[]byte)
	defer shapedRawBufs.Put(bp)
	*bp = r.frame((*bp)[:0], p)
	_, err := r.c.WriteTo(*bp, dst)
	return err
}

func (r *ShapedRawIO) SendBatch(ps [][]byte, lanes []int) error {
	if r.dst == nil {
		return errors.New("wat: no peer")
	}
	return r.SendBatchTo(ps, lanes, r.dst)
}

func (r *ShapedRawIO) SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error {
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
		bufs[k] = shapedRawBufs.Get().(*[]byte)
	}
	err := r.tx.write(len(ps), dst, func(k int, m *ipv4.Message) {
		*bufs[k] = r.frame((*bufs[k])[:0], ps[k])
		m.Buffers[0] = *bufs[k]
	})
	for _, bp := range bufs {
		shapedRawBufs.Put(bp)
	}
	return err
}

func (r *ShapedRawIO) Recv() ([]byte, int, net.Addr, error) {
	for {
		if r.rx != nil { // recvmmsg hands over the outer IP header too
			b, src, err := r.rx.next()
			if err != nil {
				return nil, 0, nil, err
			}
			if len(b) < 20 || len(b) < int(b[0]&0x0f)*4 {
				continue
			}
			if p := rawShapeStrip(r.shape, r.k, r.server, b[int(b[0]&0x0f)*4:]); p != nil {
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
		if p := rawShapeStrip(r.shape, r.k, r.server, r.rbuf[:n]); p != nil {
			return p, 0, src, nil
		}
	}
}

func (r *ShapedRawIO) CopiesOnSend() bool { return true }
func (r *ShapedRawIO) SetPeer(net.Addr)   {}
func (r *ShapedRawIO) Close() error       { return r.c.Close() }
