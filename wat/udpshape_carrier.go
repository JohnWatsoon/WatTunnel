package wat

// The carrier side of the F19 phase-2 UDP shapes (udpshape.go): thin wrappers around UDPClient/UDPServer that add the
// shape header to every datagram before handing it to the udp carrier and strip/validate it on the way in. Both ends
// must run 3.3.0 with the same carrier name and PSK; these are wattun-internal shapes, not real implementations of the
// protocols they imitate.

import (
	"net"
	"sync"
)

var shapedUDPBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// ShapedUDPClient is the client PacketIO of one phase-2 UDP-shaped carrier.
type ShapedUDPClient struct {
	u  *UDPClient
	sh *udpShaper
}

// NewShapedUDPClient dials host:port (usually the shape's conventional port) as the given shaped carrier.
func NewShapedUDPClient(name, peer string, key []byte) (*ShapedUDPClient, error) {
	return NewShapedUDPClientAddr(name, peer, nil, key)
}

// NewShapedUDPClientAddr is NewShapedUDPClient with an optional local source address.
func NewShapedUDPClientAddr(name, peer string, laddr *net.UDPAddr, key []byte) (*ShapedUDPClient, error) {
	sh, ok := newUDPShaper(name, key, false)
	if !ok {
		return nil, errShapedName(name)
	}
	u, err := NewUDPClientAddr(peer, laddr)
	if err != nil {
		return nil, err
	}
	return &ShapedUDPClient{u: u, sh: sh}, nil
}

func (c *ShapedUDPClient) Send(p []byte, lane int) error {
	bp := shapedUDPBufs.Get().(*[]byte)
	defer shapedUDPBufs.Put(bp)
	*bp = c.sh.frame((*bp)[:0], p)
	return c.u.Send(*bp, lane)
}

func (c *ShapedUDPClient) SendBatch(ps [][]byte, lanes []int) error {
	bufs := make([]*[]byte, len(ps))
	framed := make([][]byte, len(ps))
	for i := range ps {
		bp := shapedUDPBufs.Get().(*[]byte)
		bufs[i] = bp
		*bp = c.sh.frame((*bp)[:0], ps[i])
		framed[i] = *bp
	}
	err := c.u.SendBatch(framed, lanes)
	for _, bp := range bufs {
		shapedUDPBufs.Put(bp)
	}
	return err
}

func (c *ShapedUDPClient) Recv() ([]byte, int, net.Addr, error) {
	for {
		p, lane, src, err := c.u.Recv()
		if err != nil {
			return nil, 0, nil, err
		}
		if q := c.sh.strip(p); q != nil {
			return q, lane, src, nil
		}
	}
}

func (c *ShapedUDPClient) CopiesOnSend() bool { return true }
func (c *ShapedUDPClient) SetPeer(net.Addr)   {}

func (c *ShapedUDPClient) Profile() Profile {
	return Profile{MTU: c.sh.shape.mtu(), InitBps: udpProfile.InitBps}
}

func (c *ShapedUDPClient) Close() error { return c.u.Close() }

// ShapedUDPServer is the server RawIO of one phase-2 UDP-shaped carrier: one listening socket for every client, the
// same udp carrier with the shape header added/stripped per datagram.
type ShapedUDPServer struct {
	u  *UDPServer
	sh *udpShaper
}

// NewShapedUDPServer listens on addr (usually the shape's conventional port) as the given shaped carrier.
func NewShapedUDPServer(name, addr string, key []byte) (*ShapedUDPServer, error) {
	sh, ok := newUDPShaper(name, key, true)
	if !ok {
		return nil, errShapedName(name)
	}
	u, err := NewUDPServer(addr)
	if err != nil {
		return nil, err
	}
	return &ShapedUDPServer{u: u, sh: sh}, nil
}

// Addr is the bound address (useful with port 0).
func (s *ShapedUDPServer) Addr() net.Addr { return s.u.Addr() }

func (s *ShapedUDPServer) Recv() ([]byte, int, net.Addr, error) {
	for {
		p, lane, src, err := s.u.Recv()
		if err != nil {
			return nil, 0, nil, err
		}
		if q := s.sh.strip(p); q != nil {
			return q, lane, src, nil
		}
	}
}

func (s *ShapedUDPServer) SendTo(p []byte, lane int, dst net.Addr) error {
	bp := shapedUDPBufs.Get().(*[]byte)
	defer shapedUDPBufs.Put(bp)
	*bp = s.sh.frame((*bp)[:0], p)
	return s.u.SendTo(*bp, lane, dst)
}

func (s *ShapedUDPServer) SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error {
	bufs := make([]*[]byte, len(ps))
	framed := make([][]byte, len(ps))
	for i := range ps {
		bp := shapedUDPBufs.Get().(*[]byte)
		bufs[i] = bp
		*bp = s.sh.frame((*bp)[:0], ps[i])
		framed[i] = *bp
	}
	err := s.u.SendBatchTo(framed, lanes, dst)
	for _, bp := range bufs {
		shapedUDPBufs.Put(bp)
	}
	return err
}

func (s *ShapedUDPServer) CopiesOnSend() bool { return true }

func (s *ShapedUDPServer) Profile() Profile {
	return Profile{MTU: s.sh.shape.mtu(), InitBps: udpProfile.InitBps}
}

func (s *ShapedUDPServer) Close() error { return s.u.Close() }

// errShapedName reports an unknown phase-2 shaped carrier name.
func errShapedName(name string) error { return &shapeNameError{name: name} }

type shapeNameError struct{ name string }

func (e *shapeNameError) Error() string {
	return "wat: unknown shaped udp carrier " + e.name + " (want fou-gre|gue-ipip|vxlan|geneve|dnscrypt-udp|ntp-direct|openvpn-dco|srtp-direct)"
}
