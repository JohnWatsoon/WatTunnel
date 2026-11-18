package wat

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The udp carrier: one UDP datagram = one session packet. No crypto, framing or retransmit here; the session
// already encrypts, authenticates and repairs loss. Pair it with Config.MaxPayload up to 1400.

const udpSockBuf = 4 << 20 // absorb bursts: a kernel-dropped datagram is loss the session must repair

// udpProfile: a UDP datagram can carry 1400 B without fragmenting on a 1500 MTU path, and an 8 MB/s start (the pacer
// still backs off on delay) avoids spending a third of a short transfer ramping up from 1.5 MB/s (bench link, 2026-10-09).
var udpProfile = Profile{MTU: 1400, InitBps: 8e6}

// UDPClient is the client PacketIO over a connected UDP socket. The lane is ignored.
type UDPClient struct {
	c       *net.UDPConn
	rbuf    []byte
	bx      *udpBatch // recvmmsg / sendmmsg (Linux), nil elsewhere
	dns     bool      // DNS-shaped datagrams (dnsshape.go)
	dnsEdns bool      // 3.3.8 opt-in: structurally complete DNS (EDNS0 OPT on the queries)
}

// SetDNS turns the DNS framing on or off; call it before the first Send. Both ends must agree.
func (u *UDPClient) SetDNS(on bool) { u.dns = on }

// SetDNSEdns turns the 3.3.8 EDNS0 framing on or off; call it before the first Send. Both ends must agree; a
// legacy server cannot parse the OPT (dnsParse skips it only on ends that know the upgrade).
func (u *UDPClient) SetDNSEdns(on bool) { u.dnsEdns = on }

// NewUDPClient dials host:port. Dialing UDP sends nothing, so it succeeds before the server is reachable.
func NewUDPClient(peer string) (*UDPClient, error) {
	return NewUDPClientAddr(peer, nil)
}

// NewUDPClientAddr dials host:port binding to an optional local source UDP address.
func NewUDPClientAddr(peer string, laddr *net.UDPAddr) (*UDPClient, error) {
	ra, err := net.ResolveUDPAddr("udp", peer)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", laddr, ra)
	if err != nil {
		return nil, err
	}
	c.SetReadBuffer(udpSockBuf)
	c.SetWriteBuffer(udpSockBuf)
	return &UDPClient{c: c, rbuf: make([]byte, 65536), bx: newUDPBatch(c)}, nil
}

func (u *UDPClient) Send(p []byte, path int) error {
	if u.dns {
		fs, done := dnsFramesOpt([][]byte{p}, false, nil, u.dnsEdns)
		defer done()
		p = fs[0]
	}
	_, err := u.c.Write(p)
	return err
}

func (u *UDPClient) Recv() ([]byte, int, net.Addr, error) {
	for {
		var p []byte
		if u.bx != nil {
			var err error
			if p, _, err = u.bx.recv(); err != nil {
				return nil, 0, nil, err
			}
		} else {
			n, err := u.c.Read(u.rbuf)
			if err != nil {
				return nil, 0, nil, err
			}
			p = u.rbuf[:n]
		}
		if u.dns {
			if p = dnsStrip(p); p == nil {
				continue
			}
		}
		return p, 0, u.c.RemoteAddr(), nil
	}
}

func (u *UDPClient) CopiesOnSend() bool { return true }

// SendBatch sends a burst in one system call where the platform has sendmmsg, else one write each.
func (u *UDPClient) SendBatch(ps [][]byte, lanes []int) error {
	if u.dns {
		fs, done := dnsFramesOpt(ps, false, nil, u.dnsEdns)
		defer done()
		ps = fs
	}
	if u.bx != nil {
		return u.bx.send(ps, nil)
	}
	var first error
	for _, p := range ps {
		if _, err := u.c.Write(p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (u *UDPClient) SetPeer(net.Addr) {}
func (u *UDPClient) Profile() Profile { return udpProfile }
func (u *UDPClient) Close() error     { return u.c.Close() }

// UDPServer is the server RawIO: every client shares one listening socket.
type UDPServer struct {
	c    *net.UDPConn
	rbuf []byte
	bx   *udpBatch
	dns  atomic.Bool // DNS-shaped datagrams (dnsshape.go); atomic because the reverse server's punch goroutine reads it

	dnsEdns bool // 3.3.8 opt-in: structurally complete DNS (EDNS0 OPT echoed, TXT answer RDATA)
	dnsQmu  sync.Mutex
	dnsQ    map[string]*dnsQueryEcho // last query per client address: the echo source for the 3.3.8 replies

	watch atomic.Pointer[net.UDPAddr] // reverse server: the punched client, whose datagrams (by IP) set rxAt
	rxAt  atomic.Int64                // unix ns of the last datagram from watch
}

// SetDNS turns the DNS framing on or off; call it before the first Recv. Both ends must agree.
func (u *UDPServer) SetDNS(on bool) { u.dns.Store(on) }

// SetDNSEdns turns the 3.3.8 EDNS0 framing on or off; call it before the first Recv. A legacy query still gets
// the legacy reply, so the server can enable this while clients upgrade.
func (u *UDPServer) SetDNSEdns(on bool) { u.dnsEdns = on }

// dnsQRemember/lookup keep the last query per client address for the 3.3.8 reply echo (bounded; a full map is
// simply dropped - the next query from any client repopulates it).
func (u *UDPServer) dnsQRemember(ua *net.UDPAddr, q *dnsQueryEcho) {
	u.dnsQmu.Lock()
	if u.dnsQ == nil {
		u.dnsQ = make(map[string]*dnsQueryEcho)
	}
	if len(u.dnsQ) >= dnsQMax {
		u.dnsQ = make(map[string]*dnsQueryEcho)
	}
	u.dnsQ[ua.String()] = q
	u.dnsQmu.Unlock()
}

func (u *UDPServer) dnsQLookup(ua *net.UDPAddr) *dnsQueryEcho {
	u.dnsQmu.Lock()
	defer u.dnsQmu.Unlock()
	return u.dnsQ[ua.String()]
}

// NewUDPServer listens on addr (":4443", "0.0.0.0:4443").
func NewUDPServer(addr string) (*UDPServer, error) {
	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	c.SetReadBuffer(udpSockBuf)
	c.SetWriteBuffer(udpSockBuf)
	return &UDPServer{c: c, rbuf: make([]byte, 65536), bx: newUDPBatch(c)}, nil
}

func (u *UDPServer) CopiesOnSend() bool { return true }

func (u *UDPServer) Profile() Profile { return udpProfile }

// Addr is the bound address (useful with port 0).
func (u *UDPServer) Addr() net.Addr { return u.c.LocalAddr() }

func (u *UDPServer) Recv() ([]byte, int, net.Addr, error) {
	for {
		var p []byte
		var src net.Addr
		if u.bx != nil {
			var err error
			if p, src, err = u.bx.recv(); err != nil {
				return nil, 0, nil, err
			}
		} else {
			n, a, err := u.c.ReadFromUDPAddrPort(u.rbuf)
			if err != nil {
				return nil, 0, nil, err
			}
			p, src = u.rbuf[:n], net.UDPAddrFromAddrPort(a)
		}
		if u.dns.Load() {
			var q *dnsQueryEcho
			if p, q = dnsParse(p); p == nil {
				continue
			}
			if u.dnsEdns && q != nil {
				if ua, ok := src.(*net.UDPAddr); ok {
					u.dnsQRemember(ua, q) // echo source for the 3.3.8 reply
				}
			}
		}
		if w := u.watch.Load(); w != nil {
			if ua, ok := src.(*net.UDPAddr); ok && ua.IP.Equal(w.IP) { // IP only: a NAT may move the port
				u.rxAt.Store(time.Now().UnixNano())
			}
		}
		return p, 0, src, nil
	}
}

func (u *UDPServer) SendTo(p []byte, lane int, dst net.Addr) error {
	ua, ok := dst.(*net.UDPAddr)
	if !ok {
		return net.ErrClosed
	}
	if u.dns.Load() {
		var q *dnsQueryEcho
		if u.dnsEdns {
			q = u.dnsQLookup(ua) // nil (or a legacy query): the legacy reply, so mixed versions interoperate
		}
		fs, done := dnsFramesOpt([][]byte{p}, true, q, u.dnsEdns)
		defer done()
		p = fs[0]
	}
	_, err := u.c.WriteToUDP(p, ua)
	return err
}

// SendBatchTo sends a burst to one client in one system call where the platform has sendmmsg.
func (u *UDPServer) SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error {
	ua, ok := dst.(*net.UDPAddr)
	if !ok {
		return net.ErrClosed
	}
	if u.dns.Load() {
		var q *dnsQueryEcho
		if u.dnsEdns {
			q = u.dnsQLookup(ua)
		}
		fs, done := dnsFramesOpt(ps, true, q, u.dnsEdns)
		defer done()
		ps = fs
	}
	if u.bx != nil {
		return u.bx.send(ps, ua)
	}
	var first error
	for _, p := range ps {
		if _, err := u.c.WriteToUDP(p, ua); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (u *UDPServer) Close() error { return u.c.Close() }
