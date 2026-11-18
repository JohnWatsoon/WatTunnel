package wat

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Reverse udp (3.0.0): the Iran client binds a UDP port and never sends first; the Kharej server sends it small
// "punch" datagrams from its own socket, and the client answers to whatever address the latest valid punch came from.
// A flow from Iran's point of view is then started by the foreign host, like an inbound TCP connection (the model of
// Backhaul-style reverse tunnels), so a filter that restricts what an Iran VPS may START towards foreign addresses
// never sees a new outbound flow. A punch is nonce(8) + HMAC(12) + 0-40 random bytes: no constant byte, and no
// session packet (33+ bytes, its first 20 bytes random) is mistaken for one except by a 2^-96 chance.

const (
	punchCore  = 20
	punchEvery = time.Second
)

func punchKey(psk []byte) []byte {
	h := sha256.Sum256(append([]byte("wattun punch v1\x00"), psk...))
	return h[:]
}

func makePunch(key []byte) []byte {
	b := make([]byte, punchCore+mrand.IntN(41))
	rand.Read(b)
	m := hmac.New(sha256.New, key)
	m.Write(b[:8])
	copy(b[8:punchCore], m.Sum(nil))
	return b
}

func isPunch(key, p []byte) bool {
	if len(p) < punchCore || len(p) > punchCore+40 {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(p[:8])
	return hmac.Equal(p[8:punchCore], m.Sum(nil)[:punchCore-8])
}

const punchSeenMax = 1024

// UDPReverseListener is the client PacketIO of a reverse udp tunnel.
type UDPReverseListener struct {
	c       *net.UDPConn
	key     []byte
	peer    atomic.Pointer[net.UDPAddr] // where the last valid punch came from (nil: none yet, so Send drops)
	authAt  atomic.Int64                // unix ns of the newest authenticated session packet from peer
	rbuf    []byte
	bx      *udpBatch
	dns     bool // DNS-shaped datagrams (dnsshape.go)
	dnsEdns bool // 3.3.8 opt-in: structurally complete DNS (EDNS0 OPT on the queries)
	seen    map[[8]byte]struct{}
	seenQ   [][8]byte
}

// PeerAuthenticated records that a session packet authenticated from the current peer, locking out punch-replay
// address hijacks while the peer remains active.
func (u *UDPReverseListener) PeerAuthenticated(a net.Addr) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return
	}
	if cur := u.peer.Load(); cur != nil && cur.IP.Equal(ua.IP) && cur.Port == ua.Port {
		u.authAt.Store(time.Now().UnixNano())
	}
}

func (u *UDPReverseListener) seenPunch(nonce []byte) bool {
	if len(nonce) < 8 {
		return true
	}
	var k [8]byte
	copy(k[:], nonce[:8])
	if u.seen == nil {
		u.seen = make(map[[8]byte]struct{}, 64)
	}
	if _, dup := u.seen[k]; dup {
		return true
	}
	if len(u.seenQ) >= punchSeenMax {
		delete(u.seen, u.seenQ[0])
		u.seenQ = u.seenQ[1:]
	}
	u.seen[k] = struct{}{}
	u.seenQ = append(u.seenQ, k)
	return false
}

// SetDNS turns the DNS framing on or off; call it before the first Recv. Both ends must agree.
func (u *UDPReverseListener) SetDNS(on bool) { u.dns = on }

// SetDNSEdns turns the 3.3.8 EDNS0 framing on or off; call it before the first Recv. Both ends must agree.
func (u *UDPReverseListener) SetDNSEdns(on bool) { u.dnsEdns = on }

// NewUDPReverseListener binds addr (":4443") and waits for the server's punches.
func NewUDPReverseListener(addr string, psk []byte) (*UDPReverseListener, error) {
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
	return &UDPReverseListener{c: c, key: punchKey(psk), rbuf: make([]byte, 65536), bx: newUDPBatch(c)}, nil
}

func (u *UDPReverseListener) Send(p []byte, path int) error {
	dst := u.peer.Load()
	if dst == nil {
		return nil // nobody has punched yet: loss the session repairs once the server shows up
	}
	if u.dns {
		fs, done := dnsFramesOpt([][]byte{p}, false, nil, u.dnsEdns)
		defer done()
		p = fs[0]
	}
	_, err := u.c.WriteToUDP(p, dst)
	return err
}

// SendBatch sends a burst to the punching server in one system call where the platform has sendmmsg (WAT_BATCH=1 or
// -batch on). Before 3.0.0 the upload of a reverse udp tunnel was one write per datagram whatever the setting, the one
// udp direction that could not batch.
func (u *UDPReverseListener) SendBatch(ps [][]byte, lanes []int) error {
	dst := u.peer.Load()
	if dst == nil {
		return nil // nobody has punched yet, as in Send
	}
	if u.dns {
		fs, done := dnsFramesOpt(ps, false, nil, u.dnsEdns)
		defer done()
		ps = fs
	}
	if u.bx != nil {
		return u.bx.send(ps, dst)
	}
	var first error
	for _, p := range ps {
		if _, err := u.c.WriteToUDP(p, dst); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (u *UDPReverseListener) Recv() ([]byte, int, net.Addr, error) {
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
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		if u.dns {
			if p = dnsStrip(p); p == nil {
				continue
			}
		}
		if isPunch(u.key, p) {
			if u.seenPunch(p[:8]) {
				continue
			}
			cur := u.peer.Load()
			if cur == nil || !cur.IP.Equal(ua.IP) || cur.Port != ua.Port {
				// While the pinned peer is actively delivering authenticated session packets, ignore punches from other
				// addresses (blocks stale punch-replay hijacks while preserving re-homing once silent).
				if cur != nil {
					if at := u.authAt.Load(); at != 0 && time.Since(time.Unix(0, at)) < 10*time.Second {
						continue
					}
				}
				u.peer.Store(ua)
			}
			continue
		}
		if cur := u.peer.Load(); cur == nil || !cur.IP.Equal(ua.IP) || cur.Port != ua.Port {
			continue // not from the punching server: the session would reject it anyway
		}
		return p, 0, ua, nil
	}
}

func (u *UDPReverseListener) CopiesOnSend() bool { return true }
func (u *UDPReverseListener) SetPeer(net.Addr)   {}
func (u *UDPReverseListener) Profile() Profile   { return udpProfile }
func (u *UDPReverseListener) Close() error       { return u.c.Close() }

// Addr is the bound address (useful with port 0).
func (u *UDPReverseListener) Addr() net.Addr { return u.c.LocalAddr() }

// UDPReverseServer is the server RawIO of a reverse udp tunnel: a normal UDPServer that also punches towards the
// client's address until the tunnel is closed.
type UDPReverseServer struct {
	*UDPServer
	stop   chan struct{}
	cancel context.CancelFunc
	once   sync.Once
}

// SetDNS frames the punches too, so call it right after NewUDPReverseServer (a punch sent before it is unframed and
// the listener ignores it; the next one, about a second later, is framed).
func (r *UDPReverseServer) SetDNS(on bool) { r.UDPServer.SetDNS(on) }

func resolvePeerUDP(ctx context.Context, peer string) (*net.UDPAddr, bool) {
	host, portStr, err := net.SplitHostPort(peer)
	if err != nil {
		return nil, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, false
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, true
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil || len(ips) == 0 {
		return nil, false
	}
	return &net.UDPAddr{IP: ips[0].IP, Port: port, Zone: ips[0].Zone}, false
}

// NewUDPReverseServer binds listen (the source port of the punches and of every reply) and punches to peer.
func NewUDPReverseServer(listen, peer string, psk []byte) (*UDPReverseServer, error) {
	us, err := NewUDPServer(listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &UDPReverseServer{UDPServer: us, stop: make(chan struct{}), cancel: cancel}
	key := punchKey(psk)
	go func() {
		var ra *net.UDPAddr
		var staticIP bool
		var resolvedAt time.Time
		for {
			if !staticIP && (ra == nil || time.Since(resolvedAt) >= 30*time.Second) {
				if addr, isLiteral := resolvePeerUDP(ctx, peer); addr != nil {
					ra, staticIP = addr, isLiteral
					resolvedAt = time.Now()
					us.watch.Store(ra)
				}
			}
			// 3.0.0: no punch while the client is talking (it already knows us, and a datagram every second next
			// to the traffic is a pattern); punching resumes 2 punch intervals after it goes quiet, so a restarted
			// client, which waits for a punch before it sends anything, still finds us.
			if quiet := time.Since(time.Unix(0, us.rxAt.Load())); ra != nil && quiet > 2*punchEvery {
				pk := makePunch(key)
				if us.dns.Load() {
					pk = dnsFrame(nil, pk, true)
				}
				us.c.WriteToUDP(pk, ra)
			}
			select {
			case <-r.stop:
				return
			case <-time.After(time.Duration(float64(punchEvery) * (0.6 + 0.8*mrand.Float64()))):
			}
		}
	}()
	return r, nil
}

func (r *UDPReverseServer) Close() error {
	r.once.Do(func() {
		r.cancel()
		close(r.stop)
	})
	return r.UDPServer.Close()
}
