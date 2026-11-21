//go:build linux

package wat

// spray (3.4.3): raw-UDP 5-tuple rotation. One SOCK_RAW/IPPROTO_UDP socket per end (the kernel builds the
// IPv4 header, we write the 8-byte UDP header with a real checksum — the field probe sent checksum 0, legal
// on IPv4, but a verifying middlebox drops a wrong one and ours costs one pass over ~1400 B). The client
// rotates BOTH ports: a fresh (sport, dport) tuple every N..1.5N packets (-spray-hop, default 16), sports in
// 61000-64999 (above the ephemeral range, like ptcp), dports inside the server's range. The rotation itself
// is field-proven (2026-11-20, PLAN-carriers.md: 98.7-98.8% delivery at 5-100 MB/s targets, no tuple over
// 20 packets, no block over 15k tuples); the carrier around it is not field-measured yet.
//
// The server is one raw socket with a BPF filter on the dport range (the probe's corrected IHL==5 equality
// form, review F7 2026-11-20); it delivers the payload after the IP+UDP headers and remembers the NEWEST
// (ip, sport) per client, so downlink tuples rotate because the client's source ports do. The server's own
// downlink source port is fixed at the range's low end — the client's BPF filter matches it — and UDP needs
// no iptables (no RST problem). No handshake, no wire change: the payload is the session's sealed datagram,
// exactly what a udp carrier carries; both ends need 3.4.3 and the same range. Not reverse: downlink rotation
// rides the client's hops, and the field run measured no cut on Kharej->Iran.

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	sprayCLo    = 61000 // client source ports, above the default ephemeral range so no kernel socket owns them
	sprayCHi    = 64999
	sprayDefHop = 16        // packets per tuple: 16..24 keeps every tuple under the ~30-packet cut (field 2026-11-20)
	sprayMTU    = 1400 - 28 // one datagram per UDP packet; 28 = IP+UDP headers
)

// sprayProfile: like udp-hop, each tuple may take its own path, so delay spreads and the session judges
// delay by the fastest sample (Profile.Spread, the Wraith reasoning in carrier_udp.go).
var sprayProfile = Profile{MTU: sprayMTU, InitBps: 8e6, Spread: true}

// spraySum is the UDP checksum over the v4 pseudo-header (proto 17), the ptcpSum shape.
func spraySum(src, dst net.IP, pkt []byte) uint16 {
	ph := append(append(append([]byte{}, src.To4()...), dst.To4()...), 0, 17, byte(len(pkt)>>8), byte(len(pkt)))
	var s uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			s += uint32(b[len(b)-1]) << 8
		}
	}
	add(ph)
	add(pkt)
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

var sprayBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// sprayPacket builds the UDP header + payload into *bp (the raw UDP socket gets no IP header from us).
func sprayPacket(bp *[]byte, src, dst net.IP, sport, dport uint16, p []byte) []byte {
	b := (*bp)[:0]
	b = binary.BigEndian.AppendUint16(b, sport)
	b = binary.BigEndian.AppendUint16(b, dport)
	b = binary.BigEndian.AppendUint16(b, uint16(8+len(p)))
	b = append(b, 0, 0) // checksum, filled once the whole packet is summed
	b = append(b, p...)
	binary.BigEndian.PutUint16(b[6:], spraySum(src, dst, b))
	*bp = b
	return b
}

// sprayRot is the rotation state machine: a fresh (sport, dport) every n..1.5n packets, both ports random
// inside their ranges (the probe's 12-20 jitter generalized, sprayraw_sched.go). cur/max feed the tuple
// ceiling the loopback test asserts against.
type sprayRot struct {
	dLo, dHi uint16
	n        int
	sport    uint16
	dport    uint16
	left     int
	tuples   int
	cur, max int
}

// next returns the tuple for the next packet and whether it opened a fresh tuple.
func (r *sprayRot) next() (sport, dport uint16, fresh bool) {
	if r.left <= 0 {
		if r.cur > r.max {
			r.max = r.cur
		}
		r.cur = 0
		r.sport = uint16(sprayCLo + rand.IntN(sprayCHi-sprayCLo+1))
		r.dport = uint16(int(r.dLo) + rand.IntN(int(r.dHi)-int(r.dLo)+1))
		r.left = r.n + rand.IntN(r.n/2+1)
		r.tuples++
		fresh = true
	}
	r.left--
	r.cur++
	return r.sport, r.dport, fresh
}

func openRawUDP() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return 0, err
	}
	// a receive timeout keeps the read loops checking their done channel; EAGAIN is not an error
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 500000})
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20) // absorb bursts like the udp carrier
	return fd, nil
}

// sprayFilter assembles and attaches a classic-BPF program to a raw fd. All drops land on the last
// instruction; every SkipFalse/SkipTrue was hand-traced to it (the probe's F7 lesson: a wrong jump makes a
// working filter drop everything, silently).
func sprayFilter(fd int, ins []bpf.Instruction) error {
	prog, err := bpf.Assemble(ins)
	if err != nil {
		return err
	}
	fl := make([]unix.SockFilter, len(prog))
	for i, p := range prog {
		fl[i] = unix.SockFilter{Code: p.Op, Jt: p.Jt, Jf: p.Jf, K: p.K}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len: uint16(len(fl)), Filter: &fl[0]})
}

// spraySrvFilter keeps IPv4, IHL 5, UDP, dport in [lo,hi] — the receiving end of the client's spray.
func spraySrvFilter(lo, hi uint16) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1}, // version+IHL
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0f},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 5, SkipFalse: 6}, // pc 9: drop
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 4},                  // pc 9
		bpf.LoadAbsolute{Off: 22, Size: 2},                                      // dport (IP 20 + UDP 2)
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: uint32(lo), SkipFalse: 2}, // pc 9
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: uint32(hi), SkipTrue: 1},     // pc 9
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	}
}

// sprayCliFilter keeps UDP from the peer with the server's fixed downlink source port; the software
// filter below still checks the live sports, the BPF only sheds the host's other UDP traffic.
func sprayCliFilter(peer net.IP, srvPort uint16) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0f},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 5, SkipFalse: 7}, // pc 10: drop
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 5},                                  // pc 10
		bpf.LoadAbsolute{Off: 12, Size: 4},                                                      // source address
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(peer.To4()), SkipFalse: 3}, // pc 10
		bpf.LoadAbsolute{Off: 20, Size: 2},                                                      // UDP sport
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srvPort), SkipFalse: 1},                     // pc 10
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	}
}

// sprayDgram is one received datagram with its sender (copied: the read buffer is reused).
type sprayDgram struct {
	b   []byte
	src *net.UDPAddr
}

// SprayClient is the client PacketIO: one raw UDP socket, sport+dport rotating every -spray-hop..1.5x
// packets. An old sport stays eligible for downlink datagrams hopGrace (replies already in flight).
type SprayClient struct {
	fd      int
	peer    net.IP
	local   net.IP
	srvPort uint16 // the server's fixed downlink source port (the range's low end)
	mu      sync.Mutex
	rot     *sprayRot
	live    map[uint16]time.Time // sports of ours still inside hopGrace from their last send
	rx      chan sprayDgram
	rbuf    []byte
	pool    sync.Pool
	done    chan struct{}
	once    sync.Once
	prev    []byte
}

// NewSprayClient opens the client carrier. peer is "host", "host:port" or "host:lo-hi" (default port
// 41000, spanning 41000-41999 — it must derive the same range the server's -listen does); hop is packets
// per tuple (0 = sprayDefHop).
func NewSprayClient(peer, srcIP string, hop int) (*SprayClient, error) {
	host, portSpec, err := net.SplitHostPort(peer)
	if err != nil {
		host, portSpec = peer, "41000"
	}
	lo, hi, err := ParseSprayPorts(portSpec)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 || ips[0].To4() == nil {
		return nil, errors.New("wat: spray requires an IPv4 peer")
	}
	pip := ips[0].To4()
	local := net.IPv4zero
	if srcIP != "" {
		if ip := net.ParseIP(srcIP); ip != nil && ip.To4() != nil {
			local = ip.To4()
		} else {
			return nil, errors.New("wat: spray requires an IPv4 source ip")
		}
	} else if ip, err := localAddrFor(pip); err == nil {
		local = ip.To4()
	} else {
		return nil, err
	}
	fd, err := openRawUDP()
	if err != nil {
		return nil, err
	}
	// bind the source address so the IP header the kernel builds matches the one our checksum summed
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte(local.To4())}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	srv := uint16(lo)
	if err := sprayFilter(fd, sprayCliFilter(pip, srv)); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if hop <= 0 {
		hop = sprayDefHop
	}
	c := &SprayClient{fd: fd, peer: pip, local: local, srvPort: srv,
		rot:  &sprayRot{dLo: uint16(lo), dHi: uint16(hi), n: hop},
		live: map[uint16]time.Time{}, rx: make(chan sprayDgram, 256), rbuf: make([]byte, 65536),
		done: make(chan struct{})}
	c.pool.New = func() any { return make([]byte, 2048) }
	go c.readLoop()
	return c, nil
}

func (c *SprayClient) Profile() Profile { return sprayProfile }

func (c *SprayClient) readLoop() {
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, from, err := unix.Recvfrom(c.fd, c.rbuf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		p, sport, dport, ok := sprayUnwrap(c.rbuf[:n])
		if !ok || sport != c.srvPort || !net.IP(sa.Addr[:]).Equal(c.peer) {
			continue
		}
		c.mu.Lock()
		_, live := c.live[dport]
		if live {
			c.live[dport] = time.Now()
		}
		c.mu.Unlock()
		if !live {
			continue
		}
		b := c.pool.Get().([]byte)
		copy(b, p)
		select {
		case c.rx <- sprayDgram{b: b[:len(p)], src: &net.UDPAddr{IP: net.IP(append([]byte(nil), sa.Addr[:]...)), Port: int(sport)}}:
		case <-c.done:
			return
		default: // the session is not keeping up: drop rather than block the raw reader
		}
	}
}

// sprayUnwrap returns the payload after the IP+UDP headers of a raw-socket read.
func sprayUnwrap(b []byte) (p []byte, sport, dport uint16, ok bool) {
	if len(b) < 28 {
		return nil, 0, 0, false
	}
	ihl := int(b[0]&0xf) * 4
	if b[9] != unix.IPPROTO_UDP || ihl+8 > len(b) {
		return nil, 0, 0, false
	}
	return b[ihl+8:], binary.BigEndian.Uint16(b[ihl:]), binary.BigEndian.Uint16(b[ihl+2:]), true
}

// tuple returns the ports for the next packet, marking the sport live for hopGrace.
func (c *SprayClient) tuple() (uint16, uint16) {
	c.mu.Lock()
	sport, dport, fresh := c.rot.next()
	if fresh { // reap expired sports only on rotation: bounded work per packet
		now := time.Now()
		for p, t := range c.live {
			if now.Sub(t) > hopGrace {
				delete(c.live, p)
			}
		}
	}
	c.live[sport] = time.Now()
	c.mu.Unlock()
	return sport, dport
}

func (c *SprayClient) Send(dat []byte, _ int) error {
	if len(dat) > sprayMTU {
		return errors.New("wat: spray datagram exceeds the packet size")
	}
	sport, dport := c.tuple()
	bp := sprayBufs.Get().(*[]byte)
	pkt := sprayPacket(bp, c.local, c.peer, sport, dport, dat)
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], c.peer)
	err := unix.Sendto(c.fd, pkt, 0, &sa)
	sprayBufs.Put(bp)
	return err
}

// SendBatch sends the burst through sendmmsg (the probe's shape: x/sys has no Mmsghdr, so the syscall goes
// through Syscall6 with a RawSockaddrInet4 — Go's SockaddrInet4 layout reads as family 0 and the sends
// "succeed" without reaching the peer). Each packet takes whatever tuple the rotation hands it.
func (c *SprayClient) SendBatch(ps [][]byte, _ []int) error {
	for _, p := range ps {
		if len(p) > sprayMTU {
			return errors.New("wat: spray datagram exceeds the packet size")
		}
	}
	sa := &unix.RawSockaddrInet4{Family: unix.AF_INET}
	copy(sa.Addr[:], c.peer)
	bufs := make([][]byte, len(ps))
	bps := make([]*[]byte, len(ps))
	for i := range ps {
		sport, dport := c.tuple()
		bps[i] = sprayBufs.Get().(*[]byte)
		bufs[i] = sprayPacket(bps[i], c.local, c.peer, sport, dport, ps[i])
	}
	err := spraySendmmsg(c.fd, bufs, sa)
	for _, bp := range bps {
		sprayBufs.Put(bp)
	}
	return err
}

// mmsghdrU: x/sys dropped Mmsghdr; 64-bit linux only (amd64/arm64, the release targets).
type mmsghdrU struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

// spraySendmmsg sends the whole batch, resuming after partial acceptance (ENOBUFS-style backpressure),
// exactly the probe's loop.
func spraySendmmsg(fd int, pkts [][]byte, sa *unix.RawSockaddrInet4) error {
	iovs := make([]unix.Iovec, len(pkts))
	hdrs := make([]mmsghdrU, len(pkts))
	for i, p := range pkts {
		iovs[i].Base = &p[0]
		iovs[i].SetLen(len(p))
		hdrs[i].hdr.Name = (*byte)(unsafe.Pointer(sa))
		hdrs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		hdrs[i].hdr.Iov = &iovs[i]
		hdrs[i].hdr.SetIovlen(1)
	}
	for done := 0; done < len(pkts); {
		n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
			uintptr(unsafe.Pointer(&hdrs[done])), uintptr(len(pkts)-done), 0, 0, 0)
		if errno != 0 {
			return errno
		}
		if n == 0 {
			return errors.New("wat: spray sendmmsg made no progress")
		}
		done += int(n)
	}
	return nil
}

func (c *SprayClient) Recv() ([]byte, int, net.Addr, error) {
	if c.prev != nil {
		c.pool.Put(c.prev[:cap(c.prev)])
		c.prev = nil
	}
	select {
	case d := <-c.rx:
		c.prev = d.b
		return d.b, 0, d.src, nil
	case <-c.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (c *SprayClient) SetPeer(net.Addr) {}

func (c *SprayClient) Close() error {
	c.once.Do(func() { close(c.done) })
	return unix.Close(c.fd)
}

// sprayPeerState is the newest observed source of one client plus our local address towards it (the v4
// raw read carries both: the downlink checksum needs the source IP the kernel will route through).
type sprayPeerState struct {
	addr  *net.UDPAddr
	local net.IP
}

// SprayServer is the server RawIO: one raw socket, BPF-filtered to the dport range, payload delivered
// after the headers, replies always to the newest observed source port of the client SendTo names.
type SprayServer struct {
	fd       int
	dLo, dHi uint16
	mu       sync.Mutex
	peers    map[string]*sprayPeerState
	rx       chan sprayDgram
	rbuf     []byte
	pool     sync.Pool
	prev     []byte
	done     chan struct{}
	once     sync.Once
}

// NewSprayServer opens the server carrier on a dport range spec: "41000-41999", or a base port
// ("41000" spans 41000-41999). The range's low end doubles as the downlink source port.
func NewSprayServer(spec string) (*SprayServer, error) {
	if _, portSpec, err := net.SplitHostPort(spec); err == nil {
		spec = portSpec
	}
	lo, hi, err := ParseSprayPorts(spec)
	if err != nil {
		return nil, err
	}
	fd, err := openRawUDP()
	if err != nil {
		return nil, err
	}
	if err := sprayFilter(fd, spraySrvFilter(uint16(lo), uint16(hi))); err != nil {
		unix.Close(fd)
		return nil, err
	}
	s := &SprayServer{fd: fd, dLo: uint16(lo), dHi: uint16(hi), peers: map[string]*sprayPeerState{},
		rx: make(chan sprayDgram, 256), rbuf: make([]byte, 65536), done: make(chan struct{})}
	s.pool.New = func() any { return make([]byte, 2048) }
	go s.readLoop()
	return s, nil
}

func (s *SprayServer) Profile() Profile { return sprayProfile }

func (s *SprayServer) readLoop() {
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, from, err := unix.Recvfrom(s.fd, s.rbuf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		p, sport, dport, ok := sprayUnwrap(s.rbuf[:n])
		if !ok || dport < s.dLo || dport > s.dHi {
			continue
		}
		srcIP := net.IP(append([]byte(nil), sa.Addr[:]...)).To4()
		if srcIP == nil {
			continue
		}
		local := net.IP(append([]byte(nil), s.rbuf[16:20]...)).To4() // the destination of the IP header is us
		if local == nil || local.IsUnspecified() {
			if ip, err := localAddrFor(srcIP); err == nil {
				local = ip.To4()
			}
		}
		key := srcIP.String()
		s.mu.Lock()
		s.peers[key] = &sprayPeerState{addr: &net.UDPAddr{IP: srcIP, Port: int(sport)}, local: local}
		s.mu.Unlock()
		b := s.pool.Get().([]byte)
		copy(b, p)
		d := sprayDgram{b: b[:len(p)], src: &net.UDPAddr{IP: append([]byte(nil), srcIP...), Port: int(sport)}}
		select {
		case s.rx <- d:
		case <-s.done:
			return
		default: // drop rather than block the raw reader; the session repairs loss
		}
	}
}

func (s *SprayServer) Recv() ([]byte, int, net.Addr, error) {
	if s.prev != nil {
		s.pool.Put(s.prev[:cap(s.prev)])
		s.prev = nil
	}
	select {
	case d := <-s.rx:
		s.prev = d.b
		return d.b, 0, d.src, nil
	case <-s.done:
		return nil, 0, nil, net.ErrClosed
	}
}

// SendTo writes one datagram to the NEWEST observed source port of the client dst names (downlink tuples
// rotate because the client's source ports do), from the range's fixed low port.
func (s *SprayServer) SendTo(dat []byte, _ int, dst net.Addr) error {
	if len(dat) > sprayMTU {
		return errors.New("wat: spray datagram exceeds the packet size")
	}
	ua, ok := dst.(*net.UDPAddr)
	if !ok {
		return errors.New("wat: spray peer address is not a UDP addr")
	}
	s.mu.Lock()
	st := s.peers[ua.IP.String()]
	s.mu.Unlock()
	if st != nil {
		ua = st.addr // newest sport, even if the engine holds an older address
	}
	local := net.IPv4zero
	if st != nil && st.local != nil {
		local = st.local
	} else if ip, err := localAddrFor(ua.IP); err == nil {
		local = ip.To4()
	}
	bp := sprayBufs.Get().(*[]byte)
	pkt := sprayPacket(bp, local, ua.IP, s.dLo, uint16(ua.Port), dat)
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], ua.IP.To4())
	err := unix.Sendto(s.fd, pkt, 0, &sa)
	sprayBufs.Put(bp)
	return err
}

func (s *SprayServer) Close() error {
	s.once.Do(func() { close(s.done) })
	return unix.Close(s.fd)
}
