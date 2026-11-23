//go:build linux

package wat

// Phantom (ptcp, 3.4.3): the engine's sealed datagrams ride as the payload of fake TCP segments on a raw
// socket (IPPROTO_TCP), Linux + CAP_NET_RAW, IPv4 only (the field pair's IPv6 is dead — PLAN-carriers.md
// 2026-11-14). The shape is the one bench/fieldprobe proved on the live Iran->Kharej path (2026-11-14:
// ptcp passes a full flow but each 5-tuple is cut after ~29-34 packets, so the carrier is only useful with
// port hopping): every flow starts with a raw SYN (Linux-shaped options: MSS 1460, SACK-permitted,
// timestamps, wscale 7), the server answers a SYN-ACK, the client ACKs and sends the mimic ClientHello
// (tcp_mimic.go) as the first flight, and the session's datagrams follow as PSH|ACK data segments with
// moving seq/ack numbers and TCP timestamps. A new flow (fresh source port, ISN and handshake) opens every
// N..1.5N packets — the fieldprobe's spray numbers say <= 20 keeps a margin under the ~30 cut — and the
// retired flow gets a FIN|ACK and stays readable hopGrace for segments already in flight.
//
// Not reverse mode, on purpose: the field run showed Kharej -> Iran cuts NOTHING, so the reverse direction
// has no reason to look like TCP (a plain tcp carrier already passes); -reverse is refused like gre/ipip.
//
// The kernel answers stray segments for ports no socket owns with RST, which a middlebox reads as the flow
// dying. Like the fieldprobe, both ends install iptables rules that drop their own outgoing RSTs for the
// carrier's ports (idempotent: a stale rule from a crashed run is deleted before the new one is inserted;
// a crash leaves the rule behind — harmless to other traffic, and the next start or the installer's cleanup
// removes it). Every rule carries the comment tag "wattun-ptcp" (P4, 2026-11-21) so an operator or
// wattun-manager doctor can spot a crashed run's orphans by tag; all invocations pass -w so a boot-time
// insert waits for the iptables lock instead of racing systemd/ufw. Without iptables the carrier still
// runs (a warning is logged; RSTs leak).
//
// Both ends need 3.4.3 and the same carrier name; this is a wattun-internal shape, not real TCP to a peer's
// kernel. Not in the auto-test set; not field-measured as a carrier yet (only the probe shapes are).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ptcpLo       = 61000 // client source ports, above the default ephemeral range so no kernel socket owns them
	ptcpHi       = 64999
	ptcpDefHop   = 12   // packets per flow before a hop: 12..18 keeps every tuple under the ~30 cut
	ptcpMTU      = 1340 // 1400 route MTU minus IP(20)+TCP(20+12 options)+slack; one datagram per segment
	ptcpAckEvery = 4    // pure ACKs per direction: enough to look alive, not one per segment
)

// PTCPClient is the client PacketIO: raw SYNs to the server's port, data segments uplink, downlink segments
// delivered from the read loop (any live flow's port — a retired flow keeps answering hopGrace).
type PTCPClient struct {
	raw   *ptcpSock
	peer  net.IP
	local net.IP
	port  uint16 // the server's port
	sni   string
	hopN  int
	fw    *fwRules
	mu    sync.Mutex
	flow  *ptcpFlow
	flows map[uint16]*ptcpFlow // live by sport (the current one + retired ones inside hopGrace)
	rx    chan ptcpSeg
	rbuf  []byte
	done  chan struct{}
	once  sync.Once
}

// PTCPServer is the server RawIO: answers SYNs on the port with SYN-ACKs, swallows each flow's first data
// segment (the ClientHello flight), delivers the rest as datagrams, ACKs every ptcpAckEvery-th segment.
type PTCPServer struct {
	raw   *ptcpSock
	port  uint16
	fw    *fwRules
	mu    sync.Mutex
	flows map[string]*ptcpSess
	local map[string]net.IP // the server's local address per peer (the v4 raw read carries the IP header)
	rx    chan ptcpSeg
	rbuf  []byte
	done  chan struct{}
	once  sync.Once
}

// ptcpSeg is one parsed segment (see ptcpSock.read).
type ptcpSeg struct {
	src, dst net.IP
	sport    uint16
	dport    uint16
	seq, ack uint32
	flags    byte
	data     []byte
}

// ptcpFlow is the client's end of one fake TCP connection.
type ptcpFlow struct {
	sport       uint16
	seq, ack    uint32 // ack doubles as the receive watermark (rcv)
	established bool
	hello       bool // the ClientHello first flight went out
	left        int
	sent        int // packets on this flow (the hop budget's counter, kept for the tuple test)
	acksDue     int
	retired     time.Time
}

// ptcpSess is the server's end of one fake TCP connection, keyed "ip:sport".
type ptcpSess struct {
	isn, cseq uint32 // server ISN; cseq = the client's next expected-by-us byte
	sseq      uint32 // our next downlink seq (isn+1 grows with what we sent)
	segs      int
	hello     bool // the ClientHello first flight was swallowed
}

func (p *PTCPClient) Profile() Profile {
	return Profile{MTU: ptcpMTU, InitBps: 8e6, Spread: true} // every flow takes its own port: delay spreads
}

func (p *PTCPServer) Profile() Profile { return Profile{MTU: ptcpMTU, InitBps: 8e6, Spread: true} }

// ptcpSock: one raw TCP socket (v4). Reads include the IP header, so the destination address is known.
type ptcpSock struct{ fd int }

func openRawTCP() (*ptcpSock, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	// a receive timeout keeps the read loops checking their done channel; EAGAIN is not an error
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 500000})
	return &ptcpSock{fd}, nil
}

func closeRaw(r *ptcpSock) error { return unix.Close(r.fd) }

// errTimeout: the receive timeout fired; the caller's loop decides (the carrier's loops return it and their
// driver re-enters; tests treat it as a deadline).
var errTimeout = errors.New("wat: ptcp receive timeout")

// ptcpSum is the TCP checksum over the v4 pseudo-header (fieldprobe's tcpSum).
func ptcpSum(src, dst net.IP, seg []byte) uint16 {
	ph := append(append(append([]byte{}, src.To4()...), dst.To4()...), 0, 6, byte(len(seg)>>8), byte(len(seg)))
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
	add(seg)
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

var ptcpT0 = time.Now()

func ptcpTsval() uint32 { return uint32(time.Since(ptcpT0).Milliseconds()) + 1 }

// ptcpSeg_ builds one Linux-shaped TCP segment (fieldprobe's write): SYN/SYN-ACK carry MSS, SACK-permitted,
// timestamps and wscale 7; every other segment carries timestamps. win 502 (a Linux socket mid-flow at
// wscale 7), 64240 on SYN.
func ptcpBuild(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, tsecr uint32, data []byte) []byte {
	var opt []byte
	if flags&ptcpSYN != 0 {
		opt = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7}
		binary.BigEndian.PutUint32(opt[8:], ptcpTsval())
		binary.BigEndian.PutUint32(opt[12:], tsecr)
	} else {
		opt = []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(opt[4:], ptcpTsval())
		binary.BigEndian.PutUint32(opt[8:], tsecr)
	}
	hl := 20 + len(opt)
	seg := make([]byte, hl+len(data))
	binary.BigEndian.PutUint16(seg[0:], sport)
	binary.BigEndian.PutUint16(seg[2:], dport)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = byte(hl/4) << 4
	seg[13] = flags
	win := uint16(502)
	if flags&ptcpSYN != 0 {
		win = 64240
	}
	binary.BigEndian.PutUint16(seg[14:], win)
	copy(seg[20:], opt)
	copy(seg[hl:], data)
	binary.BigEndian.PutUint16(seg[16:], ptcpSum(src, dst, seg))
	return seg
}

// ptcpParse decodes one TCP segment from a buffer that starts at the TCP header; ok=false when it is not one.
func ptcpParse(b []byte) (sport, dport uint16, seq, ack uint32, flags byte, data []byte, ok bool) {
	if len(b) < 20 {
		return
	}
	off := int(b[12]>>4) * 4
	if off < 20 || off > len(b) {
		return
	}
	return binary.BigEndian.Uint16(b[0:]), binary.BigEndian.Uint16(b[2:]),
		binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), b[13], b[off:], true
}

const (
	ptcpFIN = 1 << iota
	ptcpSYN
	ptcpRST
	ptcpPSH
	ptcpACK
)

// readRawTCP returns the next parsed segment from the raw socket (v4: the IP header is included).
func readRawTCP(r *ptcpSock, buf []byte) (ptcpSeg, error) {
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return ptcpSeg{}, errTimeout
			}
			return ptcpSeg{}, err
		}
		b := buf[:n]
		if len(b) < 40 {
			continue
		}
		ihl := int(b[0]&0xf) * 4
		if len(b) < ihl+20 {
			continue
		}
		src := net.IP(append([]byte(nil), b[12:16]...))
		dst := net.IP(append([]byte(nil), b[16:20]...))
		sport, dport, seq, ack, flags, data, ok := ptcpParse(b[ihl:])
		if !ok {
			continue
		}
		// data is copied: it would alias the reader's buffer, and the next read overwrites it while the segment
		// still waits in the rx channel
		return ptcpSeg{src: src, dst: dst, sport: sport, dport: dport, seq: seq, ack: ack, flags: flags,
			data: append([]byte(nil), data...)}, nil
	}
}

// sendRawTCP writes one built segment to dst.
func sendRawTCP(r *ptcpSock, dst net.IP, seg []byte) error {
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst.To4())
	return unix.Sendto(r.fd, seg, 0, &sa)
}

// fwRules installs and removes iptables rules idempotently. Each rule is [args...] under -I/-D.
type fwRules struct {
	bin   string
	rules [][]string
}

func (f *fwRules) add(rule ...string) {
	// every rule carries the comment tag (P4, 2026-11-21): doctor/orphan hunting by tag; -m comment is
	// standard on every distro's iptables. -w waits for the xtables lock so a boot-time insert cannot race
	// another iptables user (systemd, ufw); the -D carries the identical spec or it would not match.
	rule = append(rule, "-m", "comment", "--comment", "wattun-ptcp")
	_ = exec.Command(f.bin, append([]string{"-w", "-D"}, rule...)...).Run() // stale copy from a crashed run
	if out, err := exec.Command(f.bin, append([]string{"-w", "-I"}, rule...)...).CombinedOutput(); err != nil {
		log.Printf("ptcp: %s -I %s: %v %s (RSTs may leak; install iptables or ignore)",
			f.bin, strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
		return
	}
	f.rules = append(f.rules, rule)
}

func (f *fwRules) clear() {
	for _, r := range f.rules {
		_ = exec.Command(f.bin, append([]string{"-w", "-D"}, r...)...).Run()
	}
	f.rules = nil
}

func localAddrFor(peer net.IP) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(peer.String(), "9"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}

// NewPTCPClient opens the client carrier. peer is the server's "host" or "host:port" (default port 443, a
// fake-TLS-looking destination); hop is packets per flow (0 = ptcpDefHop); sni shapes the first flight.
func NewPTCPClient(peer, srcIP, sni string, hop int) (*PTCPClient, error) {
	host, portStr, err := net.SplitHostPort(peer)
	if err != nil {
		host, portStr = peer, "443"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 || ips[0].To4() == nil {
		return nil, errors.New("wat: ptcp requires an IPv4 peer")
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil || port < 1 {
		return nil, errors.New("wat: ptcp peer port is invalid")
	}
	local := net.IPv4zero
	if srcIP != "" {
		if ip := net.ParseIP(srcIP); ip != nil && ip.To4() != nil {
			local = ip.To4()
		} else {
			return nil, errors.New("wat: ptcp requires an IPv4 source ip")
		}
	} else if ip, err := localAddrFor(ips[0].To4()); err == nil {
		local = ip
	} else {
		return nil, err
	}
	r, err := openRawTCP()
	if err != nil {
		return nil, err
	}
	if hop <= 0 {
		hop = ptcpDefHop
	}
	p := &PTCPClient{raw: r, peer: ips[0].To4(), local: local, port: uint16(port), sni: sni, hopN: hop,
		flows: map[uint16]*ptcpFlow{}, rx: make(chan ptcpSeg, 256), rbuf: make([]byte, 65536), done: make(chan struct{})}
	p.fw = &fwRules{bin: "iptables"}
	// both rules are pinned to the peer and our source-port range: a bare "--sport 443 -j ACCEPT" would let any
	// host in by sending from port 443
	rng, peer := fmt.Sprintf("%d:%d", ptcpLo, ptcpHi), p.peer.String()
	p.fw.add("OUTPUT", "-p", "tcp", "-d", peer, "--sport", rng, "--tcp-flags", "RST", "RST", "-j", "DROP")
	p.fw.add("INPUT", "-p", "tcp", "-s", peer, "--sport", fmt.Sprint(port), "--dport", rng, "-j", "ACCEPT")
	go p.readLoop()
	return p, nil
}

func (p *PTCPClient) readLoop() {
	for {
		select {
		case <-p.done:
			return
		default:
		}
		seg, err := readRawTCP(p.raw, p.rbuf)
		if err != nil {
			if errors.Is(err, errTimeout) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if seg.sport != p.port || seg.dport < ptcpLo || seg.dport > ptcpHi || seg.flags&ptcpRST != 0 {
			continue
		}
		p.mu.Lock()
		f := p.flows[seg.dport]
		p.mu.Unlock()
		if f == nil {
			continue
		}
		if seg.flags&ptcpSYN != 0 && seg.flags&ptcpACK != 0 {
			p.mu.Lock() // Send polls established under p.mu
			if !f.established {
				f.established, f.ack = true, seg.seq+1
			}
			p.mu.Unlock()
		}
		if len(seg.data) == 0 {
			continue
		}
		f.acksDue += len(seg.data)
		if f.acksDue >= ptcpAckEvery*ptcpMTU {
			f.acksDue = 0
			_ = sendRawTCP(p.raw, seg.src, ptcpBuild(p.local, seg.src, f.sport, seg.sport, f.seq, f.rcv(seg), ptcpACK, 0, nil))
		}
		select {
		case p.rx <- seg:
		default: // the session is not keeping up: drop rather than block the raw reader
		}
	}
}

// rcv advances the flow's receive watermark (the next byte we acknowledge) and returns it.
func (f *ptcpFlow) rcv(seg ptcpSeg) uint32 {
	e := seg.seq + uint32(len(seg.data))
	if int32(e-f.ack) > 0 {
		f.ack = e
	}
	return f.ack
}

// newFlow opens the next flow: SYN now, established when the SYN-ACK lands (data before that waits for it
// or goes out with ack 0 after the grace, exactly the fieldprobe's behaviour).
func (p *PTCPClient) newFlow() *ptcpFlow {
	sport := uint16(rand.IntN(ptcpHi-ptcpLo+1) + ptcpLo)
	f := &ptcpFlow{sport: sport, seq: rand.Uint32(), left: p.hopN + rand.IntN(p.hopN/2+1)}
	_ = sendRawTCP(p.raw, p.peer, ptcpBuild(p.local, p.peer, sport, p.port, f.seq, 0, ptcpSYN, 0, nil))
	f.seq++
	p.mu.Lock()
	p.flows[sport] = f
	p.mu.Unlock()
	return f
}

// Send writes one datagram as a data segment on the current flow, hopping when the quota is spent.
func (p *PTCPClient) Send(dat []byte, _ int) error {
	if len(dat) > ptcpMTU {
		return errors.New("wat: ptcp datagram exceeds the segment size")
	}
	p.mu.Lock()
	f := p.flow
	retire := f != nil && f.left <= 0
	p.mu.Unlock()
	if f == nil || retire {
		if retire {
			// a FIN looks like the natural end of a flow; the port stays readable hopGrace for in-flight data
			_ = sendRawTCP(p.raw, p.peer, ptcpBuild(p.local, p.peer, f.sport, p.port, f.seq, f.ack, ptcpFIN|ptcpACK, 0, nil))
			f.retired = time.Now()
			time.AfterFunc(hopGrace, func() {
				p.mu.Lock()
				delete(p.flows, f.sport)
				p.mu.Unlock()
			})
		}
		f = p.newFlow()
		deadline := time.Now().Add(250 * time.Millisecond) // ~the path RTT: the SYN-ACK normally lands first
		es := false                                        // f.established is written by readLoop under p.mu
		for !es && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
			p.mu.Lock()
			es = f.established
			p.mu.Unlock()
		}
		if es {
			// complete the handshake, then the camouflage first flight
			_ = sendRawTCP(p.raw, p.peer, ptcpBuild(p.local, p.peer, f.sport, p.port, f.seq, f.ack, ptcpACK, 0, nil))
		}
		p.mu.Lock()
		p.flow = f
		p.mu.Unlock()
	}
	data := dat
	first := false
	if !f.hello { // the mimic ClientHello rides as this flow's first data segment
		hello := FakeClientHello(p.sniOrDefault())
		data = append(hello, dat...) // hello and the datagram in one segment keeps one flight per flow
		if len(data) > ptcpMTU {
			data = dat // a hello that does not fit the first segment goes alone after it
			first = true
		}
	}
	if first {
		hello := FakeClientHello(p.sniOrDefault())
		_ = sendRawTCP(p.raw, p.peer, ptcpBuild(p.local, p.peer, f.sport, p.port, f.seq, f.ack, ptcpPSH|ptcpACK, 0, hello))
		f.seq += uint32(len(hello))
	}
	err := sendRawTCP(p.raw, p.peer, ptcpBuild(p.local, p.peer, f.sport, p.port, f.seq, f.ack, ptcpPSH|ptcpACK, 0, data))
	f.seq += uint32(len(data))
	f.left--
	f.sent++
	f.hello = true
	return err
}

func (p *PTCPClient) Recv() ([]byte, int, net.Addr, error) {
	select {
	case seg := <-p.rx:
		return seg.data, 0, &net.TCPAddr{IP: seg.src, Port: int(seg.sport)}, nil
	case <-p.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (p *PTCPClient) sniOrDefault() string {
	if p.sni != "" {
		return p.sni
	}
	return "www.google.com"
}

func (p *PTCPClient) SetPeer(net.Addr) {}

func (p *PTCPClient) Close() error {
	p.once.Do(func() { close(p.done) })
	if p.fw != nil {
		p.fw.clear()
	}
	return closeRaw(p.raw)
}

// NewPTCPServer opens the server carrier on the port (the -listen value; a fake TLS port like 443 is the
// natural choice). It answers SYNs from any source.
func NewPTCPServer(port int) (*PTCPServer, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("wat: ptcp listen port is invalid")
	}
	r, err := openRawTCP()
	if err != nil {
		return nil, err
	}
	s := &PTCPServer{raw: r, port: uint16(port), flows: map[string]*ptcpSess{}, local: map[string]net.IP{},
		rx: make(chan ptcpSeg, 256), rbuf: make([]byte, 65536), done: make(chan struct{})}
	s.fw = &fwRules{bin: "iptables"}
	s.fw.add("OUTPUT", "-p", "tcp", "--sport", fmt.Sprint(port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	s.fw.add("INPUT", "-p", "tcp", "--dport", fmt.Sprint(port), "-j", "ACCEPT")
	go s.readLoop()
	return s, nil
}

func (s *PTCPServer) readLoop() {
	for {
		select {
		case <-s.done:
			return
		default:
		}
		seg, err := readRawTCP(s.raw, s.rbuf)
		if err != nil {
			if errors.Is(err, errTimeout) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if seg.dport != s.port || seg.flags&ptcpRST != 0 {
			continue
		}
		key := seg.src.String() + ":" + fmt.Sprint(seg.sport)
		local := seg.dst // the v4 raw read carries our own address
		if local == nil || local.IsUnspecified() {
			if ip, err := localAddrFor(seg.src); err == nil {
				local = ip
			}
		}
		s.mu.Lock()
		s.local[key] = local
		f := s.flows[key]
		if seg.flags&ptcpSYN != 0 {
			f = &ptcpSess{isn: rand.Uint32()}
			f.cseq = seg.seq + 1
			f.sseq = f.isn + 1
			s.flows[key] = f
			_ = sendRawTCP(s.raw, seg.src, ptcpBuild(local, seg.src, s.port, seg.sport, f.isn, f.cseq, ptcpSYN|ptcpACK, 0, nil))
			s.mu.Unlock()
			continue
		}
		if f == nil {
			s.mu.Unlock()
			continue
		}
		if len(seg.data) > 0 {
			if e := seg.seq + uint32(len(seg.data)); int32(e-f.cseq) > 0 {
				f.cseq = e
			}
			data := seg.data
			if !f.hello {
				// the ClientHello first flight is camouflage; the client may put the flow's first datagram right
				// after it in the same segment, so strip exactly the TLS record and keep the rest
				f.hello = true
				if len(data) >= 5 && data[0] == 0x16 {
					if n := 5 + int(binary.BigEndian.Uint16(data[3:5])); n <= len(data) {
						data = data[n:]
					}
				}
			}
			if len(data) > 0 {
				seg.data = data
				f.segs++
				select {
				case s.rx <- seg:
				default:
				}
				if f.segs%ptcpAckEvery == 0 {
					_ = sendRawTCP(s.raw, seg.src, ptcpBuild(local, seg.src, s.port, seg.sport, f.sseq, f.cseq, ptcpACK, 0, nil))
				}
			}
		}
		s.mu.Unlock()
	}
}

func (s *PTCPServer) Recv() ([]byte, int, net.Addr, error) {
	select {
	case seg := <-s.rx:
		return seg.data, 0, &net.TCPAddr{IP: seg.src, Port: int(seg.sport)}, nil
	case <-s.done:
		return nil, 0, nil, net.ErrClosed
	}
}

// SendTo writes one datagram as a data segment down the flow the address names.
func (s *PTCPServer) SendTo(dat []byte, _ int, dst net.Addr) error {
	if len(dat) > ptcpMTU {
		return errors.New("wat: ptcp datagram exceeds the segment size")
	}
	ta, ok := dst.(*net.TCPAddr)
	if !ok {
		return errors.New("wat: ptcp peer address is not a TCP addr")
	}
	key := ta.IP.String() + ":" + fmt.Sprint(ta.Port)
	s.mu.Lock()
	f := s.flows[key]
	local := s.local[key]
	s.mu.Unlock()
	if f == nil {
		return errors.New("wat: ptcp flow is gone")
	}
	err := sendRawTCP(s.raw, ta.IP, ptcpBuild(local, ta.IP, s.port, uint16(ta.Port), f.sseq, f.cseq, ptcpPSH|ptcpACK, 0, dat))
	f.sseq += uint32(len(dat))
	return err
}

func (s *PTCPServer) Close() error {
	s.once.Do(func() { close(s.done) })
	if s.fw != nil {
		s.fw.clear()
	}
	return closeRaw(s.raw)
}
