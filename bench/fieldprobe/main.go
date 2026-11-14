//go:build linux

// fieldprobe: one-shot field test for the planned Spray and Phantom (ptcp) carriers, over IPv4 and IPv6.
// No tunnel, no key. Run the receiver on one server and the sender on the other; swap roles for the other direction.
//
//	recv:  fieldprobe -role recv -port 40400            (prints one RESULT line per test; Ctrl-C or -for ends it)
//	send:  fieldprobe -role send -peer IP -port 40400   (IP may be v4 or v6; runs every test, ~40 s)
//
// While running it inserts iptables/ip6tables rules (ACCEPT the probe port, DROP the kernel's RSTs for the fake TCP
// flows) and deletes them on exit. Needs root (raw sockets).
//
// Tests (payload carries test id, flow, seq, so the receiver counts what arrived):
//
//	udp         one UDP flow, 50 datagrams: the control (the Iran->Kharej cut shows here as ~3 arrived)
//	spray       50 UDP flows (fresh source port each) x 3 datagrams: all 150 arrive = cut is per 5-tuple
//	ptcp        fake TCP: raw SYN, SYN-ACK from the receiver, a TLS ClientHello, then 50 data segments
//	ptcp-spray  50 fake TCP flows, data in the SYN plus one more segment each
//	udp-bulk    one UDP flow at -rate MB/s for -secs
//	spray-bulk  UDP, new source port every 2 datagrams, at -rate for -secs (watch persec: a block mid-run shows)
//	ptcp-bulk   one fake TCP flow at -rate for -secs
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
	"golang.org/x/sys/unix"
)

const (
	magic   = "WFP1"
	hdrSize = 21    // magic, id, flow, seq, total, flows
	spLo    = 61000 // fake TCP source ports, above the default ephemeral range so no kernel socket owns them
	spHi    = 64999
)

var testIDs = map[string]byte{"udp": 1, "spray": 2, "ptcp": 3, "ptcp-spray": 4, "udp-bulk": 5, "spray-bulk": 6, "ptcp-bulk": 7}

func testName(id byte) string {
	for n, i := range testIDs {
		if i == id {
			return n
		}
	}
	return fmt.Sprintf("id%d", id)
}

var (
	role  = flag.String("role", "", "recv|send")
	peerF = flag.String("peer", "", "send: receiver IP (v4 or v6)")
	port  = flag.Int("port", 40400, "probe port (UDP and fake TCP), same on both ends")
	tests = flag.String("tests", "udp,spray,ptcp,ptcp-spray,udp-bulk,spray-bulk,ptcp-bulk", "send: tests to run, in order")
	rate  = flag.Float64("rate", 10, "send: bulk tests, MB/s")
	secs  = flag.Int("secs", 5, "send: bulk tests, seconds each")
	size  = flag.Int("size", 1200, "payload bytes per packet")
	sni   = flag.String("sni", "www.google.com", "send: SNI of the ptcp ClientHello")
	dur   = flag.Duration("for", 10*time.Minute, "recv: stop after this long")
	nofw  = flag.Bool("no-fw", false, "do not touch iptables")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)
	if *size < hdrSize {
		*size = hdrSize
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch *role {
	case "recv":
		recv(ctx)
	case "send":
		send(ctx)
	default:
		log.Fatal("-role recv|send")
	}
}

// ---- payload ----

func mk(id byte, flow, seq, total, flows uint32) []byte {
	b := make([]byte, *size)
	copy(b, magic)
	b[4] = id
	binary.BigEndian.PutUint32(b[5:], flow)
	binary.BigEndian.PutUint32(b[9:], seq)
	binary.BigEndian.PutUint32(b[13:], total)
	binary.BigEndian.PutUint32(b[17:], flows)
	return b
}

type hdr struct {
	id                      byte
	flow, seq, total, flows uint32
}

func parse(b []byte) (hdr, bool) {
	if len(b) < hdrSize || string(b[:4]) != magic {
		return hdr{}, false
	}
	return hdr{b[4], binary.BigEndian.Uint32(b[5:]), binary.BigEndian.Uint32(b[9:]), binary.BigEndian.Uint32(b[13:]), binary.BigEndian.Uint32(b[17:])}, true
}

// ---- firewall ----

type fw struct{ rules [][]string } // each rule: bin, chain, match args...

func (f *fw) add(bin string, rule ...string) {
	if *nofw {
		return
	}
	if out, err := exec.Command(bin, append([]string{"-I"}, rule...)...).CombinedOutput(); err != nil {
		log.Printf("%s -I %s: %v %s", bin, strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
		return
	}
	f.rules = append(f.rules, append([]string{bin}, rule...))
}

func (f *fw) clear() {
	for _, r := range f.rules {
		_ = exec.Command(r[0], append([]string{"-D"}, r[1:]...)...).Run()
	}
	f.rules = nil
}

// ---- raw TCP ----

type rawSock struct {
	fd int
	v6 bool
}

func openRaw(v6 bool) (*rawSock, error) {
	af := unix.AF_INET
	if v6 {
		af = unix.AF_INET6
	}
	fd, err := unix.Socket(af, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	return &rawSock{fd, v6}, nil
}

type tcpPkt struct {
	src, dst     net.IP
	sport, dport uint16
	seq, ack     uint32
	flags        byte
	data         []byte
}

const (
	fFIN = 1 << iota
	fSYN
	fRST
	fPSH
	fACK
)

// read returns the next TCP segment (v4: the kernel includes the IP header; v6: it does not, the source is the
// sockaddr and the local address is not needed by the callers).
func (r *rawSock) read(buf []byte) (tcpPkt, error) {
	for {
		n, from, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			return tcpPkt{}, err
		}
		b := buf[:n]
		var p tcpPkt
		if r.v6 {
			sa, ok := from.(*unix.SockaddrInet6)
			if !ok {
				continue
			}
			p.src = net.IP(append([]byte(nil), sa.Addr[:]...))
		} else {
			if n < 20 {
				continue
			}
			ihl := int(b[0]&0xf) * 4
			if n < ihl+20 {
				continue
			}
			p.src = net.IP(append([]byte(nil), b[12:16]...))
			p.dst = net.IP(append([]byte(nil), b[16:20]...))
			b = b[ihl:]
		}
		if len(b) < 20 {
			continue
		}
		off := int(b[12]>>4) * 4
		if off < 20 || off > len(b) {
			continue
		}
		p.sport = binary.BigEndian.Uint16(b[0:])
		p.dport = binary.BigEndian.Uint16(b[2:])
		p.seq = binary.BigEndian.Uint32(b[4:])
		p.ack = binary.BigEndian.Uint32(b[8:])
		p.flags = b[13]
		p.data = append([]byte(nil), b[off:]...)
		return p, nil
	}
}

var t0 = time.Now()

func tsval() uint32 { return uint32(time.Since(t0).Milliseconds()) + 1 }

// write sends one segment shaped like Linux TCP: SYN/SYN-ACK carry MSS, SACK-permitted, timestamps and window scale;
// every other segment carries timestamps.
func (r *rawSock) write(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, tsecr uint32, data []byte) error {
	var opt []byte
	if flags&fSYN != 0 {
		opt = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7}
		binary.BigEndian.PutUint32(opt[8:], tsval())
		binary.BigEndian.PutUint32(opt[12:], tsecr)
	} else {
		opt = []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(opt[4:], tsval())
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
	win := uint16(502) // with wscale 7, like a Linux socket mid-flow
	if flags&fSYN != 0 {
		win = 64240
	}
	binary.BigEndian.PutUint16(seg[14:], win)
	copy(seg[20:], opt)
	copy(seg[hl:], data)
	binary.BigEndian.PutUint16(seg[16:], tcpSum(src, dst, seg))
	if r.v6 {
		var sa unix.SockaddrInet6
		copy(sa.Addr[:], dst.To16())
		return unix.Sendto(r.fd, seg, 0, &sa)
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst.To4())
	return unix.Sendto(r.fd, seg, 0, &sa)
}

func tcpSum(src, dst net.IP, seg []byte) uint16 {
	var ph []byte
	if s4, d4 := src.To4(), dst.To4(); s4 != nil && d4 != nil {
		ph = append(append(append([]byte{}, s4...), d4...), 0, 6, byte(len(seg)>>8), byte(len(seg)))
	} else {
		ph = append(append([]byte{}, src.To16()...), dst.To16()...)
		ph = binary.BigEndian.AppendUint32(ph, uint32(len(seg)))
		ph = append(ph, 0, 0, 0, 6)
	}
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

// localFor is the source address the kernel routes to peer (needed for the TCP checksum).
func localFor(peer net.IP) net.IP {
	c, err := net.Dial("udp", net.JoinHostPort(peer.String(), "9"))
	if err != nil {
		log.Fatalf("no route to %s: %v", peer, err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}

func rnd32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func rndPort() uint16 {
	n, _ := rand.Int(rand.Reader, big.NewInt(spHi-spLo+1))
	return uint16(spLo + n.Int64())
}

// ---- receiver ----

type key struct {
	id byte
	v6 bool
}

type stat struct {
	got, bytes, total, flows int
	flowSet                  map[uint32]bool
	first, last              time.Time
	sec                      []int // bytes per second since first
}

type board struct {
	mu    sync.Mutex
	m     map[key]*stat
	hello atomic.Int64 // ClientHello first flights seen on fake TCP
	acks  atomic.Int64
}

func (b *board) rec(h hdr, v6 bool, n int) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{h.id, v6}
	s := b.m[k]
	if s == nil {
		s = &stat{flowSet: map[uint32]bool{}, first: now}
		b.m[k] = s
	}
	s.got++
	s.bytes += n
	s.total, s.flows = int(h.total), int(h.flows)
	s.flowSet[h.flow] = true
	s.last = now
	i := int(now.Sub(s.first) / time.Second)
	for len(s.sec) <= i {
		s.sec = append(s.sec, 0)
	}
	s.sec[i] += n
}

// flush prints and drops every test idle for 2 s.
func (b *board) flush(all bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := make([]key, 0, len(b.m))
	for k := range b.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].id < keys[j].id })
	for _, k := range keys {
		s := b.m[k]
		if !all && time.Since(s.last) < 2*time.Second {
			continue
		}
		fam := "v4"
		if k.v6 {
			fam = "v6"
		}
		d := s.last.Sub(s.first).Seconds()
		line := fmt.Sprintf("RESULT test=%s %s got=%d", testName(k.id), fam, s.got)
		if s.total > 0 {
			line += fmt.Sprintf("/%d", s.total)
		}
		line += fmt.Sprintf(" flows=%d", len(s.flowSet))
		if s.flows > 0 {
			line += fmt.Sprintf("/%d", s.flows)
		}
		if d > 0.5 {
			line += fmt.Sprintf(" MB/s=%.2f", float64(s.bytes)/d/1e6)
			ps := make([]string, len(s.sec))
			for i, x := range s.sec {
				ps[i] = fmt.Sprintf("%.1f", float64(x)/1e6)
			}
			line += " persec=" + strings.Join(ps, ",")
		}
		if k.id == testIDs["ptcp"] {
			line += fmt.Sprintf(" hello=%d", b.hello.Swap(0))
		}
		fmt.Println(line)
		delete(b.m, k)
	}
}

func recv(ctx context.Context) {
	var f fw
	defer f.clear()
	p := fmt.Sprint(*port)
	for _, bin := range []string{"iptables", "ip6tables"} {
		f.add(bin, "INPUT", "-p", "udp", "--dport", p, "-j", "ACCEPT")
		f.add(bin, "INPUT", "-p", "tcp", "--dport", p, "-j", "ACCEPT")
		f.add(bin, "OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP")
	}
	b := &board{m: map[key]*stat{}}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port}) // [::]: v4 and v6
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if h, ok := parse(buf[:n]); ok {
				b.rec(h, a.IP.To4() == nil, n)
			}
		}
	}()
	for _, v6 := range []bool{false, true} {
		r, err := openRaw(v6)
		if err != nil {
			log.Printf("raw tcp v6=%v: %v (ptcp tests on it will show nothing)", v6, err)
			continue
		}
		go recvTCP(r, b)
	}
	log.Printf("receiving on port %d (udp + fake tcp, v4 + v6) for %s", *port, *dur)
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	end := time.After(*dur)
	for {
		select {
		case <-ctx.Done():
			b.flush(true)
			return
		case <-end:
			b.flush(true)
			return
		case <-tk.C:
			b.flush(false)
		}
	}
}

type rflow struct {
	isn, next uint32
	segs      int
	tsecr     uint32
}

// recvTCP answers SYNs with a SYN-ACK, ACKs every 4th data segment, and counts payloads.
func recvTCP(r *rawSock, b *board) {
	flows := map[string]*rflow{}
	local := map[string]net.IP{}
	buf := make([]byte, 65536)
	for {
		p, err := r.read(buf)
		if err != nil {
			return
		}
		if int(p.dport) != *port || p.flags&fRST != 0 {
			continue
		}
		dst := p.dst
		if dst == nil {
			if dst = local[p.src.String()]; dst == nil {
				dst = localFor(p.src)
				local[p.src.String()] = dst
			}
		}
		fk := fmt.Sprintf("%s:%d", p.src, p.sport)
		f := flows[fk]
		if p.flags&fSYN != 0 {
			f = &rflow{isn: rnd32(), next: p.seq + 1 + uint32(len(p.data))}
			flows[fk] = f
			_ = r.write(dst, p.src, p.dport, p.sport, f.isn, f.next, fSYN|fACK, 0, nil)
		}
		if len(p.data) == 0 {
			continue
		}
		if h, ok := parse(p.data); ok {
			b.rec(h, r.v6, len(p.data))
		} else if p.data[0] == 0x16 {
			b.hello.Add(1)
		}
		if f != nil && p.flags&fSYN == 0 {
			if e := p.seq + uint32(len(p.data)); int32(e-f.next) > 0 {
				f.next = e
			}
			if f.segs++; f.segs%4 == 0 {
				_ = r.write(dst, p.src, p.dport, p.sport, f.isn+1, f.next, fACK, 0, nil)
			}
		}
	}
}

// ---- sender ----

type pacer struct {
	start time.Time
	bps   float64
	sent  float64
}

func (p *pacer) wait(n int) {
	p.sent += float64(n)
	if d := time.Until(p.start.Add(time.Duration(p.sent / p.bps * 1e9))); d > 0 {
		time.Sleep(d)
	}
}

type sender struct {
	peer, local net.IP
	raw         *rawSock
	mu          sync.Mutex
	synack      map[uint16]chan tcpPkt
	acks        atomic.Int64
}

func send(ctx context.Context) {
	peer := net.ParseIP(*peerF)
	if peer == nil {
		ips, err := net.LookupIP(*peerF)
		if err != nil || len(ips) == 0 {
			log.Fatalf("-peer %q: not an IP", *peerF)
		}
		peer = ips[0]
	}
	v6 := peer.To4() == nil
	s := &sender{peer: peer, local: localFor(peer), synack: map[uint16]chan tcpPkt{}}
	var f fw
	defer f.clear()
	bin := "iptables"
	if v6 {
		bin = "ip6tables"
	}
	f.add(bin, "INPUT", "-p", "tcp", "--sport", fmt.Sprint(*port), "-j", "ACCEPT")
	f.add(bin, "OUTPUT", "-p", "tcp", "--sport", fmt.Sprintf("%d:%d", spLo, spHi), "--tcp-flags", "RST", "RST", "-j", "DROP")
	if r, err := openRaw(v6); err != nil {
		log.Printf("raw tcp: %v (ptcp tests skipped)", err)
	} else {
		s.raw = r
		go s.readLoop()
	}
	log.Printf("sending %s -> %s port %d", s.local, peer, *port)
	for i, t := range strings.Split(*tests, ",") {
		if ctx.Err() != nil {
			return
		}
		if i > 0 {
			time.Sleep(3 * time.Second) // receiver closes a test after 2 s idle
		}
		id, ok := testIDs[t]
		if !ok {
			log.Printf("unknown test %q", t)
			continue
		}
		if strings.HasPrefix(t, "ptcp") && s.raw == nil {
			continue
		}
		s.acks.Store(0)
		start := time.Now()
		line := s.run(ctx, t, id)
		fmt.Printf("SENT test=%s %s secs=%.1f\n", t, line, time.Since(start).Seconds())
	}
}

func (s *sender) readLoop() {
	buf := make([]byte, 65536)
	for {
		p, err := s.raw.read(buf)
		if err != nil {
			return
		}
		if int(p.sport) != *port || p.dport < spLo || p.dport > spHi {
			continue
		}
		if p.flags&(fSYN|fACK) == fSYN|fACK {
			s.mu.Lock()
			ch := s.synack[p.dport]
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch <- p:
				default:
				}
			}
		} else if p.flags&fACK != 0 {
			s.acks.Add(1)
		}
	}
}

type pflow struct {
	sport    uint16
	seq, ack uint32
	ch       chan tcpPkt
	got      bool
}

func (s *sender) newFlow() *pflow {
	f := &pflow{sport: rndPort(), seq: rnd32(), ch: make(chan tcpPkt, 1)}
	s.mu.Lock()
	s.synack[f.sport] = f.ch
	s.mu.Unlock()
	return f
}

func (s *sender) wr(f *pflow, flags byte, data []byte) {
	if err := s.raw.write(s.local, s.peer, f.sport, uint16(*port), f.seq, f.ack, flags, 0, data); err != nil {
		log.Printf("raw send: %v", err)
	}
	f.seq += uint32(len(data))
	if flags&fSYN != 0 {
		f.seq++
	}
}

// waitSynAck takes the SYN-ACK if it came; without one the flow goes on with ack 0, to see if data passes anyway.
func (f *pflow) waitSynAck(d time.Duration) {
	select {
	case p := <-f.ch:
		f.got = true
		f.ack = p.seq + 1
	case <-time.After(d):
	}
}

func (s *sender) run(ctx context.Context, t string, id byte) string {
	ua := &net.UDPAddr{IP: s.peer, Port: *port}
	bulk := func(each func(seq uint32) int) (int, int) {
		p := &pacer{start: time.Now(), bps: *rate * 1e6}
		end := time.Now().Add(time.Duration(*secs) * time.Second)
		n, flows := 0, 0
		for time.Now().Before(end) && ctx.Err() == nil {
			flows += each(uint32(n))
			n++
			p.wait(*size)
		}
		return n, flows
	}
	switch t {
	case "udp":
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			return err.Error()
		}
		defer c.Close()
		for i := uint32(0); i < 50; i++ {
			_, _ = c.Write(mk(id, 0, i, 50, 1))
			time.Sleep(20 * time.Millisecond)
		}
		return "pkts=50 flows=1"
	case "spray":
		for fl := uint32(0); fl < 50; fl++ {
			c, err := net.DialUDP("udp", nil, ua)
			if err != nil {
				return err.Error()
			}
			for i := uint32(0); i < 3; i++ {
				_, _ = c.Write(mk(id, fl, fl*3+i, 150, 50))
			}
			c.Close()
			time.Sleep(10 * time.Millisecond)
		}
		return "pkts=150 flows=50"
	case "udp-bulk":
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			return err.Error()
		}
		defer c.Close()
		n, _ := bulk(func(seq uint32) int { _, _ = c.Write(mk(id, 0, seq, 0, 1)); return 0 })
		return fmt.Sprintf("pkts=%d flows=1 rate=%.0fMB/s", n, *rate)
	case "spray-bulk":
		var c *net.UDPConn
		fl := uint32(0)
		n, flows := bulk(func(seq uint32) int {
			nf := 0
			if seq%2 == 0 {
				if c != nil {
					c.Close()
				}
				var err error
				if c, err = net.DialUDP("udp", nil, ua); err != nil {
					return 0
				}
				fl++
				nf = 1
			}
			_, _ = c.Write(mk(id, fl, seq, 0, 0))
			return nf
		})
		if c != nil {
			c.Close()
		}
		return fmt.Sprintf("pkts=%d flows=%d rate=%.0fMB/s", n, flows, *rate)
	case "ptcp", "ptcp-bulk":
		f := s.newFlow()
		s.wr(f, fSYN, nil)
		f.waitSynAck(1500 * time.Millisecond)
		s.wr(f, fACK, nil)
		s.wr(f, fPSH|fACK, wat.FakeClientHello(*sni))
		var n int
		if t == "ptcp" {
			for i := uint32(0); i < 50; i++ {
				s.wr(f, fPSH|fACK, mk(id, 0, i, 50, 1))
				time.Sleep(20 * time.Millisecond)
			}
			n = 50
		} else {
			n, _ = bulk(func(seq uint32) int { s.wr(f, fACK, mk(id, 0, seq, 0, 1)); return 0 })
		}
		time.Sleep(300 * time.Millisecond)
		return fmt.Sprintf("pkts=%d flows=1 synack=%v acks_back=%d", n, f.got, s.acks.Load())
	case "ptcp-spray":
		fs := make([]*pflow, 50)
		for i := range fs {
			fs[i] = s.newFlow()
			s.wr(fs[i], fSYN, mk(id, uint32(i), uint32(2*i), 100, 50))
			time.Sleep(10 * time.Millisecond)
		}
		synacks := 0
		for i, f := range fs {
			f.waitSynAck(time.Duration(0))
			if !f.got {
				f.waitSynAck(time.Second / 50)
			}
			if f.got {
				synacks++
			}
			s.wr(f, fPSH|fACK, mk(id, uint32(i), uint32(2*i+1), 100, 50))
		}
		return fmt.Sprintf("pkts=100 flows=50 synacks=%d/50", synacks)
	}
	return "?"
}
