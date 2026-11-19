//go:build linux

// spray-raw: ceiling probe for raw-socket UDP 5-tuple rotation. The 2026-11-14 field run showed
// per-5-tuple packet-count cutters kill a flow at ~29-34 packets while rotation itself passed
// 99.7% of datagrams, and the userspace spray test stalled at ~4,000 sockets/s on synchronous
// DialUDP+Close. This mode removes the socket churn: one SOCK_RAW/IPPROTO_UDP socket, our own
// 8-byte UDP header (checksum 0, legal on IPv4), the kernel builds the IPv4 header, sport+dport
// rotate every 12-20 packets (jittered), and bursts go out through sendmmsg. A return path is
// pinned: one ordinary UDP socket whose port rides in every payload, and the receiver replies
// ordinary UDP to it so the sender can report the reply delivery ratio.
//
// Usage (owner runs this on the authorized live pair, IPv4 only, root on both ends):
//
//	Kharej (recv):  ./fieldprobe -role recv -port 40400 -spray-dports 41000-41999 -for 10m
//	Iran  (send):   ./fieldprobe -role send -peer KHAREJ_IP -port 40400 -tests spray-raw \
//	                -size 1400 -secs 5 -spray-rates 30,60,100 -spray-tuples 5000
//
// Keep -port outside -spray-dports (defaults already are) so the probe datagrams never land on
// the receiver's ordinary UDP socket. Sender output: one SPRAYRAW line per rate; the receiver
// prints the usual RESULT line plus pkts_per_tuple_max / tuples_over_34 (rotation should hold
// every tuple under the ~34-packet cut, so tuples_over_34 should stay 0).
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const magic2 = "WFP2"

// srHdrSize: magic, id, flow(=tuple id), seq, total, flows, replyport.
const srHdrSize = 23

// fillRaw writes the spray-raw header into dst (rest of the payload stays zero, like mk).
func fillRaw(dst []byte, id byte, flow, seq uint32, replyPort uint16) {
	copy(dst, magic2)
	dst[4] = id
	binary.BigEndian.PutUint32(dst[5:], flow)
	binary.BigEndian.PutUint32(dst[9:], seq)
	binary.BigEndian.PutUint16(dst[21:], replyPort)
}

type srHdr struct {
	id        byte
	flow, seq uint32
	replyPort uint16
}

func parse2(b []byte) (srHdr, bool) {
	if len(b) < srHdrSize || string(b[:4]) != magic2 {
		return srHdr{}, false
	}
	return srHdr{
		id:        b[4],
		flow:      binary.BigEndian.Uint32(b[5:]),
		seq:       binary.BigEndian.Uint32(b[9:]),
		replyPort: binary.BigEndian.Uint16(b[21:]),
	}, true
}

// ---- raw UDP send: kernel builds the IPv4 header, we write the UDP header (checksum 0, RFC 768)

func fillUDPHdr(b []byte, sport, dport uint16, plen int) {
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(8+plen))
	// b[6:8] checksum stays 0: optional on IPv4, and the kernel does not compute it for raw sends
}

// x/sys has no Mmsghdr (dropped long ago), so sendmmsg goes through Syscall6 directly.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte // pad to 64 bytes; fieldprobe targets 64-bit linux only (amd64/arm64)
}

// sendmmsgRaw sends the batch and returns how many messages the kernel accepted (a partial batch
// is possible under ENOBUFS-style backpressure — the caller must count sent, not attempted, or the
// reply ratio and MB/s lie; 2026-11-20 review F8).
func sendmmsgRaw(fd int, pkts [][]byte, sa *unix.SockaddrInet4) (int, error) {
	iovs := make([]unix.Iovec, len(pkts))
	hdrs := make([]mmsghdr, len(pkts))
	for i, p := range pkts {
		iovs[i].Base = &p[0]
		iovs[i].SetLen(len(p))
		hdrs[i].hdr.Name = (*byte)(unsafe.Pointer(sa))
		hdrs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		hdrs[i].hdr.Iov = &iovs[i]
	}
	sent := 0
	for done := 0; done < len(pkts); {
		n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
			uintptr(unsafe.Pointer(&hdrs[done])), uintptr(len(pkts)-done), 0, 0, 0)
		if errno != 0 {
			return sent, errno
		}
		if n == 0 {
			return sent, io.ErrUnexpectedEOF
		}
		sent += int(n)
		done += int(n)
	}
	return sent, nil
}

// ---- sender side

func (s *sender) sprayRaw(ctx context.Context, id byte) string {
	if s.peer.To4() == nil {
		return "spray-raw: IPv4 only (SOCK_RAW/IPPROTO_UDP builds an IPv4 header)"
	}
	var rates []float64
	for _, f := range strings.Split(*sprayRates, ",") {
		r, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
		if err != nil || r <= 0 {
			return fmt.Sprintf("bad -spray-rates %q", *sprayRates)
		}
		rates = append(rates, r)
	}
	sports, ok := parsePortRange(*spraySports)
	if !ok {
		return fmt.Sprintf("bad -spray-ports %q (want lo-hi)", *spraySports)
	}
	dports, ok := parsePortRange(*sprayDports)
	if !ok {
		return fmt.Sprintf("bad -spray-dports %q (want lo-hi)", *sprayDports)
	}
	if *size < srHdrSize {
		*size = srHdrSize
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return "raw udp socket: " + err.Error()
	}
	defer unix.Close(fd)

	// Pinned return path: one ordinary UDP socket; its port rides in every payload.
	rc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: s.local.To4()})
	if err != nil {
		return "reply socket: " + err.Error()
	}
	defer rc.Close()
	replyPort := uint16(rc.LocalAddr().(*net.UDPAddr).Port)
	var replies atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := rc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, ok := parse2(buf[:n]); ok {
				replies.Add(1)
			}
		}
	}()

	var f fw
	defer f.clear()
	// replies come back from the receiver's ordinary socket on -port
	f.add("iptables", "INPUT", "-p", "udp", "--sport", fmt.Sprint(*port), "-j", "ACCEPT")

	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], s.peer.To4())
	bufs := make([][]byte, 20) // one buffer per packet of the largest burst, reused every burst
	for i := range bufs {
		bufs[i] = make([]byte, 8+*size)
	}
	for _, r := range rates {
		sched := newTupleSched(sports, dports, int64(rnd32()))
		tb := newTokenBucket(*sprayTupleCap)
		p := &pacer{start: time.Now(), bps: r * 1e6}
		end := time.Now().Add(time.Duration(*secs) * time.Second)
		pkts, sent, tuples := 0, 0, 0 // attempted, kernel-accepted, tuples (F8: ratio and MB/s go by sent)
		r0 := replies.Load()
		for time.Now().Before(end) && ctx.Err() == nil {
			if d := tb.delay(time.Now()); d > 0 {
				time.Sleep(d)
				continue
			}
			sport, dport, burst := sched.next()
			tuple := uint32(tuples)
			for i := 0; i < burst; i++ {
				fillUDPHdr(bufs[i], sport, dport, *size)
				fillRaw(bufs[i][8:], id, tuple, uint32(pkts+i), replyPort)
			}
			n, err := sendmmsgRaw(fd, bufs[:burst], sa)
			if err != nil {
				log.Printf("sendmmsg: %v", err)
			}
			pkts += burst
			sent += n
			tuples++
			p.wait(burst * *size)
		}
		el := time.Since(p.start).Seconds()
		time.Sleep(1500 * time.Millisecond) // let tail replies arrive before reading the counter
		got := replies.Load() - r0
		ratio := 0.0
		if sent > 0 {
			ratio = float64(got) / float64(sent)
		}
		tps := 0.0
		if el > 0 {
			tps = float64(tuples) / el
		}
		fmt.Printf("SPRAYRAW rate=%.0f pkts=%d sent=%d MB/s=%.2f tuples=%d tuples/s=%.0f replies=%d reply_ratio=%.4f\n",
			r, pkts, sent, float64(sent**size)/el/1e6, tuples, tps, got, ratio)
		time.Sleep(500 * time.Millisecond) // receiver flushes a test after 2 s idle
	}
	return fmt.Sprintf("rates=%v size=%d sports=%s dports=%s tuple_cap=%.0f/s reply_port=%d",
		rates, *size, *spraySports, *sprayDports, *sprayTupleCap, replyPort)
}

// ---- receiver side

// bpfDport converts the platform-independent program (sprayraw_sched.go, where its test runs) to
// the kernel's sock_filter shape.
func bpfDport(lo, hi uint16) []unix.SockFilter {
	prog := bpfDportProgram(lo, hi)
	out := make([]unix.SockFilter, len(prog))
	for i, ins := range prog {
		out[i] = unix.SockFilter{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return out
}

// recvSprayUDP listens on one raw IPPROTO_UDP socket filtered to the spray dport range — a range
// does not fit the ≤16 bound-socket alternative, and one raw socket reuses fieldprobe's
// single-listener structure. Every parsed packet is counted on the board (flow = tuple id) and
// answered with one ordinary UDP datagram from the main socket to the payload's reply port.
func recvSprayUDP(b *board, f *fw, reply *net.UDPConn) {
	dports, ok := parsePortRange(*sprayDports)
	if !ok {
		log.Printf("spray-raw recv: bad -spray-dports %q", *sprayDports)
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		log.Printf("spray-raw recv: raw udp socket: %v", err)
		return
	}
	defer unix.Close(fd)
	prog := bpfDport(dports.lo, dports.hi)
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Filter: &prog[0], Len: uint16(len(prog)),
	}); err != nil {
		log.Printf("spray-raw recv: BPF filter: %v (continuing unfiltered)", err)
	}
	f.add("iptables", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d:%d", dports.lo, dports.hi), "-j", "ACCEPT")
	// no socket is bound on the spray dports: silence the kernel's port-unreachable ICMPs
	f.add("iptables", "OUTPUT", "-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP")

	log.Printf("spray-raw recv: raw udp, dports %d-%d", dports.lo, dports.hi)
	buf := make([]byte, 65536)
	rp := make([]byte, srHdrSize) // one reply per received packet, echoing its header
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok || n < 28 { // 20 IP + 8 UDP
			continue
		}
		ihl := int(buf[0]&0xf) * 4
		if buf[9] != unix.IPPROTO_UDP || ihl+8 > n {
			continue
		}
		h, ok := parse2(buf[ihl+8:])
		if !ok {
			continue
		}
		b.rec(hdr{h.id, h.flow, h.seq, 0, 0}, false, n-ihl-8)
		copy(rp, buf[ihl+8:ihl+8+srHdrSize])
		_, _ = reply.WriteToUDP(rp, &net.UDPAddr{IP: net.IP(sa.Addr[:]).To4(), Port: int(h.replyPort)})
	}
}
