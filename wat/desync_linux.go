//go:build linux

package wat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Raw injection of the fake ClientHello (see desync.go): one AF_PACKET sniffer watches every IPv4 and IPv6 TCP
// packet of the host and advances the portable tracker. Requires CAP_NET_RAW, like the ICMP carrier.
//
// Wrap announces each pool connection the moment dial returns. The stream start is probed off the socket with
// TCP_REPAIR + TCP_QUEUE_SEQ (the only kernel interface that reports a socket's sequence numbers; TCP_INFO does
// not carry one), so the fake normally fires on the handshake's final ACK — before any real data — even when the
// sniffer missed the SYN/SYN-ACK. When the probe fails (needs CAP_NET_ADMIN), Wrap announces the key with
// isnKnown=false and the tracker fires anchored to the first outbound data segment instead (the late path of
// desync.go). A 500 ms timeout releases a Wrap whose handshake was never observed: the tunnel still works, it is
// just unclassified (or, with WAT_DESYNC_FAIL_CLOSED=1, the dial fails and the pool redials).

// desyncWrapTimeout bounds how long Wrap waits for the fake before giving up on classification. The fake normally
// fires inside announce (the sniffer remembered the handshake), so this only covers a handshake it never saw.
const desyncWrapTimeout = 500 * time.Millisecond

// desyncFailClosed (WAT_DESYNC_FAIL_CLOSED=1, 3.0.0): a connection whose marker was never seen to land (fake not
// fired, or no duplicate ACK after the retransmit) fails its dial, so the pool redials instead of running a flow the
// filter may cut. Off by default: direct rst needs no duplicate ACK, and an unclassified flow still works on most
// routes.
var desyncFailClosed = os.Getenv("WAT_DESYNC_FAIL_CLOSED") == "1"

var errDesyncUnconfirmed = errors.New("wat: fake-sni marker not confirmed (WAT_DESYNC_FAIL_CLOSED)")

// ackWaitFor is how long Wrap waits for the duplicate ACK of the marker: two handshake RTTs (one for the marker, one
// spare for its retransmit), at least 300 ms, at most 2 s. Before 3.0.0 it was a fixed 200 ms, less than one RTT on
// a 250 ms path, so the real hello often left before the filter had seen the fake.
func ackWaitFor(rtt time.Duration) time.Duration {
	return min(max(2*rtt, 300*time.Millisecond), 2*time.Second)
}

// handshakeRTT reads the kernel's smoothed RTT for the socket (TCP_INFO); right after connect it is the handshake RTT.
func handshakeRTT(tc *net.TCPConn) time.Duration {
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0
	}
	var rtt time.Duration
	_ = raw.Control(func(fd uintptr) {
		if ti, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			rtt = time.Duration(ti.Rtt) * time.Microsecond
		}
	})
	return rtt
}

// bytesAcked is the socket's acknowledged byte count (TCP_INFO bytes_acked, Linux 4.6+); the filter probe's signal.
func bytesAcked(tc *net.TCPConn) (n uint64, ok bool) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	_ = raw.Control(func(fd uintptr) {
		if ti, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			n, ok = ti.Bytes_acked, true
		}
	})
	return n, ok
}

// tcpStreamBase returns the socket's send-queue sequence number (SND.NXT) and receive-queue sequence number
// (RCV.NXT) as the stream-start anchor for the tracker. TCP_REPAIR freezes the socket's queues without touching its
// buffers; TCP_REPAIR_QUEUE selects the send/recv queue and TCP_QUEUE_SEQ then reports its sequence number.
// ok false = probe unavailable (it needs CAP_NET_ADMIN): the tracker falls back to the wire-learned ISN.
func tcpStreamBase(tc *net.TCPConn) (nxt, rcv uint32, ok bool) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var serr error
	verr := raw.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, 1); serr != nil {
			return
		}
		defer func() { _ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, 0) }()
		// Linux include/uapi/linux/tcp.h: TCP_NO_QUEUE=0, TCP_RECV_QUEUE=1, TCP_SEND_QUEUE=2
		const tcpRecvQueue = 1
		const tcpSendQueue = 2
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue); serr != nil {
			return
		}
		// x/sys/unix has no TCP_QUEUE_SEQ getsockopt wrapper; the raw getsockopt is 4 bytes, host order
		var b [4]byte
		l := uint32(4)
		if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.IPPROTO_TCP), unix.TCP_QUEUE_SEQ,
			uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0); errno != 0 {
			serr = errno
			return
		}
		nxt = binary.LittleEndian.Uint32(b[:])

		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRecvQueue); serr != nil {
			return
		}
		l = uint32(4)
		if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.IPPROTO_TCP), unix.TCP_QUEUE_SEQ,
			uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0); errno != 0 {
			serr = errno
			return
		}
		rcv = binary.LittleEndian.Uint32(b[:])
	})
	if verr != nil || serr != nil || nxt == 0 {
		return 0, 0, false
	}
	return nxt, rcv, true
}

// Desync is the fake-SNI injector of one client process: created once with NewDesync, every pool connection
// passes through Wrap after the kernel handshake.
type Desync struct {
	inj *desyncInjector
}

// NewDesync starts the sniffer for the peer (host:port or IP). Linux only; needs CAP_NET_RAW.
func NewDesync(cfg DesyncConfig, peer string) (*Desync, error) {
	if err := validateDesync(cfg); err != nil {
		return nil, err
	}
	ipStr, _ := desyncPeerHostPort(peer)
	p, ok := ipAddrOf(net.ParseIP(ipStr))
	if !ok {
		return nil, errors.New("wat: desync needs an IP -peer")
	}
	inj, err := newDesyncInjector(cfg, p)
	if err != nil {
		return nil, err
	}
	for _, ip := range desyncAllPeerIPs(peer) {
		inj.tr.addPeerIP(ip)
	}
	return &Desync{inj: inj}, nil
}

// PeerTTL reports the inbound TTL the sniffer learned from the peer's SYN-ACK (0 = none seen): the probe
// uses it so its sum marker mirrors what the production marker would send.
func (d *Desync) PeerTTL() int { return int(d.inj.tr.peerTTL()) }

// Wrap announces the connection to the sniffer, waits for the fake to fire, and returns the connection unchanged.
// A connection that is not a plain TCP connection passes through unwrapped; a handshake the sniffer never
// sees (offload paths) passes through after desyncWrapTimeout.
func (d *Desync) Wrap(c net.Conn) (net.Conn, error) { // the tls/wss/h2 carriers hand their hook an already-handshaked *tls.Conn (or a WS/HTTP framing wrapper);
	// unwrap to the socket underneath, like newPoolConn does (rawTCP)
	tc := rawTCP(c)
	if tc == nil {
		return c, nil
	}
	la, ok := tc.LocalAddr().(*net.TCPAddr)
	ra, ok2 := tc.RemoteAddr().(*net.TCPAddr)
	if !ok || !ok2 {
		return c, nil
	}
	s, sok := ipAddrOf(la.IP)
	r, rok := ipAddrOf(ra.IP)
	if !sok || !rok {
		return c, nil
	}
	k := desyncKey{s, r, uint16(la.Port), uint16(ra.Port)}
	// The probe reports SND.NXT = the next unsent sequence number and RCV.NXT = the next expected byte from the peer.
	// The tracker's announce stores the ISN (the stream start minus one): the early fire compares segment seq against synSeq+1,
	// and the NAT follow rebuilds synSeq from a SYN-ACK's ack the same way. Handshake just finished => SND.NXT = ISN+1 => ISN = SND.NXT-1.
	isn, rcvNxt, known := tcpStreamBase(tc)
	if known {
		isn--
	}
	d.inj.tr.addPeerIP(r)
	ch := d.inj.tr.announce(k, isn, known, rcvNxt)
	ackCh := d.inj.tr.ackChan(k)
	if !known { // no socket probe: the fake fires late, off the first data segment, which only the caller's write produces
		select {
		case <-ch:
		default:
			return c, nil
		}
	}
	select {
	case <-ch: // fake fired on announce or on the handshake's final ACK
	case <-time.After(desyncWrapTimeout): // never observed: connect anyway, the tunnel still works
		d.inj.tr.abandon(k)
		if desyncFailClosed {
			c.Close() // the caller only gets the error: the conn would leak
			return nil, errDesyncUnconfirmed
		}
		return c, nil
	}
	// patterniha duplicate ACK synchronization:
	// Wait for the server (Cloudflare) to send back a duplicate ACK for the out-of-window
	// fake packet before sending real data. This ensures:
	// 1) The fake packet traversed the middlebox DPI and reached Cloudflare.
	// 2) The DPI parsed the fake SNI and whitelisted this TCP 5-tuple.
	// 3) At least one RTT separates the fake packet and the real ClientHello.
	// 3.0.0: the wait follows the path RTT, and the marker is sent once more after one RTT without the ACK (a lost
	// marker otherwise left the flow unclassified).
	if ackCh != nil && d.inj.tr.needsAck() {
		rtt := handshakeRTT(tc)
		total := ackWaitFor(rtt)
		first := min(max(rtt+rtt/4, 50*time.Millisecond), total/2)
		if rtt == 0 { // no TCP_INFO: no RTT to judge a lost marker by, resend halfway
			first = total / 2
		}
		select {
		case <-ackCh: // duplicate ACK received from server!
			return c, nil
		case <-time.After(first):
		}
		d.inj.tr.resend(k)
		select {
		case <-ackCh:
		case <-time.After(total - first): // safety fallback
			d.inj.tr.abandon(k)
			if desyncFailClosed {
				c.Close()
				return nil, errDesyncUnconfirmed
			}
		}
	}
	return c, nil
}

// Close stops the sniffer.
func (d *Desync) Close() error { d.inj.close(); return nil }

// ---------------------------------------------------------------- injector

// desyncInjector is one sniffer for the pool of one client process, over the portable tracker.
type desyncInjector struct {
	tr      *desyncTracker
	fd      int
	closing atomic.Bool
	wg      sync.WaitGroup
	closed  sync.Once
}

// newDesyncInjector starts the sniffer. peerIP is the pool's server IP.
func newDesyncInjector(cfg DesyncConfig, peerIP ipAddr) (*desyncInjector, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("wat: -fake-sni needs CAP_NET_RAW: %w", err)
	}
	d := &desyncInjector{fd: fd, tr: newDesyncTracker(cfg, peerIP)}
	d.tr.send = d.sendRaw
	d.wg.Add(1)
	go d.loop()
	return d, nil
}

func (d *desyncInjector) close() {
	d.closed.Do(func() {
		d.closing.Store(true)
		d.tr.close()
		d.wg.Wait()
		unix.Close(d.fd)
	})
}

// loop reads ethernet frames and feeds them to the tracker.
func (d *desyncInjector) loop() {
	defer d.wg.Done()
	// 64 KB: AF_PACKET delivers one frame per read, and TSO/GRO can hand the tap multi-KB
	// super-frames; a 2048-byte read silently truncated them and the fake trigger was missed
	// intermittently (audit 2026-10-22).
	buf := make([]byte, 65536)
	pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
	for !d.closing.Load() {
		// Poll with 200 ms timeout so the goroutine sleeps in the kernel when idle instead of spinning on EAGAIN.
		nReady, err := unix.Poll(pfd, 200)
		if d.closing.Load() {
			return
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if nReady == 0 {
			continue
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return
		}
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		if ip := parseEthIP(buf[:n]); ip != nil {
			d.tr.handleIP(ip)
		}
	}
}

// sendRaw writes one crafted IPv4 or IPv6 packet through a raw IP socket (HDRINCL, the kernel fills the IPv4
// checksum; IPv6 has none to fill). One socket per fire: a fire happens once per pool connection, orders of
// magnitude too rare to matter.
func (d *desyncInjector) sendRaw(pkt []byte) {
	sendRawPacket(pkt)
}

// sendRawPacket is the raw injector every fire path shares (the tracker's send seam and the startup probe).
// A send failure means the fake never left the host and the real SNI went out unprotected: count it and say
// so once - silently shipping the real SNI is the one failure this package must not hide (audit 2026-10-22).
var rawSendFails atomic.Uint64

func sendRawPacket(pkt []byte) {
	if len(pkt) < 24 {
		return
	}
	if pkt[0]>>4 == 6 {
		sendRawPacket6(pkt)
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		rawSendFail(1, err)
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	src := pkt[12:16]
	if src[0] != 0 || src[1] != 0 || src[2] != 0 || src[3] != 0 {
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{src[0], src[1], src[2], src[3]}}); err != nil {
			// a re-homed host can lose the old source IP: send unbound (the kernel picks one)
			// instead of dropping the fire
			note("wat: fake-sni could not bind the old source IP (%v); sending unbound", err)
		}
	}
	dst := pkt[16:20]
	if err := unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Port: int(binary.BigEndian.Uint16(pkt[22:])), Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}}); err != nil {
		rawSendFail(1, err)
	}
}

// sendRawPacket6 is sendRawPacket's IPv6 half: IPV6_HDRINCL (the IPv6 analogue of IP_HDRINCL — Linux still fills
// the TCP checksum's pseudo-header contribution itself only for IPv4; fakePacketWithOptions/fakeFlagPacket compute
// the IPv6 TCP checksum themselves via tcpChecksum, so nothing is left for the kernel to add here).
func sendRawPacket6(pkt []byte) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		rawSendFail(1, err)
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	var src [16]byte
	copy(src[:], pkt[8:24])
	if src != ([16]byte{}) {
		if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: src}); err != nil {
			note("wat: fake-sni could not bind the old source IP (%v); sending unbound", err)
		}
	}
	var dst [16]byte
	copy(dst[:], pkt[24:40])
	// Port 0, unlike the IPv4 socket: on a raw IPv6 socket sin6_port is read as the protocol number (the kernel
	// answers EINVAL above 255), and 0 means "the socket's own protocol"; the header's next-header field (TCP) is
	// what actually goes out because of IPV6_HDRINCL.
	if err := unix.Sendto(fd, pkt, 0, &unix.SockaddrInet6{Addr: dst}); err != nil {
		rawSendFail(1, err)
	}
}

// rawSendFail counts failed fires and complains once per process: raw egress can be filtered while the
// AF_PACKET sniffer still works, and that is exactly the environment where silence is dangerous.
func rawSendFail(n uint64, err error) {
	if rawSendFails.Add(n) == n { // first failure
		note("wat: fake-sni raw send failed (%v); the real SNI may be going out unprotected (counted as raw_send_fails)", err)
	}
}
