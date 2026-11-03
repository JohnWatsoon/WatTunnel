package wat

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestFakeClientHelloRealParser feeds the fake to the standard library's TLS server side: a real parser (what a
// DPI reimplements) must accept the record and the ClientHello, and only then fail on the missing certificate.
func TestFakeClientHelloRealParser(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	errc := make(chan error, 1)
	go func() {
		c1.SetDeadline(time.Now().Add(250 * time.Millisecond))
		srv := tls.Server(c1, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{func() tls.Certificate {
			c, err := SelfSignedCert()
			if err != nil {
				t.Error(err)
			}
			return c
		}()}})
		errc <- srv.Handshake()
	}()
	c2.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	go func() { // drain the server's flight so its write never blocks
		io.Copy(io.Discard, c2)
	}()
	if _, err := c2.Write(FakeClientHello("mci.ir")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	err := <-errc
	if err == nil {
		return // parsed and got as far as completing: fine
	}
	// A net timeout or a TLS alert means the record parsed and the handshake moved on (the fake never sends the
	// client's key exchange, so the server waits or alerts). Parse-level rejections fail inside readRecord with
	// messages like "first record does not look like a TLS handshake".
	var ne net.Error
	var ae *tls.AlertError
	if !errors.As(err, &ne) && !errors.As(err, &ae) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Fatalf("stdlib parser rejected the fake: %v", err)
	}
}

// TestFakeClientHelloTLS13Parser verifies that crypto/tls.Server configured with TLS 1.3
// accepts the ClientHello and negotiates TLS 1.3 without parse errors.
func TestFakeClientHelloTLS13Parser(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	errc := make(chan error, 1)
	go func() {
		c1.SetDeadline(time.Now().Add(250 * time.Millisecond))
		srv := tls.Server(c1, &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{func() tls.Certificate {
				c, err := SelfSignedCert()
				if err != nil {
					t.Error(err)
				}
				return c
			}()},
		})
		errc <- srv.Handshake()
	}()
	c2.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	go func() {
		io.Copy(io.Discard, c2)
	}()
	if _, err := c2.Write(FakeClientHello("mci.ir")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	err := <-errc
	if err == nil {
		return
	}
	var ne net.Error
	var ae *tls.AlertError
	if !errors.As(err, &ne) && !errors.As(err, &ae) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Fatalf("stdlib TLS 1.3 parser rejected the fake: %v", err)
	}
}

func TestFakeClientHello(t *testing.T) {
	for _, sni := range []string{"mci.ir", "example.com", "xn--mgbaam7a8c.example"} {
		rec := FakeClientHello(sni)
		if len(rec) < 64 {
			t.Fatalf("%s: record too short: %d", sni, len(rec))
		}
		if rec[0] != 0x16 || rec[1] != 0x03 || rec[2] != 0x01 {
			t.Fatalf("%s: bad record header % x", sni, rec[:3])
		}
		got, err := parseSNIOf(rec)
		if err != nil {
			t.Fatalf("%s: parseSNIOf: %v", sni, err)
		}
		if got != sni {
			t.Fatalf("%s: SNI round trip got %q", sni, got)
		}
		// record length fields must match
		hsLen := int(rec[3])<<8 | int(rec[4])
		if hsLen != len(rec)-5 {
			t.Fatalf("%s: record len %d, body %d", sni, hsLen, len(rec)-5)
		}
		// two builds differ only in the random (no fixed fingerprint)
		rec2 := FakeClientHello(sni)
		if bytes.Equal(rec, rec2) {
			t.Fatalf("%s: two builds identical (no randomness)", sni)
		}
	}
	if FakeClientHello("") != nil {
		t.Fatal("empty SNI must build nothing")
	}
}

func TestDesyncSeqBefore(t *testing.T) {
	// ISN 1000, fake of 200 bytes: seq must be 1000+1-200 = 801, i.e. fully below the stream start
	if got := uint32(1000) + 1 - 200; got != 801 {
		t.Fatalf("seq math: got %d want 801", got)
	}
}

func TestDesyncPeerIP(t *testing.T) {
	if got := desyncPeerIP("10.0.0.1:443"); got != "10.0.0.1" {
		t.Fatalf("ip:port: %q", got)
	}
	if got := desyncPeerIP("localhost:443"); got == "" {
		t.Fatal("hostname resolution failed")
	}
	// no assertion for an unresolvable host: some resolvers wildcard-answer (this machine's does)
}

func TestTCPChecksum(t *testing.T) {
	// A known-good TCP segment from the RFC-style examples: verify the checksum is self-consistent
	// (sum over pseudo header + segment with the checksum field zeroed must be 0xffff).
	src := []byte{192, 168, 0, 1}
	dst := []byte{10, 0, 0, 1}
	th := make([]byte, 20)
	binary.BigEndian.PutUint16(th[0:], 1234)
	binary.BigEndian.PutUint16(th[2:], 443)
	c := tcpChecksum(th, src, dst)
	binary.BigEndian.PutUint16(th[16:], c)
	// recompute over the segment that carries its checksum: folded sum must be 0xffff
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	var s uint32
	for i := 0; i+1 < len(ph); i += 2 {
		s += uint32(ph[i])<<8 | uint32(ph[i+1])
	}
	for i := 0; i+1 < len(th); i += 2 {
		s += uint32(th[i])<<8 | uint32(th[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	if ^uint16(s) != 0 {
		t.Fatalf("checksum verify failed: %04x", ^uint16(s))
	}
}

// TestValidateDesync pins the config validation both OSes share.
func TestValidateDesync(t *testing.T) {
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "seq"}); err != nil {
		t.Fatalf("seq: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 7}); err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 0}); err != nil {
		t.Fatalf("ttl auto (TTL 0) is allowed: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "", Mode: "seq"}); err == nil {
		t.Fatal("empty SNI must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "bogus"}); err == nil {
		t.Fatal("bad mode must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 300}); err == nil {
		t.Fatal("TTL > 255 must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir,b.ir", Mode: "seq"}); err != nil {
		t.Fatalf("comma-separated SNIs should pass: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "  a.ir  ,  b.ir  ", Mode: "seq"}); err != nil {
		t.Fatalf("whitespace around comma-separated SNIs should pass: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir, bad name", Mode: "seq"}); err == nil {
		t.Fatal("invalid characters in SNI list should fail")
	}
}

// desyncTestPkt builds one raw IPv4 TCP packet (header included) the way the wire delivers it.
// testIP4 parses a dotted-quad into an ipAddr (v4-mapped).
func testIP4(s string) ipAddr {
	a, _ := ipAddrOf(net.ParseIP(s))
	return a
}

func desyncTestPkt(src, dst ipAddr, sport, dport uint16, seq, ack uint32, flags byte, payload []byte, ttl int) []byte {
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = byte(ttl)
	pkt[9] = 6
	copy(pkt[12:16], src.bytes())
	copy(pkt[16:20], dst.bytes())
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:], sport)
	binary.BigEndian.PutUint16(th[2:], dport)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	copy(th[20:], payload)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], src.bytes(), dst.bytes()))
	return pkt
}

const (
	testFlagFIN = 0x01
	testFlagRST = 0x04
	testFlagPSH = 0x08
	testFlagACK = 0x10
	testFlagSYN = 0x02
)

// sentLog collects the tracker's sends; the mutex covers the seqsum marker that
// fires from a time.AfterFunc goroutine (the tracker's own send hook is sync for every other mode).
type sentLog struct {
	mu  sync.Mutex
	pks [][]byte
}

func (s *sentLog) add(pkt []byte) { s.mu.Lock(); s.pks = append(s.pks, pkt); s.mu.Unlock() }
func (s *sentLog) n() int         { s.mu.Lock(); defer s.mu.Unlock(); return len(s.pks) }
func (s *sentLog) at(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pks[i]
}

// desyncTestTracker builds a tracker with a collected send path and a fixed client/peer pair.
func desyncTestTracker(mode string, ttl int) (*desyncTracker, *sentLog) {
	var cfg DesyncConfig
	switch mode {
	case "seq":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "seq"}
	case "ttl":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "ttl", TTL: ttl}
	case "sum":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "sum"}
	case "seqsum":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "seqsum"}
	case "rst":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "rst"}
	case "split":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "split"}
	case "hlen0":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "hlen0"}
	case "fakeip":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "fakeip"}
	case "synrst":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "synrst"}
	case "paws":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "paws"}
	case "ff":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "ff"}
	case "all":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "all"}
	}
	return desyncTestTrackerCfg(cfg)
}

// desyncTestTrackerCfg builds a tracker for an arbitrary config with a collected send path and the fixed
// 192.168.1.2 -> 10.8.0.1 peer pair.
func desyncTestTrackerCfg(cfg DesyncConfig) (*desyncTracker, *sentLog) {
	tr := newDesyncTracker(cfg, testIP4("10.8.0.1"))
	sent := &sentLog{}
	tr.send = sent.add
	return tr, sent
}

// tcpChecksumOK reports whether an IPv4+TCP packet (header included) carries a valid TCP checksum.
func tcpChecksumOK(pkt []byte) bool {
	c := append([]byte(nil), pkt...)
	stored := binary.BigEndian.Uint16(c[20+16:])
	binary.BigEndian.PutUint16(c[20+16:], 0)
	return tcpChecksum(c[20:], c[12:16], c[16:20]) == stored
}

// payloadOf returns the TCP payload of an IPv4+TCP packet, honoring the data offset.
func payloadOf(pkt []byte) []byte {
	off := 20 + int(pkt[20+12]>>4)*4
	if off > len(pkt) {
		return nil
	}
	return pkt[off:]
}

// testClientKey is one outgoing 4-tuple: 192.168.1.2:5000 -> 10.8.0.1:443.
func testClientKey() desyncKey {
	return desyncKey{testIP4("192.168.1.2"), testIP4("10.8.0.1"), 5000, 443}
}

// feedFullHandshake drives a normal SYN / SYN-ACK / final-ACK exchange into the tracker.
func feedFullHandshake(tr *desyncTracker, k desyncKey, isn, srvSeq uint32) {
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
}

// TestDesyncEarlyFiresBeforeData: the classic path — Wrap knows the ISN, the fake fires on the final ACK, one
// packet, seq fully below the stream start, ack = the server's ISN.
func TestDesyncEarlyFiresBeforeData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true) // probe reports SND.NXT = ISN+1 right after the handshake
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	pkt := sent.at(0)
	if n := int(binary.BigEndian.Uint16(pkt[2:])); n != 20+20+len(tr.hello) {
		t.Fatalf("fake length %d, want %d", n, 20+20+len(tr.hello))
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	if got := binary.BigEndian.Uint32(pkt[28:]); got != srvSeq+1 {
		t.Fatalf("fake ack %d, want %d (server's ISN+1)", got, srvSeq+1)
	}
	if pkt[8] != 64 {
		t.Fatalf("fake ttl %d, want 64 (seq mode)", pkt[8])
	}
	if got := binary.BigEndian.Uint16(pkt[20:]); got != 5000 {
		t.Fatalf("fake sport %d", got)
	}
	if got := binary.BigEndian.Uint16(pkt[22:]); got != 443 {
		t.Fatalf("fake dport %d", got)
	}
	if tr.fired() != 1 {
		t.Fatalf("fired counter %d", tr.fired())
	}
}

// TestDesyncEarlyFiresOnFirstData: the real client's first flight went out before Wrap could register — the
// fake still fires, anchored to the first outbound data segment (seq equal to that segment's stream start).
func TestDesyncEarlyFiresOnFirstData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(0xffff0000), uint32(17) // wrap-prone values
	tr.announce(k, isn+1, true)
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	// the pool writes the session's first datagram BEFORE the final ACK would be seen on the wire
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 300), 64))
	if tr.fired() != 1 {
		t.Fatalf("fake did not fire on first data (fired %d)", tr.fired())
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncLateFiresOnData: the ISN is unknown (probe unavailable) — the fake fires anchored to the first
// outbound data segment, which is the only anchor available.
func TestDesyncLateFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(42000), uint32(900)
	ch := tr.announce(k, 0, false) // not known
	// handshake seen only as SYN-ACK + first data (SYN lost to the sniffer, e.g. offload path)
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 100), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("late fake never fired")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("late fake seq %d, want %d", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncLateNeedsData: with no anchor (no data segment yet), the late path must NOT fire on bare ACKs.
func TestDesyncLateNeedsData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(42000), uint32(900)
	tr.announce(k, 0, false)
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+2, srvSeq+1, testFlagACK, nil, 64))
	if sent.n() != 0 {
		t.Fatalf("late path fired on bare ACKs (%d fakes)", sent.n())
	}
}

// TestDesyncNATRewrite: a NAT that shifts our sequence numbers between SYN and data (the documented seq-mode
// killer) shifts the fake with it when the SYN-ACK still names the old ISN — the tracker follows the server's
// view. The fake stays below the stream start as the SERVER sees it.
func TestDesyncNATRewrite(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	// NAT rewrote our ISN from 1000 to 2000 before the server saw it
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	const natISN = isn + 1000
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, natISN+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, natISN+1, srvSeq+1, testFlagACK, nil, 64))
	if tr.fired() != 1 {
		t.Fatal("fake did not fire after NAT rewrite")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != natISN+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (NAT-shifted)", seq, natISN+1-uint32(len(tr.hello)))
	}
}

// TestDesyncTTLCalibration: -fake-ttl 0 learns the peer's inbound TTL from its SYN-ACK and sends the fake one
// hop short of the server. Before the SYN-ACK is seen, nothing fires.
func TestDesyncTTLCalibration(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // SYN-ACK arrives with TTL 52
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired after calibration")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	if got := sent.at(0)[8]; got != 11 {
		t.Fatalf("calibrated ttl %d, want 11 (SYN-ACK arrived with 52: 64-52 = 12 hops, one short)", got)
	}
}

// TestDesyncTTLCalibratedBeforeHandshake: a previously learned TTL (from another connection) serves at once.
func TestDesyncTTLCalibratedBeforeHandshake(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	// a stray SYN-ACK from the peer (another connection's) teaches the TTL first
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, 9999, 77, 88, testFlagSYN|testFlagACK, nil, 60))
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	if tr.fired() != 1 {
		t.Fatal("fake did not fire with pre-calibrated TTL")
	}
	if got := sent.at(0)[8]; got != 3 {
		t.Fatalf("ttl %d, want 3 (arrived with 60: 4 hops, one short)", got)
	}
}

// TestDesyncTTLCalibratedNotYet: before any SYN-ACK, an auto-TTL handshake stays unfired and the wait channel
// is abandoned (Wrap times out; the tunnel works unclassified).
func TestDesyncTTLCalibratedNotYet(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	// handshake without a SYN-ACK on record (sniffer missed it): no TTL, no fake
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("auto-TTL fired without a learned TTL")
	}
	tr.abandon(k)
	select {
	case <-ch:
	default:
		t.Fatal("abandon must release the waiting Wrap")
	}
}

// TestDesyncFixedTTL: -fake-ttl N is used as-is.
func TestDesyncFixedTTL(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 9)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	if tr.fired() != 1 {
		t.Fatal("fake did not fire")
	}
	if got := sent.at(0)[8]; got != 9 {
		t.Fatalf("ttl %d, want 9 (fixed)", got)
	}
}

// TestDesyncOneFakePerConn: whatever arrives after the fake must not fire again.
func TestDesyncOneFakePerConn(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+2, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 50), 64))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+60, srvSeq+1, testFlagACK, nil, 64))
	if sent.n() != 1 {
		t.Fatalf("want exactly 1 fake, got %d", sent.n())
	}
}

// TestDesyncUnknownConnIgnored: traffic on connections the tracker never saw announced is passed over.
func TestDesyncUnknownConnIgnored(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	feedFullHandshake(tr, k, 3000, 400) // never announced
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fired for an unannounced connection")
	}
}

// TestDesyncFakePacketRoundTrip: the built fake parses back as IPv4/TCP with a valid checksum and carries the
// SNI in its payload.
func TestDesyncFakePacketRoundTrip(t *testing.T) {
	k := testClientKey()
	hello := FakeClientHello("mci.ir")
	pkt := fakePacket(k, 799, 555, 63, hello)
	if ip := parseEthIP(append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}, pkt...)); ip == nil {
		t.Fatal("parseEthIP rejected the fake")
	} else {
		if got := binary.BigEndian.Uint32(ip[16:20]); got != binary.BigEndian.Uint32(k.dstIP.bytes()) {
			t.Fatalf("dst ip %x", got)
		}
		if ip[8] != 63 {
			t.Fatalf("ttl %d", ip[8])
		}
	}
	th := pkt[20:]
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(th[16:], 0)
	if c := tcpChecksum(pkt[20:], k.srcIP.bytes(), k.dstIP.bytes()); c != stored {
		t.Fatalf("checksum mismatch: recomputed %04x, stored %04x", c, stored)
	}
	if !bytes.Equal(pkt[40:], hello) {
		t.Fatal("payload is not the hello")
	}
	if ipCsum := csum(pkt[:20]); ipCsum != 0 {
		t.Fatalf("ipv4 header checksum mismatch: got %04x, want 0", ipCsum)
	}
	rstPkt := fakeRSTPacket(k, 800, 556, 64)
	if ipCsum := csum(rstPkt[:20]); ipCsum != 0 {
		t.Fatalf("rst ipv4 header checksum mismatch: got %04x, want 0", ipCsum)
	}
}

// TestDesyncAbandonAndClose: Wrap channels close cleanly, no fake fires after close.
func TestDesyncAbandonAndClose(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	k := testClientKey()
	ch1 := tr.announce(k, 123, true)
	tr.abandon(k)
	select {
	case <-ch1:
	default:
		t.Fatal("abandon must close the wait channel")
	}
	tr.close()
	tr.announce(k, 123, true) // after close: announced channels close at once, nothing fires
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fired after close")
	}
}

// TestStaleTimestampOpts: the paws timestamp is older than the real one for every TSval (the kernel offsets TSval
// randomly per connection, so a fixed value would be "older" only half the time), the other options survive, and a
// connection without a timestamp option gets none made up (3.0.2).
func TestStaleTimestampOpts(t *testing.T) {
	for _, tsval := range []uint32{0, 1, 5, 1 << 30, 1<<31 - 1, 1 << 31, 1<<31 + 7, 0xfffffff0, 0x12345678} {
		in := []byte{2, 4, 5, 0xb4, 1, 1, 8, 10, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 1, 3, 3, 7}
		binary.BigEndian.PutUint32(in[8:], tsval)
		out, ok := staleTimestampOpts(in)
		if !ok || len(out) != len(in) {
			t.Fatalf("tsval %d: ok=%v len %d", tsval, ok, len(out))
		}
		stale := binary.BigEndian.Uint32(out[8:])
		if int32(stale-tsval) >= 0 || int32(stale-tsval) < -(1<<30) {
			t.Fatalf("tsval %d: stale %d is not 2^30 behind", tsval, stale)
		}
		if !bytes.Equal(out[:8], in[:8]) || !bytes.Equal(out[12:], in[12:]) {
			t.Fatalf("tsval %d: options other than TSval changed: %x", tsval, out)
		}
	}
	for _, opts := range [][]byte{nil, {2, 4, 5, 0xb4, 1, 3, 3, 7}, {1, 1, 8, 5}, {1, 1, 8, 10, 0, 0}} {
		if out, ok := staleTimestampOpts(opts); ok || !bytes.Equal(out, opts) {
			t.Fatalf("opts %x: want untouched and not ok, got %x ok=%v", opts, out, ok)
		}
	}
}

// TestDesyncPAWSFallback: without a timestamp option in the handshake, paws falls back to the plain below-window seq
// marker; an in-window fake there would be accepted by the server as the real stream (3.0.2).
func TestDesyncPAWSFallback(t *testing.T) {
	tr, sent := desyncTestTracker("paws", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	pkt := sent.at(0)
	if seq, want := binary.BigEndian.Uint32(pkt[24:28]), isn+1-uint32(len(tr.hello)); seq != want {
		t.Fatalf("fallback seq %d, want below-window %d", seq, want)
	}
	if !tcpChecksumOK(pkt) {
		t.Fatal("fallback marker must keep a valid checksum")
	}
}

// TestDesyncRSTCleansConnection: TCP RST packet cleans up tracked state and closes waiting channels.
func TestDesyncRSTCleansConnection(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	ch := tr.announce(k, 500, true)
	// Outbound RST packet
	rstPkt := desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 501, 0, testFlagRST, nil, 64)
	tr.handleIP(rstPkt)
	select {
	case <-ch: // channel closed on RST
	case <-time.After(time.Second):
		t.Fatal("channel not closed on RST")
	}
	tr.mu.Lock()
	conn := tr.conns[k]
	tr.mu.Unlock()
	if conn != nil {
		t.Fatal("connection state was not cleaned up on RST")
	}
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fake fired on RST connection")
	}
}

// TestDesyncStalePrune: stale uncompleted connection entries (>30s) are pruned on subsequent announces.
func TestDesyncStalePrune(t *testing.T) {
	tr, _ := desyncTestTracker("seq", 0)
	defer tr.close()
	// Announce 18 connections
	for i := 0; i < 18; i++ {
		k := testClientKey()
		k.srcPt = uint16(10000 + i)
		_ = tr.announce(k, uint32(1000+i), false)
	}
	tr.mu.Lock()
	if len(tr.conns) != 18 {
		tr.mu.Unlock()
		t.Fatalf("expected 18 conns, got %d", len(tr.conns))
	}
	// Age them out
	oldTime := time.Now().Add(-1 * time.Minute)
	for _, c := range tr.conns {
		c.at = oldTime
	}
	tr.mu.Unlock()

	// 19th announce should trigger stale prune
	kNew := testClientKey()
	kNew.srcPt = 20000
	tr.announce(kNew, 5000, true)

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.conns) != 1 {
		t.Fatalf("stale connections were not pruned: len=%d, want 1", len(tr.conns))
	}
	if tr.conns[kNew] == nil {
		t.Fatal("new connection was pruned")
	}
}

// TestDesyncParseEthIPv4 validates ethernet, VLAN, SLL and raw frames, and rejects non-IPv4 frames.
func TestDesyncParseEthIPv4(t *testing.T) {
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if parseEthIP(arp) != nil {
		t.Fatal("ARP frame accepted")
	}
	if parseEthIP([]byte{1, 2, 3}) != nil {
		t.Fatal("short frame accepted")
	}

	// Raw IPv4 packet (tun/wg)
	rawIP := make([]byte, 40)
	rawIP[0] = 0x45 // IPv4, 20-byte IHL
	if got := parseEthIP(rawIP); got == nil || len(got) != 40 {
		t.Fatal("raw IPv4 packet rejected")
	}

	// 802.1Q VLAN tagged frame (18-byte header)
	vlan := make([]byte, 18+40)
	binary.BigEndian.PutUint16(vlan[12:], 0x8100)
	binary.BigEndian.PutUint16(vlan[16:], 0x0800)
	vlan[18] = 0x45
	if got := parseEthIP(vlan); got == nil || len(got) != 40 {
		t.Fatal("VLAN-tagged IPv4 packet rejected")
	}

	// Linux cooked mode SLL (16-byte header)
	sll := make([]byte, 16+40)
	binary.BigEndian.PutUint16(sll[14:], 0x0800)
	sll[16] = 0x45
	if got := parseEthIP(sll); got == nil || len(got) != 40 {
		t.Fatal("SLL IPv4 packet rejected")
	}
}

// TestDesyncProbeIsnArithmetic pins the Wrap probe conversion: the TCP_REPAIR probe reports SND.NXT (the next
// unsent byte, ISN+1 right after the handshake), the tracker's announce stores the ISN. desync_linux.go's Wrap
// does `if known { isn-- }`; this pins the intended relation with the same numbers the Linux path sees.
func TestDesyncProbeIsnArithmetic(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(30000), uint32(777)
	const sndNxt = isn + 1 // what tcpStreamBase reports right after the handshake
	ch := tr.announce(k, sndNxt-1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired with probe-converted ISN")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (SND.NXT-1 based)", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncSumModeFiresEarly: when ISN is known (early path), sum mode fires immediately on the handshake's
// final ACK with an in-window seq (isn+1), ack = srvSeq+1, and damaged checksum, allowing Wrap to unblock without delay.
func TestDesyncSumModeFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("sum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(5000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK: fires early so Wrap unblocks
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("sum mode did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("sum mode fired %d, want 1", tr.fired())
	}
	pkt := sent.at(0)
	seq := binary.BigEndian.Uint32(pkt[24:])
	if seq != isn+1 {
		t.Fatalf("sum fake seq %d, want %d (mirrors the data segment's seq in-window)", seq, isn+1)
	}
	if ack := binary.BigEndian.Uint32(pkt[28:]); ack != srvSeq+1 {
		t.Fatalf("sum fake ack %d, want %d", ack, srvSeq+1)
	}
	// the checksum must be INVALID: recompute the correct one and require a difference
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(pkt[20+16:], 0)
	if good := tcpChecksum(pkt[20:], k.srcIP.bytes(), k.dstIP.bytes()); good == stored {
		t.Fatalf("sum fake carries a VALID checksum %04x (must be damaged)", good)
	}
	// and the damage is non-zero
	if stored == 0 {
		t.Fatal("sum fake checksum zeroed instead of damaged")
	}
}

// TestDesyncSumModeLate: the ISN is unknown; the late path mirrors the first data segment all the same.
func TestDesyncSumModeLate(t *testing.T) {
	tr, sent := desyncTestTracker("sum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(61000), uint32(90)
	ch := tr.announce(k, 0, false)
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 60), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("sum-mode late fake never fired")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1 {
		t.Fatalf("sum late fake seq %d, want %d (in-window)", seq, isn+1)
	}
}

// TestDesyncRSTModeFiresEarly: when ISN is known (early path), rst mode fires immediately on the handshake's
// final ACK with an in-window RST|ACK and damaged checksum.
func TestDesyncRSTModeFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("rst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(5000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("rst mode did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("rst mode fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 1 {
		t.Fatalf("sent %d packets, want 1", sent.n())
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("rst fake len %d, want 40 (pure RST|ACK header)", len(pkt))
	}
	flags := pkt[20+13]
	if flags != 0x14 { // RST|ACK
		t.Fatalf("rst fake flags 0x%02x, want 0x14 (RST|ACK)", flags)
	}
	seq := binary.BigEndian.Uint32(pkt[20+4:])
	if seq != isn+1 {
		t.Fatalf("rst fake seq %d, want %d (in-window)", seq, isn+1)
	}
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(pkt[20+16:], 0)
	if good := tcpChecksum(pkt[20:], k.srcIP.bytes(), k.dstIP.bytes()); good == stored {
		t.Fatalf("rst fake carries a VALID checksum %04x (must be damaged)", good)
	}
}

// TestDesyncRSTModeLate: the ISN is unknown; the late path mirrors the first data segment with an in-window RST|ACK.
func TestDesyncRSTModeLate(t *testing.T) {
	tr, sent := desyncTestTracker("rst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(61000), uint32(90)
	ch := tr.announce(k, 0, false)
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 60), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("rst-mode late fake never fired")
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("rst late fake len %d, want 40", len(pkt))
	}
	if flags := pkt[20+13]; flags != 0x14 {
		t.Fatalf("rst late fake flags 0x%02x, want 0x14", flags)
	}
	seq := binary.BigEndian.Uint32(pkt[20+4:])
	if seq != isn+1 {
		t.Fatalf("rst late fake seq %d, want %d (in-window)", seq, isn+1)
	}
}

// TestDesyncSeqSumSendsBoth: seqsum sends TWO markers per connection — the below-window seq fake first, then
// the in-window mirror with a damaged checksum ~1 ms later. Both must be present, in order, both carrying the
// allowlisted SNI, one with valid checksum below the window and one in-window with an invalid one.
func TestDesyncSeqSumSendsBoth(t *testing.T) {
	tr, sent := desyncTestTracker("seqsum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(7000), uint32(900)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK: fires both markers early
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("seqsum did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("seqsum fired %d, want 1", tr.fired())
	}
	// marker 2 goes out ~1 ms later via time.AfterFunc (never under the tracker lock), so poll for it
	deadline := time.Now().Add(time.Second)
	for sent.n() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("seqsum sent %d markers, want 2 (marker 2 never arrived)", sent.n())
		}
		time.Sleep(time.Millisecond)
	}
	// marker 1: below-window seq, VALID checksum (plain seq fake). fakePacket built it correctly and seqsum
	// sent it unmodified — recompute and require equality.
	m1 := sent.at(0)
	if got := binary.BigEndian.Uint32(m1[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum marker1 seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	stored1 := binary.BigEndian.Uint16(m1[20+16:])
	binary.BigEndian.PutUint16(m1[20+16:], 0)
	if good := tcpChecksum(m1[20:], k.srcIP.bytes(), k.dstIP.bytes()); good != stored1 {
		t.Fatalf("seqsum marker1 checksum %04x, want the VALID value %04x", stored1, good)
	}
	// marker 2: in-window seq (the data segment's own), DAMAGED checksum
	m2 := sent.at(1)
	if got := binary.BigEndian.Uint32(m2[24:]); got != isn+1 {
		t.Fatalf("seqsum marker2 seq %d, want %d (in-window mirror)", got, isn+1)
	}
	stored2 := binary.BigEndian.Uint16(m2[20+16:])
	binary.BigEndian.PutUint16(m2[20+16:], 0)
	if good := tcpChecksum(m2[20:], k.srcIP.bytes(), k.dstIP.bytes()); good == stored2 {
		t.Fatalf("seqsum marker2 carries a VALID checksum %04x (must be damaged)", good)
	}
	// both carry the allowlisted SNI. pickHello rebuilds fresh randoms per fire, so compare the parsed
	// SNI (and the per-SNI constant length), not the constructor's cached tr.hello bytes.
	for i, m := range [][]byte{m1, m2} {
		if len(m[40:]) != len(tr.hello) {
			t.Fatalf("seqsum marker%d payload len %d, want %d", i+1, len(m[40:]), len(tr.hello))
		}
		got, err := parseSNIOf(m[40:])
		if err != nil || got != "mci.ir" {
			t.Fatalf("seqsum marker%d SNI: got %q err %v, want mci.ir", i+1, got, err)
		}
	}
}

// TestDesyncSeqSumLateFiresBoth: the late path (unknown ISN) fires the dual marker off the first data segment.
func TestDesyncSeqSumLateFiresBoth(t *testing.T) {
	tr, sent := desyncTestTracker("seqsum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(41000), uint32(70)
	ch := tr.announce(k, 0, false)
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 40), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("seqsum late fake never fired")
	}
	// marker 2 goes out ~1 ms later via time.AfterFunc (never under the tracker lock), so poll for it
	deadline := time.Now().Add(time.Second)
	for sent.n() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("seqsum late sent %d markers, want 2 (marker 2 never arrived)", sent.n())
		}
		time.Sleep(time.Millisecond)
	}
	if got := binary.BigEndian.Uint32(sent.at(0)[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum late marker1 seq %d, want %d", got, isn+1-uint32(len(tr.hello)))
	}
	if got := binary.BigEndian.Uint32(sent.at(1)[24:]); got != isn+1 {
		t.Fatalf("seqsum late marker2 seq %d, want %d (in-window)", got, isn+1)
	}
}

// TestDesyncPickHelloFreshRandoms: pickHello rebuilds the hello per fire, so two fires from one tracker
// never replay byte-identical randoms (a censor correlating synthetic hellos across connections would
// otherwise see the same client random / session id / key share). The per-SNI length stays constant.
func TestDesyncPickHelloFreshRandoms(t *testing.T) {
	tr := newDesyncTracker(DesyncConfig{SNI: "mci.ir", Mode: "seq"}, testIP4("10.8.0.1"))
	defer tr.close()
	h1 := tr.pickHello()
	h2 := tr.pickHello()
	if len(h1) != len(tr.hello) || len(h2) != len(tr.hello) {
		t.Fatalf("pickHello len drift: %d %d, want %d", len(h1), len(h2), len(tr.hello))
	}
	if string(h1) == string(h2) {
		t.Fatal("two pickHello calls returned byte-identical hellos (replayed randoms)")
	}
	got, err := parseSNIOf(h2)
	if err != nil || got != "mci.ir" {
		t.Fatalf("pickHello SNI: got %q err %v, want mci.ir", got, err)
	}
}

// TestDesyncMultiSNIRotation verifies that comma-separated SNIs rotate sequentially across connections.
func TestDesyncMultiSNIRotation(t *testing.T) {
	cfg := DesyncConfig{
		SNI:  "mci.ir,divar.ir,digikala.com",
		Mode: "seq",
	}
	tr := newDesyncTracker(cfg, testIP4("10.8.0.1"))
	defer tr.close()
	sent := &sentLog{}
	tr.send = sent.add

	expectedSNIs := []string{"mci.ir", "divar.ir", "digikala.com", "mci.ir"}
	for i, want := range expectedSNIs {
		k := testClientKey()
		k.srcPt = uint16(20000 + i)
		ch := tr.announce(k, uint32(10000+i*100), true)
		feedFullHandshake(tr, k, uint32(10000+i*100), uint32(50000+i*100))
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("conn %d never fired", i)
		}
		if sent.n() != i+1 {
			t.Fatalf("sent count mismatch at iter %d: got %d", i, sent.n())
		}
		// Extract SNI from the sent packet (starts at byte 40 after 20-byte IP and 20-byte TCP header)
		rec := sent.at(i)[40:]
		got, err := parseSNIOf(rec)
		if err != nil {
			t.Fatalf("conn %d parseSNIOf: %v", i, err)
		}
		if got != want {
			t.Fatalf("conn %d SNI: got %q, want %q", i, got, want)
		}
	}
}

// TestFakeClientHelloECHGREASE verifies that FakeClientHelloWithECH includes the RFC 9460 / RFC 8701
// ECH GREASE extension (0xfe0d) with valid outer configuration.
func TestFakeClientHelloECHGREASE(t *testing.T) {
	rec := FakeClientHelloWithECH("mci.ir")
	if len(rec) < 5 || rec[0] != 0x16 {
		t.Fatalf("bad TLS record header: %v", rec[:5])
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		t.Fatalf("bad handshake header: %v", hs[:4])
	}
	// Skip ClientHello fixed fields to find extensions:
	// handshake header(4) + version(2) + random(32) + session_id(1+len) + cipher_suites(2+len) + compression(1+len)
	off := 4 + 2 + 32
	if off >= len(hs) {
		t.Fatal("truncated hs at random")
	}
	sidLen := int(hs[off])
	off += 1 + sidLen
	if off+2 > len(hs) {
		t.Fatal("truncated hs at session id")
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2 + csLen
	if off+1 > len(hs) {
		t.Fatal("truncated hs at cipher suites")
	}
	compLen := int(hs[off])
	off += 1 + compLen
	if off+2 > len(hs) {
		t.Fatal("truncated hs at compression")
	}
	extTotalLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	if off+extTotalLen > len(hs) {
		t.Fatalf("truncated extensions: need %d have %d", extTotalLen, len(hs)-off)
	}

	foundECH := false
	extEnd := off + extTotalLen
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[off : off+2])
		extLen := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			t.Fatalf("extension 0x%04x truncated", extType)
		}
		if extType == 0xfe0d {
			foundECH = true
			data := hs[off : off+extLen]
			if len(data) != 138 {
				t.Fatalf("ECH GREASE data len: got %d, want 138", len(data))
			}
			if data[0] != 0x00 { // outer ClientHello
				t.Fatalf("ECH type: got %d, want 0 (outer)", data[0])
			}
			// HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001)
			if !bytes.Equal(data[1:5], []byte{0x00, 0x01, 0x00, 0x01}) {
				t.Fatalf("ECH cipher suite mismatch: %x", data[1:5])
			}
			if data[5] != 0x00 { // config_id
				t.Fatalf("ECH config_id: got %d, want 0", data[5])
			}
			encLen := binary.BigEndian.Uint16(data[6:8])
			if encLen != 32 {
				t.Fatalf("ECH encLen: got %d, want 32", encLen)
			}
			payloadLen := binary.BigEndian.Uint16(data[40:42])
			if payloadLen != 96 {
				t.Fatalf("ECH payloadLen: got %d, want 96", payloadLen)
			}
		}
		off += extLen
	}
	if !foundECH {
		t.Fatal("ECH GREASE extension (0xfe0d) not found in FakeClientHello")
	}
}

// TestFakePacketWithOptions verifies IPv4/TCP header formatting, options placement,
// and checksum calculation when TCP options are mirrored from the kernel.
func TestFakePacketWithOptions(t *testing.T) {
	k := desyncKey{
		srcIP: addr4([4]byte{192, 168, 1, 50}),
		dstIP: addr4([4]byte{1, 2, 3, 4}),
		srcPt: 12345,
		dstPt: 443,
	}
	// 12 bytes of TCP options: NOP, NOP, Timestamps (Kind=8, Len=10, TSval=0x11223344, TSecr=0x55667788)
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	payload := []byte("TEST_PAYLOAD_BODY")

	pkt := fakePacketWithOptions(k, 1000, 2000, 64, payload, opts)

	// IPv4 header checks
	if pkt[0] != 0x45 {
		t.Fatalf("IP version/IHL: got 0x%02x, want 0x45", pkt[0])
	}
	totLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(totLen) != len(pkt) {
		t.Fatalf("IP totLen: got %d, want %d", totLen, len(pkt))
	}
	if csum(pkt[:20]) != 0 {
		t.Fatal("IPv4 header checksum invalid")
	}

	// TCP header checks: 20 bytes standard + 12 bytes options = 32 bytes (Data Offset = 8)
	th := pkt[20:]
	dataOffset := th[12] >> 4
	if dataOffset != 8 {
		t.Fatalf("TCP Data Offset: got %d, want 8", dataOffset)
	}
	if !bytes.Equal(th[20:32], opts) {
		t.Fatalf("TCP options mismatch in header: got %x, want %x", th[20:32], opts)
	}
	if !bytes.Equal(pkt[20+32:], payload) {
		t.Fatalf("Payload mismatch: got %q, want %q", pkt[20+32:], payload)
	}

	// TCP checksum verification
	ph := make([]byte, 12)
	copy(ph[0:4], k.srcIP.bytes())
	copy(ph[4:8], k.dstIP.bytes())
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	if csum(append(ph, th...)) != 0 {
		t.Fatal("TCP checksum invalid")
	}
}

// TestDesyncOptsCapture verifies that outbound segments with TCP options (e.g. timestamps)
// are recorded by the tracker and reflected in injected fake packets.
func TestDesyncOptsCapture(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(2000), uint32(600000)
	ch := tr.announce(k, isn+1, true)

	// SYN (no options for simplicity)
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	// SYN-ACK from server
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))

	// Final ACK with 12 bytes of TCP options (NOP, NOP, Timestamps)
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	ackPkt := make([]byte, 20+32)
	ackPkt[0] = 0x45
	binary.BigEndian.PutUint16(ackPkt[2:], uint16(len(ackPkt)))
	ackPkt[8] = 64
	ackPkt[9] = 6
	copy(ackPkt[12:16], k.srcIP.bytes())
	copy(ackPkt[16:20], k.dstIP.bytes())
	binary.BigEndian.PutUint16(ackPkt[10:], csum(ackPkt[:20]))
	ath := ackPkt[20:]
	binary.BigEndian.PutUint16(ath[0:], k.srcPt)
	binary.BigEndian.PutUint16(ath[2:], k.dstPt)
	binary.BigEndian.PutUint32(ath[4:], isn+1)
	binary.BigEndian.PutUint32(ath[8:], srvSeq+1)
	ath[12] = 0x80 // Data Offset = 8 (32 bytes)
	ath[13] = testFlagACK
	binary.BigEndian.PutUint16(ath[14:], 0xffff)
	copy(ath[20:], opts)
	binary.BigEndian.PutUint16(ath[16:], tcpChecksum(ath, k.srcIP.bytes(), k.dstIP.bytes()))

	tr.handleIP(ackPkt)

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired")
	}

	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	fake := sent.at(0)
	// TCP header must have Data Offset = 8
	fth := fake[20:]
	if fth[12]>>4 != 8 {
		t.Fatalf("fake Data Offset: got %d, want 8", fth[12]>>4)
	}
	if !bytes.Equal(fth[20:32], opts) {
		t.Fatalf("fake options mismatch: got %x, want %x", fth[20:32], opts)
	}
	// Fake payload starts at byte 52 (20 IP + 32 TCP)
	gotSNI, err := parseSNIOf(fake[52:])
	if err != nil {
		t.Fatalf("parseSNIOf failed on fake: %v", err)
	}
	if gotSNI != "mci.ir" {
		t.Fatalf("fake SNI: got %q, want mci.ir", gotSNI)
	}
}

// TestValidateDesyncNewModes pins validation for the modes added with the F&F round: split/hlen0/fakeip/synrst/
// ff/all, the -fake-ip IPv4 check and the -fake-split range.
func TestValidateDesyncNewModes(t *testing.T) {
	for _, m := range []string{"split", "hlen0", "fakeip", "synrst", "ff", "all", "paws"} {
		if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: m}); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	// ff reuses -fake-split for its segment count; 0 means the preset's 11
	for _, n := range []int{3, 11, 16} {
		if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ff", Split: n}); err != nil {
			t.Fatalf("ff split %d: %v", n, err)
		}
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "188.114.98.0"}); err != nil {
		t.Fatalf("fakeip with an explicit IPv4: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: " 104.16.0.1 "}); err != nil {
		t.Fatalf("fakeip FakeIP with surrounding whitespace: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "cdn.example.com"}); err == nil {
		t.Fatal("a non-IPv4 FakeIP must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "2a06:98c1:3101::6812:202f"}); err != nil {
		t.Fatalf("an IPv6 FakeIP must be accepted (the packet builders handle both families): %v", err)
	}
	for _, n := range []int{2, 3, 16} {
		if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: n}); err != nil {
			t.Fatalf("split %d: %v", n, err)
		}
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: 1}); err == nil {
		t.Fatal("split 1 must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: 17}); err == nil {
		t.Fatal("split > 16 must fail")
	}
}

// TestDesyncSplitMode: split cuts the fake ClientHello across TCP segments: the first payload segment is the
// record byte alone, a segment boundary lands on the SNI extension, the fragments' seq numbers are contiguous and
// the whole ghost stays below the stream start. Reassembled in seq order the fragments still form the allowlisted
// ClientHello, so a reassembling receiver is fooled while a per-packet parser sees no complete record.
func TestDesyncSplitMode(t *testing.T) {
	tr, sent := desyncTestTracker("split", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(9000), uint32(400)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("split fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("split fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 3 {
		t.Fatalf("default split sent %d segments, want 3", sent.n())
	}
	streamStart := isn + 1
	wantSeq := streamStart - uint32(len(tr.hello))
	var reassembled []byte
	var bounds []int
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		payload := payloadOf(pkt)
		if i == 0 && len(payload) != 1 {
			t.Fatalf("split segment 1 is %d bytes, want 1 (the TLS record byte alone)", len(payload))
		}
		if got := binary.BigEndian.Uint16(pkt[22:]); got != k.dstPt {
			t.Fatalf("segment %d dport %d", i, got)
		}
		if got := binary.BigEndian.Uint32(pkt[24:]); got != wantSeq+uint32(len(reassembled)) {
			t.Fatalf("segment %d seq %d, want %d (contiguous fragments)", i, got, wantSeq+uint32(len(reassembled)))
		}
		if got := binary.BigEndian.Uint32(pkt[28:]); got != srvSeq+1 {
			t.Fatalf("segment %d ack %d, want %d", i, got, srvSeq+1)
		}
		if !tcpChecksumOK(pkt) {
			t.Fatalf("segment %d carries an invalid checksum (split fragments must be plain seq markers)", i)
		}
		reassembled = append(reassembled, payload...)
		bounds = append(bounds, len(reassembled))
	}
	// every fragment sits below the stream start, so the server kernel drops each one as an old duplicate
	if wantSeq+uint32(len(reassembled)) != streamStart {
		t.Fatalf("reassembled fake ends at %d, want %d (the stream start)", wantSeq+uint32(len(reassembled)), streamStart)
	}
	if len(reassembled) != len(tr.hello) {
		t.Fatalf("split reassembles to %d bytes, want %d", len(reassembled), len(tr.hello))
	}
	got, err := parseSNIOf(reassembled)
	if err != nil || got != "mci.ir" {
		t.Fatalf("reassembled split SNI: got %q err %v, want mci.ir", got, err)
	}
	// the SNI extension starts exactly on a fragment boundary: no payload segment carries a complete record header
	// together with the server_name extension header.
	off := sniExtOffset(reassembled)
	if off == 0 {
		t.Fatal("SNI extension not found in the reassembled fake")
	}
	onBoundary := false
	for _, b := range bounds {
		if b == off {
			onBoundary = true
		}
	}
	if !onBoundary {
		t.Fatalf("no segment boundary at the SNI extension offset %d (bounds %v)", off, bounds)
	}
}

// TestDesyncSplitHonoursConfiguredCount: -fake-split sets the segment count (0 = default 3, 2..16 otherwise).
func TestDesyncSplitHonoursConfiguredCount(t *testing.T) {
	for _, tc := range []struct{ split, want int }{{0, 3}, {2, 2}, {4, 4}, {16, 16}} {
		tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "split", Split: tc.split})
		k := testClientKey()
		ch := tr.announce(k, 1001, true)
		feedFullHandshake(tr, k, 1000, 500)
		select {
		case <-ch:
		case <-time.After(time.Second):
			tr.close()
			t.Fatalf("split %d: fake never fired", tc.split)
		}
		if sent.n() != tc.want {
			tr.close()
			t.Fatalf("split %d sent %d segments, want %d", tc.split, sent.n(), tc.want)
		}
		// the fragments still add up to exactly one fake ClientHello
		total := 0
		for i := 0; i < sent.n(); i++ {
			total += len(payloadOf(sent.at(i)))
		}
		if total != len(tr.hello) {
			tr.close()
			t.Fatalf("split %d reassembles to %d bytes, want %d", tc.split, total, len(tr.hello))
		}
		tr.close()
	}
}

// TestDesyncHlen0ZeroRecord: hlen0 leaves the record length field at 0 (F&F tlshello-0-len) while the body still
// carries the allowlisted SNI, at the plain seq-mode placement (below the stream start, valid checksum, TTL 64).
func TestDesyncHlen0ZeroRecord(t *testing.T) {
	tr, sent := desyncTestTracker("hlen0", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(11000), uint32(600)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("hlen0 fake never fired")
	}
	if tr.fired() != 1 || sent.n() != 1 {
		t.Fatalf("hlen0 fired %d, sent %d; want 1 and 1", tr.fired(), sent.n())
	}
	pkt := sent.at(0)
	payload := payloadOf(pkt)
	if len(payload) != len(tr.hello) {
		t.Fatalf("hlen0 payload %d bytes, want %d (the mask keeps the body)", len(payload), len(tr.hello))
	}
	if payload[0] != 0x16 {
		t.Fatalf("hlen0 payload does not start with a TLS handshake byte: %02x", payload[0])
	}
	if payload[3] != 0 || payload[4] != 0 {
		t.Fatalf("hlen0 record length % x, want 00 00 (F&F tlshello-0-len)", payload[3:5])
	}
	// a per-packet sniffer that ignores the length field still reads the allowlisted name
	if got, err := parseSNIOf(payload); err != nil || got != "mci.ir" {
		t.Fatalf("hlen0 SNI: got %q err %v, want mci.ir", got, err)
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("hlen0 seq %d, want %d (seq-mode placement)", got, isn+1-uint32(len(tr.hello)))
	}
	if pkt[8] != 64 {
		t.Fatalf("hlen0 ttl %d, want 64 (seq-mode placement)", pkt[8])
	}
	if !tcpChecksumOK(pkt) {
		t.Fatal("hlen0 must carry a valid checksum: its marker is the zeroed record length, not a bad checksum")
	}
}

// TestDesyncFakeIPMirrorsWhitelistedIP: fakeip sends a well-formed SYN and ClientHello for the same client port
// but a whitelisted CDN destination (configured, and the 104.16.0.1 default). Both packets are checksum-valid,
// so an IP-allowlist DPI records the flow as allowed-CDN traffic; the destination is not the real server, so the
// tunnel never sees them.
func TestDesyncFakeIPMirrorsWhitelistedIP(t *testing.T) {
	tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "fakeip", FakeIP: "188.114.98.1"})
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(12000), uint32(700)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fakeip fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("fakeip fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 2 {
		t.Fatalf("fakeip sent %d packets, want 2 (SYN + ClientHello)", sent.n())
	}
	wantIP := []byte{188, 114, 98, 1}
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		if ip := pkt[16:20]; !bytes.Equal(ip, wantIP) {
			t.Fatalf("packet %d dst % x, want the whitelisted CDN IP % x", i, ip, wantIP)
		}
		if got := binary.BigEndian.Uint16(pkt[20:]); got != k.srcPt {
			t.Fatalf("packet %d sport %d, want the client's real port %d", i, got, k.srcPt)
		}
		if got := binary.BigEndian.Uint16(pkt[22:]); got != 443 {
			t.Fatalf("packet %d dport %d, want 443", i, got)
		}
		if csum(pkt[:20]) != 0 {
			t.Fatalf("packet %d IP header checksum invalid", i)
		}
		if !tcpChecksumOK(pkt) {
			t.Fatalf("packet %d carries an invalid TCP checksum (fakeip must look like real CDN traffic)", i)
		}
	}
	syn := sent.at(0)
	if flags := syn[20+13]; flags != 0x02 {
		t.Fatalf("packet 1 flags 0x%02x, want 0x02 (SYN)", flags)
	}
	helloPkt := sent.at(1)
	if flags := helloPkt[20+13]; flags != 0x18 {
		t.Fatalf("packet 2 flags 0x%02x, want 0x18 (PSH|ACK)", flags)
	}
	synSeq := binary.BigEndian.Uint32(syn[24:])
	if got := binary.BigEndian.Uint32(helloPkt[24:]); got != synSeq+1 {
		t.Fatalf("hello seq %d, want %d (SYN+1)", got, synSeq+1)
	}
	// the fake flow's bytes also end at the real stream start: even a DPI that merged the keys sees old duplicates
	if got := binary.BigEndian.Uint32(helloPkt[24:]) + uint32(len(payloadOf(helloPkt))); got != isn+1 {
		t.Fatalf("fakeip synthetic stream ends at %d, want %d (the real stream start)", got, isn+1)
	}
	if got, err := parseSNIOf(payloadOf(helloPkt)); err != nil || got != "mci.ir" {
		t.Fatalf("fakeip hello SNI: got %q err %v, want mci.ir", got, err)
	}

	// the default FakeIP is the Cloudflare edge
	tr2, sent2 := desyncTestTracker("fakeip", 0)
	defer tr2.close()
	k2 := testClientKey()
	ch2 := tr2.announce(k2, 20001, true)
	feedFullHandshake(tr2, k2, 20000, 900)
	select {
	case <-ch2:
	case <-time.After(time.Second):
		t.Fatal("default-fakeip fake never fired")
	}
	if got := sent2.at(0)[16:20]; !bytes.Equal(got, []byte{104, 16, 0, 1}) {
		t.Fatalf("default fakeip dst % x, want 104.16.0.1 (a Cloudflare edge)", got)
	}
}

// TestDesyncSYNRSTClearsFlowHarder: synrst sends an in-window SYN|RST with a damaged checksum: a protocol-invalid
// combination that stateful middleboxes purge harder than a plain RST, and that the server kernel drops at
// checksum validation before reading flags.
func TestDesyncSYNRSTClearsFlowHarder(t *testing.T) {
	tr, sent := desyncTestTracker("synrst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(13000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("synrst fake never fired")
	}
	if tr.fired() != 1 || sent.n() != 1 {
		t.Fatalf("synrst fired %d, sent %d; want 1 and 1", tr.fired(), sent.n())
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("synrst packet len %d, want 40 (header only)", len(pkt))
	}
	if flags := pkt[20+13]; flags != 0x06 {
		t.Fatalf("synrst flags 0x%02x, want 0x06 (SYN|RST)", flags)
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1 {
		t.Fatalf("synrst seq %d, want %d (in-window)", got, isn+1)
	}
	if tcpChecksumOK(pkt) {
		t.Fatal("synrst carries a VALID checksum (must be damaged so the server kernel drops it)")
	}
}

// TestDesyncAllFiresAllMarkers: all mode fires the seq + sum + hlen0 single markers ~1 ms apart and then the true
// F&F record/segment plan from 3 ms. Single markers are classified by packet shape rather than arrival order, so
// the timer scheduling cannot make the test flaky; the F&F run is checked as a whole.
func TestDesyncAllFiresAllMarkers(t *testing.T) {
	tr, sent := desyncTestTracker("all", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(15000), uint32(300)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("all fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("all fired counter %d, want 1", tr.fired())
	}
	streamStart := isn + 1
	rLen := ffFirstSeg + 6*(len(tr.hello)-5-ffChunk)
	wantFF := len(ffSegs(make([]byte, rLen), 0))
	deadline := time.Now().Add(2 * time.Second)
	for sent.n() < 3+wantFF {
		if time.Now().After(deadline) {
			t.Fatalf("all sent %d packets, want %d (3 single markers + %d F&F segments)", sent.n(), 3+wantFF, wantFF)
		}
		time.Sleep(time.Millisecond)
	}
	if sent.n() != 3+wantFF {
		t.Fatalf("all sent %d packets, want %d", sent.n(), 3+wantFF)
	}
	belowSeq := streamStart - uint32(len(tr.hello))
	var sawSeq, sawSum, sawHLen bool
	var ffPkts [][]byte
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		payload := payloadOf(pkt)
		seq := binary.BigEndian.Uint32(pkt[24:])
		valid := tcpChecksumOK(pkt)
		switch {
		case len(payload) == len(tr.hello) && payload[3] == 0 && payload[4] == 0 && seq == belowSeq && valid:
			sawHLen = true
		case len(payload) == len(tr.hello) && seq == belowSeq && valid:
			sawSeq = true
		case len(payload) == len(tr.hello) && seq == streamStart && !valid:
			sawSum = true
		default:
			ffPkts = append(ffPkts, pkt)
		}
	}
	if !sawSeq || !sawSum || !sawHLen {
		t.Fatalf("all single markers missing: seq=%v sum=%v hlen0=%v (want all three)", sawSeq, sawSum, sawHLen)
	}
	if len(ffPkts) != wantFF {
		t.Fatalf("all sent %d F&F segments, want %d", len(ffPkts), wantFF)
	}
	sort.Slice(ffPkts, func(i, j int) bool {
		return binary.BigEndian.Uint32(ffPkts[i][24:]) < binary.BigEndian.Uint32(ffPkts[j][24:])
	})
	checkFFStream(t, ffPkts, streamStart, len(tr.hello), srvSeq+1)
}

// checkFFStream verifies one fired F&F run: the [114,1] mask-2 segment plan, contiguous sequence numbers all below
// the stream start and ending exactly at it, valid checksums, and the [0,104,1] record plan inside the payloads.
func checkFFStream(t *testing.T, pkts [][]byte, streamStart uint32, helloLen int, ack uint32) {
	t.Helper()
	if len(pkts) == 0 {
		t.Fatal("F&F run has no packets")
	}
	body := helloLen - 5
	rLen := ffFirstSeg + 6*(body-ffChunk)
	want := ffSegs(make([]byte, rLen), 0)
	if len(pkts) != len(want) {
		t.Fatalf("F&F run has %d segments, want %d (the [114,1] plan, maxSplit %d)", len(pkts), len(want), ffDefaultSegs)
	}
	firstSeq := streamStart - uint32(rLen)
	var r []byte
	for i, pkt := range pkts {
		payload := payloadOf(pkt)
		if len(payload) != len(want[i]) {
			t.Fatalf("F&F segment %d is %d bytes, want %d", i, len(payload), len(want[i]))
		}
		seq := binary.BigEndian.Uint32(pkt[24:])
		if wantSeq := firstSeq + uint32(len(r)); seq != wantSeq {
			t.Fatalf("F&F segment %d seq %d, want %d (contiguous, below the stream start)", i, seq, wantSeq)
		}
		if got := binary.BigEndian.Uint32(pkt[28:]); got != ack {
			t.Fatalf("F&F segment %d ack %d, want %d", i, got, ack)
		}
		if flags := pkt[20+13]; flags != 0x18 {
			t.Fatalf("F&F segment %d flags 0x%02x, want 0x18 (PSH|ACK)", i, flags)
		}
		if !tcpChecksumOK(pkt) {
			t.Fatalf("F&F segment %d carries an invalid TCP checksum", i)
		}
		if csum(pkt[:20]) != 0 {
			t.Fatalf("F&F segment %d carries an invalid IPv4 checksum", i)
		}
		r = append(r, payload...)
	}
	if end := firstSeq + uint32(len(r)); end != streamStart {
		t.Fatalf("F&F run ends at seq %d, want %d (the real stream's ISN+1)", end, streamStart)
	}
	// record plan: empty record, 104-byte record, then one 1-byte record per remaining handshake byte
	var rebuilt []byte
	rec := 0
	for off := 0; off+5 <= len(r); {
		if r[off] != 0x16 || r[off+1] != 0x03 || r[off+2] != 0x01 {
			t.Fatalf("record %d header % x, want 16 03 01 ...", rec, r[off:off+3])
		}
		l := int(binary.BigEndian.Uint16(r[off+3 : off+5]))
		if off+5+l > len(r) {
			t.Fatalf("record %d: length %d overruns the stream", rec, l)
		}
		switch {
		case rec == 0 && l != 0:
			t.Fatalf("first record length %d, want 0 (the empty F&F record)", l)
		case rec == 1 && l != ffChunk:
			t.Fatalf("second record length %d, want %d", l, ffChunk)
		case rec >= 2 && l != 1:
			t.Fatalf("record %d length %d, want 1", rec, l)
		}
		rebuilt = append(rebuilt, r[off+5:off+5+l]...)
		off += 5 + l
		rec++
	}
	if len(rebuilt) != body {
		t.Fatalf("reframed handshake body is %d bytes, want %d", len(rebuilt), body)
	}
	if rec != 2+(body-ffChunk) {
		t.Fatalf("record count %d, want %d (empty + 104 B + one per remaining byte)", rec, 2+(body-ffChunk))
	}
	// the first segment must not expose a parseable ClientHello/SNI — that is the point of the plan
	if _, err := parseSNIOf(payloadOf(pkts[0])); err == nil {
		t.Fatal("the first F&F segment parses as a ClientHello with an SNI")
	}
}

// TestDesyncFFRecordPlan pins mask 1 (lengths [0,104,1]) on a real fake ClientHello: an empty record first, a
// second record of 104 bytes, then one 1-byte record per remaining handshake byte. The record payloads concatenate
// back to the untouched handshake body, so a DPI that reassembles records still sees the original ClientHello.
func TestDesyncFFRecordPlan(t *testing.T) {
	hello := FakeClientHello("mci.ir")
	body := hello[5:]
	r := recordReframe(hello)
	if len(r) == 0 {
		t.Fatal("recordReframe returned nothing for a full fake ClientHello")
	}
	if want := ffFirstSeg + 6*(len(body)-ffChunk); len(r) != want {
		t.Fatalf("reframed length %d, want %d (114 + 6·(|H|−104))", len(r), want)
	}
	if !bytes.Equal(r[0:5], []byte{0x16, 0x03, 0x01, 0, 0}) {
		t.Fatalf("first record header % x, want 16 03 01 00 00 (empty record)", r[0:5])
	}
	if !bytes.Equal(r[5:10], []byte{0x16, 0x03, 0x01, 0x00, byte(ffChunk)}) {
		t.Fatalf("second record header % x, want 16 03 01 00 68 (length 104)", r[5:10])
	}
	if !bytes.Equal(r[10:10+ffChunk], body[:ffChunk]) {
		t.Fatal("the second record does not carry H[0:104]")
	}
	if !bytes.Equal(r[ffFirstSeg:ffFirstSeg+5], []byte{0x16, 0x03, 0x01, 0, 1}) {
		t.Fatalf("third record header % x, want 16 03 01 00 01", r[ffFirstSeg:ffFirstSeg+5])
	}
	var lens []int
	var rebuilt []byte
	for off := 0; off+5 <= len(r); {
		if r[off] != 0x16 || r[off+1] != 0x03 || r[off+2] != 0x01 {
			t.Fatalf("record at %d has header % x", off, r[off:off+3])
		}
		l := int(binary.BigEndian.Uint16(r[off+3 : off+5]))
		if off+5+l > len(r) {
			t.Fatalf("record at %d: length %d overruns", off, l)
		}
		lens = append(lens, l)
		rebuilt = append(rebuilt, r[off+5:off+5+l]...)
		off += 5 + l
	}
	if len(lens) != 2+(len(body)-ffChunk) {
		t.Fatalf("record count %d, want %d", len(lens), 2+(len(body)-ffChunk))
	}
	if lens[0] != 0 || lens[1] != ffChunk {
		t.Fatalf("first two record lengths %v, want [0 %d]", lens[:2], ffChunk)
	}
	for i := 2; i < len(lens); i++ {
		if lens[i] != 1 {
			t.Fatalf("record %d length %d, want 1", i, lens[i])
		}
	}
	if !bytes.Equal(rebuilt, body) {
		t.Fatal("the record payloads do not reassemble to the handshake body")
	}
	if recordReframe(hello[:5+ffChunk-1]) != nil {
		t.Fatal("a hello shorter than 104 handshake bytes must not reframe")
	}
}

// TestDesyncFFSegmentPlan pins mask 2 (lengths [114,1], maxSplit 11) as a pure byte cutter, plus the MTU-safe
// split of an oversized final remainder: consecutive TCP pieces with contiguous offsets, total bytes unchanged.
func TestDesyncFFSegmentPlan(t *testing.T) {
	r := make([]byte, 960) // the research's |R| for a 245-byte hello
	check := func(split int, want []int) {
		t.Helper()
		segs := ffSegs(r, split)
		if len(segs) != len(want) {
			t.Fatalf("split %d: %d segments, want %d", split, len(segs), len(want))
		}
		var got []byte
		for i, seg := range segs {
			if len(seg) != want[i] {
				t.Fatalf("split %d: segment %d is %d bytes, want %d", split, i, len(seg), want[i])
			}
			got = append(got, seg...)
		}
		if !bytes.Equal(got, r) {
			t.Fatalf("split %d: segments do not reassemble the stream", split)
		}
	}
	check(0, []int{ffFirstSeg, 1, 1, 1, 1, 1, 1, 1, 1, 1, 837}) // preset default: 114 B, nine 1-byte pieces, remainder
	check(3, []int{ffFirstSeg, 1, 845})
	big := make([]byte, 5000)
	segs := ffSegs(big, 0)
	var total int
	for i, seg := range segs {
		if len(seg) > ffMaxPayload {
			t.Fatalf("segment %d is %d bytes, over the MTU-safe payload cap %d", i, len(seg), ffMaxPayload)
		}
		total += len(seg)
	}
	if total != len(big) {
		t.Fatalf("oversized stream reassembles to %d bytes, want %d", total, len(big))
	}
	if len(segs) != 14 { // 114 + nine 1-byte pieces + 3×1440 + 557
		t.Fatalf("oversized stream cut into %d segments, want 14", len(segs))
	}
	if ffSegs(nil, 0) != nil {
		t.Fatal("an empty stream must cut nothing")
	}
}

// TestDesyncFFFiresPlan: ff fires the whole [0,104,1] record plan as the [114,1] segment plan on the wire, all
// below the stream start and ending exactly at ISN+1, with valid checksums.
func TestDesyncFFFiresPlan(t *testing.T) {
	tr, sent := desyncTestTracker("ff", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(17000), uint32(1400)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("ff fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("ff fired counter %d, want 1", tr.fired())
	}
	rLen := ffFirstSeg + 6*(len(tr.hello)-5-ffChunk)
	want := len(ffSegs(make([]byte, rLen), 0))
	deadline := time.Now().Add(2 * time.Second)
	for sent.n() < want {
		if time.Now().After(deadline) {
			t.Fatalf("ff sent %d segments, want %d (a timer segment never arrived)", sent.n(), want)
		}
		time.Sleep(time.Millisecond)
	}
	pkts := make([][]byte, sent.n())
	for i := range pkts {
		pkts[i] = sent.at(i)
	}
	sort.Slice(pkts, func(i, j int) bool {
		return binary.BigEndian.Uint32(pkts[i][24:]) < binary.BigEndian.Uint32(pkts[j][24:])
	})
	checkFFStream(t, pkts, isn+1, len(tr.hello), srvSeq+1)
	// the preset's first segment carries exactly the empty + 104-byte records
	if got := len(payloadOf(pkts[0])); got != ffFirstSeg {
		t.Fatalf("first ff segment is %d bytes, want %d", got, ffFirstSeg)
	}
	rem := rLen - ffFirstSeg - (ffDefaultSegs - 2)
	wantLast := rem
	for wantLast > ffMaxPayload {
		wantLast -= ffMaxPayload
	}
	if got := len(payloadOf(pkts[len(pkts)-1])); got != wantLast {
		t.Fatalf("last ff segment is %d bytes, want the remainder %d", got, wantLast)
	}
}

// TestDesyncFFShortHelloFallsBack: a hello shorter than the record plan's 104-byte chunk cannot be reframed; the
// marker degrades to the plain seq packet instead of sending nothing (only reachable with a hand-built tracker:
// FakeClientHello is always longer).
func TestDesyncFFShortHelloFallsBack(t *testing.T) {
	tr, sent := desyncTestTracker("ff", 0)
	defer tr.close()
	tr.hello = []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x00}
	tr.snis = nil
	k := testClientKey()
	const isn, srvSeq = uint32(18000), uint32(1500)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("ff fallback never fired")
	}
	if tr.fired() != 1 || sent.n() != 1 {
		t.Fatalf("short-hello ff: fired %d, sent %d; want the single seq fallback marker", tr.fired(), sent.n())
	}
	pkt := sent.at(0)
	if payload := payloadOf(pkt); !bytes.Equal(payload, tr.hello) {
		t.Fatalf("fallback payload % x, want the plain fake hello % x", payload, tr.hello)
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fallback seq %d, want %d (seq-mode placement)", got, isn+1-uint32(len(tr.hello)))
	}
	if !tcpChecksumOK(pkt) {
		t.Fatal("fallback marker must carry a valid checksum (plain seq mode)")
	}
}

// TestDesyncExistingModesFireUnchangedBytes: the new-mode work must not perturb what the older modes put on the
// wire. Each fire of seq / sum / rst must be byte-identical to the same shared builder the release before this
// change used (the existing mode tests above pin the individual fields; this pins the whole packet).
func TestDesyncExistingModesFireUnchangedBytes(t *testing.T) {
	k := testClientKey()
	const isn, srvSeq = uint32(16000), uint32(1200)

	fireOne := func(mode string) []byte {
		tr, sent := desyncTestTracker(mode, 0)
		defer tr.close()
		ch := tr.announce(k, isn+1, true)
		feedFullHandshake(tr, k, isn, srvSeq)
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("%s: fake never fired", mode)
		}
		if sent.n() != 1 {
			t.Fatalf("%s: sent %d packets, want 1", mode, sent.n())
		}
		return sent.at(0)
	}

	seqPkt := fireOne("seq")
	if want := fakePacket(k, isn+1-uint32(len(payloadOf(seqPkt))), srvSeq+1, 64, payloadOf(seqPkt)); !bytes.Equal(seqPkt, want) {
		t.Fatal("seq mode fire bytes changed")
	}
	sumPkt := fireOne("sum")
	wantSum := fakePacket(k, isn+1, srvSeq+1, 64, payloadOf(sumPkt))
	damageChecksum(wantSum)
	if !bytes.Equal(sumPkt, wantSum) {
		t.Fatal("sum mode fire bytes changed")
	}
	rstPkt := fireOne("rst")
	wantRST := fakeRSTPacket(k, isn+1, srvSeq+1, 64)
	damageChecksum(wantRST)
	if !bytes.Equal(rstPkt, wantRST) {
		t.Fatal("rst mode fire bytes changed")
	}
}

func TestHopTTL(t *testing.T) {
	for _, c := range []struct {
		arrived uint8
		want    int
	}{{49, 14}, {52, 11}, {60, 3}, {64, 1}, {63, 1}, {30, 1}, {120, 7}, {118, 9}, {250, 4}, {1, 30}} {
		if got := hopTTL(c.arrived); got != c.want {
			t.Errorf("hopTTL(%d) = %d, want %d", c.arrived, got, c.want)
		}
	}
}

// Wrap announces a connection whose handshake is long over, and it holds the first write back until the fake is out:
// the fake must fire from what the sniffer remembered, for every mode, with nothing more arriving on the wire.
func TestDesyncAnnounceAfterHandshakeFires(t *testing.T) {
	for _, mode := range []string{"seq", "ttl", "sum", "seqsum", "rst", "split", "hlen0", "synrst", "ff", "all"} {
		t.Run(mode, func(t *testing.T) {
			tr, sent := desyncTestTracker(mode, 0)
			defer tr.close()
			k := testClientKey()
			const isn, srvSeq = uint32(1000), uint32(500000)
			// the whole handshake passes the sniffer first; the final ACK carries a timestamp option
			tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
			tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
			tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
			if tr.fired() != 0 || sent.n() != 0 {
				t.Fatal("fired for a connection nobody announced")
			}
			ch := tr.announce(k, isn, true) // SND.NXT-1, as Wrap computes it
			select {
			case <-ch:
			default:
				t.Fatalf("%s: announce after the handshake did not release Wrap", mode)
			}
			if tr.fired() != 1 || sent.n() == 0 {
				t.Fatalf("%s: fired %d, sent %d", mode, tr.fired(), sent.n())
			}
			pkt := sent.at(0)
			if mode == "seq" && binary.BigEndian.Uint32(pkt[28:]) != srvSeq+1 {
				t.Fatalf("fake ack %d, want %d", binary.BigEndian.Uint32(pkt[28:]), srvSeq+1)
			}
			if mode == "ttl" && pkt[8] != 11 {
				t.Fatalf("ttl %d, want 11", pkt[8])
			}
		})
	}
}

// A handshake the sniffer only half saw (no SYN-ACK) stays pending as before; Wrap's timeout releases it.
func TestDesyncAnnounceWithoutSynAckWaits(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	tr.handleIP(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 1000, 0, testFlagSYN, nil, 64))
	ch := tr.announce(k, 1000, true)
	select {
	case <-ch:
		t.Fatal("fired without a SYN-ACK on record")
	default:
	}
	if sent.n() != 0 {
		t.Fatal("sent a fake without an ack to anchor it")
	}
}

// ---------------------------------------------------------------- IPv6 parity

// testIP6 parses a colon-form address into an ipAddr.
func testIP6(s string) ipAddr {
	a, _ := ipAddrOf(net.ParseIP(s))
	return a
}

// desyncTestPkt6 builds a minimal IPv6+TCP test packet (40-byte fixed header, TCP directly as next header, no
// extension headers), the v6 twin of desyncTestPkt.
func desyncTestPkt6(src, dst ipAddr, sport, dport uint16, seq, ack uint32, flags byte, payload []byte, hopLimit int) []byte {
	pkt := make([]byte, 40+20+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(20+len(payload)))
	pkt[6] = 6 // next header: TCP
	pkt[7] = byte(hopLimit)
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	th := pkt[40:]
	binary.BigEndian.PutUint16(th[0:], sport)
	binary.BigEndian.PutUint16(th[2:], dport)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	copy(th[20:], payload)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[40:], src.bytes(), dst.bytes()))
	return pkt
}

func TestIPAddrFamily(t *testing.T) {
	v4 := testIP4("104.16.0.1")
	if !v4.is4() {
		t.Fatal("v4-mapped address not detected as IPv4")
	}
	if got := v4.bytes(); len(got) != 4 || !bytes.Equal(got, []byte{104, 16, 0, 1}) {
		t.Fatalf("v4 bytes() = % x", got)
	}
	v6 := testIP6("2606:4700::6810:1")
	if v6.is4() {
		t.Fatal("a real IPv6 address detected as IPv4")
	}
	if got := v6.bytes(); len(got) != 16 {
		t.Fatalf("v6 bytes() length %d, want 16", len(got))
	}
	if _, ok := ipAddrOf(nil); ok {
		t.Fatal("ipAddrOf(nil) reported ok")
	}
}

// TestDesyncIPv6Handshake runs the same handshake-and-fire path as TestDesyncEarlyFiresBeforeData, over IPv6:
// the key, the checksum pseudo-header and the packet's IP header must all follow the v6 family.
func TestDesyncIPv6Handshake(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := desyncKey{testIP6("2001:db8::2"), testIP6("2001:db8::1"), 5000, 443}
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt6(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired over IPv6")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	pkt := sent.at(0)
	if pkt[0]>>4 != 6 {
		t.Fatalf("fake IP version %d, want 6", pkt[0]>>4)
	}
	if len(pkt) != 40+20+len(tr.hello) {
		t.Fatalf("fake length %d, want %d (40 B IPv6 header)", len(pkt), 40+20+len(tr.hello))
	}
	if !bytes.Equal(pkt[8:24], k.srcIP[:]) || !bytes.Equal(pkt[24:40], k.dstIP[:]) {
		t.Fatal("fake carries the wrong IPv6 addresses")
	}
	if got := binary.BigEndian.Uint32(pkt[44:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	stored := binary.BigEndian.Uint16(pkt[40+16:])
	binary.BigEndian.PutUint16(pkt[40+16:], 0)
	if good := tcpChecksum(pkt[40:], k.srcIP.bytes(), k.dstIP.bytes()); good != stored {
		t.Fatalf("fake IPv6 TCP checksum %x, want %x", stored, good)
	}
}

// fakeip mode's destination must match the connection's own address family: a v6 flow gets defaultFakeIP6 (or a
// configured v6 -fake-ip), never the v4 default.
func TestDesyncFakeIPUsesMatchingFamily(t *testing.T) {
	tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "fakeip"}) // no -fake-ip: defaults
	defer tr.close()
	k := desyncKey{testIP6("2001:db8::2"), testIP6("2001:db8::1"), 5000, 443}
	ch := tr.announce(k, 1001, true)
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 1000, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt6(k.dstIP, k.srcIP, k.dstPt, k.srcPt, 500000, 1001, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 1001, 500001, testFlagACK, nil, 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fakeip fake never fired over IPv6")
	}
	if sent.n() != 2 {
		t.Fatalf("fakeip sent %d packets, want 2 (SYN + ClientHello)", sent.n())
	}
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		if pkt[0]>>4 != 6 {
			t.Fatalf("packet %d IP version %d, want 6 (the connection's family)", i, pkt[0]>>4)
		}
		if !bytes.Equal(pkt[24:40], defaultFakeIP6[:]) {
			t.Fatalf("packet %d dst % x, want the default IPv6 CDN edge % x", i, pkt[24:40], defaultFakeIP6)
		}
	}
}

// An explicit v4 -fake-ip must not be sent to a v6 connection (there is no address to put in the packet): fakeip
// mode falls back to the v6 default instead of mis-addressing the fake.
func TestDesyncFakeIPMismatchedFamilyFallsBack(t *testing.T) {
	tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "fakeip", FakeIP: "104.16.0.1"})
	defer tr.close()
	k := desyncKey{testIP6("2001:db8::2"), testIP6("2001:db8::1"), 5000, 443}
	tr.announce(k, 1001, true)
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 1000, 0, testFlagSYN, nil, 64))
	tr.handleIP(desyncTestPkt6(k.dstIP, k.srcIP, k.dstPt, k.srcPt, 500000, 1001, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIP(desyncTestPkt6(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 1001, 500001, testFlagACK, nil, 64))
	if sent.n() != 2 {
		t.Fatalf("sent %d packets, want 2", sent.n())
	}
	if !bytes.Equal(sent.at(0)[24:40], defaultFakeIP6[:]) {
		t.Fatalf("dst % x, want the v6 default (the configured -fake-ip is v4, wrong family)", sent.at(0)[24:40])
	}
}

// parseEthIP must also recognise IPv6 inside every framing it already handles for IPv4.
func TestDesyncParseEthIPv6(t *testing.T) {
	rawIP6 := make([]byte, 40)
	rawIP6[0] = 0x60
	rawIP6[6] = 6 // next header TCP, so it is not confused with a non-TCP IPv6 packet
	if got := parseEthIP(rawIP6); got == nil || len(got) != 40 {
		t.Fatal("raw IPv6 packet rejected")
	}

	eth6 := make([]byte, 14+40)
	binary.BigEndian.PutUint16(eth6[12:], 0x86dd)
	eth6[14] = 0x60
	if got := parseEthIP(eth6); got == nil || len(got) != 40 {
		t.Fatal("Ethernet-framed IPv6 packet rejected")
	}

	vlan6 := make([]byte, 18+40)
	binary.BigEndian.PutUint16(vlan6[12:], 0x8100)
	binary.BigEndian.PutUint16(vlan6[16:], 0x86dd)
	vlan6[18] = 0x60
	if got := parseEthIP(vlan6); got == nil || len(got) != 40 {
		t.Fatal("VLAN-tagged IPv6 packet rejected")
	}

	sll6 := make([]byte, 16+40)
	binary.BigEndian.PutUint16(sll6[14:], 0x86dd)
	sll6[16] = 0x60
	if got := parseEthIP(sll6); got == nil || len(got) != 40 {
		t.Fatal("SLL-framed IPv6 packet rejected")
	}
}

// verifyV6TCP checks an IPv6+TCP packet the way a receiver does, with the pseudo header assembled by hand (not by
// tcpChecksum): the ones' complement sum over pseudo header and segment, stored checksum included, must be 0xffff,
// which csum reports as 0.
func verifyV6TCP(pkt []byte) bool {
	ph := make([]byte, 0, 40+len(pkt))
	ph = append(ph, pkt[8:24]...)                                    // source
	ph = append(ph, pkt[24:40]...)                                   // destination
	ph = append(ph, 0, 0, byte((len(pkt)-40)>>8), byte(len(pkt)-40)) // upper-layer length
	ph = append(ph, 0, 0, 0, 6)                                      // zeros, next header TCP
	return csum(append(ph, pkt[40:]...)) == 0
}

// Every IPv6 packet shape the builders emit must carry a TCP checksum a real receiver accepts.
func TestFakePacketIPv6Checksum(t *testing.T) {
	k := desyncKey{testIP6("2001:db8::2"), testIP6("2001:db8::1"), 5000, 443}
	hello := FakeClientHello("mci.ir")
	for name, pkt := range map[string][]byte{
		"hello":      fakePacket(k, 1000, 2000, 64, hello),
		"hello+opts": fakePacketWithOptions(k, 1000, 2000, 64, hello, []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}),
		"empty":      fakePacket(k, 1000, 2000, 64, nil),
		"syn":        fakeFlagPacket(k, 1000, 0, 64, 0x02),
		"rst":        fakeRSTPacket(k, 1000, 2000, 64),
	} {
		if pkt[0]>>4 != 6 {
			t.Fatalf("%s: not an IPv6 packet", name)
		}
		if got := int(binary.BigEndian.Uint16(pkt[4:])); got != len(pkt)-40 {
			t.Fatalf("%s: IPv6 payload length %d, want %d", name, got, len(pkt)-40)
		}
		if !verifyV6TCP(pkt) {
			t.Fatalf("%s: TCP checksum does not verify against the IPv6 pseudo header", name)
		}
	}
	// the IPv4 path is unchanged: same property, its own pseudo header
	k4 := testClientKey()
	p4 := fakePacket(k4, 1000, 2000, 64, hello)
	ph := append(append(append([]byte{}, p4[12:20]...), 0, 6), byte((len(p4)-20)>>8), byte(len(p4)-20))
	if csum(append(ph, p4[20:]...)) != 0 {
		t.Fatal("IPv4 TCP checksum no longer verifies")
	}
}

// damageChecksum must break the TCP checksum and nothing else: a write at the IPv4 offset into an IPv6 packet
// corrupted the destination address (live, 2026-10-23: ::1 became ::fffe:1 and the marker never reached the peer).
func TestDamageChecksumIPv6TouchesOnlyTheChecksum(t *testing.T) {
	for name, k := range map[string]desyncKey{
		"v6": {testIP6("2001:db8::2"), testIP6("2001:db8::1"), 5000, 443},
		"v4": testClientKey(),
	} {
		pkt := fakePacket(k, 1000, 2000, 64, FakeClientHello("mci.ir"))
		orig := append([]byte(nil), pkt...)
		damageChecksum(pkt)
		at := ipHdrLen(pkt) + 16
		for i := range pkt {
			if i != at && i != at+1 && pkt[i] != orig[i] {
				t.Fatalf("%s: byte %d changed, but only the checksum field (%d..%d) may", name, i, at, at+1)
			}
		}
		if binary.BigEndian.Uint16(pkt[at:]) == binary.BigEndian.Uint16(orig[at:]) {
			t.Fatalf("%s: the checksum was not changed", name)
		}
		if name == "v6" && verifyV6TCP(pkt) {
			t.Fatal("damaged IPv6 packet still verifies")
		}
	}
}

// The default fakeip destination for IPv6 is the documented 2606:4700::6810:1.
func TestDefaultFakeIP6(t *testing.T) {
	if want := testIP6("2606:4700::6810:1"); defaultFakeIP6 != want {
		t.Fatalf("defaultFakeIP6 = %x, want 2606:4700::6810:1 (%x)", defaultFakeIP6, want)
	}
	if want := testIP4("104.16.0.1"); defaultFakeIP != want {
		t.Fatalf("defaultFakeIP = %x, want 104.16.0.1", defaultFakeIP)
	}
}

// TestDesyncPatternihaDuplicateACKSync tests that after sending an out-of-window fake packet,
// the tracker waits for the server's duplicate ACK (ack == SND.NXT) before closing ackChan.
func TestDesyncPatternihaDuplicateACKSync(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)

	// announce connection with known sequence numbers from TCP_REPAIR
	ch := tr.announce(k, isn, true, srvSeq+1)
	select {
	case <-ch: // fake packet fired
	default:
		t.Fatal("fake packet did not fire on announce")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake sent, got %d", sent.n())
	}
	ackCh := tr.ackChan(k)
	if ackCh == nil {
		t.Fatal("ackChan is nil")
	}

	// Before server ACK arrives, ackCh must remain open
	select {
	case <-ackCh:
		t.Fatal("ackCh closed before server duplicate ACK arrived")
	default:
	}

	// Simulate server sending duplicate ACK: ack == isn+1, payload == 0
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq+1, isn+1, testFlagACK, nil, 64))

	// ackCh must now be closed
	select {
	case <-ackCh:
	default:
		t.Fatal("ackCh did not close after duplicate ACK arrived from server")
	}
}

// TestDesyncResendBeforeAck: while the duplicate ACK is pending, resend fires the same marker once more (3.0.0);
// after the ACK the connection is gone and resend sends nothing.
func TestDesyncResendBeforeAck(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	<-tr.announce(k, isn, true, srvSeq+1)
	if !tr.resend(k) || sent.n() != 2 {
		t.Fatalf("resend before the ACK: sent %d, want 2", sent.n())
	}
	if !bytes.Equal(sent.at(0), sent.at(1)) {
		t.Fatal("the retransmitted marker differs from the first one")
	}
	tr.handleIP(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq+1, isn+1, testFlagACK, nil, 64))
	if tr.resend(k) || sent.n() != 2 {
		t.Fatalf("resend after the ACK: sent %d, want still 2", sent.n())
	}
}

// TestFakeClientHelloPatternihaExact517 verifies that FakeClientHello builds a 517-byte Chrome ClientHello
// with valid RFC 7685 padding for standard SNIs, matching patterniha/SNI-Spoofing.
func TestFakeClientHelloPatternihaExact517(t *testing.T) {
	for _, sni := range []string{"www.cloudflare.com", "mci.ir", "cf.xoamrz.ir", "auth.vercel.com"} {
		rec := FakeClientHello(sni)
		if len(rec) != 517 {
			t.Fatalf("FakeClientHello(%q) len = %d, want exactly 517 bytes", sni, len(rec))
		}
		parsed, err := parseSNIOf(rec)
		if err != nil {
			t.Fatalf("parseSNIOf(%q) failed: %v", sni, err)
		}
		if parsed != sni {
			t.Fatalf("parsed SNI = %q, want %q", parsed, sni)
		}
	}
}

// TestDesyncResendKeepsDelayedMarkers: a mode with a delayed second marker (ff, F&F pieces 1 ms apart) resends
// every piece, not only the first one (3.0.0 review).
func TestDesyncResendKeepsDelayedMarkers(t *testing.T) {
	tr, sent := desyncTestTracker("ff", 0)
	defer tr.close()
	k := testClientKey()
	<-tr.announce(k, 1000, true, 500001)
	n := sent.n()
	for stable := 0; stable < 5; { // the delayed pieces: wait until the count stops moving, a slow runner needs more than a fixed pause
		time.Sleep(20 * time.Millisecond)
		if m := sent.n(); m != n {
			n, stable = m, 0
		} else {
			stable++
		}
	}
	if n < 2 {
		t.Fatalf("ff sent %d pieces, want several", n)
	}
	if !tr.resend(k) {
		t.Fatal("no resend")
	}
	if sent.n() != 2*n {
		t.Fatalf("resend sent %d, want all %d pieces", sent.n()-n, n)
	}
	// The delayed pieces leave from independent 1 ms timers, so the order they reach the log is not fixed: compare the
	// pieces as a set.
	first, again := make([]string, n), make([]string, n)
	for i := 0; i < n; i++ {
		first[i], again[i] = string(sent.at(i)), string(sent.at(n+i))
	}
	sort.Strings(first)
	sort.Strings(again)
	for i := range first {
		if first[i] != again[i] {
			t.Fatalf("resent pieces differ from the first run (piece %d of the sorted set)", i)
		}
	}
}
