//go:build linux

package wat

// Phantom (ptcp) tests: the segment codec (checksums, options, seq/ack) runs anywhere on Linux; the
// loopback session test needs root's raw socket and runs in CI's root job (it skips as non-root, the
// icmp/rawip tests' pattern).

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// A built segment's checksum must verify: the ones-complement sum over pseudo-header + segment (checksum
// included) folds to 0xffff.
func verifySum(src, dst net.IP, seg []byte) bool {
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
	return s == 0xffff
}

func TestPTCPSegmentCodec(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(203, 0, 113, 9)
	syn := ptcpBuild(src, dst, 61000, 443, 1000, 0, ptcpSYN, 0, nil)
	if !verifySum(src, dst, syn) {
		t.Fatal("SYN checksum does not verify")
	}
	if syn[12]>>4 != 10 { // 20 + 20 B options
		t.Fatalf("SYN header length = %d words", syn[12]>>4)
	}
	// MSS 1460 at option offset 2, SACK-permitted (4,2), timestamps (8,10), wscale (1,3,3,7)
	if syn[22] != 2 || syn[23] != 4 || binary.BigEndian.Uint16(syn[24:]) != 1460 {
		t.Errorf("SYN MSS option malformed: % x", syn[20:40])
	}
	if syn[28] != 4 || syn[29] != 2 {
		t.Errorf("SYN SACK-permitted option missing")
	}
	if syn[30] != 8 || syn[31] != 10 {
		t.Errorf("SYN timestamp option missing")
	}
	if syn[38] != 1 || syn[39] != 3 || syn[40] != 3 || syn[41] != 7 {
		t.Errorf("SYN wscale option malformed")
	}
	sport, dport, seq, ack, flags, data, ok := ptcpParse(syn)
	if !ok || sport != 61000 || dport != 443 || seq != 1000 || flags != ptcpSYN || len(data) != 0 {
		t.Fatalf("SYN parse: %+v ok=%v", sport, ok)
	}

	dat := []byte("wat-test-payload")
	seg := ptcpBuild(src, dst, 61000, 443, 2000, 3001, ptcpPSH|ptcpACK, 77, dat)
	if !verifySum(src, dst, seg) {
		t.Fatal("data checksum does not verify")
	}
	sport, dport, seq, ack, flags, data, ok = ptcpParse(seg)
	if !ok || seq != 2000 || ack != 3001 || flags != ptcpPSH|ptcpACK || string(data) != string(dat) {
		t.Fatalf("data parse: %d/%d %d %d %x %q", sport, dport, seq, ack, flags, data)
	}
	if seg[12]>>4 != 8 { // 20 + 12 B timestamp options on every non-SYN segment
		t.Fatalf("data header length = %d words", seg[12]>>4)
	}
	if binary.BigEndian.Uint32(seg[24:]) != 77 { // TSecr echoes the peer's TSval
		t.Errorf("TSecr = %d, want 77", binary.BigEndian.Uint32(seg[24:]))
	}
}

// A full exchange on loopback with real raw sockets (root only): the handshake rides, datagrams flow both
// ways, and with hop=4 thirty packets spread over several flows, every flow under the ~30-packet cut.
func TestPTCPLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need root")
	}
	srv, err := NewPTCPServer(40443)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := NewPTCPClient("127.0.0.1:40443", "", "www.example.com", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// uplink: 30 datagrams, hop budget 4..6 per flow
	for i := 0; i < 30; i++ {
		if err := cli.Send([]byte{byte(i)}, 0); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	got := map[byte]bool{}
	var dst net.Addr
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < 30 && time.Now().Before(deadline) {
		p, _, src, err := srv.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if dst == nil {
			dst = src // the newest flow's address is where the downlink goes
		}
		if len(p) == 1 {
			got[p[0]] = true
		}
	}
	if len(got) < 30 {
		t.Fatalf("server got %d/30 datagrams", len(got))
	}

	// downlink: the server replies down the newest flow's address
	for i := 0; i < 10; i++ {
		if err := srv.SendTo([]byte{byte(200 + i)}, 0, dst); err != nil {
			t.Fatalf("sendto %d: %v", i, err)
		}
	}
	dg := 0
	deadline = time.Now().Add(5 * time.Second)
	for dg < 10 && time.Now().Before(deadline) {
		p, _, _, err := cli.Recv()
		if err != nil {
			continue
		}
		if len(p) == 1 && p[0] >= 200 {
			dg++
		}
	}
	if dg < 10 {
		t.Fatalf("client got %d/10 downlink datagrams", dg)
	}

	// the hop rule: every flow stayed under 30 packets (the measured cut), several flows were used
	cli.mu.Lock()
	n, mx := len(cli.flows), 0
	for _, f := range cli.flows {
		mx = max(mx, f.sent)
	}
	cli.mu.Unlock()
	if mx >= 30 {
		t.Errorf("one flow carried %d packets (the cut is ~30)", mx)
	}
	if n < 4 {
		t.Errorf("only %d flows for 30 packets with hop=4; hopping did not happen", n)
	}
	t.Logf("loopback: %d flows, max %d packets per flow, 30 up + 10 down delivered", n, mx)
}
