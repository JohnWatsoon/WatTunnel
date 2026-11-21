//go:build linux

package wat

// spray tests: the packet codec and the rotation state machine run anywhere on Linux; the loopback
// exchange needs root's raw socket and runs in CI's root job (skips as non-root, the ptcp pattern).

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// A built packet's checksum must verify: the ones-complement sum over pseudo-header (proto 17) + packet
// (checksum included) folds to 0xffff.
func verifySpraySum(src, dst net.IP, pkt []byte) bool {
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
	return s == 0xffff
}

func TestSprayPacketCodec(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(203, 0, 113, 9)
	payload := []byte("wat-spray-payload")
	var buf []byte
	pkt := sprayPacket(&buf, src, dst, 61234, 41567, payload)
	if len(pkt) != 8+len(payload) {
		t.Fatalf("packet length = %d", len(pkt))
	}
	if sport := binary.BigEndian.Uint16(pkt[0:]); sport != 61234 {
		t.Errorf("sport = %d", sport)
	}
	if dport := binary.BigEndian.Uint16(pkt[2:]); dport != 41567 {
		t.Errorf("dport = %d", dport)
	}
	if plen := binary.BigEndian.Uint16(pkt[4:]); plen != uint16(8+len(payload)) {
		t.Errorf("length field = %d", plen)
	}
	if !verifySpraySum(src, dst, pkt) {
		t.Fatal("UDP checksum does not verify")
	}
	if string(pkt[8:]) != string(payload) {
		t.Fatal("payload not intact")
	}
	// odd-length payload: the checksum folds the trailing byte as low byte
	pkt = sprayPacket(&buf, src, dst, 61234, 41567, payload[:7])
	if !verifySpraySum(src, dst, pkt) {
		t.Fatal("odd-length checksum does not verify")
	}
	// unwrap round-trip on a fake raw read: 20-byte IP header + the packet
	raw := append(append([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0}, src.To4()...), dst.To4()...)
	raw = append(raw, pkt...)
	p, sport, dport, ok := sprayUnwrap(raw)
	if !ok || sport != 61234 || dport != 41567 || string(p) != string(pkt[8:]) {
		t.Fatalf("unwrap: ok=%v %d %d %q", ok, sport, dport, p)
	}
}

// The rotation hands every tuple N..1.5N packets — never more — and both ports stay inside their ranges.
func TestSprayRotation(t *testing.T) {
	for _, n := range []int{4, 16, 33} {
		r := &sprayRot{dLo: 41000, dHi: 41999, n: n}
		perTuple := 0
		sports, dports := map[uint16]bool{}, map[uint16]bool{}
		for i := 0; i < 20000; i++ {
			sport, dport, fresh := r.next()
			if fresh && i > 0 {
				if perTuple < n || perTuple > n+n/2 {
					t.Fatalf("n=%d: tuple held %d packets (want %d..%d)", n, perTuple, n, n+n/2)
				}
				perTuple = 0
			}
			perTuple++
			if sport < sprayCLo || sport > sprayCHi {
				t.Fatalf("sport %d outside %d-%d", sport, sprayCLo, sprayCHi)
			}
			if dport < 41000 || dport > 41999 {
				t.Fatalf("dport %d outside the range", dport)
			}
			sports[sport] = true
			dports[dport] = true
		}
		if r.max > n+n/2 {
			t.Fatalf("n=%d: max tuple %d packets", n, r.max)
		}
		if r.tuples < 100 {
			t.Fatalf("n=%d: only %d tuples in 20000 packets", n, r.tuples)
		}
		if len(sports) < 50 || len(dports) < 50 {
			t.Fatalf("n=%d: rotation reused ports (%d sports, %d dports)", n, len(sports), len(dports))
		}
	}
}

// A full exchange on loopback with real raw sockets (root only), hop=4: several hundred datagrams both
// ways, all delivered, several tuples used and every tuple far under the ~30-packet field cut.
func TestSprayLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need root")
	}
	srv, err := NewSprayServer("43100-43199")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := NewSprayClient("127.0.0.1:43100-43199", "", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const up = 220
	send := make([][]byte, 0, up)
	for i := 0; i < up; i++ {
		b := make([]byte, 64)
		binary.BigEndian.PutUint16(b, uint16(i))
		send = append(send, b)
	}
	if err := cli.SendBatch(send[:20], nil); err != nil {
		t.Fatal(err)
	}
	for _, b := range send[20:] {
		if err := cli.Send(b, 0); err != nil {
			t.Fatal(err)
		}
	}

	got := map[uint16]bool{}
	perSport := map[int]int{} // the client's tuples, counted by the server per source port
	var dst net.Addr
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < up && time.Now().Before(deadline) {
		p, _, src, err := srv.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if dst == nil {
			dst = src
		}
		ua := src.(*net.UDPAddr)
		perSport[ua.Port]++
		if len(p) >= 2 {
			got[binary.BigEndian.Uint16(p)] = true
		}
		// echo it back: the downlink rides the newest sport
		if err := srv.SendTo(p, 0, dst); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) < up {
		t.Fatalf("server got %d/%d uplink datagrams", len(got), up)
	}
	if len(perSport) < 10 {
		t.Fatalf("only %d tuples carried %d packets (rotation did not spread)", len(perSport), up)
	}
	for port, n := range perSport {
		if n > 30 {
			t.Fatalf("tuple :%d carried %d packets (>30, the field cut)", port, n)
		}
	}

	back := map[uint16]bool{}
	deadline = time.Now().Add(10 * time.Second)
	for len(back) < up && time.Now().Before(deadline) {
		p, _, _, err := cli.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) >= 2 {
			back[binary.BigEndian.Uint16(p)] = true
		}
	}
	if len(back) < up {
		t.Fatalf("client got %d/%d downlink datagrams", len(back), up)
	}
	cli.mu.Lock()
	maxTuple, tuples := cli.rot.max, cli.rot.tuples
	cli.mu.Unlock()
	if maxTuple > 30 {
		t.Fatalf("uplink max tuple = %d packets", maxTuple)
	}
	if tuples < 10 {
		t.Fatalf("client used only %d tuples", tuples)
	}
}
