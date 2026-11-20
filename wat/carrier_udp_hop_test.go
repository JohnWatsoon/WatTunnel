package wat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Wraith: every source port carries at most 1.5N packets, and replies to the newest port reach Recv.
func TestUDPHopRotatesSourcePort(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	u, err := NewUDPClient(srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	const n = 4
	if err := u.SetHop(n); err != nil {
		t.Fatal(err)
	}
	per := map[int]int{}
	buf := make([]byte, 2048)
	for i := 0; i < 60; i++ {
		if i%2 == 0 {
			if err := u.Send([]byte{byte(i)}, 0); err != nil {
				t.Fatal(err)
			}
		} else if err := u.SendBatch([][]byte{{byte(i)}}, nil); err != nil {
			t.Fatal(err)
		}
		srv.SetReadDeadline(time.Now().Add(2 * time.Second))
		k, src, err := srv.ReadFromUDP(buf)
		if err != nil || k != 1 || buf[0] != byte(i) {
			t.Fatalf("packet %d: k=%d err=%v", i, k, err)
		}
		per[src.Port]++
		if _, err := srv.WriteToUDP([]byte{byte(i), 0xee}, src); err != nil { // reply to the newest source, like Session.SetPeer
			t.Fatal(err)
		}
		p, _, _, err := u.Recv()
		if err != nil || len(p) != 2 || p[0] != byte(i) {
			t.Fatalf("reply %d: %v %v", i, p, err)
		}
	}
	if len(per) < 60/(n+n/2) {
		t.Errorf("only %d source ports for 60 packets", len(per))
	}
	for port, c := range per {
		if c > n+n/2 {
			t.Errorf("port %d carried %d packets, cap %d", port, c, n+n/2)
		}
	}
	u.Close()
	if _, _, _, err := u.Recv(); err == nil {
		t.Error("Recv after Close must fail")
	}
}

// A whole session over Wraith against a plain udp Server: 4 MB each way with the source port changing every 12-18
// packets (the field setting), so the server must keep following the newest port.
func TestUDPHopSessionBulk(t *testing.T) {
	r := newUDPRig(t, 0)
	uc, err := NewUDPClient(r.addr)
	if err != nil {
		t.Fatal(err)
	}
	uc.SetHop(12)
	cli, err := NewSession(Config{Key: r.key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	const n = 4 << 20
	up := pattern(n, 3)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(append([]byte{'U'}, up...)); st.CloseWrite() }()
	sum, err := readAll(st)
	want := sha256.Sum256(up)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("upload digest mismatch: err=%v len=%d", err, len(sum))
	}
	st, err = cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{'D', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(req[1:], n)
	go func() { st.Write(req); st.CloseWrite() }()
	got, err := readAll(st)
	if err != nil || !bytes.Equal(got, pattern(n, 7)) {
		t.Fatalf("download mismatch: err=%v got %d want %d", err, len(got), n)
	}
}
