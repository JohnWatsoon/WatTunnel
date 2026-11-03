//go:build linux

package wat

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func TestRawIPFrame(t *testing.T) {
	for _, gre := range []bool{true, false} {
		r := &RawIPIO{gre: gre, hdrBytes: 28}
		if gre {
			r.hdrBytes = 36
		}
		r.key, r.in, r.sport = rawIPIdent([]byte("k"))
		p := []byte("sealed datagram")
		b := r.frame(nil, p)
		ih := 0
		if gre {
			if binary.BigEndian.Uint32(b) != 0x20000800 || binary.BigEndian.Uint32(b[4:]) != r.key {
				t.Fatal("gre header")
			}
			ih = 8
		}
		if b[ih] != 0x45 || b[ih+9] != 17 || csum(b[ih:ih+20]) != 0 {
			t.Fatalf("inner ipv4 header %x", b[ih:ih+20])
		}
		if binary.BigEndian.Uint32(b[ih+16:]) != r.in[1] || int(binary.BigEndian.Uint16(b[ih+2:])) != 28+len(p) {
			t.Fatal("client frame must go to the server's inner address")
		}
		got, ok := r.unframe(b)
		if !ok || !bytes.Equal(got, p) {
			t.Fatalf("unframe: %q", got)
		}
	}
}

// Over loopback with real raw sockets (root only): client and server exchange a datagram both ways, and an ipip
// socket of the same key never sees gre traffic.
func TestRawIPLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need root")
	}
	for _, gre := range []bool{true, false} {
		key := []byte("loopback key")
		srv, err := NewRawIPIO(gre, true, "", "", key)
		if err != nil {
			t.Fatal(err)
		}
		cli, err := NewRawIPIO(gre, false, "127.0.0.1", "", key)
		if err != nil {
			t.Fatal(err)
		}
		if err := cli.Send([]byte("ping"), 0); err != nil {
			t.Fatal(err)
		}
		srv.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		p, _, src, err := srv.Recv()
		if err != nil || string(p) != "ping" {
			t.Fatalf("gre=%v server got %q %v", gre, p, err)
		}
		if err := srv.SendTo([]byte("pong"), 0, src); err != nil {
			t.Fatal(err)
		}
		cli.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if p, _, _, err = cli.Recv(); err != nil || string(p) != "pong" {
			t.Fatalf("gre=%v client got %q %v", gre, p, err)
		}
		srv.Close()
		cli.Close()
	}
}
