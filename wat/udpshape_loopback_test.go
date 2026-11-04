package wat

// F19 phase-2 UDP-shaped carriers (3.3.0): one real loopback row per shipped shape — the shaped carrier comes up, a
// stream's payload passes byte-exact both ways, and a datagram with the wrong shape/key is dropped instead of being
// adopted. Runs on every platform (plain UDP loopback, no root).

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

// shapedUDPPair brings up a real Server over one shaped loopback carrier and returns a connected client Session.
func shapedUDPPair(t *testing.T, name string) *Session {
	t.Helper()
	key := []byte("udp-shape-loopback-key")
	us, err := NewShapedUDPServer(name, "127.0.0.1:0", key)
	if err != nil {
		t.Fatalf("%s server: %v", name, err)
	}
	srv := NewServer(Config{Key: key}, us)
	srv.IdleTimeout = 5 * time.Second
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go serveUDPStream(st)
				}
			}(s)
		}
	}()
	uc, err := NewShapedUDPClient(name, us.Addr().String(), key)
	if err != nil {
		t.Fatalf("%s client: %v", name, err)
	}
	cli, err := NewSession(Config{Key: key}, uc)
	if err != nil {
		t.Fatalf("%s session: %v", name, err)
	}
	t.Cleanup(cli.Close)
	deadline := time.Now().Add(5 * time.Second)
	for !cli.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cli.Alive() {
		t.Fatalf("%s: session never came up over the shaped carrier", name)
	}
	return cli
}

func TestShapedUDPLoopback(t *testing.T) {
	for _, sh := range udpShapeTable {
		sh := sh
		t.Run(sh.name, func(t *testing.T) {
			cli := shapedUDPPair(t, sh.name)
			// 'E' echo: the server's serveUDPStream mirrors the bytes, so this is a full payload round trip.
			udpEcho(t, cli, 3000, 11)
			// 'U' upload: read to EOF, reply the sha256 — proves a larger payload is delivered intact after shaping.
			up := pattern(200<<10, 3)
			st, err := cli.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			go func() { st.Write(append([]byte{'U'}, up...)); st.CloseWrite() }()
			sum, err := readAll(st)
			want := sha256.Sum256(up)
			if err != nil || !bytes.Equal(sum, want[:]) {
				t.Fatalf("upload digest: err=%v got %x want %x", err, sum, want)
			}
		})
	}
}

// TestShapedUDPMismatch: a plain udp client and a differently-shaped client must not get a session against a shaped
// server — the strip rejects every datagram it cannot validate, rather than handing it to the session layer.
func TestShapedUDPMismatch(t *testing.T) {
	key := []byte("udp-shape-mismatch")
	us, err := NewShapedUDPServer("vxlan", "127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Key: key}, us)
	t.Cleanup(srv.Close)
	for _, name := range []string{"", "geneve"} { // "" = plain udp carrier, "geneve" = wrong shaped carrier
		var pio PacketIO
		if name == "" {
			pio, err = NewUDPClient(us.Addr().String())
		} else {
			pio, err = NewShapedUDPClient(name, us.Addr().String(), key)
		}
		if err != nil {
			t.Fatal(err)
		}
		cli, err := NewSession(Config{Key: key}, pio)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(1200 * time.Millisecond)
		if cli.Alive() {
			t.Errorf("%s client got a session against a vxlan-shaped server", name)
		}
		select {
		case <-srv.New:
			t.Errorf("%s client was admitted by a vxlan-shaped server", name)
		default:
		}
		cli.Close()
	}
}
