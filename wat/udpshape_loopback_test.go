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
			// F29 (audit 2026-11-04): bound the read, or a stuck stream runs into the package timeout instead of
			// failing this test.
			type readResult struct {
				b   []byte
				err error
			}
			done := make(chan readResult, 1)
			go func() { b, rerr := readAll(st); done <- readResult{b, rerr} }()
			select {
			case r := <-done:
				want := sha256.Sum256(up)
				if r.err != nil || !bytes.Equal(r.b, want[:]) {
					t.Fatalf("upload digest: err=%v got %x want %x", r.err, r.b, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("upload read did not finish within 10 s")
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
		// F29 (audit 2026-11-04): no fixed sleep. Two send attempts with no authenticated reply is the no-admission
		// condition: on loopback a server that admitted the first packet would have answered it before the second one
		// was built (the handshake retry is at least 1 s; poll for the packet counter instead of sleeping).
		cli, err := NewSession(Config{Key: key}, pio)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for cli.Stats().PktsOut < 2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := cli.Stats().PktsOut; n < 2 {
			t.Fatalf("%s client made %d send attempts, want at least 2", name, n)
		}
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
