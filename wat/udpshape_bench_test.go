package wat

// F19 phase-2 UDP-shaped carriers (3.3.0): loopback throughput of each shape against the plain udp carrier. Run with:
//
//	go test -run xxx -bench 'ShapedUDP' -benchtime 2s ./wat/
import (
	"crypto/sha256"
	"io"
	"testing"
	"time"
)

// benchShapedUDP uploads b.N * 64 KiB through one stream over the given carrier (name == "" is plain udp).
func benchShapedUDP(b *testing.B, name string) {
	key := []byte("udp-shape-bench-key")
	var raw RawIO
	var addr string
	if name == "" {
		us, err := NewUDPServer("127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		raw, addr = us, us.Addr().String()
	} else {
		us, err := NewShapedUDPServer(name, "127.0.0.1:0", key)
		if err != nil {
			b.Fatal(err)
		}
		raw, addr = us, us.Addr().String()
	}
	cfg := Config{Key: key, InitBps: 1e9, MaxBps: 1e9} // no rate ramp: this row isolates the shape's overhead
	srv := NewServer(cfg, raw)
	srv.IdleTimeout = 10 * time.Second
	b.Cleanup(srv.Close)
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
	var pio PacketIO
	var err error
	if name == "" {
		pio, err = NewUDPClient(addr)
	} else {
		pio, err = NewShapedUDPClient(name, addr, key)
	}
	if err != nil {
		b.Fatal(err)
	}
	cli, err := NewSession(cfg, pio)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(cli.Close)
	deadline := time.Now().Add(5 * time.Second)
	for !cli.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cli.Alive() {
		b.Fatal("session never came up")
	}
	st, err := cli.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := st.Write([]byte{'U'}); err != nil { // 'U': read to EOF, reply sha256
		b.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	st.CloseWrite()
	if _, err := io.ReadFull(st, make([]byte, sha256.Size)); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkShapedUDP(b *testing.B) {
	b.Run("udp", func(b *testing.B) { benchShapedUDP(b, "") })
	for _, sh := range udpShapeTable {
		sh := sh
		b.Run(sh.name, func(b *testing.B) { benchShapedUDP(b, sh.name) })
	}
}
