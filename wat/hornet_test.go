package wat

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// R3 Hornet-MTU (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md,
// disposition table). Hornet itself (multi-IP ICMP striping, reply amplification) is rejected/split; what survives
// is the question: "consider live MTU adaptation independently: lower MTU during transfer, verify integrity,
// bounded recovery and return to the larger size."
//
// The scenario it models: an ISP clamps a path's payload mid-download (measured on live Iran paths: ICMP above
// ~668 B vanishes while small pings pass). The sender must shrink its packets without resetting any stream, keep
// the transfer flowing (bounded stall), and later return to the larger size when the clamp lifts.
//
// The engine has no production API for this yet (maxPlain is fixed at NewSession; the old carrier plan assumed a
// SetMaxPayload that never existed). The mutator below is the experiment: it edits s.maxPlain + s.cc.maxPlain
// under s.mu, which is safe by construction - build() sizes packets from maxPlain (smaller is always wire-legal),
// plainBuf/out buffers are scratch append handles, and a receiver accepts smaller packets without any signal.
// If the experiment passes, a real design review decides the production shape (a frame-flagged clamp the peer
// mirrors, not a silent local edit).

// sessionSetMaxPayload changes a live session's packet payload ceiling. TEST-ONLY (see above).
func sessionSetMaxPayload(s *Session, payload int) {
	s.mu.Lock()
	s.maxPlain = payload - overhead
	s.cc.maxPlain = s.maxPlain
	s.mu.Unlock()
}

// hornetPair is a sim pair whose links accept full 1400 B payload packets (the shared newPair caps at 700 B, the
// ICMP-path model, which would drop every 1400 B packet before the experiment even starts).
func hornetPair(t *testing.T, cfg Config) (cli, srv *Session) {
	up := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 1, 1500)
	down := newSimDirCap(0.002, 20*time.Millisecond, 10e6, 100*time.Millisecond, 2, 1500)
	key := []byte("hornet-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	var err error
	cli, err = NewSession(cc, &simIO{up, down, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(sc, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// TestHornetMTUShrinkRecovers: a bulk download over the sim link (1400 B packets); mid-transfer the sender's
// payload ceiling drops to 640 B, later returns to 1400 B. Requirements: data arrives byte-intact, the stall at
// each switch is bounded (no reset, < 2 s), the on-wire packet size follows the ceiling down and back up.
func TestHornetMTUShrinkRecovers(t *testing.T) {
	cli, srv := hornetPair(t, Config{MaxPayload: 1400})
	const n = 24 << 20
	data := pattern(n, 9)
	done := make(chan error, 1)
	var got []byte
	go func() {
		st, err := srv.Accept()
		if err != nil {
			done <- err
			return
		}
		b, err := readAll(st)
		got = b
		done <- err
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()

	// The data sender here is the CLIENT (upload scenario); its outgoing average packet size is the metric.
	// (The server's PktsOut is mostly small ACKs and would hide the effect.)
	time.Sleep(1 * time.Second)
	full0 := cli.Stats()
	avgBefore := float64(full0.BytesOut) / float64(max(full0.PktsOut, 1))

	// shrink mid-transfer on the data sender
	sessionSetMaxPayload(cli, 640)
	time.Sleep(1 * time.Second)
	shrunk := cli.Stats()
	avgShrunk := float64(shrunk.BytesOut-full0.BytesOut) / float64(max(shrunk.PktsOut-full0.PktsOut, 1))

	// return to the larger size
	sessionSetMaxPayload(cli, 1400)
	time.Sleep(1 * time.Second)
	back := cli.Stats()
	avgBack := float64(back.BytesOut-shrunk.BytesOut) / float64(max(back.PktsOut-shrunk.PktsOut, 1))

	t.Logf("avg packet bytes: full %.0f, shrunk %.0f, back %.0f (client pkts %d, bytes %.1f MB)",
		avgBefore, avgShrunk, avgBack, back.PktsOut, float64(back.BytesOut)/1e6)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed across the MTU changes: %v", err)
		}
		if len(got) != n {
			t.Fatalf("short download: %d of %d", len(got), n)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("data corrupted across the MTU changes")
		}
	case <-time.After(120 * time.Second):
		t.Fatal("download timed out across the MTU changes")
	}

	// the wire followed the ceiling: full-size before, ~640-sized during the clamp, full-size after
	if avgBefore < 1200 {
		t.Fatalf("pre-shrink packets averaged %.0f B, expected near-full 1400 B packets", avgBefore)
	}
	if avgShrunk > 800 {
		t.Fatalf("shrunken packets averaged %.0f B, want ~640 B on the wire", avgShrunk)
	}
	if avgBack < 1200 {
		t.Fatalf("post-grow packets averaged %.0f B, want the full size back", avgBack)
	}
}

// TestHornetMTUSmallSurvivesClamp: the clamp scenario's other half - SMALL interactive exchanges keep flowing
// while a bulk transfer is shrunken, i.e. the shrink does not stall the interactive path. Streams are
// opcode-prefixed: 'E' = echo 4 bytes back, 'D' = bulk upload the server just reads.
func TestHornetMTUSmallSurvivesClamp(t *testing.T) {
	cli, srv := hornetPair(t, Config{MaxPayload: 1400})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func(st *Stream) {
				var op [1]byte
				if _, err := readFull(st, op[:]); err != nil {
					return
				}
				if op[0] == 'E' {
					var b [4]byte
					if _, err := readFull(st, b[:]); err != nil {
						return
					}
					st.Write(b[:])
					st.CloseWrite()
					return
				}
				readAll(st) // 'D': bulk upload, nothing echoed
			}(st)
		}
	}()

	bulk, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	bulk.Write([]byte{'D'})
	bulk.Write(pattern(16<<20, 3))
	bulk.CloseWrite()
	time.Sleep(300 * time.Millisecond)

	sessionSetMaxPayload(cli, 640) // clamp hits while the interactive exchanges run
	var worst time.Duration
	for i := 0; i < 20; i++ {
		st, _ := cli.OpenStream()
		t0 := time.Now()
		st.Write([]byte{'E', 'e', 'c', 'h', 'o'})
		buf := make([]byte, 4)
		readFull(st, buf)
		if d := time.Since(t0); d > worst {
			worst = d
		}
		st.CloseWrite()
		time.Sleep(20 * time.Millisecond)
	}
	sessionSetMaxPayload(cli, 1400)
	t.Logf("20 x 4 B exchanges during the clamp: worst %v", worst.Round(time.Millisecond))
	if worst > 2*time.Second {
		t.Fatalf("an interactive exchange took %v during the clamp", worst)
	}
}
