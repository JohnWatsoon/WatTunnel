package wat

// Coded repair (repair.go, 3.4.3): correctness of the round trip, and the mixed-version rule — a pair with
// repair off on either end exchanges NO repair frames and transfers exactly like today (the negotiation
// gates on frRepairCap, which an old peer never sends).

import (
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

// newPairMixed: like newPairCap but each side gets its own Config (the mixed-version tests fake the old
// peer with repair off).
func newPairMixed(t testing.TB, loss float64, mtu int, cliCfg, srvCfg Config) (cli, srv *Session) {
	t.Helper()
	up := newSimDirCap(loss, 20*time.Millisecond, 10e6, 100*time.Millisecond, 13, mtu)
	down := newSimDirCap(loss, 20*time.Millisecond, 10e6, 100*time.Millisecond, 14, mtu)
	key := []byte("test-key")
	cliCfg.Key, srvCfg.Key = key, key
	cliCfg.Server, srvCfg.Server = false, true
	cliCfg.SID, srvCfg.SID = 0x1234567, 0x1234567
	cliCfg.MaxPayload, srvCfg.MaxPayload = mtu, mtu
	cliCfg.Paths = 4
	var err error
	cli, err = NewSession(cliCfg, &simIO{up, down, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(srvCfg, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

func downloadOnce(t *testing.T, cli, srv *Session, size int, seed byte) {
	t.Helper()
	data := pattern(size, seed)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		st.Write(data)
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte{1})
	st.CloseWrite()
	done := make(chan []byte, 1)
	go func() { b, _ := readAll(st); done <- b }()
	select {
	case got := <-done:
		if sha256.Sum256(got) != sha256.Sum256(data) {
			t.Fatalf("data mismatch: got %d want %d bytes", len(got), len(data))
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
}

// A lossy download with repair on both ends must deliver intact data, send symbols, and actually rebuild
// holes at the receiver.
func TestRepairRoundTrip(t *testing.T) {
	cli, srv := newPairMixed(t, 0.02, 1400, Config{Repair: true}, Config{Repair: true})
	downloadOnce(t, cli, srv, 6<<20, 31)
	ss, cs := srv.Stats(), cli.Stats()
	t.Logf("repair round trip: symbols sent=%d recovered=%d retrans=%d", ss.RepairSent, cs.RepairRecovered, ss.Retrans)
	if ss.RepairSent == 0 {
		t.Error("no repair symbols sent")
	}
	if cs.RepairRecovered == 0 {
		t.Error("no holes rebuilt by repair")
	}
}

// The v2 ask layer on top of the periodic one: with RepairAsk on both ends a lossy download must send
// frRepairAsks, answer them with targeted symbols, and rebuild more holes than v1 alone.
func TestRepairAskRoundTrip(t *testing.T) {
	cli, srv := newPairMixed(t, 0.02, 1400, Config{Repair: true, RepairAsk: true}, Config{Repair: true, RepairAsk: true})
	downloadOnce(t, cli, srv, 6<<20, 51)
	ss, cs := srv.Stats(), cli.Stats()
	t.Logf("repair+ask round trip: symbols sent=%d recovered=%d asks=%d askHit=%d askMiss=%d retrans=%d",
		ss.RepairSent, cs.RepairRecovered, cli.repair.askSent, srv.repair.askHit, srv.repair.askMiss, ss.Retrans)
	if ss.RepairSent == 0 {
		t.Error("no repair symbols sent")
	}
	if cs.RepairRecovered == 0 {
		t.Error("no holes rebuilt by repair")
	}
	if cli.repair == nil || cli.repair.askSent == 0 {
		t.Error("no frRepairAsks sent")
	}
	if srv.repair.askHit == 0 {
		t.Error("no ask answered with a targeted symbol")
	}
}

// askCount: the internal ask counter, 0 for a session without the repair state (mixed-version checks).
func askCount(s *Session) uint64 {
	if s.repair != nil {
		return s.repair.askSent
	}
	return 0
}

// Mixed pair, both directions (the "old" peer is one with repair off — it never sends frRepairCap, exactly
// what a pre-3.4.3 binary does with the frame): no repair frames of ANY kind may flow — symbols, caps that
// engage, or asks (the new end has RepairAsk on, so this also pins the peerOK gate on the ask path) — and the
// transfer must be correct.
func TestRepairMixedVersions(t *testing.T) {
	t.Run("new_client_old_server", func(t *testing.T) {
		cli, srv := newPairMixed(t, 0.01, 1400, Config{Repair: true, RepairAsk: true}, Config{})
		downloadOnce(t, cli, srv, 2<<20, 41)
		if s, r := srv.Stats().RepairSent, cli.Stats().RepairRecovered; s != 0 || r != 0 {
			t.Errorf("sent=%d recovered=%d repair frames; a mixed pair must send none", s, r)
		}
		if a := askCount(cli) + askCount(srv); a != 0 {
			t.Errorf("%d frRepairAsks; a mixed pair must exchange zero repair frames of any kind", a)
		}
	})
	t.Run("old_client_new_server", func(t *testing.T) {
		cli, srv := newPairMixed(t, 0.01, 1400, Config{}, Config{Repair: true, RepairAsk: true})
		downloadOnce(t, cli, srv, 2<<20, 42)
		if s, r := srv.Stats().RepairSent, cli.Stats().RepairRecovered; s != 0 || r != 0 {
			t.Errorf("sent=%d recovered=%d repair frames; a mixed pair must send none", s, r)
		}
		if a := askCount(cli) + askCount(srv); a != 0 {
			t.Errorf("%d frRepairAsks; a mixed pair must exchange zero repair frames of any kind", a)
		}
	})
}

// repairCover must be a deterministic half-subset on both ends, and two packets must rarely share a whole
// coverage pattern across many k (the GF(2) rank property the decoder leans on).
func TestRepairCoverProperties(t *testing.T) {
	if !repairCover(12345, 7) == repairCover(12345, 7) {
		t.Fatal("cover is not deterministic")
	}
	half := 0
	n := 10000
	for k := uint64(0); k < uint64(n); k++ {
		if repairCover(999, k) {
			half++
		}
	}
	if half < n/2*9/10 || half > n/2*11/10 {
		t.Errorf("cover hits %d of %d symbols; want ~half", half, n)
	}
	same := 0
	for k := uint64(0); k < uint64(n); k++ {
		if repairCover(100, k) == repairCover(101, k) {
			same++
		}
	}
	if same > n*3/4 {
		t.Errorf("neighbouring pns share coverage in %d of %d symbols; want ~half", same, n)
	}
	// 2026-11-21 v2 pin: two pns must be JOINTLY covered by some k (the v1 single-bit-of-XOR form collapsed
	// to two fixed subsets and half of all pairs were never jointly covered — the real reason v1 measured no
	// gain). Coverage must also vary across k per pn, not flip the whole set.
	for _, pr := range [][2]uint64{{0, 1}, {5, 9}, {100, 101}, {1 << 63, 1<<63 + 1}} {
		ok := false
		for k := uint64(0); k < 64; k++ {
			if repairCover(pr[0], k) && repairCover(pr[1], k) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("pns %v never jointly covered within the ask search bound", pr)
		}
	}
}
