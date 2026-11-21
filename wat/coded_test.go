package wat

// The coded-downlink kill test (docs/handoff/PLAN-phase2.md, Track A step 3). These are MEASURING tests:
// they log p50/p90/p99 latency and bulk throughput so a later coded-repair build can be compared against
// today's numbers with the same harness, seeds and link model. They assert only correctness (data intact,
// run completes) — the pass/fail judgement of the kill test is made from the logged numbers, not here.
//
// Link model: the target path — 20 ms one way (40 ms RTT), 10 MB/s, random loss, 100 ms max queue, packet
// cap = the MTU under test (640 B = the ICMP path today, 1400 B = the full-route MTU since 2026-10-12).

import (
	"crypto/sha256"
	"io"
	"sort"
	"sync"
	"testing"
	"time"
)

func newPairCap(t testing.TB, loss float64, delay time.Duration, bps float64, mtu int, cfg Config) (cli, srv *Session) {
	t.Helper()
	up := newSimDirCap(loss, delay, bps, 100*time.Millisecond, 11, mtu)
	down := newSimDirCap(loss, delay, bps, 100*time.Millisecond, 12, mtu)
	key := []byte("test-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	cc.MaxPayload = mtu
	cc.Paths = 4
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
	return cli, srv
}

// killLatency runs a bulk download on one stream and measures small echo latencies on other streams while
// it runs. It returns the sorted latencies plus the sender's stats snapshot.
func killLatency(t testing.TB, loss float64, mtu int, samples int, warmup, gap time.Duration, cfg Config) (lat []time.Duration, st Stats) {
	t.Helper()
	cli, srv := newPairCap(t, loss, 20*time.Millisecond, 10e6, mtu, cfg)
	bulkData := pattern(96<<20, 5)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulkData)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(warmup)
	for i := 0; i < samples; i++ {
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		time.Sleep(gap)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat, srv.Stats()
}

// TestKillInteractiveP99: p50/p90/p99/max of a 1-byte echo next to a bulk download, 1 % loss, 40 ms RTT,
// at both MTUs. The retransmit path (detect after ~1.25xRTT of ACK silence, resend, another RTT) puts a
// lost downlink packet's echo at roughly 2-3xRTT; a repair that lands with the following packets should
// pull p99 toward the no-loss floor.
func TestKillInteractiveP99(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, cfg := range []Config{{}, {Repair: true}, {Repair: true, RepairAsk: true}} {
		mode := "today"
		if cfg.Repair {
			mode = "repair"
		}
		if cfg.RepairAsk {
			mode = "repair+ask"
		}
		for _, mtu := range []int{640, 1400} {
			lat, st := killLatency(t, 0.01, mtu, 120, 3*time.Second, 50*time.Millisecond, cfg)
			q := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }
			t.Logf("KILL p99 %s mtu=%d loss=1%%: p50=%v p90=%v p99=%v max=%v (retrans=%d, srtt=%v, min=%v)",
				mode, mtu, q(0.5), q(0.9), q(0.99), lat[len(lat)-1], st.Retrans, st.SRTT, st.MinRTT)
		}
	}
}

// TestKillBulkThroughput: download MB/s at 0, 0.5, 1 and 2 % loss, 1400 MTU, today vs repair. Coded repair
// must not cost throughput at 0 % (no overhead) and should recover some of the loss-induced rate at 0.5-2 %.
func TestKillBulkThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, cfg := range []Config{{}, {Repair: true}, {Repair: true, RepairAsk: true}} {
		mode := "today"
		if cfg.Repair {
			mode = "repair"
		}
		if cfg.RepairAsk {
			mode = "repair+ask"
		}
		for _, loss := range []float64{0, 0.005, 0.01, 0.02} {
			mb, retrans := bulkOnce(t, loss, 8<<20, cfg)
			t.Logf("KILL throughput %s loss=%.1f%%: %.1f MB/s (8 MB, retrans=%d)", mode, loss*100, mb, retrans)
		}
	}
}

func bulkOnce(t testing.TB, loss float64, size int, cfg Config) (mbps float64, retrans uint64) {
	t.Helper()
	cli, srv := newPairCap(t, loss, 20*time.Millisecond, 10e6, 1400, cfg)
	data := pattern(size, 21)
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
	t0 := time.Now()
	go func() { b, _ := readAll(st); done <- b }()
	select {
	case got := <-done:
		el := time.Since(t0)
		if sha256.Sum256(got) != sha256.Sum256(data) {
			t.Fatalf("data mismatch at loss=%v", loss)
		}
		s := srv.Stats()
		return float64(len(data)) / el.Seconds() / 1e6, s.Retrans
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
	return 0, 0
}

// BenchmarkRepairCodec: the CPU price of repair per data packet — one symbol per 16 packets (the mid
// adaptive rate), full-size members, build + solve, no transport.
func BenchmarkRepairCodec(b *testing.B) {
	tx := bareRepairSession(1)
	tx.maxPlain = 1340
	rx := bareRepairSession(1)
	p := padPacket(1340, 'q')
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pn := uint64(i)
		tx.repairNoteSent(pn, p)
		rx.rxRing[pn%rx.replayWin] = pn + 1
		if !rx.rxAny || pn > rx.rxLargest {
			rx.rxLargest, rx.rxAny, rx.rxAt = pn, true, time.Now()
		}
		rx.rxRanges.add(pn, pn+1)
		rx.repairKeep(pn, p)
		if i%16 == 15 {
			tx.repair.buildChunks(tx, uint64(i/16))
			for _, q := range tx.repair.queue {
				r := &reader{b: q}
				r.byte()
				rx.onRepair(r, time.Now(), nil)
			}
			tx.repair.queue = nil
		}
	}
}
