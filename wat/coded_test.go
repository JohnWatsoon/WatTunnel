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
	"fmt"
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

// killClass is one echo sample's loss diagnosis: which direction's retransmit/repair machinery moved
// while the sample was in flight. If the CLEAN samples carry the same p99 as the whole run, the tail
// is queueing/scheduling/pacing, not loss (the P3 tail diagnosis, 2026-11-21).
type killClass int

const (
	kcClean killClass = iota // no counter moved: no retransmit or repair touched this sample
	kcDown                   // downlink: the server retransmitted or the client's repair rebuilt a hole
	kcUp                     // uplink: the client retransmitted (the echo request was lost)
	kcOther                  // both directions moved in one sample
)

var killClassNames = [4]string{"clean", "down", "up", "other"}

// classifyKill: up = the client's Retrans rose (the request packet), down = the server's Retrans rose
// or the client's RepairRecovered rose (a downlink hole, retransmitted or rebuilt).
func classifyKill(up, down bool) killClass {
	switch {
	case !up && !down:
		return kcClean
	case down && !up:
		return kcDown
	case up && !down:
		return kcUp
	}
	return kcOther
}

// killLatency runs a bulk download on one stream and measures small echo latencies on other streams while
// it runs. It returns the sorted latencies, the per-sample loss classes (still paired: lat[i] and cls[i]
// describe the same sample), and the sender's stats snapshot.
//
// The pairing matters: until 2026-11-21 this sorted lat AFTER appending cls, so a caller reading
// lat[i] at a chronologically-clean cls[i] got the i-th SLOWEST latency, and every "clean-subset"
// number since P3 read loss-recovery samples (clean p50 ~87 ms) instead of the real clean floor
// (~41 ms). TestDiagSchedKillTRun (diagsched_test.go) was the discovery: interleaved byte-identical
// copies with and without the trailing sort report clean p50 ~85 vs ~41 ms.
func killLatency(t testing.TB, loss float64, mtu int, samples int, warmup, gap time.Duration, cfg Config) (lat []time.Duration, cls []killClass, st Stats) {
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
		c0, s0 := cli.Stats(), srv.Stats()
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		c1, s1 := cli.Stats(), srv.Stats()
		cls = append(cls, classifyKill(
			c1.Retrans > c0.Retrans,
			s1.Retrans > s0.Retrans || c1.RepairRecovered > c0.RepairRecovered))
		time.Sleep(gap)
	}
	// sort lat and cls together, so the class pairing survives the sort (see the doc comment above)
	pair := make([]struct {
		lat time.Duration
		c   killClass
	}, len(lat))
	for i := range lat {
		pair[i].lat, pair[i].c = lat[i], cls[i]
	}
	sort.Slice(pair, func(i, j int) bool { return pair[i].lat < pair[j].lat })
	for i := range pair {
		lat[i], cls[i] = pair[i].lat, pair[i].c
	}
	return lat, cls, srv.Stats()
}

// killPct returns the p-percentile of a sorted slice (or 0 when empty, logged as n/a by the caller).
func killPct(lat []time.Duration, p float64) time.Duration {
	if len(lat) == 0 {
		return 0
	}
	return lat[int(float64(len(lat)-1)*p)]
}

// TestKillInteractiveP99: p50/p90/p99/max of a 1-byte echo next to a bulk download, 1 % loss, 40 ms RTT,
// at both MTUs. The retransmit path (detect after ~1.25xRTT of ACK silence, resend, another RTT) puts a
// lost downlink packet's echo at roughly 2-3xRTT; a repair that lands with the following packets should
// pull p99 toward the no-loss floor.
func TestKillInteractiveP99(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, cfg := range []Config{{}, {FastRtx: true}, {Repair: true, RepairAsk: true, FastRtx: true}} {
		mode := "today"
		if cfg.Repair {
			mode = "repair+ask"
		}
		if cfg.FastRtx {
			if cfg.Repair {
				mode = "repair+ask+fast"
			} else {
				mode = "fast-rtx"
			}
		}
		for _, mtu := range []int{640, 1400} {
			lat, cls, st := killLatency(t, 0.01, mtu, 120, 3*time.Second, 50*time.Millisecond, cfg)
			var clean []time.Duration
			var cnt [4]int
			for i, c := range cls {
				cnt[c]++
				if c == kcClean {
					clean = append(clean, lat[i])
				}
			}
			sort.Slice(clean, func(i, j int) bool { return clean[i] < clean[j] })
			cleanP99 := "n/a"
			if len(clean) > 0 {
				cleanP99 = fmt.Sprintf("%v (n=%d, p50=%v, max=%v)", killPct(clean, 0.99), len(clean), killPct(clean, 0.5), clean[len(clean)-1])
			}
			t.Logf("KILL p99 %s mtu=%d loss=1%%: p50=%v p90=%v p99=%v max=%v cleanP99=%s classes clean=%d down=%d up=%d other=%d (retrans=%d, srtt=%v, min=%v)",
				mode, mtu, killPct(lat, 0.5), killPct(lat, 0.9), killPct(lat, 0.99), lat[len(lat)-1],
				cleanP99, cnt[kcClean], cnt[kcDown], cnt[kcUp], cnt[kcOther], st.Retrans, st.SRTT, st.MinRTT)
		}
	}
}

// The loss-classification rule behind the kill harness's tail diagnosis, pinned separately so the
// harness numbers cannot drift on a refactor (P3, 2026-11-21).
func TestKillClassify(t *testing.T) {
	for _, tc := range []struct {
		up, down bool
		want     killClass
	}{
		{false, false, kcClean},
		{false, true, kcDown},
		{true, false, kcUp},
		{true, true, kcOther},
	} {
		if got := classifyKill(tc.up, tc.down); got != tc.want {
			t.Fatalf("classifyKill(up=%v, down=%v) = %v, want %v", tc.up, tc.down, got, tc.want)
		}
	}
}

// TestKillBulkThroughput: download MB/s at 0, 0.5, 1 and 2 % loss, 1400 MTU, today vs repair. Coded repair
// must not cost throughput at 0 % (no overhead) and should recover some of the loss-induced rate at 0.5-2 %.
func TestKillBulkThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, cfg := range []Config{{}, {FastRtx: true}, {Repair: true, RepairAsk: true, FastRtx: true}, {BurstCap: float64(8 * (1400 - overhead))}} {
		mode := "today"
		if cfg.BurstCap > 0 {
			mode = "burst-cap"
		}
		if cfg.FastRtx && !cfg.Repair {
			mode = "fast-rtx"
		} else if cfg.Repair {
			mode = "repair+ask+fast"
		}
		for _, loss := range []float64{0, 0.005, 0.01, 0.02} {
			mb, retrans := bulkOnce(t, loss, 8<<20, cfg)
			t.Logf("KILL throughput %s loss=%.1f%%: %.1f MB/s (8 MB, retrans=%d)", mode, loss*100, mb, retrans)
		}
	}
}

// TestKillBurstCap: the token-burst cap (Config.BurstCap) judged on the kill harness (speed-swarm phase 2,
// 2026-11-21). The phase-1 diag measured a late pump tick dumping ~94 KB (the dynamic bucket ceiling
// rate*0.005+64 KB) onto the link in one wakeup, a 60 ms link-queue p99 an interactive echo queues behind.
// Here the cap is 8xmaxPlain (8 packets: the catch-up spreads over wakeups; steady bulk is untouched because
// tokens sit below one packet in 100 % of busy ticks). Measuring test — logs p50/p90/p99 at 1 % loss, both
// MTUs, cap vs today; the pass/fail judgement is made from the logged numbers.
func TestKillBurstCap(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, mtu := range []int{640, 1400} {
		for _, c := range []struct {
			name string
			cfg  Config
		}{{"today", Config{}}, {"burst-cap", Config{BurstCap: float64(8 * (mtu - overhead))}}} {
			lat, cls, st := killLatency(t, 0.01, mtu, 120, 3*time.Second, 50*time.Millisecond, c.cfg)
			var clean []time.Duration
			var cnt [4]int
			for i, k := range cls {
				cnt[k]++
				if k == kcClean {
					clean = append(clean, lat[i])
				}
			}
			sort.Slice(clean, func(i, j int) bool { return clean[i] < clean[j] })
			cleanStr := "n/a"
			if len(clean) > 0 {
				cleanStr = fmt.Sprintf("%v (n=%d, p50=%v)", killPct(clean, 0.99), len(clean), killPct(clean, 0.5))
			}
			t.Logf("KILL burstcap %s mtu=%d loss=1%%: p50=%v p90=%v p99=%v max=%v cleanP99=%s classes clean=%d down=%d up=%d other=%d (retrans=%d, srtt=%v, min=%v)",
				c.name, mtu, killPct(lat, 0.5), killPct(lat, 0.9), killPct(lat, 0.99), lat[len(lat)-1],
				cleanStr, cnt[kcClean], cnt[kcDown], cnt[kcUp], cnt[kcOther], st.Retrans, st.SRTT, st.MinRTT)
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
