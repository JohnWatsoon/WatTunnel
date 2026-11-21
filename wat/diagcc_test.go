//go:build diag

// The speed-swarm diagnostics (2026-11-21): measurement tools, NOT regression pins — they add ~7 min to
// the suite, so they build only under the diag tag:  go test -tags diag -run Diag ./wat/
package wat

// Diagnostic-only tests (supervisor mission 2026-11-21): why does bulk throughput cap at ~half of a
// 10 MB/s zero-loss sim link? Measuring tests — they log numbers, assert only correctness, and touch
// no production file. Run: go test -count=1 -run DiagCC ./wat/

import (
	"crypto/sha256"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// diagIO wraps simIO and counts sealed bytes + packets per direction (ACK pressure experiment).
type diagIO struct {
	simIO
	txBytes, txPkts uint64
}

func (d *diagIO) Send(p []byte, lane int) error {
	atomic.AddUint64(&d.txBytes, uint64(len(p)))
	atomic.AddUint64(&d.txPkts, 1)
	return d.simIO.Send(p, lane)
}

// diagPair: newPair but honors cfg.Paths / cfg.MaxPayload and returns counting IOs.
func diagPair(t testing.TB, loss float64, delay time.Duration, bps float64, mtu int, cfg Config) (cli, srv *Session, cio, sio *diagIO) {
	t.Helper()
	up := newSimDirCap(loss, delay, bps, 100*time.Millisecond, 21, mtu)
	down := newSimDirCap(loss, delay, bps, 100*time.Millisecond, 22, mtu)
	key := []byte("test-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	cc.MaxPayload = mtu
	if cc.Paths <= 0 {
		cc.Paths = 4
	}
	sc.Paths = cc.Paths
	cio = &diagIO{simIO: simIO{up, down, make(chan struct{}), sync.Once{}}}
	sio = &diagIO{simIO: simIO{down, up, make(chan struct{}), sync.Once{}}}
	var err error
	cli, err = NewSession(cc, cio)
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(sc, sio)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// diagDownload runs one bulk download of size bytes; returns MB/s plus sender stats at the end.
func diagDownload(t testing.TB, loss float64, mtu int, size int, cfg Config, sample func(t time.Duration, s Stats)) (mbps float64, st Stats) {
	t.Helper()
	cli, srv, cio, sio := diagPair(t, loss, 20*time.Millisecond, 10e6, mtu, cfg)
	data := pattern(size, 31)
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
				st.Write(data)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	done := make(chan struct{})
	t0 := time.Now()
	go func() { io.Copy(io.Discard, bs); close(done) }()
	if sample != nil {
		go func() {
			tk := time.NewTicker(50 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					sample(time.Since(t0), srv.Stats())
				}
			}
		}()
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
	el := time.Since(t0)
	st = srv.Stats()
	st.BytesOut = atomic.LoadUint64(&sio.txBytes)
	st.PktsOut = atomic.LoadUint64(&sio.txPkts)
	_ = cio
	return float64(size) / el.Seconds() / 1e6, st
}

// Experiment 1: constraint telemetry at 0% loss. Which limiter binds, ramp vs steady.
func TestDiagCCConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, mtu := range []int{640, 1400} {
		t.Logf("=== mtu=%d loss=0 10MB/s download, 16 MB ===", mtu)
		mbps, st := diagDownload(t, 0, mtu, 16<<20, Config{}, func(el time.Duration, s Stats) {
			t.Logf("t=%5.2fs rate=%5.2fMB/s cwnd=%7d inflight=%7d winBlocked=%d ticks: tok=%d cwnd=%d app=%d pool=%d cuts: delay=%d loss=%d",
				el.Seconds(), s.RateBps/1e6, s.Cwnd, s.Inflight, s.WinBlocked,
				s.CC.TokLimited, s.CC.CwndLimited, s.CC.AppLimited, s.CC.PoolFull, s.CC.DelayCuts, s.CC.LossCuts)
		})
		t.Logf("RESULT mtu=%d: %.2f MB/s | ticks tok=%d cwnd=%d app=%d pool=%d | delayCuts=%d lossCuts=%d deep=%d | ackBytesDown=%d ackPktsDown=%d dataBytes=%d srtt=%v min=%v cwnd=%d",
			mtu, mbps, st.CC.TokLimited, st.CC.CwndLimited, st.CC.AppLimited, st.CC.PoolFull,
			st.CC.DelayCuts, st.CC.LossCuts, st.CC.DeepTrips, st.BytesOut, st.PktsOut, uint64(16<<20), st.SRTT, st.MinRTT, st.Cwnd)
	}
}

// Experiment 2: knob sweeps at 0% loss, 1400 MTU, 8 MB each.
func TestDiagCCSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	type tc struct {
		name string
		cfg  Config
	}
	cases := []tc{
		{"default", Config{}},
		{"init8M", Config{InitBps: 8e6}},
		{"init16M", Config{InitBps: 16e6}},
		{"max64M", Config{MaxBps: 64e6}},
		{"init8+max64", Config{InitBps: 8e6, MaxBps: 64e6}},
		{"slack20ms", Config{Slack: 20 * time.Millisecond}},
		{"slack50ms", Config{Slack: 50 * time.Millisecond}},
		{"slack50+init8", Config{Slack: 50 * time.Millisecond, InitBps: 8e6}},
		{"slack100+init8+max64", Config{Slack: 100 * time.Millisecond, InitBps: 8e6, MaxBps: 64e6}},
		{"hedge", Config{Hedge: true}},
		{"win64M", Config{WinMax: 64 << 20}},
	}
	for _, mtu := range []int{640, 1400} {
		for _, c := range cases {
			mbps, st := diagDownload(t, 0, mtu, 8<<20, c.cfg, nil)
			t.Logf("SWEEP mtu=%d %-22s %5.2f MB/s (rate=%.2f srtt=%v min=%v tok=%d cwnd=%d app=%d delayCuts=%d winBlk=%d)",
				mtu, c.name, mbps, st.RateBps/1e6, st.SRTT, st.MinRTT, st.CC.TokLimited, st.CC.CwndLimited, st.CC.AppLimited, st.CC.DelayCuts, st.WinBlocked)
		}
	}
	// paths sweep (needs cfg.Paths honored; diagPair does)
	for _, p := range []int{1, 4, 8} {
		mbps, st := diagDownload(t, 0, 1400, 8<<20, Config{Paths: p}, nil)
		t.Logf("SWEEP mtu=1400 paths=%d             %5.2f MB/s (rate=%.2f tok=%d cwnd=%d app=%d delayCuts=%d)",
			p, mbps, st.RateBps/1e6, st.CC.TokLimited, st.CC.CwndLimited, st.CC.AppLimited, st.CC.DelayCuts)
	}
}

// Experiment 2b: parallel streams in one session vs one stream (shared 10 MB/s link).
func TestDiagCCParallelStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, n := range []int{1, 4} {
		cli, srv, _, _ := diagPair(t, 0, 20*time.Millisecond, 10e6, 1400, Config{})
		const per = 4 << 20
		data := pattern(per, 41)
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
					st.Write(data)
					st.CloseWrite()
				}()
			}
		}()
		var wg sync.WaitGroup
		t0 := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				bs, _ := cli.OpenStream()
				bs.Write([]byte{'B'})
				bs.CloseWrite()
				h := sha256.Sum256(data)
				b, _ := readAll(bs)
				if sha256.Sum256(b) != h {
					t.Error("mismatch")
				}
			}()
		}
		wg.Wait()
		el := time.Since(t0)
		s := srv.Stats()
		t.Logf("SWEEP streams=%d total=%.2f MB/s (rate=%.2f tok=%d cwnd=%d app=%d delayCuts=%d winBlk=%d)",
			n, float64(n*per)/el.Seconds()/1e6, s.RateBps/1e6, s.CC.TokLimited, s.CC.CwndLimited, s.CC.AppLimited, s.CC.DelayCuts, s.WinBlocked)
	}
}

// Experiment 3: ACK pressure. Count reverse-direction (client->server) bytes during a download:
// how much of the 10 MB/s uplink the ACK stream consumes, and its packet count.
func TestDiagCCAckPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, mtu := range []int{640, 1400} {
		cli, srv, cio, _ := diagPair(t, 0, 20*time.Millisecond, 10e6, mtu, Config{})
		data := pattern(8<<20, 51)
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
					st.Write(data)
					st.CloseWrite()
				}()
			}
		}()
		bs, _ := cli.OpenStream()
		bs.Write([]byte{'B'})
		bs.CloseWrite()
		t0 := time.Now()
		io.Copy(io.Discard, bs)
		el := time.Since(t0)
		t.Logf("ACK mtu=%d: download %.2f MB/s, client reverse tx=%d B in %d pkts (avg %d B/pkt) = %.3f MB/s of reverse bw",
			mtu, float64(len(data))/el.Seconds()/1e6,
			atomic.LoadUint64(&cio.txBytes), atomic.LoadUint64(&cio.txPkts),
			atomic.LoadUint64(&cio.txBytes)/max(1, atomic.LoadUint64(&cio.txPkts)),
			float64(atomic.LoadUint64(&cio.txBytes))/el.Seconds()/1e6)
		_ = srv
	}
}

// Steady state: longer transfers (32 MB) so the ramp is a small fraction, with the knobs that won the sweep.
func TestDiagCCSteady(t *testing.T) {
	if testing.Short() {
		t.Skip("measuring test")
	}
	for _, c := range []struct {
		name string
		cfg  Config
	}{{"default", Config{}}, {"init8", Config{InitBps: 8e6}}, {"init8+slack50", Config{InitBps: 8e6, Slack: 50 * time.Millisecond}}, {"init8+slack50+max64", Config{InitBps: 8e6, Slack: 50 * time.Millisecond, MaxBps: 64e6}}, {"rate-tune", Config{RateTune: true}}, {"rate-tune+init8", Config{RateTune: true, InitBps: 8e6}}} {
		mbps, st := diagDownload(t, 0, 1400, 32<<20, c.cfg, nil)
		t.Logf("STEADY %-22s %5.2f MB/s (rate=%.2f srtt=%v min=%v tok=%d cwnd=%d app=%d delayCuts=%d lost=%d spur=%d)",
			c.name, mbps, st.RateBps/1e6, st.SRTT, st.MinRTT, st.CC.TokLimited, st.CC.CwndLimited, st.CC.AppLimited, st.CC.DelayCuts, st.CC.Lost, st.CC.Spurious)
	}
}
