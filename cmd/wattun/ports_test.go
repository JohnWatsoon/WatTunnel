package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// tcpRig: a wattun client+server pair over the udp carrier on loopback, one echo service, one public port.
type tcpRig struct {
	pub, target int
	cs, ss      *portStat
}

func newTCPRig(t *testing.T) *tcpRig {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go acceptLoop(echo, func(c net.Conn) { io.Copy(c, c); c.Close() })
	target := echo.Addr().(*net.TCPAddr).Port

	key := []byte("ports-test-key")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key}, us)
	t.Cleanup(srv.Close)
	al := newAllow("", "")
	al.setPorts([]int{target})
	go func() {
		for s := range srv.New {
			go serve(s, 1, 65535, al)
		}
	}()
	uc, err := wat.NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := wat.NewSession(wat.Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	waitFor(t, "session alive", 5*time.Second, sess.Alive)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pub := ln.Addr().(*net.TCPAddr).Port
	cs := portReg.get("c", pub)
	tun := newTunnel([]*wat.Session{sess})
	go acceptLoop(ln, func(c net.Conn) { forward(tun, c, target, cs) })
	return &tcpRig{pub: pub, target: target, cs: cs, ss: portReg.get("s", target)}
}

// echoN sends n bytes through the public port and reads them back; returns bytes read and the elapsed time.
func (r *tcpRig) echoN(t *testing.T, n int) (int, time.Duration) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t0 := time.Now()
	go func() {
		buf := make([]byte, 16<<10)
		for sent := 0; sent < n; {
			k := min(len(buf), n-sent)
			if _, err := c.Write(buf[:k]); err != nil {
				return
			}
			sent += k
		}
	}()
	got, _ := io.CopyN(io.Discard, c, int64(n))
	return int(got), time.Since(t0)
}

func within(got, want int64, pct float64) bool {
	d := float64(got - want)
	if d < 0 {
		d = -d
	}
	return d <= float64(want)*pct/100
}

func TestPortCountersAndShape(t *testing.T) {
	r := newTCPRig(t)
	const n = 1 << 20
	hold, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "active conn", 3*time.Second, func() bool { return r.cs.connsActive.Load() == 1 && r.ss.connsActive.Load() == 1 })
	got, _ := r.echoN(t, n)
	if got != n {
		t.Fatalf("echoed %d of %d", got, n)
	}
	hold.Close()
	waitFor(t, "conns drained", 3*time.Second, func() bool { return r.cs.connsActive.Load() == 0 && r.ss.connsActive.Load() == 0 })
	for name, p := range map[string]*portStat{"client": r.cs, "server": r.ss} {
		if !within(p.bytesUp.Load(), n, 1) || !within(p.bytesDown.Load(), n, 1) {
			t.Errorf("%s: up=%d down=%d, want ~%d", name, p.bytesUp.Load(), p.bytesDown.Load(), n)
		}
		if p.connsTotal.Load() != 2 {
			t.Errorf("%s conns_total=%d, want 2", name, p.connsTotal.Load())
		}
	}
	portReg.tick()
	snap := portReg.snapshot("c")
	b, _ := json.Marshal(snap)
	var back map[string]map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	e := back[strconv.Itoa(r.pub)]
	for _, k := range []string{"bytes_up", "bytes_down", "conns_total", "conns_active", "udp_flows_active", "dgram_up", "dgram_down",
		"errors", "refused", "rate_bps_up", "rate_bps_down", "peak_bps_up", "peak_bps_down", "rate_limit_bps", "quota_limit", "quota_used", "quota_exceeded"} {
		if _, ok := e[k]; !ok {
			t.Errorf("/ports entry lacks %q", k)
		}
	}
	if e["peak_bps_up"].(float64) <= 0 {
		t.Errorf("peak not recorded: %v", e["peak_bps_up"])
	}
}

func TestPortRateLimit(t *testing.T) {
	r := newTCPRig(t)
	portReg.applyLimits([]limitSpec{{Port: r.pub, Rate: 1_000_000}})
	t.Cleanup(func() { portReg.applyLimits(nil) })
	const n = 2_000_000
	got, el := r.echoN(t, n)
	if got != n {
		t.Fatalf("echoed %d of %d", got, n)
	}
	mbs := float64(n) / el.Seconds() / 1e6
	t.Logf("%.2f MB/s", mbs)
	if mbs < 0.8 || mbs > 1.2 {
		t.Fatalf("rate %.2f MB/s, want 0.8-1.2", mbs)
	}
}

func TestPortQuotaCutoff(t *testing.T) {
	r := newTCPRig(t)
	portReg.applyLimits([]limitSpec{{Port: r.pub, Quota: 400_000}})
	t.Cleanup(func() { portReg.applyLimits(nil); portReg.resetQuota(r.pub) })
	got, _ := r.echoN(t, 3_000_000)
	if got >= 3_000_000 {
		t.Fatalf("transfer was not cut off (%d bytes)", got)
	}
	waitFor(t, "quota exceeded", 3*time.Second, func() bool { return r.cs.exceeded() })
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("new connection was served")
	}
	if r.cs.refused.Load() == 0 {
		t.Error("refused counter not incremented")
	}
	// reset (loopback only) lets traffic through again
	req := httptest.NewRequest("POST", "/quota/reset?port="+strconv.Itoa(r.pub), nil)
	req.RemoteAddr = "8.8.8.8:1234"
	w := httptest.NewRecorder()
	quotaResetHandler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-loopback reset got %d", w.Code)
	}
	req.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	quotaResetHandler(w, req)
	if w.Code != 200 || r.cs.exceeded() {
		t.Errorf("loopback reset: code %d exceeded=%v", w.Code, r.cs.exceeded())
	}
}

func TestQuotaPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wat.yml.quota.json")
	r1 := newRegistry()
	r1.loadQuota(path)
	r1.applyLimits([]limitSpec{{Port: 4242, Quota: 1000}})
	r1.get("c", 4242).add(true, 300)
	r1.get("c", 4242).add(false, 200)
	r1.save()
	r2 := newRegistry() // "restart"
	r2.loadQuota(path)
	r2.applyLimits([]limitSpec{{Port: 4242, Quota: 1000}})
	if u := r2.get("c", 4242).qused.Load(); u != 500 {
		t.Fatalf("restored usage %d, want 500", u)
	}
	r2.get("c", 4242).add(true, 600)
	if !r2.get("c", 4242).exceeded() {
		t.Fatal("quota should be exceeded after restore + 600")
	}
	if !r2.resetQuota(4242) || r2.get("c", 4242).exceeded() {
		t.Fatal("reset failed")
	}
	r3 := newRegistry()
	r3.loadQuota(path)
	if u := r3.get("c", 4242).qused.Load(); u != 0 {
		t.Fatalf("reset not persisted: %d", u)
	}
}

func TestLimitsConfigAndHotReload(t *testing.T) {
	c, err := parseConfig("mode: client\nports:\n  - 7001\nlimits:\n  - 7001 rate=5MB quota=100GB\n  - 7002 rate=300k\n", knownKeys)
	if err != nil || len(c.Limits) != 2 || c.Limits[0] != (limitSpec{Port: 7001, Rate: 5_000_000, Quota: 100_000_000_000}) || c.Limits[1].Rate != 300_000 {
		t.Fatalf("parse: %+v %v", c, err)
	}
	for _, bad := range []string{"limits:\n  - 7001 rate=abc\n", "limits:\n  - 7001 speed=1\n", "limits:\n  - x\n"} {
		if _, err := parseConfig(bad, knownKeys); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "wat.yml")
	writeCfg(t, path, "mode: client\nlimits:\n  - 7003 rate=1MB\n", 1)
	r := newRegistry()
	c, _ = parseConfig(mustRead(t, path), knownKeys)
	r.applyLimits(c.Limits)
	st := r.get("c", 7003)
	w := &cfgWatcher{path: path, known: knownKeys, interval: 20 * time.Millisecond, onPorts: func(*fileConfig) []error { return nil },
		onLimits: func(c *fileConfig) { r.applyLimits(c.Limits) }}
	w.start(c)
	go w.run()
	if st.rateLim.Load() != 1_000_000 || st.bUp.Load() == nil {
		t.Fatal("initial limit not applied")
	}
	writeCfg(t, path, "mode: client\nlimits:\n  - 7003 rate=2MB quota=1GB\n", 2)
	waitFor(t, "limit reload", 3*time.Second, func() bool { return st.rateLim.Load() == 2_000_000 && st.quota.Load() == 1_000_000_000 })
	writeCfg(t, path, "mode: client\nlimits:\n", 3)
	waitFor(t, "limit removal", 3*time.Second, func() bool { return st.rateLim.Load() == 0 && st.bUp.Load() == nil && st.quota.Load() == 0 })
}

// Lifetime totals survive a restart: a new registry loads what the old one saved and reports base + new traffic.
func TestTotalsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.totals.json")
	a := newRegistry()
	a.loadTotals(path, func() (uint64, uint64) { return 1000, 2000 })
	p := a.get("c", 20001)
	p.add(true, 300)
	p.add(false, 700)
	p.connsTotal.Add(2)
	a.save()

	b := newRegistry()
	b.loadTotals(path, func() (uint64, uint64) { return 10, 20 })
	q := b.get("c", 20001)
	q.add(true, 5)
	m := b.snapshot("c")["20001"].(map[string]any)
	if m["bytes_up_total"] != int64(305) || m["bytes_down_total"] != int64(700) || m["conns_all_time"] != int64(2) {
		t.Fatalf("totals after restart: %v", m)
	}
	if m["bytes_up"] != int64(5) {
		t.Fatalf("live counter should start at zero: %v", m["bytes_up"])
	}
	if in, out := b.sessionTotals(10, 20); in != 1010 || out != 2020 {
		t.Fatalf("session totals %d/%d", in, out)
	}
}

// Totals belong to the machine that wrote them: a config copied to another server starts from zero.
func TestTotalsResetOnAnotherMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.totals.json")
	saved := hostID
	defer func() { hostID = saved }()

	hostID = "machine-a"
	a := newRegistry()
	a.loadTotals(path, func() (uint64, uint64) { return 1000, 2000 })
	a.get("c", 20001).add(true, 300)
	a.save()

	hostID = "machine-b"
	b := newRegistry()
	b.loadTotals(path, func() (uint64, uint64) { return 7, 9 })
	if in, out := b.sessionTotals(7, 9); in != 7 || out != 9 {
		t.Fatalf("foreign totals leaked into this machine: %d/%d", in, out)
	}
	b.get("c", 20001)
	m := b.snapshot("c")["20001"].(map[string]any)
	if m["bytes_up_total"] != int64(0) || m["bytes_down_total"] != int64(0) {
		t.Fatalf("per-port totals from another machine: %v", m)
	}
}

// TestQuotaPeriod covers period=: parsing, the calendar starts, rollover on an injected clock and the state file,
// including an old numbers-only file and an old loader reading the new one (3.3.6).
func TestQuotaPeriod(t *testing.T) {
	if ls, err := parseLimitItem("7001 quota=1GB period=month"); err != nil || ls.Period != "month" || ls.Quota != 1e9 {
		t.Fatalf("parse: %+v %v", ls, err)
	}
	for _, bad := range []string{"7001 quota=1GB period=year", "7001 rate=1MB period=day"} {
		if _, err := parseLimitItem(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	loc := time.FixedZone("x", 3*3600+1800)
	wed := time.Date(2026, 11, 11, 15, 4, 0, 0, loc) // a Wednesday
	for _, c := range []struct {
		per         string
		start, next time.Time
	}{
		{"day", time.Date(2026, 11, 11, 0, 0, 0, 0, loc), time.Date(2026, 11, 12, 0, 0, 0, 0, loc)},
		{"week", time.Date(2026, 11, 9, 0, 0, 0, 0, loc), time.Date(2026, 11, 16, 0, 0, 0, 0, loc)},
		{"month", time.Date(2026, 11, 1, 0, 0, 0, 0, loc), time.Date(2026, 12, 1, 0, 0, 0, 0, loc)},
	} {
		if s, n := periodStart(wed, c.per), periodNext(wed, c.per); !s.Equal(c.start) || !n.Equal(c.next) {
			t.Errorf("%s: start %v next %v", c.per, s, n)
		}
	}

	// an old state file (numbers only) still loads; the used-up port reopens when the month rolls over
	path := filepath.Join(t.TempDir(), "q.json")
	if err := os.WriteFile(path, []byte(`{"7001":2000000000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRegistry()
	r.loadQuota(path)
	r.applyLimits([]limitSpec{{Port: 7001, Quota: 1e9, Period: "month"}})
	p := r.get("s", 7001)
	if r.rollPeriods(wed) || !p.exceeded() {
		t.Fatal("first sight of a period must only record its start")
	}
	if r.rollPeriods(wed.AddDate(0, 0, 10)) || !p.exceeded() {
		t.Fatal("same month: no reset")
	}
	if !r.rollPeriods(time.Date(2026, 12, 1, 0, 0, 1, 0, loc)) || p.exceeded() || p.qused.Load() != 0 {
		t.Fatal("new month: usage must reset")
	}
	p.qused.Store(5)
	r.save()

	// the new file round-trips, and an old loader (map[string]int64, numeric keys only) still reads it
	b, _ := os.ReadFile(path)
	var old map[string]int64
	if err := json.Unmarshal(b, &old); err != nil || old["7001"] != 5 {
		t.Fatalf("old loader: %v %s", err, b)
	}
	r2 := newRegistry()
	r2.loadQuota(path)
	if r2.pstart[7001] != time.Date(2026, 12, 1, 0, 0, 0, 0, loc).Unix() || r2.loaded[7001] != 5 {
		t.Fatalf("round trip: %v %v", r2.pstart, r2.loaded)
	}
	// a restart after the period ended resets on the first tick, even with no connection on the port yet
	r2.applyLimits([]limitSpec{{Port: 7001, Quota: 1e9, Period: "month"}})
	if !r2.rollPeriods(time.Date(2027, 1, 2, 0, 0, 0, 0, loc)) || r2.loaded[7001] != 0 || r2.get("c", 7001).qused.Load() != 0 {
		t.Fatal("rollover while stopped not applied")
	}
	snap := r2.snapshot("c")["7001"].(map[string]any)
	if snap["quota_period"] != "month" || snap["quota_resets_at"].(int64) <= time.Now().Unix() {
		t.Fatalf("snapshot: %v", snap)
	}
}
