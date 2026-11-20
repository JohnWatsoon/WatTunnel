//go:build mgrp3

package mgr

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ---- speedtest HTTP stub ----

var origHTTPClient = httpClient

// testClient swaps SpeedTest's transport for one that answers the queued JSON bodies
// in order (down first, then up — the bash curls them in that order).
func testClient(bodies []string) *http.Client {
	i := 0
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := bodies[min(i, len(bodies)-1)]
		i++
		return &http.Response{
			StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)),
			Header: http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})
	return &http.Client{Transport: rt}
}

func defaultHTTPClient() *http.Client { return origHTTPClient }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func resetAdapters() {
	p1Cfg = func(name, key string) string { return "" }
	p1Tunnels = func() []string { return nil }
	p1Stats = func(name string) (map[string]any, error) { return nil, errP1 }
	p1IsActive = func(unit string) bool { return false }
	p1TermCols = func() int { return 80 }
	p1CompanionOf = func(string) string { return "" }
	p1IsAutoKharej = func(string) bool { return false }
	p1CarrierLabel = func(name string) string { return p1Cfg(name, "carrier") }
	p1YmlMaps = func(string) []string { return nil }
	p1Uptime = func(string) string { return "" }
}

func fixtureStats() map[string]any {
	return map[string]any{
		"alive": true, "sessions": 2, "streams_total": 14, "dgram_flows": 3,
		"rtt_ms": 42.5, "min_rtt_ms": 38.0, "loss_pct": 0.4,
		"bytes_in_total": 3.4e9, "bytes_out_total": 9.5e8, "rate_bps": 2.1e6,
		"version": "3.3.6", "pkts_in": 1000, "pkts_out": 900,
		"carriers": []any{
			map[string]any{"name": "tls", "alive": true, "srtt_ms": 41.0, "loss": 0.004, "share": 0.7, "muted": false},
			map[string]any{"name": "udp", "alive": false, "srtt_ms": 55.0, "loss": 0.02, "share": 0.3, "muted": false},
		},
	}
}

// ---- formatting (human / tbar / state_cell) ----

func TestHuman(t *testing.T) {
	for in, want := range map[float64]string{
		512: "512.0 B", 2048: "2.0 KB", 3.4e6: "3.2 MB", 5e9: "4.7 GB",
	} {
		if got := Human(in); got != want {
			t.Errorf("Human(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestTbar(t *testing.T) {
	if got := tbar(5, 10, 10); got != "▰▰▰▰▰▱▱▱▱▱" {
		t.Errorf("tbar(5,10,10) = %q", got)
	}
	if got := tbar(0, 0, 4); got != "▱▱▱▱" { // max<=0 clamps to 1 -> 0 filled
		t.Errorf("tbar(0,0,4) = %q", got)
	}
}

func TestStateCell(t *testing.T) {
	if _, _, txt := stateCell("Kharej", "down"); txt != "waiting" {
		t.Errorf("Kharej down = %q, want waiting", txt)
	}
	if _, _, txt := stateCell("Iran", "down"); txt != "down" {
		t.Errorf("Iran down = %q", txt)
	}
	if _, dot, txt := stateCell("Iran", "degraded"); dot != "◐" || txt != "partial" {
		t.Errorf("degraded = %q %q", dot, txt)
	}
}

// ---- field extraction incl. fallbacks ----

func TestGetFallbacks(t *testing.T) {
	m := fixtureStats()
	if got := getFlat(m, "streams_total", "streams"); got != "14" {
		t.Errorf("streams_total = %q", got)
	}
	// legacy: only the old key present
	old := map[string]any{"streams": 7, "bytes_in": 100, "bytes_out": 50, "alive": true}
	ti := &tunnelInfo{State: "up"}
	fillTI(ti, old)
	if ti.Streams != 7 || ti.In != 100 || ti.Out != 50 {
		t.Errorf("legacy fallback: streams=%d in=%v out=%v", ti.Streams, ti.In, ti.Out)
	}
	// missing everything: zeros, not garbage
	ti2 := &tunnelInfo{State: "up"}
	fillTI(ti2, map[string]any{})
	if ti2.RTT != 0 || ti2.In != 0 || ti2.Sess != 0 || ti2.CarCount != 0 {
		t.Errorf("empty stats not zeroed: %+v", ti2)
	}
	// srtt 0 between samples -> min_rtt takes over
	ti3 := &tunnelInfo{State: "up"}
	fillTI(ti3, map[string]any{"rtt_ms": 0.0, "srtt_ms": 0.2, "min_rtt_ms": 33.0})
	if ti3.RTT != 33.0 {
		t.Errorf("srtt<0.5 should use min_rtt, got %v", ti3.RTT)
	}
}

func TestFillTIDegraded(t *testing.T) {
	ti := &tunnelInfo{State: "up"}
	fillTI(ti, fixtureStats())
	if ti.State != "degraded" || ti.Why != "1 of 2 carriers down" {
		t.Errorf("degraded verdict: state=%s why=%q", ti.State, ti.Why)
	}
	if ti.Live != "tls" {
		t.Errorf("live = %q, want tls", ti.Live)
	}
	if ti.CarMuted != 0 || ti.CarAlive != 1 {
		t.Errorf("unmuted live=%d muted=%d", ti.CarAlive, ti.CarMuted)
	}
}

// ---- dashboard render from the fixture ----

func TestDashTable(t *testing.T) {
	resetAdapters()
	p1Tunnels = func() []string { return []string{"mytunnel"} }
	p1IsActive = func(u string) bool { return u == "wattun@mytunnel" }
	p1Stats = func(name string) (map[string]any, error) { return fixtureStats(), nil }
	p1Cfg = func(name, key string) string {
		return map[string]string{"carrier": "tls+udp", "mode": "client"}[key]
	}
	p1YmlMaps = func(string) []string { return []string{"443:443/tcp", "53/udp"} }
	var b bytes.Buffer
	dashTable(&b)
	s := StripANSI(b.String())
	for _, want := range []string{
		"TRAFFIC",
		"mytunnel", "Iran", "tls+udp", "◐ partial", "42 ms",
		"↓3.2 GB ↑906.0 MB · 14s",
		"443 · 53/udp",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dash table missing %q\ngot:\n%s", want, s)
		}
	}
}

func TestStatusRow(t *testing.T) {
	resetAdapters()
	p1Tunnels = func() []string { return []string{"t1"} }
	p1IsActive = func(string) bool { return true }
	p1Stats = func(string) (map[string]any, error) { return fixtureStats(), nil }
	p1Cfg = func(name, key string) string { return map[string]string{"carrier": "tls"}[key] }
	var b bytes.Buffer
	StatusRow(&b, "t1")
	want := "  t1           Iran   tls   ● up           43ms   streams 14  no ports yet"
	if got := StripANSI(b.String()); got != want+"\n" && !strings.Contains(got, "streams 14") {
		t.Errorf("status row = %q", got)
	}
	if !strings.Contains(StripANSI(b.String()), "no ports yet") {
		t.Errorf("status row ports fallback missing: %q", StripANSI(b.String()))
	}
}

// ---- speedtest request formation (against the handler in cmd/wattun/speedtest.go) ----

func TestSpeedtestURL(t *testing.T) {
	u := speedtestURL("127.0.0.1:19700", "down", 10)
	if !strings.HasPrefix(u, "http://127.0.0.1:19700/speedtest?") {
		t.Fatalf("url = %q", u)
	}
	q, err := url.ParseQuery(u[strings.Index(u, "?")+1:])
	if err != nil {
		t.Fatal(err)
	}
	// the handler reads exactly dir (down|up), mb (int >=1), streams (optional int)
	if q.Get("dir") != "down" {
		t.Errorf("dir = %q", q.Get("dir"))
	}
	if q.Get("mb") != "10" {
		t.Errorf("mb = %q", q.Get("mb"))
	}
	u2 := speedtestURLStreams("127.0.0.1:19700", "up", 8, 16)
	q2, _ := url.ParseQuery(u2[strings.Index(u2, "?")+1:])
	if q2.Get("streams") != "16" || q2.Get("dir") != "up" {
		t.Errorf("streams url = %q", u2)
	}
	// sanity: the strings the handler itself would accept (strconv.Atoi on mb)
	if _, err := parseInt(q2.Get("mb")); err != nil {
		t.Errorf("mb not an int: %v", err)
	}
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errP1
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func TestSpeedTestOutput(t *testing.T) {
	resetAdapters()
	// serve the two answers the engine would (down first, then up)
	httpClient = testClient([]string{
		`{"ok":true,"dir":"down","mb":10,"seconds":2.05,"mb_per_s":4.87,"mbit_per_s":41,"streams":8}`,
		`{"ok":true,"dir":"up","mb":10,"seconds":3.10,"mb_per_s":3.22,"mbit_per_s":27,"streams":8}`,
	})
	defer func() { httpClient = defaultHTTPClient() }()
	p1Cfg = func(name, key string) string {
		return map[string]string{"metrics": "127.0.0.1:19700", "mode": "client"}[key]
	}
	var b bytes.Buffer
	SpeedTest("t", 10, &b)
	s := StripANSI(b.String())
	for _, want := range []string{
		"Speed test · 10 MB",
		"Download", "4.9 MB/s", "41 Mbps", "2.05 s",
		"Upload", "3.2 MB/s", "27 Mbps", "3.10 s",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("speed test output missing %q\ngot:\n%s", want, s)
		}
	}
}

func TestSpeedTestKharejRefused(t *testing.T) {
	resetAdapters()
	p1Cfg = func(name, key string) string { return map[string]string{"mode": "server"}[key] }
	var b bytes.Buffer
	SpeedTest("k", 10, &b)
	if !strings.Contains(b.String(), "Speed test runs on Iran only") {
		t.Errorf("kharej refusal missing: %q", b.String())
	}
}

// ---- doctor verdicts ----

func doctorFixture(io_ *DoctorIO) *DoctorIO {
	io_.Out = &bytes.Buffer{}
	io_.PingHost = func(string) bool { return true }
	io_.TCPProbe = func(string, string) bool { return true }
	io_.PortBusy = func(string, string) bool { return true }
	io_.Journal = func(string, ...string) string { return "" }
	return io_
}

func TestDoctorConnected(t *testing.T) {
	resetAdapters()
	d := doctorFixture(&DoctorIO{})
	p1IsActive = func(string) bool { return true }
	p1Stats = func(string) (map[string]any, error) { return fixtureStats(), nil }
	p1Cfg = func(name, key string) string {
		return map[string]string{"carrier": "tls", "peer": "1.2.3.4:443", "mode": "client"}[key]
	}
	d.SpeedTest = func(string) {}
	Doctor("t", d)
	s := StripANSI(d.Out.(*bytes.Buffer).String())
	for _, want := range []string{
		"Service     running (wattun@t)",
		"TCP         1.2.3.4:443 open",
		"Link        CONNECTED · RTT 42.5 ms",
		"Live paths",
		"● up", "○ down", "41 ms", "55 ms",
		"loss  0.4%", "share  70%",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor missing %q\ngot:\n%s", want, s)
		}
	}
}

func TestDoctorDisconnectedKharej(t *testing.T) {
	resetAdapters()
	d := doctorFixture(&DoctorIO{})
	p1IsActive = func(string) bool { return true }
	p1Stats = func(string) (map[string]any, error) { return map[string]any{"alive": false, "version": "3.3.6"}, nil }
	p1Cfg = func(name, key string) string { return map[string]string{"carrier": "tls", "mode": "server"}[key] }
	d.Journal = func(string, ...string) string {
		return "new client session\nidle, closing\nnew client session\n"
	}
	Doctor("k", d)
	s := StripANSI(d.Out.(*bytes.Buffer).String())
	for _, want := range []string{
		"Link        no Iran client connected",
		"Iran connected 2 time(s) in 6h, went idle 1 time(s) (return path blocked?)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor missing %q\ngot:\n%s", want, s)
		}
	}
}

func TestIcmpPathReportVerdicts(t *testing.T) {
	resetAdapters()
	p1Stats = func(string) (map[string]any, error) { return map[string]any{"pkts_in": 10, "pkts_out": 10}, nil }
	// ping answers only <=200 B -> max size below the tunnel's 256 B minimum
	d := doctorFixture(&DoctorIO{})
	d.PingHost = func(hp string) bool {
		p := hp[strings.LastIndex(hp, "/")+1:]
		return p == "56" || p == "200"
	}
	icmpPathReport("t", "5.6.7.8", d)
	s := StripANSI(d.Out.(*bytes.Buffer).String())
	if !strings.Contains(s, "Max ICMP size ~200 B (below tunnel 256 B minimum)") {
		t.Errorf("below-minimum verdict missing:\n%s", s)
	}
	if !strings.Contains(s, "Switch both sides to another carrier (udp, tcp, wss)") {
		t.Errorf("carrier hint missing:\n%s", s)
	}
	// 56..400 B pass -> the mtu hint with the measured ceiling
	d1 := doctorFixture(&DoctorIO{})
	d1.PingHost = func(hp string) bool {
		p := hp[strings.LastIndex(hp, "/")+1:]
		return p == "56" || p == "200" || p == "400"
	}
	icmpPathReport("t", "5.6.7.8", d1)
	s1 := StripANSI(d1.Out.(*bytes.Buffer).String())
	if !strings.Contains(s1, "Path drops ICMP > ~400 B") || !strings.Contains(s1, "Set  mtu: 400") {
		t.Errorf("mtu verdict missing:\n%s", s1)
	}
	// no ping at all -> every size drops
	d2 := doctorFixture(&DoctorIO{})
	d2.PingHost = func(string) bool { return false }
	icmpPathReport("t", "5.6.7.8", d2)
	s2 := StripANSI(d2.Out.(*bytes.Buffer).String())
	if !strings.Contains(s2, "Kharej drops ping at every size") {
		t.Errorf("drop-all verdict missing:\n%s", s2)
	}
	// ping passes, tunnel silent (pkts_out>0, pkts_in==0)
	d3 := doctorFixture(&DoctorIO{})
	p1Stats = func(string) (map[string]any, error) { return map[string]any{"pkts_in": 0.0, "pkts_out": 5.0}, nil }
	icmpPathReport("t", "5.6.7.8", d3)
	s3 := StripANSI(d3.Out.(*bytes.Buffer).String())
	if !strings.Contains(s3, "Ping passes, tunnel packets get no reply") {
		t.Errorf("silent-tunnel verdict missing:\n%s", s3)
	}
}

// ---- matrix: plan order, ranking, probe sizing ----

func TestMatrixPlanOrder(t *testing.T) {
	resetAdapters()
	// a 2.10.5 binary: every AC_MODES mode except paws is known
	cfg := func(string) string { return "" }
	vs := matrixPlan("t", "tls", "1.2.3.4:443", "", "2.10.5", cfg, true)
	var labels []string
	for _, v := range vs {
		labels = append(labels, v.Label)
	}
	want := []string{
		"base (no desync)",
		"desync mci.ir → seq", "desync mci.ir → seqsum", "desync mci.ir → sum",
		"desync mci.ir → ttl", "desync mci.ir → rst", "desync mci.ir → synrst",
		"desync irancell.ir → rst", "desync tci.ir → rst", "desync divar.ir → rst",
		"desync www.cloudflare.com → rst", "desync www.cloudflare.com → synrst",
		"ech ladder (no desync)",
		"desync auto-probe",
		"fallback ICMP echo",
	}
	if len(labels) != len(want) {
		t.Fatalf("plan length = %d (%v), want %d", len(labels), labels, len(want))
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Errorf("plan[%d] = %q, want %q", i, labels[i], want[i])
		}
	}
	// paws appears on a 3.0.2 binary; an old 2.7 binary has no synrst/paws/ech/auto
	vsOld := matrixPlan("t", "tls", "1.2.3.4:443", "", "2.7.0", cfg, false)
	for _, v := range vsOld {
		if strings.Contains(v.Label, "synrst") || strings.Contains(v.Label, "ech ladder") || strings.Contains(v.Label, "auto-probe") {
			t.Errorf("old binary should not test %q", v.Label)
		}
	}
	vsNew := matrixPlan("t", "tls", "1.2.3.4:443", "", "3.0.2", cfg, false)
	found := false
	for _, v := range vsNew {
		if v.Label == "desync mci.ir → paws" {
			found = true
		}
	}
	if !found {
		t.Error("3.0.2 plan missing paws")
	}
}

func TestMatrixPlanBondLegs(t *testing.T) {
	cfg := map[string]string{"peer-tls": "1.1.1.1:4443"}
	cfgFn := func(k string) string { return cfg[k] }
	vs := matrixPlan("t", "udp+tls+icmp", "9.9.9.9:443", "", "2.10.5", cfgFn, false)
	// a bond probes its POOL legs only (bash is_pool: udp is not one) — tls here,
	// each variant tagged "tls ", peer from peer-tls; icmp is never probed
	if len(vs) == 0 {
		t.Fatal("bond plan empty")
	}
	for _, v := range vs {
		if v.Car != "tls" {
			t.Errorf("non-pool leg probed: %q", v.Car)
		}
		if !strings.HasPrefix(v.Label, "tls ") {
			t.Errorf("bond variant label missing the leg tag: %q", v.Label)
		}
		if v.Peer != "1.1.1.1:4443" {
			t.Errorf("tls leg does not use peer-tls: %q", v.Peer)
		}
	}
}

func TestAtRank(t *testing.T) {
	vs := []variant{
		{Label: "base", Car: "tls", Kind: "d"},
		{Label: "desync mci.ir → rst", Car: "tls", Kind: "d", FS: "mci.ir", FM: "rst"},
		{Label: "udp", Car: "udp", Kind: "d"},
	}
	rs := []result{
		{OK: true, Down: 10, Up: 10, RTT: 50},     // score 20
		{OK: true, Down: 10.5, Up: 10.5, RTT: 40}, // 21 * 0.92 = 19.32 -> below base
		{OK: true, Down: 6, Up: 6, RTT: 30},       // 12
	}
	rank := atRank(vs, rs, "speed")
	if len(rank) != 3 || rank[0] != 0 || rank[1] != 1 || rank[2] != 2 {
		t.Errorf("speed rank = %v, want [0 1 2] (anti variant penalized)", rank)
	}
	lat := atRank(vs, rs, "latency")
	if lat[0] != 2 {
		t.Errorf("latency rank = %v, want udp first", lat)
	}
	rs[1].Down, rs[1].Up = 12, 12 // 24*0.92 = 22.08 -> now wins
	rank2 := atRank(vs, rs, "speed")
	if rank2[0] != 1 {
		t.Errorf("rank after boost = %v, want desync first", rank2)
	}
}

func TestAtProbeMB(t *testing.T) {
	if got := atProbeMB(0, 1.5, 16); got != 8 {
		t.Errorf("zero rate = %d, want 8", got)
	}
	if got := atProbeMB(8, 1.5, 16); got != 16 { // 8/8 = 1.0 s < 1.5 -> x4 = 32 -> cap 16
		t.Errorf("8 MB/s = %d, want 16", got)
	}
	if got := atProbeMB(2, 1.5, 16); got != 8 { // 8/2=4s >= 1.5 -> stays 8
		t.Errorf("2 MB/s = %d, want 8", got)
	}
	if got := atProbeMB(7, 1.5, 40); got != 32 { // 8/7=1.14<1.5 -> 32; 32/7=4.6>=1.5
		t.Errorf("7 MB/s = %d, want 32", got)
	}
}

func TestAtTableAndPrint(t *testing.T) {
	vs := []variant{
		{Label: "base (no desync)", Car: "tls", Kind: "d"},
		{Label: "a very long variant label that gets cut", Car: "tls", Kind: "d", FS: "x", FM: "rst"},
	}
	rs := []result{{OK: true, Down: 4.5, Up: 3.0, RTT: 42}, {OK: false, Why: "no link in 8 s"}}
	rank := atRank(vs, rs, "speed")
	var b bytes.Buffer
	atTable(&b, vs, rs, rank, 8, 61)
	s := StripANSI(b.String())
	for _, want := range []string{
		"Results · 1 working · 61 s",
		"Carrier", "Down", "Up", "RTT",
		"▸ 1  base (no desync)", "4.5", "3.0", "42ms",
		"✗  a very long variant ..", "no link in 8 s",
		"8 MB/probe · 61 s",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q\ngot:\n%s", want, s)
		}
	}
}

func TestAvKey(t *testing.T) {
	if got := avKey(variant{Car: "tls", Kind: "d"}); got != "tls/d" {
		t.Errorf("plain key = %q", got)
	}
	if got := avKey(variant{Car: "udp", Kind: "r"}); got != "udp/r" {
		t.Errorf("reverse key = %q", got)
	}
	if got := avKey(variant{Car: "tls+udp", Kind: "r"}); got != "bond/r" {
		t.Errorf("bond key = %q", got)
	}
	k := avKey(variant{Car: "tls", Kind: "d", FS: "mci.ir", FM: "rst", FP: "chrome", ECH: "auto", Frag: "-1"})
	if k != "tls/d/mci.ir-rst-chrome-auto--1" {
		t.Errorf("anti key = %q", k)
	}
}

// ---- small pure helpers ----

func TestSpecHelpers(t *testing.T) {
	if SpecHuman("8443:443/tcp") != "8443→443" {
		t.Errorf("specHuman = %q", SpecHuman("8443:443/tcp"))
	}
	if SpecHuman("53/udp") != "53/udp" {
		t.Errorf("specHuman udp = %q", SpecHuman("53/udp"))
	}
	if SpecYaml("8443:443/tcp") != "8443:443" {
		t.Errorf("specYaml = %q", SpecYaml("8443:443/tcp"))
	}
	if portsSummary("k", 50) != "no ports yet" && portsSummary("k", 50) != "any port" {
		// with no maps: Iran -> "no ports yet"
	}
}

func TestPortsSummary(t *testing.T) {
	resetAdapters()
	p1YmlMaps = func(string) []string { return []string{"443:443/tcp", "8443:443/tcp", "53/udp"} }
	p1Cfg = func(name, key string) string { return "" } // Iran
	if got := portsSummary("t", 50); got != "443 · 8443→443 · 53/udp" {
		t.Errorf("portsSummary = %q", got)
	}
	// Kharej shows target ports
	p1Cfg = func(name, key string) string { return map[string]string{"mode": "server"}[key] }
	if got := portsSummary("k", 50); got != "443 · 443 · 53/udp" {
		t.Errorf("kharej portsSummary = %q", got)
	}
	// clipping adds +N
	p1Cfg = func(name, key string) string { return "" }
	p1YmlMaps = func(string) []string { return []string{"1111:1111/tcp", "2222:2222/tcp", "3333:3333/tcp"} }
	if got := portsSummary("t", 10); got != "1111 +2" {
		t.Errorf("clipped portsSummary = %q", got)
	}
}

func TestSparkAndHumanMonitor(t *testing.T) {
	if got := spark([]int{0, 1, 2, 3, 4, 5, 6, 7}, 8); got != "▁▂▃▄▅▆▇█" {
		t.Errorf("spark = %q", got)
	}
	if got := spark([]int{}, 4); got != "····" {
		t.Errorf("empty spark = %q", got)
	}
	if got := spark([]int{0, 0}, 4); got != "··▁▁" {
		t.Errorf("flat spark = %q", got)
	}
}

func TestVerGE(t *testing.T) {
	if !verGE("2.10.5", "2.9.0") || verGE("2.8.9", "2.9.0") || !verGE("3.0.2", "3.0.2") {
		t.Error("verGE broken")
	}
}
