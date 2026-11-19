package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// harnessStatsBlob is a realistic /stats answer of a bonded client (icmp+udp), derived from the stats handler
// in cmd/wattun/main.go: flat top-level keys, the statsAliases merges (rtt_ms, streams_total), the nested cc
// map, the carriers array (bond only), the ports map and the client-side sessions_up. The byte counters exceed
// 2^53 on purpose: the float64 path would round them, the harness must not.
const harnessStatsBlob = `{
 "ack_late": 12,
 "alive": true,
 "bytes_in": 12345678901234567890,
 "bytes_in_total": 13345678901234567890,
 "bytes_out": 9876543210987654,
 "bytes_out_total": 10876543210987654,
 "cc": {"app_limited": 12, "cwnd": 2048, "cwnd_limited": 3, "deep_trips": 0, "delay_cuts": 8,
        "floor_bps": 250000, "loss_cuts": 1, "loss_time_ms": 0, "lost": 4, "loss_timer_x": 1.5,
        "pool_full": 0, "pto_ms": 0, "spurious": 2, "ticks": 4401, "tok_limited": 30, "win_blocked": 0},
 "carriers": [
   {"name": "icmp", "alive": true, "muted": false, "srtt_ms": 42.75, "share": 0.35,
    "sent": 5000, "acked": 4990, "lost": 10},
   {"name": "udp", "alive": true, "muted": true, "srtt_ms": 31.25, "share": 0.65,
    "sent": 9000, "acked": 8998, "lost": 2}
 ],
 "ceiling_bps": 25000000,
 "conn_limit_drops": 0,
 "conns_active": 2,
 "dgram_dropped_queue": 0,
 "dgram_dropped_rx": 0,
 "dgram_dropped_size": 0,
 "dgram_flows": 1,
 "dgram_flow_cap_drops": 0,
 "dgram_fragmented": 0,
 "dgram_reassembled": 0,
 "dgram_rejected": 0,
 "dgram_recv": 44,
 "dgram_sent": 44,
 "draining": false,
 "dup_recv": 1,
 "fec_recovered": 3,
 "fec_sent": 210,
 "fec_state": "off",
 "filter_profile": "",
 "inflight": 5,
 "last_rx_age_ms": 120,
 "loss_pct": 0.1,
 "min_rtt_ms": 31,
 "noise_bytes": 2048,
 "noise_sent": 2,
 "pkts_in": 95000,
 "pkts_out": 96000,
 "pool_conn_deaths": 0,
 "pool_conns": {},
 "pool_drops": 0,
 "pool_slow_closed": 0,
 "ports": {"10001": {"bytes_up": 1000, "bytes_down": 2000, "bytes_up_total": 1000,
            "bytes_down_total": 2000, "conns_total": 5, "conns_all_time": 5, "conns_active": 1,
            "udp_flows_active": 0, "dgram_up": 0, "dgram_down": 0, "errors": 0, "refused": 0,
            "rate_bps_up": 0, "rate_bps_down": 0, "peak_bps_up": 0, "peak_bps_down": 0,
            "rate_limit_bps": 0, "quota_limit": 0, "quota_used": 0, "quota_exceeded": false,
            "quota_period": "", "quota_resets_at": 0}},
 "raw_send_fails": 0,
 "rate_bps": 9250000.5,
 "retrans": 87,
 "rtt_ms": 42.75,
 "rx_too_old": 0,
 "send_errors": 3,
 "sessions": 1,
 "sessions_up": 1,
 "shape_data_bytes": 4096,
 "srtt_ms": 42.75,
 "streams": 3,
 "streams_total": 3,
 "tcp_cc": "cubic",
 "version": "3.3.9"
}`

func harnessStatsServer(t *testing.T, code int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code != http.StatusOK {
			http.Error(w, body, code)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchStatsRealBlob(t *testing.T) {
	srv := harnessStatsServer(t, http.StatusOK, harnessStatsBlob)
	st, err := FetchStats(srv.URL)
	if err != nil {
		t.Fatalf("FetchStats: %v", err)
	}
	if st.Version != "3.3.9" || !st.Alive || st.Sessions != 1 || st.Streams != 3 {
		t.Errorf("scalar fields wrong: %+v", st)
	}
	// > 2^53: must arrive exactly, proof the decode never went through float64
	if st.BytesIn != 12345678901234567890 || st.BytesOut != 9876543210987654 {
		t.Errorf("byte counters not exact: in=%d out=%d", st.BytesIn, st.BytesOut)
	}
	if st.PktsOut != 96000 || st.PktsIn != 95000 || st.Retrans != 87 {
		t.Errorf("packet counters wrong: %+v", st)
	}
	if st.RateBps != 9250000.5 || st.CeilingBps != 25000000 {
		t.Errorf("rates wrong: rate=%v ceiling=%v", st.RateBps, st.CeilingBps)
	}
	if st.SRTT != time.Duration(42.75*float64(time.Millisecond)) || st.MinRTT != 31*time.Millisecond {
		t.Errorf("rtt conversion wrong: srtt=%v min=%v", st.SRTT, st.MinRTT)
	}
	if len(st.Carriers) != 2 {
		t.Fatalf("carriers = %d, want 2", len(st.Carriers))
	}
	icmp, udp := st.Carriers[0], st.Carriers[1]
	if icmp.Name != "icmp" || !icmp.Alive || icmp.Muted || icmp.Share != 0.35 || icmp.SRTTms != 42.75 ||
		icmp.Sent != 5000 || icmp.Acked != 4990 || icmp.Lost != 10 {
		t.Errorf("carrier[0] wrong: %+v", icmp)
	}
	if udp.Name != "udp" || udp.Muted != true || udp.Share != 0.65 || udp.Lost != 2 {
		t.Errorf("carrier[1] wrong: %+v", udp)
	}
}

func TestFetchStatsLenient(t *testing.T) {
	// renamed/missing fields must not error: everything unknown is ignored, everything missing stays zero
	srv := harnessStatsServer(t, http.StatusOK, `{"version":"9.9.9","futuristic_new_field":123,"alive":false}`)
	st, err := FetchStats(srv.URL)
	if err != nil {
		t.Fatalf("FetchStats on a foreign shape: %v", err)
	}
	if st.Version != "9.9.9" || st.Alive || st.BytesIn != 0 || st.Carriers != nil {
		t.Errorf("lenient decode wrong: %+v", st)
	}
	// carriers: [] also parses to no carriers
	srv2 := harnessStatsServer(t, http.StatusOK, `{"carriers":[]}`)
	if st2, err := FetchStats(srv2.URL); err != nil || st2.Carriers != nil {
		t.Errorf("empty carriers list: %+v err=%v", st2, err)
	}
	// a malformed carrier entry is skipped, the good ones kept
	srv3 := harnessStatsServer(t, http.StatusOK, `{"carriers":[{"name":"icmp","sent":"bad"},{"name":"udp","sent":7}]}`)
	if st3, err := FetchStats(srv3.URL); err != nil || len(st3.Carriers) != 1 || st3.Carriers[0].Name != "udp" {
		t.Errorf("malformed carrier handling: %+v err=%v", st3, err)
	}
}

func TestFetchStatsErrors(t *testing.T) {
	if _, err := FetchStats("127.0.0.1:1"); err == nil { // nothing listens there
		t.Error("no error on a dead endpoint")
	}
	srv := harnessStatsServer(t, http.StatusInternalServerError, "boom")
	if _, err := FetchStats(srv.URL); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("no error on HTTP 500: %v", err)
	}
	srv = harnessStatsServer(t, http.StatusOK, "this is not json")
	if _, err := FetchStats(srv.URL); err == nil {
		t.Error("no error on a non-JSON body")
	}
}

func TestFetchStatsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // hang until the harness client gives up (2 s timeout), then the test ends without waiting
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	start := time.Now()
	_, err := FetchStats(srv.URL)
	if err == nil {
		t.Fatal("no error on a hanging /stats")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("FetchStats took %v, the 2 s timeout did not fire", el)
	}
}

func TestToggleMute(t *testing.T) {
	var gotPath, gotCarrier string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		gotPath, gotCarrier = r.URL.Path, r.URL.Query().Get("carrier")
		// the exact response the engine writes (cmd/wattun/main.go /carrier/toggle)
		w.Write([]byte(`{"path":1,"carrier":"udp","muted":true}` + "\n"))
	}))
	defer srv.Close()
	muted, err := ToggleMute(srv.URL, "udp")
	if err != nil {
		t.Fatalf("ToggleMute: %v", err)
	}
	if !muted {
		t.Error("muted = false, want true")
	}
	if gotPath != "/carrier/toggle" || gotCarrier != "udp" {
		t.Errorf("request was %s?carrier=%s", gotPath, gotCarrier)
	}
	// the engine's error answer for a bad carrier name
	srv2 := harnessStatsServer(t, http.StatusBadRequest, "invalid path or carrier\n")
	if _, err := ToggleMute(srv2.URL, "nope"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("no error on a 400 toggle: %v", err)
	}
}

func TestPostSpeedtest(t *testing.T) {
	var gotMB, gotDir, gotStreams string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotMB, gotDir, gotStreams = q.Get("mb"), q.Get("dir"), q.Get("streams")
		json.NewEncoder(w).Encode(map[string]any{
			"dir": "down", "bytes": 10485760, "seconds": 1.5, "mb_per_s": 6.99, "mbit_per_s": 55.92,
			"ok": true, "sessions": 1, "streams": 16,
		})
	}))
	defer srv.Close()
	res, err := PostSpeedtest(srv.URL, 10)
	if err != nil {
		t.Fatalf("PostSpeedtest: %v", err)
	}
	if !res.OK || res.Bytes != 10485760 || res.MBps != 6.99 || res.Mbit != 55.92 || res.Seconds != 1.5 ||
		res.Streams != 16 || res.Sessions != 1 {
		t.Errorf("result decoded wrong: %+v", res)
	}
	if gotMB != "10" || gotDir != "down" || gotStreams != "" {
		t.Errorf("query wrong: mb=%q dir=%q streams=%q", gotMB, gotDir, gotStreams)
	}
	// mb < 1 takes the handler default
	if _, err := PostSpeedtest(srv.URL, 0); err != nil {
		t.Fatalf("PostSpeedtest(0): %v", err)
	}
	if gotMB != "10" {
		t.Errorf("default mb not applied: %q", gotMB)
	}
	// the full variant passes dir and streams through
	if _, err := PostSpeedtestFull(srv.URL, "up", 32, 8); err != nil {
		t.Fatalf("PostSpeedtestFull: %v", err)
	}
	if gotDir != "up" || gotMB != "32" || gotStreams != "8" {
		t.Errorf("full query wrong: mb=%q dir=%q streams=%q", gotMB, gotDir, gotStreams)
	}
	// the busy error (409) surfaces
	srv2 := harnessStatsServer(t, http.StatusTooManyRequests, "speedtest already running\n")
	if _, err := PostSpeedtest(srv2.URL, 10); err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("no error on a busy speedtest: %v", err)
	}
}

func TestReadTunnels(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WAT_CONF_DIR", dir)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// a full client tunnel: comments, quoted values, the ports matrix forms
	write("alpha.yml", "# the bond\nmode: client\ncarrier: icmp+udp\npeer: \"198.51.100.7\"\nlisten: ':4443'\nmetrics: 127.0.0.1:19701 # loopback only\n\nports:\n  - 8443:443\n  - 10001\n  - 27003:27002\n  - 10002/udp\n")
	// a bare server tunnel, and the file shapes that are NOT tunnels
	write("main.yml", "mode: server\ncarrier: icmp\nlisten: :4443\n")
	write("main-r.yml", "helper\n")
	write("wattun-e-ladder.yml", "helper\n")
	write("notes.txt", "ignored\n")

	tuns, err := ReadTunnels()
	if err != nil {
		t.Fatalf("ReadTunnels: %v", err)
	}
	if len(tuns) != 2 {
		t.Fatalf("tunnels = %d (%+v), want 2", len(tuns), tuns)
	}
	a, m := tuns[0], tuns[1]
	if a.Name != "alpha" || a.Mode != "client" || a.Carrier != "icmp+udp" || a.Peer != "198.51.100.7" ||
		a.Listen != ":4443" || a.Metrics != "127.0.0.1:19701" {
		t.Errorf("alpha fields wrong: %+v", a)
	}
	wantPorts := []string{"8443:443", "10001", "27003:27002", "10002/udp"}
	if len(a.Ports) != len(wantPorts) {
		t.Fatalf("alpha ports = %v, want %v", a.Ports, wantPorts)
	}
	for i, p := range wantPorts {
		if a.Ports[i] != p {
			t.Errorf("alpha ports[%d] = %q, want %q", i, a.Ports[i], p)
		}
	}
	if m.Name != "main" || m.Mode != "server" || m.Carrier != "icmp" || m.Metrics != "" || len(m.Ports) != 0 {
		t.Errorf("main fields wrong: %+v", m)
	}
	// Active: no wattun@alpha / wattun@main unit exists anywhere, so both are false
	if a.Active || m.Active {
		t.Errorf("Active wrong: alpha=%v main=%v", a.Active, m.Active)
	}
}

func TestReadTunnelsMissingDir(t *testing.T) {
	t.Setenv("WAT_CONF_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	if _, err := ReadTunnels(); err == nil {
		t.Error("no error on a missing config dir")
	}
}

func TestSystemctlRejectsUnknownAction(t *testing.T) {
	if err := Systemctl("frobnicate", "wattun@x"); err == nil {
		t.Error("no error on an unknown action")
	}
}

func TestIsActiveMissingUnit(t *testing.T) {
	// a unit that exists nowhere: false with or without systemd on the box
	if IsActive("wattun@zz-harness-selftest-no-such-unit") {
		t.Error("IsActive = true for a unit that does not exist")
	}
}
