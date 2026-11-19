package mgr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// statsBlob reuses the JSON shape captured in cmd/wattun/ui/harness_test.go
// (harnessStatsBlob): a realistic bonded-client /stats answer with the flat
// top-level keys, the nested cc map, the carriers array and byte counters above
// 2^53 on purpose.
const statsBlob = `{
 "ack_late": 12,
 "alive": true,
 "bytes_in": 12345678901234567890,
 "bytes_in_total": 13345678901234567890,
 "bytes_out": 9876543210987654,
 "bytes_out_total": 10876543210987654,
 "cc": {"app_limited": 12, "cwnd": 2048},
 "carriers": [
   {"name": "icmp", "alive": true, "muted": false, "srtt_ms": 42.75, "share": 0.35,
    "sent": 5000, "acked": 4990, "lost": 10},
   {"name": "udp", "alive": true, "muted": true, "srtt_ms": 31.25, "share": 0.65,
    "sent": 9000, "acked": 8998, "lost": 2}
 ],
 "ceiling_bps": 25000000,
 "conns_active": 2,
 "dgram_flows": 1,
 "fec_state": "off",
 "filter_profile": "",
 "inflight": 5,
 "last_rx_age_ms": 120,
 "loss_pct": 0.1,
 "min_rtt_ms": 31,
 "pkts_in": 95000,
 "pkts_out": 96000,
 "rate_bps": 9250000.5,
 "retrans": 87,
 "rtt_ms": 42.75,
 "srtt_ms": 42.75,
 "sessions": 1,
 "sessions_up": 1,
 "streams": 3,
 "streams_total": 3,
 "version": "3.3.9"
}`

func TestJgetJSONAndFlat(t *testing.T) {
	// JSON form: top-level value, quotes stripped
	if got := Jget(statsBlob, "version"); got != "3.3.9" {
		t.Errorf("version = %q", got)
	}
	if got := Jget(statsBlob, "alive"); got != "true" {
		t.Errorf("alive = %q", got)
	}
	if got := Jget(statsBlob, "min_rtt_ms"); got != "31" {
		t.Errorf("min_rtt_ms = %q", got)
	}
	// unknown key, and a nested key is not found (jget reads top level only)
	if got := Jget(statsBlob, "nope"); got != "" {
		t.Errorf("unknown key = %q", got)
	}
	if got := Jget(statsBlob, "cwnd"); got != "" {
		t.Errorf("nested key leaked = %q", got)
	}
	// flat form: key=value lines (stats_flat of a 3.3.6+ binary)
	flat := "alive=true\nrtt_ms=17.5\nstreams_total=9\n"
	if got := Jget(flat, "rtt_ms"); got != "17.5" {
		t.Errorf("flat rtt_ms = %q", got)
	}
	if got := Jget(flat, "alive"); got != "true" {
		t.Errorf("flat alive = %q", got)
	}
	// legacy fallback pair
	if got := JgetFlat(flat, "streams_total", "streams"); got != "9" {
		t.Errorf("jget_flat = %q", got)
	}
	if got := JgetFlat("streams=7\n", "streams_total", "streams"); got != "7" {
		t.Errorf("legacy fallback = %q", got)
	}
}

func TestParseStatsFieldExtraction(t *testing.T) {
	st, err := ParseStats(statsBlob)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}
	if st.Version != "3.3.9" || !st.Alive || st.Sessions != 1 || st.Streams != 3 || st.DgramFlows != 1 {
		t.Errorf("scalars wrong: %+v", st)
	}
	// > 2^53: the counters stay exact digit strings (int64 would clamp, the
	// bash awk float path would round)
	if st.BytesIn != "13345678901234567890" || st.BytesOut != "10876543210987654" {
		t.Errorf("byte counters not exact: in=%q out=%q", st.BytesIn, st.BytesOut)
	}
	if st.RTTms != 42.75 || st.MinRTT != 31 || st.LossPct != 0.1 || st.RateBps != 9250000.5 {
		t.Errorf("rtt/loss/rate wrong: %+v", st)
	}
	if len(st.Carriers) != 2 {
		t.Fatalf("carriers = %d, want 2", len(st.Carriers))
	}
	icmp, udp := st.Carriers[0], st.Carriers[1]
	if icmp.Name != "icmp" || !icmp.Alive || icmp.Muted || icmp.Share != 0.35 || icmp.SRTTms != 42.75 || icmp.Sent != 5000 || icmp.Acked != 4990 || icmp.Lost != 10 {
		t.Errorf("carrier[0] wrong: %+v", icmp)
	}
	if udp.Name != "udp" || !udp.Muted || udp.Share != 0.65 || udp.Lost != 2 {
		t.Errorf("carrier[1] wrong: %+v", udp)
	}
}

func TestParseStatsLenient(t *testing.T) {
	// renamed/missing fields must not error: everything unknown is ignored,
	// everything missing stays zero — the same contract the ui harness tests
	st, err := ParseStats(`{"version":"9.9.9","futuristic_new_field":123,"alive":false}`)
	if err != nil {
		t.Fatalf("foreign shape: %v", err)
	}
	if st.Version != "9.9.9" || st.Alive || st.BytesIn != "" || st.Carriers != nil {
		t.Errorf("lenient decode wrong: %+v", st)
	}
	// a malformed carrier entry is skipped, the good ones kept
	st2, err := ParseStats(`{"carriers":[{"name":"icmp","sent":"bad"},{"name":"udp","sent":7}]}`)
	if err != nil || len(st2.Carriers) != 1 || st2.Carriers[0].Name != "udp" {
		t.Errorf("malformed carrier handling: %+v err=%v", st2, err)
	}
	// the rtt_ms -> srtt_ms fallback
	st3, _ := ParseStats(`{"srtt_ms":8.25}`)
	if st3.RTTms != 8.25 {
		t.Errorf("srtt fallback = %v", st3.RTTms)
	}
	// the bytes_in -> bytes_in_total fallback for pre-2.4.19 binaries
	st4, _ := ParseStats(`{"bytes_in":11,"bytes_out":12}`)
	if st4.BytesIn != "11" || st4.BytesOut != "12" {
		t.Errorf("legacy byte fallback = %q/%q", st4.BytesIn, st4.BytesOut)
	}
	if _, err := ParseStats("this is not json"); err == nil {
		t.Error("no error on a non-JSON body")
	}
}

func TestFetchStatsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"alive":true}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	st, err := FetchStats(addr)
	if err != nil {
		t.Fatalf("FetchStats: %v", err)
	}
	if !st.Alive {
		t.Error("alive lost")
	}
	raw, err := FetchStatsRaw(addr)
	if err != nil || raw != `{"alive":true}` {
		t.Errorf("FetchStatsRaw = %q err=%v", raw, err)
	}
	// non-200 surfaces as an error
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv2.Close()
	if _, err := FetchStats(strings.TrimPrefix(srv2.URL, "http://")); err == nil {
		t.Error("no error on HTTP 500")
	}
	if _, err := FetchStats("127.0.0.1:1"); err == nil {
		t.Error("no error on a dead endpoint")
	}
}

func TestFetchPortsAndFlat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ports":
			w.Write([]byte(`{"10001":{"conns_total":5}}`))
		case r.URL.Path == "/stats" && r.URL.RawQuery == "flat=1":
			w.Write([]byte("alive=true\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if p := FetchPorts(addr); !strings.Contains(p, "10001") {
		t.Errorf("FetchPorts = %q", p)
	}
	if p := FetchPorts("127.0.0.1:1"); p != "" {
		t.Errorf("FetchPorts on a dead endpoint = %q", p)
	}
	if f, err := FetchStatsFlat(addr); err != nil || f != "alive=true\n" {
		t.Errorf("FetchStatsFlat = %q err=%v", f, err)
	}
	// flat endpoint empty (older binary): falls back to plain /stats
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats" && r.URL.RawQuery == "flat=1" {
			return // empty answer
		}
		w.Write([]byte(`{"alive":false}`))
	}))
	defer srv2.Close()
	addr2 := strings.TrimPrefix(srv2.URL, "http://")
	if f, err := FetchStatsFlat(addr2); err != nil || !strings.HasPrefix(f, "{") {
		t.Errorf("flat fallback = %q err=%v", f, err)
	}
}

func TestHumanAndVerCompare(t *testing.T) {
	if Human(0) != "0.0 B" || Human(1024) != "1.0 KB" || Human(1536) != "1.5 KB" ||
		Human(1024*1024*1024) != "1.0 GB" {
		t.Errorf("Human wrong: %q %q %q %q", Human(0), Human(1024), Human(1536), Human(1024*1024*1024))
	}
	if verCompare("3.3.9", "2.7.0") != 1 || verCompare("2.7.0", "2.7.0") != 0 ||
		verCompare("2.6.9", "2.7.0") != -1 || verCompare("", "2.7.0") != -1 ||
		verCompare("3.3", "3.3.0") != 0 {
		t.Error("verCompare wrong")
	}
}
