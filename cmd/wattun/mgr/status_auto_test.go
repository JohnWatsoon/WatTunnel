package mgr

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Task 4 (PLAN-go-manager): an auto Kharej tunnel sums the parent and its
// hidden helpers (NAME-r, NAME-e-*) the way the bash dashboard prints them:
// totals summed, best RTT/loss over live helpers, carrier rows per helper.
func TestTinfoAutoKharejAggregation(t *testing.T) {
	oldCfg, oldAuto, oldHelpers, oldActive, oldStats, oldFlat, oldComp := p1Cfg, p1IsAutoKharej, p1AutoHelpers, p1IsActive, p1Stats, p1StatsFlat, p1CompanionOf
	defer func() {
		p1Cfg, p1IsAutoKharej, p1AutoHelpers, p1IsActive, p1Stats, p1StatsFlat, p1CompanionOf = oldCfg, oldAuto, oldHelpers, oldActive, oldStats, oldFlat, oldComp
	}()
	p1Cfg = func(n, k string) string {
		if n == "auto1" && k == "carrier" {
			return "icmp+udp+tcp"
		}
		return ""
	}
	p1IsAutoKharej = func(n string) bool { return n == "auto1" }
	p1AutoHelpers = func(n string) []string {
		if n == "auto1" {
			return []string{"auto1-r", "auto1-e-vxlan"}
		}
		return nil
	}
	p1IsActive = func(string) bool { return true }
	p1CompanionOf = func(string) string { return "" }
	p1Stats = func(n string) (map[string]any, error) {
		switch n {
		case "auto1":
			return map[string]any{"alive": true, "sessions": 2, "streams_total": 5, "dgram_flows": 1,
				"rtt_ms": 42.0, "min_rtt_ms": 40.0, "loss_pct": 0.5,
				"bytes_in_total": 100.0, "bytes_out_total": 200.0, "rate_bps": 1000.0,
				"carriers": []any{
					map[string]any{"name": "udp", "alive": true, "srtt_ms": 41.0, "loss": 0.004, "share": 0.7, "muted": false},
					map[string]any{"name": "tcp", "alive": false, "srtt_ms": 55.0, "loss": 0.02, "share": 0.3, "muted": true},
				}}, nil
		case "auto1-r":
			return map[string]any{"alive": false, "sessions": 1, "streams_total": 2, "dgram_flows": 2,
				"rtt_ms": 30.0, "min_rtt_ms": 28.0, "loss_pct": 1.0,
				"bytes_in_total": 50.0, "bytes_out_total": 60.0, "rate_bps": 100.0,
				"carriers": []any{
					map[string]any{"name": "icmp", "alive": true, "srtt_ms": 30.0, "loss": 0.0, "share": 1.0, "muted": false},
				}}, nil
		}
		return nil, errP1
	}
	p1StatsFlat = func(n string) (map[string]any, error) {
		if n == "auto1-e-vxlan" {
			return map[string]any{"alive": true, "sessions": 0, "streams_total": 1, "dgram_flows": 0,
				"rtt_ms": 9.0, "min_rtt_ms": 8.0, "loss_pct": 2.0,
				"bytes_in_total": 10.0, "bytes_out_total": 20.0, "rate_bps": 5.0}, nil
		}
		return nil, errP1
	}

	ti := tinfo("auto1")
	if ti.State != "up" {
		t.Errorf("state = %q (%s)", ti.State, ti.Why)
	}
	if ti.In != 160 || ti.Out != 280 || ti.Rate != 1105 {
		t.Errorf("totals = %v/%v/%v (want 160/280/1105)", ti.In, ti.Out, ti.Rate)
	}
	if ti.Sess != 3 || ti.Streams != 8 || ti.DgramFlows != 3 {
		t.Errorf("sessions/streams/dgram = %d/%d/%d (want 3/8/3)", ti.Sess, ti.Streams, ti.DgramFlows)
	}
	if ti.RTT != 9 { // the best (lowest) RTT of the live helpers: the -e- shape's 9 ms
		t.Errorf("rtt = %v (want 9)", ti.RTT)
	}
	if ti.LivePick != "udp+r:icmp+vxlan" {
		t.Errorf("live pick = %q (want udp+r:icmp+vxlan)", ti.LivePick)
	}
	if len(ti.Cars) != 4 { // parent udp+tcp(muted), companion r:icmp, shape vxlan
		t.Fatalf("carrier rows = %d: %+v", len(ti.Cars), ti.Cars)
	}
	if ti.Cars[0].Name != "udp" || ti.Cars[1].Name != "tcp" || ti.Cars[1].Muted != "true" || ti.Cars[2].Name != "r:icmp" {
		t.Errorf("rows = %+v", ti.Cars)
	}
	if ti.Cars[3].Name != "vxlan" || ti.Cars[3].Alive != "true" || ti.Cars[3].Loss != "0.0200" || ti.Cars[3].Share != "1" {
		t.Errorf("shape row = %+v", ti.Cars[3])
	}

	// an active helper whose stats did not answer is unknown, not down
	p1Stats = func(string) (map[string]any, error) { return nil, errP1 }
	p1StatsFlat = func(string) (map[string]any, error) { return nil, errP1 }
	if ti := tinfo("auto1"); ti.State != "unknown" {
		t.Errorf("state with dead stats = %q (want unknown)", ti.State)
	}

	// nothing active: stopped
	p1IsActive = func(string) bool { return false }
	if ti := tinfo("auto1"); ti.State != "stopped" {
		t.Errorf("state with nothing running = %q (want stopped)", ti.State)
	}
}

// statsFlatOf reads /stats?flat=1 and parses both the key=value form and the
// JSON an older binary answers with (stats_flat 589).
func TestStatsFlatOf(t *testing.T) {
	oldCfg, oldClient := p1Cfg, statsClient
	defer func() { p1Cfg, statsClient = oldCfg, oldClient }()
	p1Cfg = func(_, key string) string {
		if key == "metrics" {
			return "127.0.0.1:19750"
		}
		return ""
	}
	body := "alive=true\nsessions=3\nrtt_ms=12.5\n"
	statsClient = &http.Client{Transport: roundTripStat(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	m, err := statsFlatOf("auto1")
	if err != nil {
		t.Fatal(err)
	}
	if get(m, "alive") != "true" || getI(m, "sessions") != 3 || getF(m, "rtt_ms") != 12.5 {
		t.Errorf("flat form: %+v", m)
	}
	body = `{"alive":true,"sessions":4,"rtt_ms":11}`
	if m, err = statsFlatOf("auto1"); err != nil || getI(m, "sessions") != 4 || getF(m, "rtt_ms") != 11 {
		t.Errorf("json fallback: %+v err=%v", m, err)
	}
	p1Cfg = func(string, string) string { return "" }
	if _, err := statsFlatOf("auto1"); err == nil {
		t.Error("no metrics address must error")
	}
}

type roundTripStat func(*http.Request) (*http.Response, error)

func (f roundTripStat) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
