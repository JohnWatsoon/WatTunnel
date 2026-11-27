package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHistoryRing (P4, 2026-11-21): the ring is bounded at historyCap (5 min x 5 s), oldest dropped.
func TestHistoryRing(t *testing.T) {
	h := newStatsHistory()
	for i := 0; i < historyCap+10; i++ {
		h.add(historySample{T: int64(i)})
	}
	got := h.snapshot()
	if len(got) != historyCap {
		t.Fatalf("ring holds %d samples, want %d", len(got), historyCap)
	}
	if got[0].T != 10 || got[historyCap-1].T != int64(historyCap+9) {
		t.Errorf("oldest/newest wrong: got t0=%d tN=%d, want 10/%d", got[0].T, got[historyCap-1].T, historyCap+9)
	}
}

// TestHistoryJSON: stable JSON shape, loss_pct omitted when unset, byte totals always present (the panel tells a 4.0.1 engine by them), empty ring marshals as [].
func TestHistoryJSON(t *testing.T) {
	var b []byte
	var err error

	h := newStatsHistory()
	if b, err = json.Marshal(h.snapshot()); err != nil || string(b) != "[]" {
		t.Fatalf("empty history: got %s, %v; want []", b, err)
	}

	lp := 1.25
	h.add(historySample{T: 1732161000, RateBps: 5e6, SrttMs: 42.5, LossPct: &lp, Streams: 3, Alive: true})
	h.add(historySample{T: 1732161005, RateBps: 4e6, SrttMs: 40, Streams: 0, Alive: false})
	want := `[{"t":1732161000,"rate_bps":5000000,"srtt_ms":42.5,"loss_pct":1.25,"streams":3,"alive":true,"bytes_in":0,"bytes_out":0,"pkts_out":0,"retrans":0},` +
		`{"t":1732161005,"rate_bps":4000000,"srtt_ms":40,"streams":0,"alive":false,"bytes_in":0,"bytes_out":0,"pkts_out":0,"retrans":0}]`
	if b, err = json.Marshal(h.snapshot()); err != nil || string(b) != want {
		t.Fatalf("json:\n got %s\n want %s (%v)", b, want, err)
	}
}

// TestHistoryHandler: the handler serves the ring as an array over HTTP.
func TestHistoryHandler(t *testing.T) {
	h := newStatsHistory()
	h.add(historySample{T: 1, Alive: true})
	srv := httptest.NewServer(http.HandlerFunc(h.serveHTTP))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content-type %q, want application/json", resp.Header.Get("Content-Type"))
	}
	var got []historySample
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].T != 1 || !got[0].Alive {
		t.Errorf("handler round-trip wrong: %+v", got)
	}
}
