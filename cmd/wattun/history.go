package main

// /stats/history (P4, 2026-11-21): a 5-minute ring of 5 s samples of the SAME totals /stats reports
// (rate, srtt, loss, streams, alive) so an operator can see the last minutes of trend without polling.
// Server-side multi-session processes aggregate through the /stats totals already; this never recomputes.

import (
	"encoding/json"
	"net/http"
	"sync"
)

// historyCap: 60 samples x 5 s = 5 minutes; the ring drops the oldest when full.
const historyCap = 60

// historySample is one 5 s snapshot (unix seconds + the /stats scalars an operator trends).
type historySample struct {
	T       int64    `json:"t"`
	RateBps float64  `json:"rate_bps"`
	SrttMs  float64  `json:"srtt_ms"`
	LossPct *float64 `json:"loss_pct,omitempty"` // pointer: 0 is "not measured yet", not a measured zero
	Streams int      `json:"streams"`
	Alive   bool     `json:"alive"`
}

type statsHistory struct {
	mu   sync.Mutex
	ring []historySample // len <= historyCap; index 0 is the oldest
}

func newStatsHistory() *statsHistory {
	return &statsHistory{ring: make([]historySample, 0, historyCap)}
}

func (h *statsHistory) add(s historySample) {
	h.mu.Lock()
	if len(h.ring) == historyCap {
		copy(h.ring, h.ring[1:])
		h.ring[historyCap-1] = s
	} else {
		h.ring = append(h.ring, s)
	}
	h.mu.Unlock()
}

// snapshot returns the samples oldest-first; never nil, so the empty case marshals as [] not null.
func (h *statsHistory) snapshot() []historySample {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]historySample, len(h.ring))
	copy(out, h.ring)
	return out
}

func (h *statsHistory) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	b, err := json.Marshal(h.snapshot())
	if err != nil { // cannot happen for this struct; guard anyway rather than write a half body
		http.Error(w, "history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
