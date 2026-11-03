package main

import (
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func TestStatsAliases(t *testing.T) {
	got := statsAliases(wat.Stats{SRTT: 12_500 * time.Microsecond, Streams: 3})
	if len(got) != 2 {
		t.Fatalf("statsAliases returned %d keys, want exactly rtt_ms and streams_total: %v", len(got), got)
	}
	if rtt, ok := got["rtt_ms"].(float64); !ok || rtt != 12.5 {
		t.Errorf("rtt_ms = %#v (%T), want float64 12.5", got["rtt_ms"], got["rtt_ms"])
	}
	if streams, ok := got["streams_total"].(int); !ok || streams != 3 {
		t.Errorf("streams_total = %#v (%T), want int 3", got["streams_total"], got["streams_total"])
	}
}
