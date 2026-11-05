package main

// F19 (3.3.0) carrier wiring: the name/port tables and the shaped-carrier address defaulting, which runs on every
// platform even though the raw-tier sockets are Linux-only.

import (
	"testing"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func TestF19CarrierTables(t *testing.T) {
	inCarrierNames := nameSet(carrierNames)
	rawShapes, udpShapes := wat.RawShapedCarrierNames(), wat.UDPShapedCarrierNames()
	for _, n := range rawShapes {
		if !validCarrier[n] || !inCarrierNames[n] {
			t.Errorf("%s: missing from validCarrier/carrierNames", n)
		}
		if !rawIPCarrier[n] || !carrierNoListen[n] {
			t.Errorf("%s: must be a raw carrier without -listen", n)
		}
		if shapedUDPCarrier[n] {
			t.Errorf("%s: raw carrier listed as a shaped udp carrier", n)
		}
	}
	for _, n := range udpShapes {
		if !validCarrier[n] || !inCarrierNames[n] {
			t.Errorf("%s: missing from validCarrier/carrierNames", n)
		}
		if !shapedUDPCarrier[n] || rawIPCarrier[n] || carrierNoListen[n] {
			t.Errorf("%s: must be a shaped udp carrier that listens", n)
		}
	}
	for _, n := range append(rawShapes, udpShapes...) {
		if carrierRealName[n] == "" {
			t.Errorf("%s: missing from carrierRealName", n)
		}
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := []struct {
		in   string
		port int
		want string
	}{
		{"", 4789, ":4789"},
		{"1.2.3.4", 4789, "1.2.3.4:4789"},
		{"example.com", 4789, "example.com:4789"},
		{"1.2.3.4:9999", 4789, "1.2.3.4:9999"},
		{"[::1]", 4789, "[::1]:4789"},
		{"::1", 4789, "[::1]:4789"},
		{"[::1]:9999", 4789, "[::1]:9999"},
		{"0.0.0.0:0", 4789, "0.0.0.0:0"},
		{"anything", 0, "anything"},
	}
	for _, c := range cases {
		if got := withDefaultPort(c.in, c.port); got != c.want {
			t.Errorf("withDefaultPort(%q, %d) = %q, want %q", c.in, c.port, got, c.want)
		}
	}
}
