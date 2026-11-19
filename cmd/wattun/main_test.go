package main

import "testing"

// TestValidCarrierNoFortress pins the fortress-alias boundary (2026-11-20 review): "fortress" is the manager's
// alias expanded by exact match on the whole -carrier value before any name check runs, so it must never be a
// valid BOND LEG name — build() has no case for it, and admitting it produced nil-carrier panics at startup
// (now the standard "unknown -carrier" exit 2).
func TestValidCarrierNoFortress(t *testing.T) {
	if validCarrier["fortress"] {
		t.Fatal("fortress must not be a valid bond leg: build() has no case for it (nil carriers, panic)")
	}
	for _, c := range []string{"icmp", "udp", "tcp", "tls", "wss", "grpc"} {
		if !validCarrier[c] {
			t.Fatalf("validCarrier lost %q", c)
		}
	}
}
