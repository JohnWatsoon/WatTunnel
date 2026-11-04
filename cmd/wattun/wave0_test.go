package main

// Go Wave 0 of the 2026-11-04 audit fix plan: M1/M15 (-mtu ceiling), D7 (shaped carriers are single-carrier) and M7
// (the quiet-idle stats line ignores noise-only traffic).

import (
	"testing"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func TestClampMaxPayload(t *testing.T) {
	for _, c := range []struct {
		name     string
		explicit int
		prof     wat.Profile
		want     int
		clamped  bool
	}{
		{"shaped udp ceiling", 1400, wat.Profile{MTU: 1326}, 1326, true},
		{"raw sit ceiling", 1400, wat.Profile{MTU: 1360}, 1360, true},
		{"gre ceiling", 1400, wat.Profile{MTU: 1364}, 1364, true},
		{"direct pool keeps its MaxMTU", 1 << 20, wat.Profile{MTU: 4096, MaxMTU: 16 << 10}, 16 << 10, true},
		{"under the ceiling", 1200, wat.Profile{MTU: 1326}, 1200, false},
		{"no profile (icmp) keeps -mtu", 1400, wat.Profile{}, 1400, false},
		{"unset -mtu", 0, wat.Profile{MTU: 1326}, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, clamped := clampMaxPayload(c.explicit, c.prof)
			if got != c.want || clamped != c.clamped {
				t.Fatalf("clampMaxPayload(%d, %+v) = %d, %v; want %d, %v", c.explicit, c.prof, got, clamped, c.want, c.clamped)
			}
		})
	}
}

// D7: the engine rejects a shaped carrier inside a '+' bond; the pure helper names the first offender.
func TestShapedBondCarrier(t *testing.T) {
	for _, c := range []struct {
		names []string
		want  string
	}{
		{[]string{"udp"}, ""},
		{[]string{"sit"}, ""}, // a single shaped carrier is not a bond
		{[]string{"vxlan"}, ""},
		{[]string{"icmp", "tcp", "tls"}, ""},
		{[]string{"tcp", "sit"}, "sit"},
		{[]string{"udp", "vxlan"}, "vxlan"},
		{[]string{"sit", "6to4"}, "sit"},
		{[]string{"tcp", "tls", "grpc", "dnscrypt-udp"}, "dnscrypt-udp"},
	} {
		if got := shapedBondCarrier(c.names); got != c.want {
			t.Errorf("shapedBondCarrier(%v) = %q, want %q", c.names, got, c.want)
		}
	}
	// every F19 shape must be covered by the two tables, or D7 would let it into a bond
	for _, n := range []string{"sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3",
		"fou-gre", "gue-ipip", "vxlan", "geneve", "dnscrypt-udp", "ntp-direct", "openvpn-dco", "srtp-direct"} {
		if shapedBondCarrier([]string{"tcp", n}) != n {
			t.Errorf("%s is not rejected inside a bond", n)
		}
	}
}

// M7: noise-only traffic must not keep the 10 s stats line alive; real packets or a live stream must.
func TestQuietStats(t *testing.T) {
	base := wat.Stats{PktsIn: 10, PktsOut: 20, NoiseSent: 5}
	for _, c := range []struct {
		name  string
		st    wat.Stats
		quiet bool
	}{
		{"nothing moved", base, true},
		{"noise-only growth", wat.Stats{PktsIn: 10, PktsOut: 30, NoiseSent: 15}, true},
		{"input moved", wat.Stats{PktsIn: 11, PktsOut: 20, NoiseSent: 5}, false},
		{"non-noise output moved", wat.Stats{PktsIn: 10, PktsOut: 21, NoiseSent: 5}, false},
		{"live stream", wat.Stats{PktsIn: 10, PktsOut: 20, NoiseSent: 5, Streams: 1}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := quietStats(c.st, base); got != c.quiet {
				t.Fatalf("quietStats(%+v) = %v, want %v", c.st, got, c.quiet)
			}
		})
	}
}
