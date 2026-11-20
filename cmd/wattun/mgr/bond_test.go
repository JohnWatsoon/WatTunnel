package mgr

import (
	"reflect"
	"testing"
)

func TestBondPure(t *testing.T) {
	for in, want := range map[string]string{"OFF": "off", "hourly": "1h", "360m": "6h", "daily": "daily-offpeak", "5m": ""} {
		if got := bondRetestOK(in); got != want {
			t.Errorf("bondRetestOK(%q) = %q", in, got)
		}
	}
	if got := bondRetestTimer("30m"); got != "OnBootSec=5min\nOnUnitActiveSec=30min\nRandomizedDelaySec=60\nPersistent=true\n" {
		t.Errorf("timer 30m: %q", got)
	}
	// failures outside the bond are kept; an old failure this run did not test stays queued
	if got := bondFailNext("grpc,wss", "tcp+tls", "tcp tls udp wss", "udp wss"); got != "udp,wss,grpc" {
		t.Errorf("bondFailNext = %q", got)
	}
	if !bondWorth(5, 0) || bondWorth(0, 10) || bondWorth(0.5, 10) || !bondWorth(1, 10) {
		t.Error("bondWorth: 10 % of the best leg, or any when no leg works")
	}
	if bondBudgetFit(9, 20) != 9 || bondBudgetFit(30, 20) != 10 || bondBudgetFit(5, 1) != 1 {
		t.Error("bondBudgetFit")
	}
	got := bondCandidatesPlan("tcp+tls", "tcp:443,tls:8443,wss:2053,sit:,udp:x,grpc:2083", "1.2.3.4", "cdn.example")
	want := [][2]string{{"icmp", "1.2.3.4"}, {"wss", "cdn.example:2053"}, {"grpc", "cdn.example:2083"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bondCandidatesPlan = %v", got)
	}
}
