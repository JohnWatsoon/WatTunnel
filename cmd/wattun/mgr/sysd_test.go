package mgr

import "testing"

func TestParseUnitStates(t *testing.T) {
	out := "ActiveState=active\nUnitFileState=enabled\nActiveEnterTimestampMonotonic=1000000000\n\n" +
		"ActiveState=inactive\nUnitFileState=disabled\nActiveEnterTimestampMonotonic=0\n\n" +
		"ActiveState=activating\nUnitFileState=enabled\nActiveEnterTimestampMonotonic=0\nNRestarts=12\n"
	got := parseUnitStates(out, []string{"wattun@a", "wattun@b", "wattun@c"}, 1000+2*3600+5*60)
	if s := got["wattun@a"]; !s.Active || !s.Enabled || s.Uptime != "2h 5m" {
		t.Fatalf("a: %+v", s)
	}
	if s := got["wattun@b"]; s.Active || s.Enabled || s.Uptime != "" {
		t.Fatalf("b: %+v", s)
	}
	if s := got["wattun@c"]; s.Active || !s.Enabled || s.Restarts != 12 {
		t.Fatalf("c: %+v", s)
	}
}
