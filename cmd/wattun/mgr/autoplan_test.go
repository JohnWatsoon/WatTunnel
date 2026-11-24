package mgr

import "testing"

// The shaped carriers are direct listeners: they belong in d=, never in r= (where the reverse companion would put
// them into a '+' bond the engine refuses). Tokens made by 3.3.9-3.6.0 have them in r=; reading one moves them back.
func TestPlanShapedInDirect(t *testing.T) {
	if got := autoPlanString("tcp:1", "vxlan:4,sit", "tcp:2"); got != "d=tcp:1,vxlan:4,sit;r=tcp:2" {
		t.Fatalf("plan %q", got)
	}
	d, r := planSplitShaped("tcp:1", "tcp:2,fou-gre:3,sit")
	if d != "tcp:1,fou-gre:3,sit" || r != "tcp:2" {
		t.Fatalf("split: d=%q r=%q", d, r)
	}
	if _, apR := autoPlanLists("d=tcp:1;r=tcp:2,geneve:5"); len(apR) != 2 || apR[1] != "tcp" {
		t.Fatalf("apR %v", apR)
	}
}

func TestStatsRTTOf(t *testing.T) {
	old := p1FetchStats
	defer func() { p1FetchStats = old }()
	p1FetchStats = func(string) string { return `{"alive":true,"rtt_ms":21.5}` }
	if got := statsRTTOf(1); got != 21.5 {
		t.Fatalf("statsRTTOf = %v, want 21.5", got)
	}
}
