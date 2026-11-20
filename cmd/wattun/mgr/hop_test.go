package mgr

import "testing"

// Wraith (3.3.9): a 3.3.9 engine adds "udp hop" after udp, with its own key; choosing it writes udp-hop.
func TestAutoVariantsUDPHop(t *testing.T) {
	old := engineVer
	defer func() { engineVer = old }()
	engineVer = func() string { return "3.3.9" }
	autoVariants(Token{Carrier: "auto", Peer: "203.0.113.10", Auto: "d=udp:4443,tcp:4443;r=icmp"})
	if len(av) < 3 || av[2].Label != "udp hop" || av[2].Peer != "203.0.113.10:4443" || avKey(av[2]) != "udp/d/hop" || avKey(av[1]) != "udp/d" {
		t.Fatalf("variants = %+v", av)
	}
	if c, err := atToT([]int{2}); err != nil || c.Carrier != "udp" || c.Extra != "udp-hop: 12" {
		t.Errorf("single = %+v %v", c, err)
	}
	if c, err := atToT([]int{2, 3}); err != nil || c.Carrier != "udp+tcp" || c.Extra != "peer-udp: 203.0.113.10:4443\npeer-tcp: 203.0.113.10:4443\nudp-hop: 12" {
		t.Errorf("bond = %+v %v", c, err)
	}
	if c, _ := atToT([]int{1}); c.Extra != "" {
		t.Errorf("plain udp extra = %q", c.Extra)
	}
	engineVer = func() string { return "3.3.8" }
	autoVariants(Token{Carrier: "auto", Peer: "203.0.113.10", Auto: "d=udp:4443,tcp:4443;r=icmp"})
	for _, v := range av {
		if v.Label == "udp hop" {
			t.Error("hop row on a 3.3.8 engine")
		}
	}
}
