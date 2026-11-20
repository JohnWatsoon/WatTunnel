package mgr

import (
	"reflect"
	"testing"
)

func TestCDNPure(t *testing.T) {
	got := cdnPickEdges([]string{"104.16.0.1", "104.16.0.2", "172.64.0.1", "104.16.0.3", "188.114.96.1"})
	if want := []string{"104.16.0.1", "172.64.0.1", "188.114.96.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("one per /24: %v", got)
	}
	if got := cdnPickEdges([]string{"104.16.0.1", "104.16.0.2", "104.16.0.3", "104.16.0.4"}); len(got) != 3 || got[2] != "104.16.0.3" {
		t.Errorf("fill up in order: %v", got)
	}
	if got := cdnPickEdges([]string{"2606:4700:3030::1", "2606:4700:3030::2", "2a06:98c1:3121::7"}); got[1] != "2a06:98c1:3121::7" {
		t.Errorf("v6 /48: %v", got)
	}
	if s := cdnPeerList([]string{"1.2.3.4", "2606:4700::1"}, "443"); s != "1.2.3.4:443,[2606:4700::1]:443" {
		t.Errorf("peer list: %s", s)
	}
	raw := `{"alive":true,"edges":[{"addr":"1.2.3.4:443","up":true},{"addr":"[2606:4700::1]:443","up":true},{"addr":"5.6.7.8:443","up":false}]}`
	if got := cdnParseEdges(raw); !reflect.DeepEqual(got, []string{"1.2.3.4", "2606:4700::1"}) {
		t.Errorf("edges: %v", got)
	}
	v := variant{Peer: "1.2.3.4:443,5.6.7.8:443", FP: "chrome", ECH: "auto"}
	if d := cdnDesc(v); d != "chrome fingerprint, ECH (hidden domain), 2 Cloudflare edges" {
		t.Errorf("desc: %s", d)
	}
	if d := cdnDesc(variant{Peer: "x.example:443"}); d != "default settings" {
		t.Errorf("desc default: %s", d)
	}
	if a := probeArgs(variant{SNI: "d.io", FP: "chrome", Frag: "0", FS: "mci.ir", FM: "rst", X: "-conns=4"}); !reflect.DeepEqual(a,
		[]string{"-sni", "d.io", "-host", "d.io", "-fp", "chrome", "-fake-sni", "mci.ir", "-fake-mode", "rst", "-conns=4"}) {
		t.Errorf("probeArgs: %v", a)
	}
}
