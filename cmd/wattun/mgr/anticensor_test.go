package mgr

import "testing"

func TestAnticensorValidators(t *testing.T) {
	for _, c := range []struct {
		f    func(string) bool
		in   string
		want bool
	}{
		{vFakeTTL, "", true}, {vFakeTTL, "8", true}, {vFakeTTL, "255", true}, {vFakeTTL, "256", false}, {vFakeTTL, "x", false},
		{vSNIName, "mci.ir", true}, {vSNIName, "mci.ir, tci.ir", true}, {vSNIName, "-bad.ir", false}, {vSNIName, "", false},
		{vDNSListen, "off", true}, {vDNSListen, "127.0.0.1:53", true}, {vDNSListen, "127.0.0.1:70000", false}, {vDNSListen, "localhost:53", false},
		{vSrcIP, "", true}, {vSrcIP, "10.0.0.2", true}, {vSrcIP, "[2001:db8::1]", true}, {vSrcIP, "10.0.0", false},
		{vPoolRotate, "0", true}, {vPoolRotate, "90s", true}, {vPoolRotate, "30m", true}, {vPoolRotate, "30", false},
		{vEch, "ladder", true}, {vEch, "AEX+/=abcdefghijklmnop", true}, {vEch, "short", false},
		{vFakeMode, "rst", true}, {vFakeMode, "paws", true}, {vFakeMode, "nope", false},
	} {
		if got := c.f(c.in); got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
	if s := flatMap(map[string]any{"b": 2.0, "a": "x"}); s != "a x · b 2" {
		t.Errorf("flatMap = %q", s)
	}
}
