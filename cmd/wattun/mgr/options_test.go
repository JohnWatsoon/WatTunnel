package mgr

import (
	"os"
	"path/filepath"
	"testing"
)

// A preset always passes; a custom value only inside its range, whole unless Float; an address only for IP.
func TestCheckOption(t *testing.T) {
	mtu := Option{Label: "MTU", Choices: optNums("B", "auto", "1200"), Custom: &OptRange{Min: 256, Max: 1500}}
	pad := Option{Label: "Padding", Choices: optOnOff, Custom: &OptRange{Min: 0.1, Max: 25, Float: true}}
	bind := Option{Label: "Listen on", Choices: []OptChoice{{Value: ""}}, Custom: &OptRange{IP: true}}
	fec := Option{Label: "FEC", Choices: []OptChoice{{Value: ""}, {Value: "auto"}}}
	for _, c := range []struct {
		o  Option
		v  string
		ok bool
	}{
		{mtu, "", true}, {mtu, "1200", true}, {mtu, "1400", true}, {mtu, "256", true},
		{mtu, "255", false}, {mtu, "1501", false}, {mtu, "1300.5", false}, {mtu, "x", false},
		{pad, "2.5", true}, {pad, "0", false}, {pad, "26", false},
		{bind, "10.0.0.5", true}, {bind, "[::1]", true}, {bind, "::", true}, {bind, "host", false},
		{fec, "auto", true}, {fec, "on", false},
	} {
		if err := CheckOption(c.o, c.v); (err == nil) != c.ok {
			t.Errorf("%s %q: err %v, want ok=%v", c.o.Label, c.v, err, c.ok)
		}
	}
}

// Rows follow the role and carrier: an Iran icmp tunnel offers ICMP type and no MTU preset above the carrier's
// maximum; on Kharej the both-ends rows are hidden (Iran changes Kharej first, never the other way).
func TestTunnelOptionsRows(t *testing.T) {
	dir := setTempConf(t)
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: icmp\npeer: 198.51.100.7\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "kh.yml"), []byte("mode: server\ncarrier: icmp\n"), 0o600)
	keys := func(n string) map[string]Option {
		m := map[string]Option{}
		for _, o := range TunnelOptions(n) {
			m[o.Key] = o
		}
		return m
	}
	ir, kh := keys("ir"), keys("kh")
	if !ir["icmp-type"].BothEnds || ir["bind"].Key == "" {
		t.Fatalf("Iran icmp rows: %v", ir)
	}
	if _, ok := kh["icmp-type"]; ok {
		t.Fatal("Kharej offers a both-ends row")
	}
	for _, c := range ir["mtu"].Choices {
		if c.Value != "" && atoi(c.Value) > mtuMaxFor("icmp") {
			t.Fatalf("mtu preset %s above the icmp maximum %d", c.Value, mtuMaxFor("icmp"))
		}
	}
	if err := SetTunnelOptions("ir", map[string]string{"mtu": "99999"}); err == nil {
		t.Fatal("an MTU above the maximum was written")
	}
	if err := SetTunnelOptions("ir", map[string]string{"fec": "auto", "max-mbps": "25"}); err != nil || Cfg("ir", "fec") != "auto" || Cfg("ir", "max-mbps") != "25" {
		t.Fatalf("set: %v fec=%q max=%q", err, Cfg("ir", "fec"), Cfg("ir", "max-mbps"))
	}
	if err := SetTunnelOptions("ir", map[string]string{"fec": ""}); err != nil || Cfg("ir", "fec") != "" {
		t.Fatalf("unset fec: %v %q", err, Cfg("ir", "fec"))
	}
}
