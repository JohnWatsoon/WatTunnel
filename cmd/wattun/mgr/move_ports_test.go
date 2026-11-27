package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMovePorts(t *testing.T) {
	oldP := P
	P.Conf = t.TempDir()
	defer func() { P = oldP }()
	w := func(n, ports string) {
		os.WriteFile(filepath.Join(P.Conf, n+".yml"), []byte("mode: client\ncarrier: tcp\npairing: false\nports:\n"+ports), 0o600)
	}
	w("a", "  - \"39901:18999\"\n  - \"8443:443\"\n")
	w("b", "  - \"2000\"\n")
	if err := MovePorts("a", "b", []string{"8443:443"}); err != nil {
		t.Fatal(err)
	}
	if got := yamlOf("a"); got != "39901:18999" {
		t.Errorf("a = %q", got)
	}
	if got := yamlOf("b"); got != "2000,8443:443" {
		t.Errorf("b = %q", got)
	}
	if MovePorts("a", "b", []string{"39901:18999"}) == nil {
		t.Error("moved the last port of a")
	}
	if MovePorts("b", "a", []string{"9"}) == nil {
		t.Error("moved a port b does not forward")
	}
}

func TestAllowHas(t *testing.T) {
	for _, c := range []struct {
		list, t string
		want    bool
	}{{"", "443", true}, {"443,2000-2010", "2005", true}, {"443", "443/udp", false}, {"53/udp", "53/udp", true}, {"18999", "443", false}} {
		if allowHas(c.list, c.t) != c.want {
			t.Errorf("allowHas(%q, %q) != %v", c.list, c.t, c.want)
		}
	}
}

func yamlOf(n string) string {
	var out []string
	for _, m := range YmlMaps(n) {
		out = append(out, SpecYaml(m))
	}
	return strings.Join(out, ",")
}
