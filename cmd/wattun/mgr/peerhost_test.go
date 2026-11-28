package mgr

import (
	"os"
	"path/filepath"
	"testing"
)

// A reverse tunnel whose peer is this server (127.0.0.1 stands in for it) or missing names the Kharej that dials
// its listen port; a direct tunnel keeps its peer. Before 4.0.8 the panel showed one "Kharej" per reverse tunnel,
// named after this server's own city or the tunnel, and a create through such a pair could not build its token.
func TestScepterPeerHostReverse(t *testing.T) {
	oldP, oldE := P, envEstablished
	P.Conf = t.TempDir()
	defer func() { P, envEstablished = oldP, oldE }()
	envEstablished = func(port string) string {
		if port != "11973" {
			return ""
		}
		return "0 0 [::ffff:127.0.0.1]:11973 [::ffff:203.0.113.7]:1190\n0 0 [::ffff:127.0.0.1]:11973 [::ffff:203.0.113.7]:1214\n"
	}
	w := func(n, y string) { os.WriteFile(filepath.Join(P.Conf, n+".yml"), []byte(y), 0o600) }
	w("own", "mode: client\ncarrier: tls\npeer: 127.0.0.1:11973\nreverse: true\nlisten: \":11973\"\n")
	w("none", "mode: client\ncarrier: ws\nlisten: \":11973\"\nreverse: true\n")
	w("kh", "mode: client\ncarrier: h2\npeer: 198.51.100.9:26668\nreverse: true\nlisten: \":26668\"\n")
	w("direct", "mode: client\ncarrier: icmp\npeer: 198.51.100.9\n")
	for n, want := range map[string]string{"own": "203.0.113.7", "none": "203.0.113.7", "kh": "198.51.100.9", "direct": "198.51.100.9"} {
		if got := scepterPeerHost(n); got != want {
			t.Errorf("%s: %q, want %q", n, got, want)
		}
	}
}
