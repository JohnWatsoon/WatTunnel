package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func knownKeys(k string) bool {
	switch k {
	case "mode", "carrier", "peer", "key-file", "header", "sni", "listen", "reverse":
		return true
	}
	return false
}

func TestParseConfig(t *testing.T) {
	txt := "# top comment\r\nmode: server   # trailing\nkey-file: \"/etc/a b#c\"\nsni: 'x.example.com'\nreverse: true\n\nheader: A: 1\nheader: B: 2\nports:\n  - 10001\n  - \"10002\"   # q\n  - 10003/udp\n"
	c, err := parseConfig(txt, knownKeys)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"mode": "server", "key-file": "/etc/a b#c", "sni": "x.example.com", "reverse": "true"}
	got := flatten(c)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if got["header"] != "A: 1\x00B: 2" {
		t.Errorf("header = %q", got["header"])
	}
	if !c.PortsSet || len(c.Ports) != 3 || c.Ports[2] != (portSpec{10003, 10003, true}) || c.Ports[1].Port != 10002 {
		t.Errorf("ports = %+v", c.Ports)
	}
	if tp := c.tcpPorts(); len(tp) != 2 || tp[0] != 10001 || tp[1] != 10002 {
		t.Errorf("tcpPorts = %v", tp)
	}
}

func TestParseConfigErrors(t *testing.T) {
	for name, txt := range map[string]string{
		"unknown key":          "mode: client\nbogus: 1\n",
		"bad port":             "ports:\n  - 99999\n",
		"zero port":            "ports:\n  - 0\n",
		"non-numeric":          "ports:\n  - http\n",
		"bad suffix":           "ports:\n  - 80/sctp\n",
		"item no list":         "mode: client\n- 5\n",
		"no colon":             "mode client\n",
		"dup key":              "mode: client\nmode: server\n",
		"inline ports":         "ports: 5\n",
		"dup ports":            "ports:\n  - 1\nports:\n  - 2\n",
		"item after key":       "ports:\n  - 1\nmode: x\n  - 2\n",
		"indented key in list": "ports:\n  - 1\n  mode: client\n", // an indented key inside a list is a mistake, not a setting
	} {
		if _, err := parseConfig(txt, knownKeys); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if c, err := parseConfig("ports:\n", knownKeys); err != nil || !c.PortsSet || len(c.Ports) != 0 {
		t.Errorf("empty ports list: %+v %v", c, err)
	}
	if c, err := parseConfig("\xef\xbb\xbfmode: client\n", knownKeys); err != nil || flatten(c)["mode"] != "client" {
		t.Errorf("BOM not stripped: %+v %v", c, err)
	}
}

func TestAllowFileVsConfigPorts(t *testing.T) {
	// The config's ports: list is authoritative once setPorts ran; the allow-file poller must never stomp it
	// (audit 2026-10-22 finding 1: the ticker reverted hot-reloaded config ports within 3 s).
	afile := filepath.Join(t.TempDir(), "allow.txt")
	os.WriteFile(afile, []byte("100\n200\n"), 0o644)
	path := filepath.Join(t.TempDir(), "wat.yml")
	writeCfg(t, path, "mode: server\nports:\n  - 300\n", 1)
	c, err := parseConfig(mustRead(t, path), knownKeys)
	if err != nil {
		t.Fatal(err)
	}
	al := newAllow("", afile) // starts the 3 s poller with the file's list
	if !al.ok(100, 1, 65535) {
		t.Fatal("file list not applied initially")
	}
	al.setPorts(c.tcpPorts()) // config ports: arrives (hot reload)
	al.setUDPPorts(nil)
	if al.ok(100, 1, 65535) || !al.ok(300, 1, 65535) {
		t.Fatal("config ports not authoritative")
	}
	os.WriteFile(afile, []byte("999\n"), 0o644) // change the file: the poller will see it
	mt := time.Now().Add(time.Minute)
	os.Chtimes(afile, mt, mt)
	al.reload() // what the poller does on its tick
	if al.ok(999, 1, 65535) || !al.ok(300, 1, 65535) {
		t.Fatal("allow-file poller overrode the config's authoritative ports")
	}
}

func writeCfg(t *testing.T, path, txt string, bump int) {
	t.Helper()
	if err := os.WriteFile(path, []byte(txt), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(time.Duration(bump) * time.Minute) // distinct mtimes whatever the fs granularity
	os.Chtimes(path, mt, mt)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestHotReloadServerAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wat.yml")
	writeCfg(t, path, "mode: server\nports:\n  - 100\n  - 200/udp\n", 1)
	c, err := parseConfig(mustRead(t, path), knownKeys)
	if err != nil {
		t.Fatal(err)
	}
	al := newAllow("", "")
	al.setPorts(c.tcpPorts())
	w := &cfgWatcher{path: path, known: knownKeys, onPorts: func(c *fileConfig) []error { al.setPorts(c.tcpPorts()); return nil }}
	w.start(c)
	if !al.ok(100, 1, 65535) || al.ok(200, 1, 65535) || al.ok(300, 1, 65535) {
		t.Fatal("initial allowlist wrong")
	}
	writeCfg(t, path, "mode: server\nports:\n  - 300\n", 2)
	w.check()
	if al.ok(100, 1, 65535) || !al.ok(300, 1, 65535) {
		t.Fatal("reload did not replace the allowlist")
	}
	writeCfg(t, path, "mode: server\nports:\n  - bogus\n", 3) // broken: keep the old one
	w.check()
	if !al.ok(300, 1, 65535) {
		t.Fatal("a broken file must keep the old allowlist")
	}
	writeCfg(t, path, "mode: client\nports:\n  - 400\n", 4) // mode change is not applied, ports are
	w.check()
	if !al.ok(400, 1, 65535) || al.ok(300, 1, 65535) {
		t.Fatal("ports change alongside a restart-only key must still apply")
	}
	writeCfg(t, path, "mode: client\nports:\n", 5) // empty list = deny all
	w.check()
	if al.ok(400, 1, 65535) {
		t.Fatal("empty ports list must deny everything")
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dialOK(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Client listeners are added and removed live, and a connection that is already open survives its listener closing.
func TestHotReloadClientListeners(t *testing.T) {
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	path := filepath.Join(t.TempDir(), "wat.yml")
	cfgOf := func(ps ...int) string {
		s := "mode: client\nports:\n"
		for _, p := range ps {
			s += "  - " + strconv.Itoa(p) + "\n"
		}
		return s
	}
	writeCfg(t, path, cfgOf(p1, p2), 1)
	held := make(chan net.Conn, 4)
	ls := newListeners(func(p, _ int) (net.Listener, error) {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			go acceptLoop(ln, func(c net.Conn) { held <- c })
		}
		return ln, err
	})
	t.Cleanup(func() { ls.apply(nil) })
	c, _ := parseConfig(mustRead(t, path), knownKeys)
	if errs := ls.apply(c.tcpMaps()); len(errs) > 0 {
		t.Fatal(errs)
	}
	w := &cfgWatcher{path: path, known: knownKeys, interval: 20 * time.Millisecond,
		onPorts: func(c *fileConfig) []error {
			var errs []error
			for _, e := range ls.apply(c.tcpMaps()) {
				t.Log(e)
				errs = append(errs, e)
			}
			return errs
		}}
	w.start(c)
	go w.run() // exercises the real poll loop too
	if !dialOK(p1) || !dialOK(p2) || dialOK(p3) {
		t.Fatal("initial listeners wrong")
	}
	open, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p1)))
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	writeCfg(t, path, cfgOf(p2, p3), 2) // remove p1, add p3
	deadline := time.Now().Add(3 * time.Second)
	for !(ls.has(p3) && !ls.has(p1)) {
		if time.Now().After(deadline) {
			t.Fatal("listeners were not reconciled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if dialOK(p1) || !dialOK(p2) || !dialOK(p3) {
		t.Fatal("after reload: p1 must be closed, p2 and p3 open")
	}
	// the connection opened before the reload still works
	var srvSide net.Conn
	timeout := time.After(2 * time.Second)
	for srvSide == nil {
		select {
		case sc := <-held:
			if sc.RemoteAddr().String() == open.LocalAddr().String() {
				srvSide = sc
			}
		case <-timeout:
			t.Fatal("could not pair the held connection")
		}
	}
	if _, err := open.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	srvSide.SetReadDeadline(time.Now().Add(time.Second))
	if b := make([]byte, 1); func() error { _, e := srvSide.Read(b); return e }() != nil {
		t.Fatal("existing connection broke when its listener was removed")
	}
}

func TestParseConfigIcmpType(t *testing.T) {
	c, err := parseConfig("mode: client\nicmp-type: timestamp\n", func(k string) bool { return k == "mode" || k == "icmp-type" })
	if err != nil {
		t.Fatal(err)
	}
	if got := flatten(c); got["icmp-type"] != "timestamp" {
		t.Errorf("icmp-type = %q", got["icmp-type"])
	}
}

func TestPortMappingSyntax(t *testing.T) {
	c, err := parseConfig("ports:\n  - 443\n  - 443/udp\n  - 8443:443\n  - 9000:9001/tcp\n  - 5353:53/udp\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []portSpec{{443, 443, false}, {443, 443, true}, {8443, 443, false}, {9000, 9001, false}, {5353, 53, true}}
	if len(c.Ports) != len(want) {
		t.Fatalf("ports = %v", c.Ports)
	}
	for i, w := range want {
		if c.Ports[i] != w {
			t.Errorf("item %d = %v, want %v", i, c.Ports[i], w)
		}
	}
	if tp := c.tcpPorts(); len(tp) != 3 || tp[0] != 443 || tp[1] != 443 || tp[2] != 9001 {
		t.Errorf("tcpPorts (targets) = %v", tp)
	}
	if up := c.udpPorts(); len(up) != 2 || up[1] != 53 {
		t.Errorf("udpPorts = %v", up)
	}
	if m := c.tcpMaps(); len(m) != 3 || m[1] != (portMap{8443, 443}) {
		t.Errorf("tcpMaps = %v", m)
	}
	c2, _ := parseConfig("ports:\n  - 443\n  - 8443:444\n", nil)
	c3, _ := parseConfig("ports:\n  - 443\n  - 8443:443\n", nil)
	if portsKey(c2) == portsKey(c3) {
		t.Error("portsKey ignores the target")
	}
}

func TestPortMappingRejects(t *testing.T) {
	for _, it := range []string{"0:443", "443:", ":443", "a:b", "70000:1", "1:70000", "1:2:3", "x"} {
		if _, err := parseConfig("ports:\n  - "+it+"\n", nil); err == nil {
			t.Errorf("%q accepted", it)
		}
	}
	for _, txt := range []string{"ports:\n  - 443\n  - 443:80\n", "ports:\n  - 53/udp\n  - 53:1/udp\n"} {
		if _, err := parseConfig(txt, nil); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("duplicate not rejected: %v", err)
		}
	}
	if _, err := parseConfig("ports:\n  - 443\n  - 443/udp\n  - 80:443\n", nil); err != nil {
		t.Errorf("same port on tcp and udp / shared target rejected: %v", err)
	}
}

func TestListenersRetarget(t *testing.T) {
	p := freePort(t)
	ls := newListeners(func(l, _ int) (net.Listener, error) {
		return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(l)))
	})
	t.Cleanup(func() { ls.apply(nil) })
	if errs := ls.apply([]portMap{{p, 1}}); len(errs) > 0 || ls.target(p) != 1 {
		t.Fatal(errs)
	}
	if errs := ls.apply([]portMap{{p, 2}}); len(errs) > 0 || ls.target(p) != 2 {
		t.Fatalf("retarget: %v target=%d", errs, ls.target(p))
	}
}

func TestPortRangeForwarding(t *testing.T) {
	txt := "ports:\n  - 10000-10003:20000-20003\n  - 30000-30002\n  - 40000-40001/udp\n"
	c, err := parseConfig(txt, nil)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(c.Ports) != 9 {
		t.Fatalf("expected 9 ports, got %d: %+v", len(c.Ports), c.Ports)
	}
	for i := 0; i < 4; i++ {
		p := c.Ports[i]
		if p.Port != 10000+i || p.Target != 20000+i || p.UDP {
			t.Errorf("Ports[%d] = %+v, want Port=%d Target=%d UDP=false", i, p, 10000+i, 20000+i)
		}
	}
	for i := 0; i < 3; i++ {
		p := c.Ports[4+i]
		if p.Port != 30000+i || p.Target != 30000+i || p.UDP {
			t.Errorf("Ports[%d] = %+v, want Port=%d Target=%d UDP=false", 4+i, p, 30000+i, 30000+i)
		}
	}
	for i := 0; i < 2; i++ {
		p := c.Ports[7+i]
		if p.Port != 40000+i || p.Target != 40000+i || !p.UDP {
			t.Errorf("Ports[%d] = %+v, want Port=%d Target=%d UDP=true", 7+i, p, 40000+i, 40000+i)
		}
	}

	bad := "ports:\n  - 10000-10003:20000-20001\n"
	if _, err := parseConfig(bad, nil); err == nil || !strings.Contains(err.Error(), "lengths must match") {
		t.Errorf("expected lengths must match error, got %v", err)
	}

	badInv := "ports:\n  - 10003-10000\n"
	if _, err := parseConfig(badInv, nil); err == nil {
		t.Errorf("expected inverted range to fail, got nil")
	}
}
