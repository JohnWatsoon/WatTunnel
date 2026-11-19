package mgr

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func setTempConf(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	P.Conf = dir
	P.MConf = filepath.Join(dir, ".manager.conf")
	P.Self = "wattun"
	P.Prefix = "wattun"
	P.Sandbox = false
	return dir
}

func TestCfgReadsAndStripsQuotes(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	if err := os.WriteFile(filepath.Join(dir, "a.yml"),
		[]byte("mode: client\ncarrier: icmp+udp\nmetrics: 127.0.0.1:19701\npeer: \"198.51.100.7\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Cfg("a", "mode"); got != "client" {
		t.Errorf("mode = %q", got)
	}
	if got := Cfg("a", "peer"); got != "198.51.100.7" {
		t.Errorf("peer = %q, quotes must go", got)
	}
	if got := Cfg("a", "missing"); got != "" {
		t.Errorf("missing key = %q", got)
	}
	if got := Role("a"); got != "Iran" {
		t.Errorf("role = %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.yml"), []byte("mode: server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Role("s"); got != "Kharej" {
		t.Errorf("server role = %q", got)
	}
}

func TestSetValueUnsetValueAtomic(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	body := "mode: client\ncarrier: udp\nmetrics: 127.0.0.1:19701\n"
	if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// set: lands before metrics:, replaces the old line
	if err := SetValue("t", "fake-sni", "mci.ir"); err != nil {
		t.Fatal(err)
	}
	out := readFile(t, filepath.Join(dir, "t.yml"))
	lines := strings.Split(out, "\n")
	iFake, iMetrics := -1, -1
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "fake-sni:"):
			iFake = i
		case strings.HasPrefix(l, "metrics:"):
			iMetrics = i
		}
	}
	if iFake < 0 || iMetrics < 0 || iFake > iMetrics {
		t.Errorf("fake-sni must sit before metrics:, got:\n%s", out)
	}
	if strings.Count(out, "carrier:") != 1 {
		t.Errorf("carrier line duplicated:\n%s", out)
	}
	// set over an existing key replaces it
	if err := SetValue("t", "fake-sni", "irancell.ir"); err != nil {
		t.Fatal(err)
	}
	out = readFile(t, filepath.Join(dir, "t.yml"))
	if strings.Count(out, "fake-sni:") != 1 || !strings.Contains(out, "fake-sni: irancell.ir") {
		t.Errorf("overwrite wrong:\n%s", out)
	}
	// a key without metrics:/ports: appends at the end (separate config so the
	// insertion point differs)
	if err := os.WriteFile(filepath.Join(dir, "t2.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetValue("t2", "sessions", "4"); err != nil {
		t.Fatal(err)
	}
	out = readFile(t, filepath.Join(dir, "t2.yml"))
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "sessions: 4") {
		t.Errorf("append wrong:\n%s", out)
	}
	// and the config that does have metrics: gets it inserted before metrics:
	if err := SetValue("t", "sessions", "2"); err != nil {
		t.Fatal(err)
	}
	out = readFile(t, filepath.Join(dir, "t.yml"))
	if iS, iM := strings.Index(out, "sessions: 2"), strings.Index(out, "metrics:"); iS < 0 || iM < 0 || iS > iM {
		t.Errorf("insert-before-metrics wrong:\n%s", out)
	}
	// unset removes the line, everything else survives
	if err := UnsetValue("t", "fake-sni"); err != nil {
		t.Fatal(err)
	}
	out = readFile(t, filepath.Join(dir, "t.yml"))
	if strings.Contains(out, "fake-sni:") || !strings.Contains(out, "carrier: udp") {
		t.Errorf("unset wrong:\n%s", out)
	}
}

func TestAtomicWriteNoTmpLeftovers(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	if err := ConfSet("anim", "0"); err != nil {
		t.Fatal(err)
	}
	if got := ConfGet("anim", "1"); got != "0" {
		t.Errorf("anim = %q, want 0", got)
	}
	if err := ConfSet("anim", "1"); err != nil {
		t.Fatal(err)
	}
	if got := ConfGet("anim", "0"); got != "1" {
		t.Errorf("anim = %q, want 1 (last wins)", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestNormSpecAndSpecHelpers(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"443", []string{"443:443/tcp"}},
		{"8443->443", []string{"8443:443/tcp"}},
		{"8443→443/udp", []string{"8443:443/udp"}},
		{"53/both", []string{"53:53/tcp", "53:53/udp"}},
		{"53/tcpudp", []string{"53:53/tcp", "53:53/udp"}},
		{"10002/udp", []string{"10002:10002/udp"}},
	}
	for _, c := range cases {
		got, err := NormSpec(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("NormSpec(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	if _, err := NormSpec("99999"); err == nil {
		t.Error("no error on an out-of-range port")
	}
	if _, err := NormSpec("x/y"); err == nil {
		t.Error("no error on a bad protocol")
	}
	if SpecHuman("8443:443/tcp") != "8443→443" || SpecHuman("443:443/tcp") != "443" || SpecHuman("53:53/udp") != "53/udp" {
		t.Error("SpecHuman wrong")
	}
	if SpecYaml("8443:443/tcp") != "8443:443" || SpecYaml("53:53/udp") != "53/udp" {
		t.Error("SpecYaml wrong")
	}
}

func TestYmlMapsAndAllowStr(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	body := "# the bond\nmode: client\nports:\n  - 8443:443\n  - 10001\n  - 27003:27002\n  - 10002/udp\n  - 53/both\nmetrics: 127.0.0.1:19701\n"
	if err := os.WriteFile(filepath.Join(dir, "m.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := YmlMaps("m")
	want := []string{"8443:443/tcp", "10001:10001/tcp", "27003:27002/tcp", "10002:10002/udp", "53:53/tcp", "53:53/udp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("YmlMaps = %v, want %v", got, want)
	}
	if allow := MapsAllowStr(got); allow != "443,10001,27002,10002/udp,53,53/udp" {
		t.Errorf("MapsAllowStr = %q", allow)
	}
}

func TestWritePortsReplacesBlock(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	body := "mode: client\ncarrier: udp\nports:\n  - 1\n  - 2\n  - 3\nmetrics: 127.0.0.1:19701\n"
	if err := os.WriteFile(filepath.Join(dir, "w.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WritePorts("w", []string{"443:443/tcp", "53:53/udp"}); err != nil {
		t.Fatal(err)
	}
	out := readFile(t, filepath.Join(dir, "w.yml"))
	if strings.Contains(out, "  - 1") || strings.Contains(out, "  - 3") {
		t.Errorf("old ports survived:\n%s", out)
	}
	// the bash awk keeps the rest of the file in order and appends the new
	// block at the end (maps_yaml_block >>"$tmp")
	want := "mode: client\ncarrier: udp\nmetrics: 127.0.0.1:19701\nports:\n  - 443\n  - 53/udp\n"
	if out != want {
		t.Errorf("WritePorts =\n%q\nwant\n%q", out, want)
	}
}

func TestTunnelsVisibility(t *testing.T) {
	InitColor(false, 8)
	dir := setTempConf(t)
	for _, n := range []string{"main", "main-r", "main-e-ladder", "second", "notes.txt"} {
		name := n
		if !strings.HasSuffix(name, ".txt") && !strings.HasSuffix(name, ".yml") {
			name += ".yml"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("mode: client\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// main-r is only hidden when main is an auto Kharej config; give main the auto token
	if err := os.WriteFile(filepath.Join(dir, "main.token"),
		[]byte(MakeToken("auto", "h:1", "k", "", "", "", "", "", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	// main-e-ladder is hidden only with a .autoext file naming main
	if err := os.WriteFile(filepath.Join(dir, "main-e-ladder.autoext"), []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Tunnels()
	want := []string{"main", "second"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tunnels = %v, want %v", got, want)
	}
	all := TunnelsAll()
	wantAll := []string{"main", "main-e-ladder", "main-r", "second"}
	if !reflect.DeepEqual(all, wantAll) {
		t.Errorf("TunnelsAll = %v, want %v", all, wantAll)
	}
}

func TestSplitJoinHP(t *testing.T) {
	cases := []struct {
		in, h, p string
	}{
		{"198.51.100.7:4443", "198.51.100.7", "4443"},
		{"[2001:db8::1]:4443", "2001:db8::1", "4443"},
		{"[2001:db8::1]", "2001:db8::1", ""},
		{"2001:db8::1", "2001:db8::1", ""},
		{"example.com", "example.com", ""},
		{"example.com:443", "example.com", "443"},
	}
	for _, c := range cases {
		if h, p := SplitHP(c.in); h != c.h || p != c.p {
			t.Errorf("SplitHP(%q) = %q,%q want %q,%q", c.in, h, p, c.h, c.p)
		}
	}
	join := []struct {
		h, p, want string
	}{
		{"198.51.100.7", "4443", "198.51.100.7:4443"},
		{"2001:db8::1", "4443", "[2001:db8::1]:4443"},
		{"2001:db8::1", "", "2001:db8::1"},
		{"example.com", "", "example.com"},
		{"[2001:db8::1]", "4443", "[2001:db8::1]:4443"},
	}
	for _, c := range join {
		if got := JoinHP(c.h, c.p); got != c.want {
			t.Errorf("JoinHP(%q,%q) = %q want %q", c.h, c.p, got, c.want)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
