package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoopbackMetricsAddr(t *testing.T) {
	for _, c := range []struct {
		in, out string
		changed bool
	}{
		{"127.0.0.1:19700", "127.0.0.1:19700", false},
		{"127.5.5.5:1", "127.5.5.5:1", false},
		{"localhost:19700", "localhost:19700", false},
		{"[::1]:19700", "[::1]:19700", false},
		{":19700", "127.0.0.1:19700", true},
		{"0.0.0.0:19700", "127.0.0.1:19700", true},
		{"[::]:19700", "127.0.0.1:19700", true},
		{"192.168.1.5:19700", "127.0.0.1:19700", true},
		{"example.com:80", "127.0.0.1:80", true},
		{"19700", "127.0.0.1:19700", true}, // bare port
		{"a:b:c", "a:b:c", false},          // unparseable: left for ListenAndServe to report
	} {
		got, ch := loopbackMetricsAddr(c.in)
		if got != c.out || ch != c.changed {
			t.Errorf("%q: got %q,%v want %q,%v", c.in, got, ch, c.out, c.changed)
		}
	}
}

func TestIsMetricsPort(t *testing.T) {
	defer metricsPort.Store(0)
	metricsPort.Store(0)
	if isMetricsPort(19700) {
		t.Error("metrics off: nothing is the metrics port")
	}
	metricsPort.Store(19700)
	if !isMetricsPort(19700) || isMetricsPort(19701) || isMetricsPort(0) {
		t.Error("metrics port decision wrong")
	}
}

// TestFlatStats: /stats?flat=1 keeps the top-level scalars only, sorted, strings unquoted on one line (3.3.6).
func TestFlatStats(t *testing.T) {
	type state string
	var b strings.Builder
	writeFlatStats(&b, map[string]any{"rate_bps": 15e6, "alive": true, "version": "3.3.6", "streams_total": 3,
		"fec_state": state("off"), "note": "a\nb", "cc": map[string]any{"ticks": 1}, "ports": []int{1}, "edges": nil})
	want := "alive=true\nfec_state=off\nnote=a b\nrate_bps=15000000\nstreams_total=3\nversion=3.3.6\n"
	if b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
}

// TestMemDefaults: the RAM/3 limit and RAM/8 budget split over the tunnels on a host, with floors (3.3.6).
func TestMemDefaults(t *testing.T) {
	const mb = 1 << 20
	for _, c := range []struct{ ram, n, lim, bud int64 }{ // lim, bud in bytes
		{3072, 1, 1024 * mb, 384 * mb},  // one tunnel: exactly the old defaults
		{512, 1, 512 * mb / 3, 64 * mb}, // a small host keeps RAM/3, the floor never raises it
		{3072, 4, 256 * mb, 96 * mb},
		{3072, 16, 256 * mb, 64 * mb}, // floors
		{512, 4, 512 * mb / 3, 64 * mb},
	} {
		l, b := memDefaults(int(c.ram), int(c.n))
		if l != c.lim || b != c.bud {
			t.Errorf("ram %d n %d: limit %d MB budget %d MB", c.ram, c.n, l/mb, b/mb)
		}
	}
	dir := t.TempDir()
	for _, f := range []string{"a.yml", "b.yml", "c.token"} {
		os.WriteFile(filepath.Join(dir, f), nil, 0o600)
	}
	if n := tunnelCount(filepath.Join(dir, "a.yml")); n != 2 {
		t.Errorf("tunnelCount = %d, want 2", n)
	}
	if n := tunnelCount(""); n != 1 {
		t.Errorf("tunnelCount(\"\") = %d, want 1", n)
	}
}

// TestDialLocalIPv6: a service bound to ::1 only is reached when 127.0.0.1 refuses (3.3.6).
func TestDialLocalIPv6(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		c.Close()
		t.Skip("127.0.0.1 has a listener on the same port")
	}
	c, err := dialLocal(port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ip := c.RemoteAddr().(*net.TCPAddr).IP; !ip.Equal(net.IPv6loopback) {
		t.Fatalf("dialed %v", ip)
	}
}
