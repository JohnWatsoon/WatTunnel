package wat

// W10 (3.3.0): the server-side client allowlist (Config.AllowClients). The check runs in Server.run before admit, on
// the unauthenticated packet, so a valid packet from a non-allowed source must not open a session either. These
// tests use a fake RawIO whose datagrams carry a caller-chosen source address.

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// allowPkt is one received datagram with the source address the fake raw socket reports for it.
type allowPkt struct {
	p   []byte
	src net.Addr
}

// allowHub is the RawIO of the W10 tests: packets go in with a chosen source, and the server's replies are routed
// back to the client registered under that source address string.
type allowHub struct {
	in   chan allowPkt
	mu   sync.Mutex
	down map[string]chan []byte
	done chan struct{}
	once sync.Once
}

func newAllowHub() *allowHub {
	return &allowHub{in: make(chan allowPkt, 4096), down: map[string]chan []byte{}, done: make(chan struct{})}
}

func (h *allowHub) Recv() ([]byte, int, net.Addr, error) {
	select {
	case r := <-h.in:
		return r.p, 0, r.src, nil
	case <-h.done:
		return nil, 0, nil, io.EOF
	}
}

func (h *allowHub) SendTo(p []byte, lane int, dst net.Addr) error {
	h.mu.Lock()
	ch := h.down[dst.String()]
	h.mu.Unlock()
	if ch != nil {
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	}
	return nil
}

func (h *allowHub) Close() error {
	h.once.Do(func() { close(h.done) })
	return nil
}

// allowClientIO is a PacketIO whose outgoing datagrams carry the chosen source address.
type allowClientIO struct {
	hub  *allowHub
	src  net.Addr
	rx   chan []byte
	done chan struct{}
	once sync.Once
}

func newAllowClientIO(h *allowHub, src net.Addr) *allowClientIO {
	c := &allowClientIO{hub: h, src: src, rx: make(chan []byte, 4096), done: make(chan struct{})}
	h.mu.Lock()
	h.down[src.String()] = c.rx
	h.mu.Unlock()
	return c
}

func (c *allowClientIO) Send(p []byte, lane int) error {
	select {
	case c.hub.in <- allowPkt{append([]byte(nil), p...), c.src}:
		return nil
	case <-c.done:
		return net.ErrClosed
	}
}

func (c *allowClientIO) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-c.rx:
		return p, 0, nil, nil
	case <-c.done:
		return nil, 0, nil, io.EOF
	}
}

func (c *allowClientIO) SetPeer(net.Addr) {}
func (c *allowClientIO) Close() error     { c.once.Do(func() { close(c.done) }); return nil }

// allowSrcAddr builds the source address a test client injects; a non-IP string is the unknown-source case.
func allowSrcAddr(s string) net.Addr {
	if ip := net.ParseIP(s); ip != nil {
		return &net.IPAddr{IP: ip}
	}
	return strAddr(s)
}

// The filter itself: prefixes match the client's IP, IPv4-mapped addresses match IPv4 prefixes, bonded TaggedAddr and
// pool sources resolve, and a source that carries no IP fails closed once a list is set.
func TestSourceAllowed(t *testing.T) {
	v4 := netip.MustParsePrefix("10.0.0.0/8")
	v6 := netip.MustParsePrefix("2001:db8::/32")
	allow := []netip.Prefix{v4, v6}
	for _, c := range []struct {
		name  string
		allow []netip.Prefix
		src   net.Addr
		want  bool
	}{
		{"empty list allows any source", nil, &net.IPAddr{IP: net.ParseIP("192.0.2.9")}, true},
		{"ipv4 in prefix", allow, &net.IPAddr{IP: net.ParseIP("10.1.2.3")}, true},
		{"ipv4 out of prefix", allow, &net.IPAddr{IP: net.ParseIP("192.0.2.9")}, false},
		{"ipv6 in prefix", allow, &net.IPAddr{IP: net.ParseIP("2001:db8::5")}, true},
		{"ipv6 out of prefix", allow, &net.IPAddr{IP: net.ParseIP("2001:db9::5")}, false},
		{"ipv4-mapped matches the v4 prefix", allow, &net.IPAddr{IP: net.ParseIP("::ffff:10.1.2.3")}, true},
		{"udp addr", allow, &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 53}, true},
		{"tcp addr", allow, &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 443}, false},
		{"direct pool addr", allow, poolAddr{key: "k", ip: "10.9.8.7"}, true},
		{"pool addr without an ip", allow, poolAddr{key: "k"}, false},
		{"bonded tagged addr", allow, &TaggedAddr{Idx: 1, Addr: &net.IPAddr{IP: net.ParseIP("2001:db8::9")}}, true},
		{"unknown source fails closed", allow, strAddr("sim"), false},
		{"nil source fails closed", allow, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := &Server{allow: c.allow}
			if got := srv.sourceAllowed(c.src); got != c.want {
				t.Fatalf("sourceAllowed(%v) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}

// The deny log is rate-limited per source and its table is bounded: a source spray cannot log per packet or grow it.
func TestNoteDeniedRateLimited(t *testing.T) {
	var mu sync.Mutex
	var lines int
	srv := NewServer(Config{Key: []byte("allow-key"),
		AllowClients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Logf:         func(string, ...any) { mu.Lock(); lines++; mu.Unlock() }}, newAllowHub())
	defer srv.Close()
	srv.denyEvery = 50 * time.Millisecond // production is 10 s; the test must not sleep that long
	count := func() int { mu.Lock(); defer mu.Unlock(); return lines }
	src := &net.IPAddr{IP: net.ParseIP("192.0.2.9")}
	for i := 0; i < 100; i++ {
		srv.noteDenied(src)
	}
	if got := count(); got != 1 {
		t.Fatalf("%d log lines for 100 rejected packets of one source, want 1", got)
	}
	time.Sleep(60 * time.Millisecond)
	srv.noteDenied(src)
	if got := count(); got != 2 {
		t.Fatalf("%d log lines after the rate window, want 2 (the accumulated drops reported once)", got)
	}
	for i := 0; i < clientDenyMax*3; i++ { // spray distinct sources
		srv.noteDenied(&net.IPAddr{IP: net.IPv4(198, 51, byte(i>>8), byte(i))})
	}
	if n := len(srv.deny); n > clientDenyMax {
		t.Fatalf("deny table holds %d sources, want <= %d", n, clientDenyMax)
	}
}

// A new session is admitted only from an allowed source: the same valid client whose packets authenticate opens a
// session from an allowed IP and nothing from a denied one (the reject happens before admit).
func TestServerClientAllowlistAdmission(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, c := range []struct {
		name  string
		allow []netip.Prefix
		src   string
		want  bool
	}{
		{"allowed", allow, "10.1.2.3", true},
		{"denied", allow, "192.0.2.9", false},
		{"no list allows everything", nil, "192.0.2.9", true},
		{"ipv6 allowed", []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, "2001:db8::5", true},
		{"unknown source with a list", allow, "sim", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			hub := newAllowHub()
			srv := NewServer(Config{Key: []byte("allow-key"), Paths: 2, PingEvery: time.Second, AllowClients: c.allow}, hub)
			defer srv.Close()
			go func() { // a session that is admitted must be usable, not just present in the table
				for s := range srv.New {
					go func(s *Session) {
						for {
							st, err := s.Accept()
							if err != nil {
								return
							}
							go func() { io.Copy(st, st); st.CloseWrite() }()
						}
					}(s)
				}
			}()
			cli, err := NewSession(Config{Key: []byte("allow-key"), Paths: 2}, newAllowClientIO(hub, allowSrcAddr(c.src)))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			if c.want {
				deadline := time.Now().Add(5 * time.Second)
				for srv.Sessions() == 0 && time.Now().Before(deadline) {
					time.Sleep(2 * time.Millisecond)
				}
				if srv.Sessions() == 0 {
					t.Fatal("allowed client was not admitted")
				}
				echoOnce(t, cli, 20000, 1) // admitted: the tunnel carries data
			} else {
				time.Sleep(300 * time.Millisecond) // the client keeps retrying; nothing may be admitted
				if n := srv.Sessions(); n != 0 {
					t.Fatalf("a denied source was admitted (%d sessions)", n)
				}
			}
		})
	}
}

// L8 (audit 2026-11-04): the deny log has a server-wide token bucket (3 lines/s, burst 3), so a spoofed-source spray
// cannot fill journald; the suppressed count is reported with the next line that gets through.
func TestNoteDeniedGlobalThrottle(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	srv := NewServer(Config{Key: []byte("allow-key"),
		AllowClients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Logf: func(format string, a ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(format, a...))
			mu.Unlock()
		}}, newAllowHub())
	defer srv.Close()
	srv.denyEvery = 0 // every source is due immediately; only the global bucket limits the lines
	count := func() (int, string) {
		mu.Lock()
		defer mu.Unlock()
		if len(lines) == 0 {
			return 0, ""
		}
		return len(lines), lines[len(lines)-1]
	}
	for i := 0; i < 100; i++ { // 100 distinct sources in one instant: burst 3 lines
		srv.noteDenied(&net.IPAddr{IP: net.IPv4(198, 51, 100, byte(i))})
	}
	if got, _ := count(); got != int(clientDenyLogBurst) {
		t.Fatalf("%d log lines for a 100-source spray, want the burst cap %d", got, int(clientDenyLogBurst))
	}
	if srv.denySuppressed != 100-int(clientDenyLogBurst) {
		t.Fatalf("denySuppressed = %d, want %d", srv.denySuppressed, 100-int(clientDenyLogBurst))
	}
	srv.denyTokAt = srv.denyTokAt.Add(-time.Second) // one refill interval later
	srv.noteDenied(&net.IPAddr{IP: net.IPv4(203, 0, 113, 7)})
	n, last := count()
	if n != int(clientDenyLogBurst)+1 {
		t.Fatalf("%d log lines after the refill, want %d", n, int(clientDenyLogBurst)+1)
	}
	if !strings.Contains(last, "suppressed") || !strings.Contains(last, "97") {
		t.Fatalf("the throttled line does not report the suppressed drops: %q", last)
	}
	if srv.denySuppressed != 0 {
		t.Fatalf("denySuppressed = %d after reporting it, want 0", srv.denySuppressed)
	}
}
