package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// echoUDP is a UDP echo service on 127.0.0.1.
func echoUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, a, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(buf[:n], a)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// udpRig: wattun server + client over the wat udp carrier on loopback.
type udpRig struct {
	dc *dgramClient
}

func newUDPRig(t *testing.T, al *allow, idle time.Duration) *udpRig {
	t.Helper()
	key := []byte("udp-test-key")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key}, us)
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go serveDgrams(s, 1, 65535, al, idle)
		}
	}()
	uc, err := wat.NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := wat.NewSession(wat.Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	return &udpRig{dc: newDgramClient(newTunnel([]*wat.Session{sess}), idle)}
}

func allowUDP(ports ...int) *allow {
	al := newAllow("", "")
	al.setPorts(nil)
	al.setUDPPorts(ports)
	return al
}

// sender sends n tagged datagrams (one per 300 us) to addr and returns how many distinct replies came back.
func sender(t *testing.T, addr net.Addr, tag byte, n int) (got int, wrong int) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()
	seen := make([]bool, n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			m, err := c.Read(buf)
			if err != nil {
				return
			}
			var seq int
			var tg byte
			if m < 6 {
				wrong++
				continue
			}
			tg = buf[0]
			fmt.Sscanf(string(buf[1:m]), "%d", &seq)
			if tg != tag || seq < 0 || seq >= n {
				wrong++
				continue
			}
			if !seen[seq] {
				seen[seq] = true
				got++
			}
			if got == n {
				return
			}
			c.SetReadDeadline(time.Now().Add(1 * time.Second))
		}
	}()
	for i := 0; i < n; i++ {
		c.Write([]byte(fmt.Sprintf("%c%05d-%0100d", tag, i, i)))
		time.Sleep(300 * time.Microsecond)
	}
	<-done
	return
}

func TestUDPEndToEnd(t *testing.T) {
	port := echoUDP(t)
	r := newUDPRig(t, allowUDP(port), time.Minute)
	l, err := r.dc.listen("127.0.0.1:0", port)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	got, wrong := sender(t, l.Addr(), 'A', 1000)
	t.Logf("1000 datagrams: %d replies in %v (wrong=%d)", got, time.Since(t0).Round(time.Millisecond), wrong)
	if got < 950 || wrong != 0 {
		t.Fatalf("got %d of 1000, wrong %d", got, wrong)
	}
}

func TestUDPTwoSendersGetTheirOwnReplies(t *testing.T) {
	port := echoUDP(t)
	r := newUDPRig(t, allowUDP(port), time.Minute)
	l, err := r.dc.listen("127.0.0.1:0", port)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for _, tag := range []byte{'X', 'Y'} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, wrong := sender(t, l.Addr(), tag, 400)
			if got < 380 || wrong != 0 {
				t.Errorf("sender %c: got %d of 400, wrong %d", tag, got, wrong)
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	r.dc.mu.Lock()
	n := len(r.dc.byID)
	r.dc.mu.Unlock()
	if n != 2 {
		t.Errorf("want 2 flows, have %d", n)
	}
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !f() {
		if time.Now().After(end) {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUDPIdleFlowCleanup(t *testing.T) {
	port := echoUDP(t)
	r := newUDPRig(t, allowUDP(port), 400*time.Millisecond)
	l, err := r.dc.listen("127.0.0.1:0", port)
	if err != nil {
		t.Fatal(err)
	}
	// Count this rig's own flows: udpFlowsActive is package-wide, and an earlier test's flows may expire meanwhile.
	flows := func() (int, int) {
		l.mu.Lock()
		c := len(l.flows)
		l.mu.Unlock()
		r.dc.mu.Lock()
		s := len(r.dc.byID)
		r.dc.mu.Unlock()
		return c, s
	}
	if got, _ := sender(t, l.Addr(), 'Z', 5); got != 5 {
		t.Fatalf("got %d of 5", got)
	}
	if c, s := flows(); c != 1 || s != 1 { // one client flow + one server flow
		t.Fatalf("flows client %d server %d, want 1 and 1", c, s)
	}
	waitFor(t, "idle flows closed", 5*time.Second, func() bool { c, s := flows(); return c == 0 && s == 0 })
	l.mu.Lock()
	n := len(l.flows)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("listener still tracks %d flows", n)
	}
}

func TestUDPAllowlistRejectsUnlistedPort(t *testing.T) {
	okPort, badPort := echoUDP(t), echoUDP(t)
	r := newUDPRig(t, allowUDP(okPort), time.Minute)
	good, err := r.dc.listen("127.0.0.1:0", okPort)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := r.dc.listen("127.0.0.1:0", badPort)
	if err != nil {
		t.Fatal(err)
	}
	before := udpRejected.Load()
	if got, _ := sender(t, bad.Addr(), 'B', 20); got != 0 {
		t.Fatalf("unlisted udp port answered %d times", got)
	}
	if udpRejected.Load() == before {
		t.Fatal("rejection not counted")
	}
	if got, _ := sender(t, good.Addr(), 'G', 20); got < 18 {
		t.Fatalf("listed port got only %d of 20", got)
	}
}

func TestUDPAllowParsing(t *testing.T) {
	a := newAllow("100,200/udp,300/tcp", "")
	if !a.ok(100, 1, 9) || a.ok(200, 1, 9) || !a.udpOK(200, 1, 9) || a.udpOK(100, 1, 9) {
		t.Fatal("tcp/udp lists must be separate")
	}
	if b := newAllow("", ""); !b.udpOK(500, 1, 1000) || b.udpOK(5000, 1, 1000) {
		t.Fatal("no list: the -allow-min/max range applies")
	}
	if _, _, err := parseUDPMap("0", "0.0.0.0", 0); err == nil {
		t.Fatal("port 0 accepted")
	}
	if addr, tgt, err := parseUDPMap("51820:51821@127.0.0.1", "0.0.0.0", 10); err != nil || addr != "127.0.0.1:51830" || tgt != 51821 {
		t.Fatalf("parseUDPMap: %q %d %v", addr, tgt, err)
	}
	if addr, tgt, err := parseUDPMap("51820:51821@[::1]", "0.0.0.0", 0); err != nil || addr != "[::1]:51820" || tgt != 51821 {
		t.Fatalf("parseUDPMap bracketed v6 @bind: %q %d %v", addr, tgt, err)
	}
	if addr, tgt, err := parseUDPMap("51820", "[::1]", 0); err != nil || addr != "[::1]:51820" || tgt != 51820 {
		t.Fatalf("parseUDPMap bracketed defBind: %q %d %v", addr, tgt, err)
	}
	for _, bad := range []struct {
		m   string
		off int
	}{
		{"65000", 1000},
		{"100", -200},
	} {
		if addr, _, err := parseUDPMap(bad.m, "0.0.0.0", bad.off); err == nil {
			t.Errorf("parseUDPMap(%q, %d) = %q, want overflow error", bad.m, bad.off, addr)
		}
	}
}

func TestUDPListenersApplyAddsAndRemoves(t *testing.T) {
	port := echoUDP(t)
	r := newUDPRig(t, allowUDP(port), time.Minute)
	var addr net.Addr
	ul := newUDPListeners(func(p, _ int) (*udpListener, error) {
		l, err := r.dc.listen("127.0.0.1:0", p)
		if err == nil {
			addr = l.Addr()
		}
		return l, err
	})
	if errs := ul.apply(plainMaps([]int{port})); len(errs) > 0 || !ul.has(port) {
		t.Fatalf("apply add: %v", errs)
	}
	if got, _ := sender(t, addr, 'H', 10); got != 10 {
		t.Fatalf("got %d of 10", got)
	}
	ul.apply(nil)
	if ul.has(port) {
		t.Fatal("listener not removed")
	}
	c, _ := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	defer c.Close()
	c.Write([]byte("x"))
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("closed listener still answers")
	}
}
