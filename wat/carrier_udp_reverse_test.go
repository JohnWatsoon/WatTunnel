package wat

import (
	"net"
	"testing"
	"time"
)

func TestPunchRoundTrip(t *testing.T) {
	k := punchKey([]byte("k"))
	p := makePunch(k)
	if !isPunch(k, p) {
		t.Fatal("a fresh punch does not verify")
	}
	if isPunch(punchKey([]byte("other")), p) {
		t.Fatal("a punch verifies under another key")
	}
	p[3] ^= 1
	if isPunch(k, p) {
		t.Fatal("a tampered punch verifies")
	}
	if isPunch(k, make([]byte, 40)) {
		t.Fatal("zeros verify as a punch")
	}
}

// The client binds and never sends first; once the server's punches arrive, the whole tunnel works.
func TestUDPReverse(t *testing.T) {
	key := []byte("rev-udp")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewUDPReverseServer("127.0.0.1:0", lis.Addr().String(), key)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Key: key}, rs)
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go serveUDPStream(st)
				}
			}(s)
		}
	}()
	cli, err := NewSession(Config{Key: key}, lis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	udpEcho(t, cli, 500000, 8)
}

// Before a punch the client sends nothing anywhere; after a valid punch it answers to the punch's source.
func TestUDPReverseClientWaitsForPunch(t *testing.T) {
	key := []byte("rev-udp2")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key, PingEvery: 50 * time.Millisecond}, lis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2048)
	f.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := f.ReadFromUDP(buf); err == nil {
		t.Fatal("client sent a datagram before any punch")
	}
	la := lis.Addr().(*net.UDPAddr)
	f.WriteToUDP(append([]byte("junk"), make([]byte, 40)...), la) // not a punch: must not make the client send
	f.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := f.ReadFromUDP(buf); err == nil {
		t.Fatal("client answered a datagram that is not a punch")
	}
	f.WriteToUDP(makePunch(punchKey(key)), la)
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := f.ReadFromUDP(buf); err != nil {
		t.Fatalf("client did not answer a valid punch: %v", err)
	}
}

// SendBatch reaches the punching server, framed or not (3.0.0: the reverse upload batches like the forward client).
func TestUDPReverseSendBatch(t *testing.T) {
	for _, dns := range []bool{false, true} {
		key := []byte("rev-udp3")
		lis, err := NewUDPReverseListener("127.0.0.1:0", key)
		if err != nil {
			t.Fatal(err)
		}
		lis.SetDNS(dns)
		f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		pk := makePunch(punchKey(key))
		if dns {
			pk = dnsFrame(nil, pk, true)
		}
		f.WriteToUDP(pk, lis.Addr().(*net.UDPAddr))
		go lis.Recv() // takes the punch, then waits
		deadline := time.Now().Add(2 * time.Second)
		for lis.peer.Load() == nil && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if err := lis.SendBatch([][]byte{[]byte("one-0123456789-0123456789-0123456789"), []byte("two-0123456789-0123456789-0123456789")}, []int{0, 0}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		for _, want := range []string{"one", "two"} {
			f.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := f.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("dns=%v: %v", dns, err)
			}
			p := buf[:n]
			if dns {
				if p = dnsStrip(p); p == nil {
					t.Fatalf("dns=%v: not a DNS-framed datagram", dns)
				}
			}
			if string(p[:3]) != want {
				t.Fatalf("dns=%v: got %q, want %s...", dns, p[:3], want)
			}
		}
		lis.Close()
		f.Close()
	}
}

// The reverse server stops punching while the client talks and resumes once it goes quiet (3.0.0).
func TestUDPReversePunchQuiet(t *testing.T) {
	key := []byte("rev-udp4")
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := NewUDPReverseServer("127.0.0.1:0", f.LocalAddr().String(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	go func() {
		for {
			if _, _, _, err := rs.Recv(); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 2048)
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := f.ReadFromUDP(buf); err != nil {
		t.Fatalf("no first punch: %v", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() { // the client talks every 100 ms
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				f.WriteToUDP([]byte("client traffic"), rs.Addr().(*net.UDPAddr))
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := f.ReadFromUDP(buf); err == nil {
		t.Fatal("the server punched while the client was talking")
	}
}

// 3.3.8 audit: replayed punches and punches from non-peer addresses while the current peer is actively
// authenticated must not hijack UDPReverseListener.peer.
func TestUDPReversePunchReplayGuard(t *testing.T) {
	key := []byte("rev-replay")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			if _, _, _, err := lis.Recv(); err != nil {
				return
			}
		}
	}()

	realSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer realSrv.Close()
	attacker, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()

	la := lis.Addr().(*net.UDPAddr)
	pk := makePunch(punchKey(key))
	if _, err := realSrv.WriteToUDP(pk, la); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for lis.peer.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cur := lis.peer.Load(); cur == nil || cur.Port != realSrv.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("expected peer=%v, got %v", realSrv.LocalAddr(), cur)
	}

	// Exact replay from attacker must be rejected even before authAt.
	if _, err := attacker.WriteToUDP(pk, la); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if cur := lis.peer.Load(); cur.Port != realSrv.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("replayed punch hijacked peer to %v", cur)
	}

	// Fresh punch while realSrv is actively authenticated must also be ignored.
	lis.PeerAuthenticated(realSrv.LocalAddr())
	if _, err := attacker.WriteToUDP(makePunch(punchKey(key)), la); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if cur := lis.peer.Load(); cur.Port != realSrv.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("hijacked active authenticated peer to %v", cur)
	}
}
