package wat

import (
	"bytes"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDNSFrame(t *testing.T) {
	for i := 0; i < 3000; i++ {
		pay := make([]byte, 33+i%1400)
		rand.Read(pay)
		resp := i%2 == 1
		f := dnsFrame(nil, pay, resp)
		if over := len(f) - len(pay); over < 26 || over > dnsMaxFrame {
			t.Fatalf("frame overhead %d bytes", over)
		}
		wantFlags := uint16(dnsQuery)
		if resp {
			wantFlags = dnsAnswer
		}
		if uint16(f[2])<<8|uint16(f[3]) != wantFlags || f[4] != 0 || f[5] != 1 || !bytes.Equal(f[6:12], make([]byte, 6)) {
			t.Fatalf("header %x", f[:12])
		}
		if got := dnsStrip(f); !bytes.Equal(got, pay) {
			t.Fatalf("strip returned %d bytes, want %d", len(got), len(pay))
		}
	}
	ids := map[[2]byte]bool{}
	for i := 0; i < 200; i++ {
		f := dnsFrame(nil, make([]byte, 40), false)
		ids[[2]byte{f[0], f[1]}] = true
	}
	if len(ids) < 100 {
		t.Fatalf("only %d distinct ids in 200 frames", len(ids))
	}
	for _, bad := range [][]byte{nil, make([]byte, 5), make([]byte, 60), bytes.Repeat([]byte{0xff}, 80), append(append([]byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 200), make([]byte, 80)...)} {
		if dnsStrip(bad) != nil {
			t.Fatalf("%x... accepted as a DNS frame", bad[:min(len(bad), 8)])
		}
	}
}

// udpSpy relays datagrams between a client and target and keeps every first-12-bytes header it saw per direction.
type udpSpy struct {
	c        *net.UDPConn
	mu       sync.Mutex
	up, down [][]byte
}

func newUDPSpy(t *testing.T, target string) *udpSpy {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ta, _ := net.ResolveUDPAddr("udp", target)
	s := &udpSpy{c: c}
	go func() {
		var cli *net.UDPAddr
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			if from.Port == ta.Port {
				s.down = append(s.down, append([]byte(nil), buf[:n]...))
				s.mu.Unlock()
				if cli != nil {
					c.WriteToUDP(buf[:n], cli)
				}
				continue
			}
			cli = from
			s.up = append(s.up, append([]byte(nil), buf[:n]...))
			s.mu.Unlock()
			c.WriteToUDP(buf[:n], ta)
		}
	}()
	return s
}

func checkDNSFlow(t *testing.T, name string, pkts [][]byte, flags uint16) {
	t.Helper()
	if len(pkts) < 10 {
		t.Fatalf("%s: only %d datagrams", name, len(pkts))
	}
	for i, p := range pkts {
		if uint16(p[2])<<8|uint16(p[3]) != flags || p[4] != 0 || p[5] != 1 || dnsStrip(p) == nil {
			t.Fatalf("%s: datagram %d is not DNS-shaped: %x", name, i, p[:min(len(p), 24)])
		}
	}
}

func TestUDPDNS(t *testing.T) {
	key := []byte("dns-udp")
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	us.SetDNS(true)
	srv := NewServer(Config{Key: key}, us)
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
	spy := newUDPSpy(t, us.Addr().String())
	uc, err := NewUDPClient(spy.c.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	uc.SetDNS(true)
	cli, err := NewSession(Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	udpEcho(t, cli, 1<<20, 9)
	spy.mu.Lock()
	up, down := spy.up, spy.down
	spy.mu.Unlock()
	checkDNSFlow(t, "client to server", up, dnsQuery)
	checkDNSFlow(t, "server to client", down, dnsAnswer)
}

func TestUDPDNSReverse(t *testing.T) {
	key := []byte("dns-rev")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	lis.SetDNS(true)
	spy := newUDPSpy(t, lis.Addr().String())
	rs, err := NewUDPReverseServer("127.0.0.1:0", spy.c.LocalAddr().String(), key)
	if err != nil {
		t.Fatal(err)
	}
	rs.SetDNS(true)
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
	udpEcho(t, cli, 300000, 10)
	time.Sleep(100 * time.Millisecond)
	spy.mu.Lock()
	defer spy.mu.Unlock()
	// the spy sits between the Kharej punches and the Iran listener: everything Kharej sent (punches included) is DNS-shaped
	checkDNSFlow(t, "kharej side", spy.up, dnsAnswer)
	checkDNSFlow(t, "iran side", spy.down, dnsQuery)
}

// A DNS-shaped client against a plain server must not crash anything or get a session; it just never connects.
func TestUDPDNSMismatch(t *testing.T) {
	key := []byte("dns-mismatch")
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Key: key}, us)
	t.Cleanup(srv.Close)
	uc, err := NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	uc.SetDNS(true)
	cli, err := NewSession(Config{Key: key, PingEvery: 50 * time.Millisecond}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	time.Sleep(1500 * time.Millisecond)
	select {
	case <-srv.New:
		t.Fatal("a plain server accepted a DNS-framed client")
	default:
	}
}

// udp-dns-edns (3.3.8): queries carry an EDNS0 OPT, and the server replies are real answers that echo the query's
// id and question with the payload as TXT character-strings. A legacy reply still parses on the new strip side
// (audit 2026-11-18: the legacy server reply had ANCOUNT=0 and a fresh id/question, which a strict DNS parser rejects).
func TestDNSFrameEdns(t *testing.T) {
	for _, n := range []int{1, 200, 255, 256, 1400} {
		pay := make([]byte, n)
		rand.Read(pay)
		q := dnsFrameOpt(nil, pay, false, nil, true)
		if uint16(q[2])<<8|uint16(q[3]) != dnsQuery || q[4] != 0 || q[5] != 1 || q[10] != 0 || q[11] != 1 {
			t.Fatalf("query header %x", q[:12])
		}
		got, echo := dnsParse(q)
		if !bytes.Equal(got, pay) {
			t.Fatalf("query payload %d bytes, want %d", len(got), n)
		}
		if echo == nil {
			t.Fatal("query echo missing")
		}
		resp := dnsFrameOpt(nil, pay, true, echo, true)
		if uint16(resp[0])<<8|uint16(resp[1]) != echo.txid {
			t.Fatal("reply did not echo the txid")
		}
		if uint16(resp[6])<<8|uint16(resp[7]) != 1 || uint16(resp[10])<<8|uint16(resp[11]) != 1 {
			t.Fatalf("answer counts %x", resp[6:12])
		}
		if !bytes.Equal(resp[12:12+len(echo.quest)], echo.quest) {
			t.Fatal("reply did not echo the question")
		}
		if got := dnsStrip(resp); !bytes.Equal(got, pay) {
			t.Fatalf("answer strip %d bytes, want %d", len(got), n)
		}
		// mixed versions: a legacy reply parses on the new receiver, and a legacy query gets the legacy reply form
		if got := dnsStrip(dnsFrame(nil, pay, true)); !bytes.Equal(got, pay) {
			t.Fatal("legacy reply no longer parses")
		}
		_, legEcho := dnsParse(dnsFrame(nil, pay, false)) // legacy query (no OPT)
		respLeg := dnsFrameOpt(nil, pay, true, legEcho, true)
		if uint16(respLeg[6])<<8|uint16(respLeg[7]) != 0 || uint16(respLeg[10])<<8|uint16(respLeg[11]) != 0 {
			t.Fatal("a legacy query must get the legacy reply form")
		}
	}
}

// End to end with the flag on: the server's answers echo a query the client actually sent (id + question).
func TestUDPDNSEdnsEcho(t *testing.T) {
	key := []byte("dns-edns")
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	us.SetDNS(true)
	us.SetDNSEdns(true)
	srv := NewServer(Config{Key: key}, us)
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
	spy := newUDPSpy(t, us.Addr().String())
	uc, err := NewUDPClient(spy.c.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	uc.SetDNS(true)
	uc.SetDNSEdns(true)
	cli, err := NewSession(Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	udpEcho(t, cli, 1<<20, 11)
	spy.mu.Lock()
	up, down := spy.up, spy.down
	spy.mu.Unlock()
	if len(up) < 10 || len(down) < 10 {
		t.Fatalf("only %d up / %d down datagrams", len(up), len(down))
	}
	type qk struct {
		txid  uint16
		quest string
	}
	sent := map[qk]bool{}
	for _, p := range up {
		if p[10] != 0 || p[11] != 1 {
			t.Fatalf("client query without ARCOUNT=1: %x", p[:12])
		}
		_, q := dnsParse(p)
		if q == nil {
			t.Fatal("client query did not parse")
		}
		sent[qk{q.txid, string(q.quest)}] = true
	}
	for _, p := range down {
		if uint16(p[6])<<8|uint16(p[7]) != 1 {
			t.Fatalf("server answer without ANCOUNT=1: %x", p[:12])
		}
		_, q := dnsParse(p)
		if q == nil {
			t.Fatal("server answer did not parse")
		}
		if !sent[qk{q.txid, string(q.quest)}] {
			t.Fatal("server answer echoed a query the client never sent")
		}
	}
}
