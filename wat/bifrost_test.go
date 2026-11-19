package wat

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// R2 Bifrost (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md, disposition
// table). No production CLI, no :tx/:rx syntax, no wire change. This is the QUEUED prerequisite before Bifrost
// itself may be designed: "prove leg-specific liveness on a simulator: two sending legs, fail just one, keep the
// session healthy, stop assigning data to the failed leg and verify recovery. Session-wide ACKs alone cannot
// prove this."
//
// The subtle failure mode the test guards against: a bond whose health check only looks at SESSION-WIDE ack
// arrival would keep a dead leg "alive" forever, because the surviving leg's acks keep the session chatty. The
// assertion below therefore requires the dead leg's OWN counters to freeze (no new data assigned, its own
// witnesses go quiet) while the survivor's counters keep climbing on the same session.
//
// Reuses the bond rig's emulated links (bond_test.go): a link's blocked flag drops every packet in both
// directions, including those already in flight.

// TestBifrostLegLiveness: two sending legs under one bulk download; hard-fail leg 0 mid-transfer and require
// (a) the session delivers every byte intact (no reset), (b) leg 0 is declared dead despite leg 1's acks
// flowing session-wide, (c) after death, NO new data is assigned to leg 0 (its Sent freezes) while leg 1's Sent
// climbs, and (d) after healing, leg 0 carries traffic again.
func TestBifrostLegLiveness(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	const n = 48 << 20
	done := make(chan error, 1)
	var got int
	go func() {
		g, _, err := bondDownload(rig.cli, n)
		got = g
		done <- err
	}()
	time.Sleep(1500 * time.Millisecond) // both legs warm and carrying

	cs := rig.cli.CarrierStats()
	if len(cs) != 2 || !cs[0].Alive || !cs[1].Alive {
		t.Fatalf("precondition: 2 live carriers expected, got %+v", cs)
	}
	links[0].blocked.Store(true)

	// (b) death declared while the session-wide acks keep flowing on leg 1
	deadline := time.Now().Add(5 * time.Second)
	for rig.cli.CarrierStats()[0].Alive && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rig.cli.CarrierStats()[0].Alive {
		t.Fatal("leg 0 never declared dead although its own acks stopped (session-wide acks from leg 1 must not mask it)")
	}
	sent0AtDeath := rig.cli.CarrierStats()[0].Sent
	sent1AtDeath := rig.cli.CarrierStats()[1].Sent

	// (c) over the next second of transfer: leg 0's Sent freezes (in-flight tail only), leg 1 carries everything.
	// Sent counts PACKETS (pathSet.onSend): a 6 Mbps leg with the rig's 700 B cap is ~1000 packets/s at line rate.
	time.Sleep(1 * time.Second)
	mid := rig.cli.CarrierStats()
	if mid[0].Alive {
		t.Fatal("leg 0 resurrected without its link healing")
	}
	if grew := mid[0].Sent - sent0AtDeath; grew > 50 {
		// a small tail is legitimate (packets assigned while the leg was still suspect); a steady stream is not
		t.Fatalf("leg 0 kept receiving data after death: Sent grew %d packets", grew)
	}
	if mid[1].Sent <= sent1AtDeath+200 {
		t.Fatalf("leg 1 did not take over the traffic: Sent %d -> %d packets in 1 s", sent1AtDeath, mid[1].Sent)
	}

	// (a) the transfer is still running; unblock leg 0 NOW so it can carry again (a completed transfer has no
	// traffic to assign, which is why this check happens mid-download)
	sent0BeforeHeal := rig.srv.CarrierStats()[0].Sent
	links[0].blocked.Store(false)
	t1 := time.Now()
	healed := atomic.Bool{}
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ss := rig.srv.CarrierStats()
		// The SERVER's assignment is what must resume (it owns the download direction). The client's ACK packets
		// legitimately concentrate on leg 1 after healing: the interactive chooser spreads acks only within 25%+5ms
		// of the best score, and the revived leg's probe-measured SRTT (with probe scheduling inflation) sits above
		// that window until real traffic re-measures it.
		if ss[0].Alive && ss[0].Sent > sent0BeforeHeal+200 { // >200 packets assigned to the healed leg
			healed.Store(true)
			t.Logf("leg 0 healed and carrying after %v (server Sent %d -> %d, share %.2f)",
				time.Since(t1).Round(time.Millisecond), sent0BeforeHeal, ss[0].Sent, ss[0].Share)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healed.Load() {
		t.Fatalf("leg 0 never carried bulk again after healing: srv %+v cli %+v",
			rig.srv.CarrierStats()[0], rig.cli.CarrierStats()[0])
	}

	// (a) and the session rides both legs to the end, bytes intact
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed: %v (got %d of %d)", err, got, n)
		}
		if got != n {
			t.Fatalf("short download: %d of %d", got, n)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("download timed out")
	}
}

// ---- production shape (3.3.9): directional bond legs (:up/:down) + frEndpoint 0x0e ----
//
// The R2 experiment above proved leg-specific liveness; the design review approved the production shape:
// ":up"/":down" suffixes on bond leg names (absolute direction, mirrored configs), a dir lock in pathState, and
// the frEndpoint frame (a ":down" client leg never sends, so it announces its bound receive port; the server
// binds that port to the packet's AUTHENTICATED source address — no IP ever crosses the wire). Both features are
// opt-in and name-driven: no suffix anywhere means every check below passes and behaviour is exactly as before.

// TestBifrostLegDirectionParsing: suffix parsing and every config-refusal rule the validation enforces
// (cmd/wattun prints the reason and exits 2). The base name must survive the split for the carrier-table checks.
func TestBifrostLegDirectionParsing(t *testing.T) {
	if b, d := LegDirection("udp:down"); b != "udp" || d != DirDown {
		t.Fatalf(`LegDirection("udp:down") = %q/%d, want udp/DirDown`, b, d)
	}
	if b, d := LegDirection("icmp:up"); b != "icmp" || d != DirUp {
		t.Fatalf(`LegDirection("icmp:up") = %q/%d, want icmp/DirUp`, b, d)
	}
	if b, d := LegDirection("icmp"); b != "icmp" || d != DirBoth {
		t.Fatalf(`LegDirection("icmp") = %q/%d, want icmp/DirBoth`, b, d)
	}
	if b, d := LegDirection("ws:weird"); b != "ws:weird" || d != DirBoth {
		t.Fatalf(`LegDirection("ws:weird") = %q/%d, want the whole name/DirBoth (the split never invents a carrier)`, b, d)
	}

	refuse := func(legs []string, why string) {
		t.Helper()
		if r := ValidateBondLegs(legs); r == "" {
			t.Fatalf("%s: validation accepted %v", why, legs)
		}
	}
	accept := func(legs []string) {
		t.Helper()
		if r := ValidateBondLegs(legs); r != "" {
			t.Fatalf("validation refused a legal bond %v: %s", legs, r)
		}
	}
	refuse([]string{"udp:down"}, "a single carrier cannot be directional")
	refuse([]string{"icmp:down", "tcp:down"}, ":down is udp-only in this release (frEndpoint signaling)")
	refuse([]string{"icmp", "tcp:down"}, ":down is udp-only in this release (frEndpoint signaling)")
	refuse([]string{"udp:down", "udp:down"}, "every leg :down leaves no uplink")
	refuse([]string{"icmp:up", "udp:up"}, "every leg :up leaves no downlink")
	accept([]string{"icmp", "udp"})
	accept([]string{"icmp:up", "udp:down"})
	accept([]string{"icmp:up", "udp"})

	// the dir lock is derived from the SAME names at both ends, each applying its own side's meaning
	cli := newPathSet([]string{"link0:up", "link1:down"}, true, PathTimings{}, false)
	srv := newPathSet([]string{"link0:up", "link1:down"}, true, PathTimings{}, true)
	if cli.p[0].dir != DirUp || cli.p[1].dir != DirDown || srv.p[0].dir != DirUp || srv.p[1].dir != DirDown {
		t.Fatalf("dir not derived from the leg names: cli %d/%d srv %d/%d", cli.p[0].dir, cli.p[1].dir, srv.p[0].dir, srv.p[1].dir)
	}
	if !cli.canSend(0) || cli.canSend(1) {
		t.Fatal("client: the :up leg must be sendable and the :down leg receive-only")
	}
	if srv.canSend(0) || !srv.canSend(1) {
		t.Fatal("server: the :up leg must be receive-only and the :down leg sendable")
	}
	// the chooser never targets a receive-only leg, even in the nothing-healthy passes
	for i := 0; i < 100; i++ {
		if p := cli.choose(0, false); p == 1 {
			t.Fatal("client choose() sent to the :down leg")
		}
		if p := srv.choose(0, false); p == 0 {
			t.Fatal("server choose() replied on the :up leg")
		}
		if p := cli.nextPath(false); p == 1 {
			t.Fatal("client nextPath() picked the :down leg")
		}
		if p := srv.nextPath(false); p == 0 {
			t.Fatal("server nextPath() picked the :up leg")
		}
	}
	// and a leg whose direction forbids sending here is never marked suspect/dead for its silence
	cli.mu.Lock()
	cli.p[1].firstUnacked = time.Now().Add(-time.Hour) // would be dead at once without the direction skip
	cli.p[1].lastAck = time.Now().Add(-2 * time.Hour)
	cli.p[0].firstUnacked = time.Now().Add(-time.Hour)
	cli.p[0].lastAck = time.Now().Add(-time.Minute) // witness: leg 0's acks are newer
	cli.eval(time.Now())
	d := cli.p[1].state
	cli.mu.Unlock()
	if d != pLive {
		t.Fatalf("receive-only client leg was evaluated to state %d (want pLive: its silence proves nothing)", d)
	}
}

// bifrostRig is the bond rig with directional leg names and frEndpoint-capable kids.
func bifrostRig(t *testing.T, links []*bondLink, names []string) *bondRig {
	t.Helper()
	key := []byte("bond-key")
	raws := make([]RawIO, len(links))
	for i, l := range links {
		raws[i] = &linkRaw{l: l, done: make(chan struct{})}
	}
	srv := NewServer(Config{Key: key, Bond: fastTimings}, NewMultiRaw(names, raws))
	srv.IdleTimeout = 20 * time.Second
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
	t.Cleanup(srv.Close)
	kids := make([]PacketIO, len(links))
	for i, l := range links {
		kids[i] = &linkClient{l: l, done: make(chan struct{}), port: 20000 + i}
	}
	b, err := NewBondIO(kids, BondOptions{Names: names, Timings: fastTimings})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key}, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	return &bondRig{links: links, srv: srv, key: key, cli: cli}
}

// TestBifrostDirectionalBond: link0:up carries the client's uplink only, link1:down the server's downlink only —
// one mirrored suffix pair, both ends deriving their own meaning from the same names. The ":down" leg's client
// socket never sends, so the client announces its bound port with frEndpoint and the server pushes the download
// down it; the server never replies on the ":up" leg. Requirements: the transfer completes byte-intact, the
// client's Sent on the :down leg stays exactly 0, the server's Sent on the :up leg stays exactly 0.
func TestBifrostDirectionalBond(t *testing.T) {
	links := twoLinks(t)
	rig := bifrostRig(t, links, []string{"link0:up", "link1:down"})
	const n = 24 << 20
	done := make(chan error, 1)
	var got int
	go func() {
		g, _, err := bondDownload(rig.cli, n)
		got = g
		done <- err
	}()
	// wait until both allowed directions are carrying (uplink acked on leg 0, downlink acked on leg 1)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		cs, ss := rig.cli.CarrierStats(), rig.srv.CarrierStats()
		if cs[0].Acked > 100 && ss[1].Acked > 100 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cs := rig.cli.CarrierStats()
	ss := rig.srv.CarrierStats()
	t.Logf("client %+v server %+v", cs, ss)
	if cs[1].Sent != 0 {
		t.Errorf("client sent %d packets on its :down leg (receive-only)", cs[1].Sent)
	}
	if ss[0].Sent != 0 {
		t.Errorf("server replied %d packets on the :up leg (receive-only for the server)", ss[0].Sent)
	}
	if cs[0].Sent == 0 || cs[0].Acked == 0 {
		t.Errorf("uplink did not ride the :up leg: %+v", cs[0])
	}
	if ss[1].Sent == 0 || ss[1].Acked == 0 {
		t.Errorf("downlink did not ride the :down leg (frEndpoint announce failed?): %+v", ss[1])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download failed: %v (got %d of %d)", err, got, n)
		}
		if got != n {
			t.Fatalf("short download: %d of %d", got, n)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("download timed out")
	}
}

// epFakeIO is a single-leg PacketIO for the frEndpoint round-trip: one ":down" leg with a bound local port.
type epFakeIO struct {
	done chan struct{}
	once sync.Once
}

func (f *epFakeIO) Send([]byte, int) error { return nil }
func (f *epFakeIO) Recv() ([]byte, int, net.Addr, error) {
	<-f.done
	return nil, 0, nil, net.ErrClosed
}
func (f *epFakeIO) SetPeer(net.Addr) {}
func (f *epFakeIO) Close() error     { f.once.Do(func() { close(f.done) }); return nil }
func (f *epFakeIO) PathDirs() []uint8 {
	return []uint8{DirDown} // the whole bond is one ":down" leg
}
func (f *epFakeIO) PathLocalPort(int) int { return 5501 }

// epSrvIO records what the server session hands to PathEndpointSignaler.
type epSrvIO struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	legs []int
	ps   []int
	srcs []net.Addr
}

func (s *epSrvIO) Send([]byte, int) error { return nil }
func (s *epSrvIO) Recv() ([]byte, int, net.Addr, error) {
	<-s.done
	return nil, 0, nil, net.ErrClosed
}
func (s *epSrvIO) SetPeer(net.Addr) {}
func (s *epSrvIO) Close() error     { s.once.Do(func() { close(s.done) }); return nil }
func (s *epSrvIO) SetPathEndpoint(legIdx, port int, src net.Addr) {
	s.mu.Lock()
	s.legs, s.ps, s.srcs = append(s.legs, legIdx), append(s.ps, port), append(s.srcs, src)
	s.mu.Unlock()
}
func (s *epSrvIO) record() (leg, port int, src net.Addr, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.legs) > 0 {
		return s.legs[0], s.ps[0], s.srcs[0], len(s.legs)
	}
	return -1, -1, nil, 0
}

// TestBifrostEndpointRoundTrip: the client session emits frEndpoint as the LAST frame of an uplink packet (leg
// index + announced port, nothing else — no IP on the wire), and the server session's parse hands the frame to
// PathEndpointSignaler with the AUTHENTICATED packet source address. Extra bytes after the port (a hostile
// sender's) are never read: the frame carries no address to forge.
func TestBifrostEndpointRoundTrip(t *testing.T) {
	key := []byte("ep-key")
	cfg := Config{Key: key, SID: 0x99, NoKex: true, NoMask: true, NoShape: true} // deterministic: no kex offer, no padding

	cli, err := NewSession(cfg, &epFakeIO{done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if len(cli.epLegs) != 1 || cli.epLegs[0] != 0 {
		t.Fatalf("client epLegs = %v, want [0] (the :down leg)", cli.epLegs)
	}
	cli.mu.Lock()
	cli.wantPing = true
	o, ok := cli.build(time.Now())
	cli.mu.Unlock()
	if !ok {
		t.Fatal("build emitted nothing")
	}
	plain := o.p[hdrLen:]
	want := []byte{frPing, frEndpoint, 0, 5501 >> 8, 5501 & 0xff}
	if !bytes.Equal(plain, want) {
		t.Fatalf("client uplink frames = %v, want ping + frEndpoint(leg 0, port 5501) and NOTHING else (no IP on the wire)", plain)
	}
	cli.sealOut(&o) // seal with the session key, as the send loop would

	srv, err := NewSession(Config{Key: key, SID: 0x99, Server: true, NoKex: true, NoMask: true, NoShape: true}, &epSrvIO{done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	sio := srv.io.(*epSrvIO)
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4242}
	srv.handle(o.p, 0, src)
	leg, port, gotSrc, n := sio.record()
	if n != 1 || leg != 0 || port != 5501 {
		t.Fatalf("SetPathEndpoint calls=%d leg=%d port=%d, want 1 call with leg 0 port 5501", n, leg, port)
	}
	if ua, ok := gotSrc.(*net.UDPAddr); !ok || !ua.IP.Equal(net.ParseIP("198.51.100.7")) || ua.Port != 4242 {
		t.Fatalf("SetPathEndpoint src = %v, want the packet's authenticated source address", gotSrc)
	}

	// a hostile frame cannot point the downlink anywhere else: bytes appended after the announced port (here a
	// fake 4-byte address) are never parsed — frEndpoint is the last frame and only 1+1+2 bytes of it are read
	junk := append(append([]byte(nil), want...), 9, 6, 7, 7)
	cli.mu.Lock()
	hp, _ := cli.seal(junk)
	cli.mu.Unlock()
	srv.handle(hp, 0, src)
	if _, _, _, n2 := sio.record(); n2 != 2 {
		t.Fatalf("the hostile variant was not parsed (%d calls)", n2)
	}
	sio.mu.Lock()
	leg2, port2 := sio.legs[1], sio.ps[1]
	sio.mu.Unlock()
	if leg2 != 0 || port2 != 5501 {
		t.Fatalf("hostile frame changed the endpoint: leg=%d port=%d (the junk after the port must be ignored)", leg2, port2)
	}
}
