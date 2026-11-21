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

// With -repair, frRepairCap and frEndpoint never share a packet: a 3.3.9-3.4.2 server stops parsing at the cap
// and would never learn the ":down" leg's port (review of 3.4.3).
func TestRepairCapNeverHidesEndpoint(t *testing.T) {
	cli, err := NewSession(Config{Key: []byte("ep-key"), SID: 0x9a, NoKex: true, NoMask: true, NoShape: true, Repair: true},
		&epFakeIO{done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	now := time.Now()
	var got [][]byte
	cli.mu.Lock()
	for i := 0; i < 2; i++ {
		cli.wantPing = true
		o, ok := cli.build(now)
		if !ok {
			cli.mu.Unlock()
			t.Fatal("build emitted nothing")
		}
		got = append(got, append([]byte(nil), o.p[hdrLen:]...))
	}
	cli.mu.Unlock()
	if want := []byte{frPing, frRepairCap, 1}; !bytes.Equal(got[0], want) {
		t.Fatalf("first packet = %v, want ping + cap and no endpoint", got[0])
	}
	if want := []byte{frPing, frEndpoint, 0, 5501 >> 8, 5501 & 0xff}; !bytes.Equal(got[1], want) {
		t.Fatalf("second packet = %v, want ping + endpoint", got[1])
	}
}

// ---- Bifrost NAT knock (found live 2026-11-19, Kharej box) ----
//
// A client behind NAT whose bond has a receive-only ":down" leg never sends from that leg's socket, so the NAT
// holds no mapping for it and the server's downlink to the leg is dropped at the NAT. The fix: the client
// periodically sends ONE small authenticated packet (a probe PING, no new wire format) from the ":down" leg's own
// socket, refreshing the mapping; its arrival on the server populates the leg's destination through the same
// authenticated-source path as any packet. The tests below prove the failure and the fix against a stateful NAT
// model: downlink passes only within `timeout` of an outbound packet from the same socket.

// statefulNAT models an endpoint-mapping NAT with a UDP timeout: a downlink datagram is delivered only if an
// uplink datagram left the same socket within the timeout (mapping created or refreshed by outbound traffic
// alone, the conservative case — control rig proves real deployments where inbound never refreshes).
type statefulNAT struct {
	lastOut atomic.Int64 // unix ns of the last client→server packet through the NAT
	timeout time.Duration
}

func (n *statefulNAT) allows(now time.Time) bool {
	last := n.lastOut.Load()
	return last != 0 && now.UnixNano()-last <= int64(n.timeout)
}

// natClient wraps a leg's linkClient behind the stateful NAT: outbound traffic refreshes the mapping, inbound
// traffic is dropped unless a mapping is live.
type natClient struct {
	*linkClient
	nat *statefulNAT
}

func (c *natClient) Send(p []byte, path int) error {
	c.nat.lastOut.Store(time.Now().UnixNano())
	return c.linkClient.Send(p, path)
}

func (c *natClient) Recv() ([]byte, int, net.Addr, error) {
	for {
		p, i, a, err := c.linkClient.Recv()
		if err != nil || c.nat.allows(time.Now()) {
			return p, i, a, err
		}
		// no mapping: the NAT silently drops the downlink datagram
	}
}

// natRig is bifrostRig with leg 1's client socket behind a stateful NAT and a tunable knock cadence.
func natRig(t *testing.T, links []*bondLink, tm PathTimings, timeout time.Duration) (*bondRig, *statefulNAT) {
	t.Helper()
	key := []byte("bond-key")
	names := []string{"link0:up", "link1:down"}
	raws := []RawIO{&linkRaw{l: links[0], done: make(chan struct{})}, &linkRaw{l: links[1], done: make(chan struct{})}}
	srv := NewServer(Config{Key: key, Bond: tm}, NewMultiRaw(names, raws))
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
	nat := &statefulNAT{timeout: timeout}
	kids := []PacketIO{
		&linkClient{l: links[0], done: make(chan struct{}), port: 20000},
		&natClient{linkClient: &linkClient{l: links[1], done: make(chan struct{}), port: 20001}, nat: nat},
	}
	b, err := NewBondIO(kids, BondOptions{Names: names, Timings: tm})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key}, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	return &bondRig{links: links, srv: srv, key: key, cli: cli}, nat
}

// TestBifrostNATKnock: (1) without knocks the downlink on the ":down" leg is dropped at the NAT while the server
// keeps sending (the live Kharej failure), (2) with knocks the transfer completes byte-intact, (3) the knock
// cadence is jittered and bounded, (4) knocks bypass the data scheduler: the client's Sent on the ":down" leg
// stays 0 and the knock count is observable in CarrierStats.
func TestBifrostNATKnock(t *testing.T) {
	// (3) the scheduling function directly: default base 25 s → every gap inside [25,35) s, and jittered (not a
	// fixed value, not out of bounds)
	lo, hi := 25*time.Second, 35*time.Second
	distinct := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		g := knockGap(lo)
		if g < lo || g >= hi {
			t.Fatalf("knockGap out of bounds: %v (want [%v,%v))", g, lo, hi)
		}
		distinct[g] = true
	}
	if len(distinct) < 20 {
		t.Fatalf("knockGap not jittered: %d distinct values in 200 draws", len(distinct))
	}

	// (1) control: knocks deferred beyond the test window (DownKnock 1 h) — the NAT (700 ms timeout) drops the
	// downlink although the server keeps sending on the ":down" leg
	links := twoLinks(t)
	rig, _ := natRig(t, links, PathTimings{Silence: 300 * time.Millisecond, ProbeFirst: 200 * time.Millisecond,
		ProbeMax: time.Second, Ramp: 500 * time.Millisecond, IdleProbe: time.Second, DownKnock: time.Hour}, 700*time.Millisecond)
	var got atomic.Int64
	go func() {
		g, _, _ := bondDownload(rig.cli, 1<<20)
		got.Store(int64(g))
	}()
	time.Sleep(1500 * time.Millisecond)
	if got.Load() != 0 {
		t.Fatalf("downlink crossed the NAT without any knock: %d bytes delivered", got.Load())
	}
	if ss := rig.srv.CarrierStats(); ss[1].Sent == 0 {
		t.Fatal("control precondition failed: the server never tried the :down leg")
	}
	rig.cli.Close()
	rig.srv.Close()

	// (2)+(4) the fix: knocks every 250-350 ms keep the mapping alive and the download completes byte-intact
	links = twoLinks(t)
	tm := PathTimings{Silence: 300 * time.Millisecond, ProbeFirst: 200 * time.Millisecond, ProbeMax: time.Second,
		Ramp: 500 * time.Millisecond, IdleProbe: time.Second, DownKnock: 250 * time.Millisecond}
	rig, _ = natRig(t, links, tm, 700*time.Millisecond)
	const n = 4 << 20
	done := make(chan error, 1)
	var received int
	go func() {
		g, _, err := bondDownload(rig.cli, n)
		received = g
		done <- err
	}()
	// defect 1 (2026-11-20 review): knocks must continue while downlink FLOWS — a NAT mapping is refreshed by
	// outbound traffic only, so the old lastRecv-based skip suppressed knocks mid-flow and let the mapping
	// lapse, blacking out the leg in cycles (retransmit hid the stalls and this test still passed). The counter
	// must advance inside any 400 ms window of the flow (the cadence gap tops out at 350 ms).
	time.Sleep(400 * time.Millisecond)
	k0 := rig.cli.CarrierStats()[1].Knocks
	time.Sleep(400 * time.Millisecond)
	if k1 := rig.cli.CarrierStats()[1].Knocks; k1 <= k0 {
		t.Fatalf("no knock while downlink was flowing: %d -> %d (suppression regression?)", k0, k1)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("download behind the NAT failed: %v (got %d of %d)", err, received, n)
		}
		if received != n {
			t.Fatalf("short download behind the NAT: %d of %d", received, n)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("download behind the NAT timed out (knocks did not keep the mapping alive?)")
	}
	cs := rig.cli.CarrierStats()
	if cs[1].Knocks == 0 {
		t.Fatalf("no knocks were sent on the :down leg: %+v", cs[1])
	}
	if cs[1].Sent != 0 {
		t.Fatalf("knocks counted as data: client Sent on the :down leg = %d (want 0, knocks are control-plane)", cs[1].Sent)
	}
	if cs[0].Knocks != 0 {
		t.Fatalf("knocks on the :up leg (only :down legs knock): %+v", cs[0])
	}
	t.Logf("knock rig: %d knocks on the :down leg, client %+v", cs[1].Knocks, cs)
}

// The 2026-11-19 Kharej smoke found this: Server.CarrierStats summed per-session stats but
// dropped the Muted field, so /stats on a multi-session server never showed a muted leg (the
// manager's mute state detection reads exactly this field).
func TestServerCarrierStatsKeepsMuted(t *testing.T) {
	links := twoLinks(t)
	rig := newBondRig(t, links, fastTimings)
	if _, err := rig.cli.OpenStream(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the session must be admitted so its stats exist
	if !rig.srv.ToggleMute(0) {
		t.Fatal("ToggleMute reported already-muted")
	}
	cs := rig.srv.CarrierStats()
	if len(cs) < 2 || !cs[0].Muted || cs[1].Muted {
		t.Fatalf("server stats lost the mute flag: %+v", cs)
	}
	rig.srv.ToggleMute(0)
	if cs := rig.srv.CarrierStats(); cs[0].Muted {
		t.Fatal("unmute did not clear the flag in server stats")
	}
}

// TestBifrostEndpointTrafficPrecedence pins the port-translating-NAT (NAPT) fix, found 2026-11-20 while
// re-verifying the knock: the frEndpoint announce carries the client's private listen port while a knock's
// observed source carries the NAT's translation, and the announce re-fires every endpointEvery — before the
// fix it replaced the slot wholesale, so downlink behind an NAPT flapped (correct for ≤500 ms per cadence).
// Now the announce bootstraps only: once real traffic is heard on the leg, its observed source is ground
// truth, and a client that rebinds is relearned from the new socket's next knock.
func TestBifrostEndpointTrafficPrecedence(t *testing.T) {
	links := twoLinks(t)
	raws := []RawIO{&linkRaw{l: links[0], done: make(chan struct{})}, &linkRaw{l: links[1], done: make(chan struct{})}}
	for _, r := range raws {
		r := r.(*linkRaw)
		t.Cleanup(func() { close(r.done) })
	}
	base := &subIO{inbox: make(chan rxPkt, 8), done: make(chan struct{})}
	t.Cleanup(func() { close(base.done) })
	m := newMultiSubIO(base, NewMultiRaw([]string{"link0:up", "link1:down"}, raws), PathTimings{}, 0)

	// the authenticated uplink source (the NAT's public address, learned from the ":up" packet)
	src := &TaggedAddr{Idx: 0, Lane: 0, Addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 51000}}
	slotPort := func() int {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.slots[1].dst == nil {
			return -1
		}
		return m.slots[1].dst.Addr.(*net.UDPAddr).Port
	}

	m.SetPathEndpoint(1, 5501, src) // bootstrap announce: the client's private listen port
	if p := slotPort(); p != 5501 {
		t.Fatalf("announce did not bootstrap the slot: port=%d want 5501", p)
	}
	m.SetPeer(&TaggedAddr{Idx: 1, Lane: 0, Addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49152}}) // a knock through the NAPT
	if p := slotPort(); p != 49152 {
		t.Fatalf("traffic did not take over the slot: port=%d want 49152", p)
	}
	m.SetPathEndpoint(1, 5501, src) // the announce re-fires every endpointEvery: must not clobber
	if p := slotPort(); p != 49152 {
		t.Fatalf("announce clobbered the traffic-learned endpoint (NAPT flap): port=%d want 49152", p)
	}
}
