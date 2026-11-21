package main

import (
	"net"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// newMultiRig starts a wattun server on the udp carrier (loopback) and a client tunnel of n sessions to it, plus
// `dead` extra sessions whose carrier points at a port nobody answers on (they never come alive). The live sessions
// come first in the list.
func newMultiRig(t *testing.T, n, dead int, al *allow) *tunnel {
	t.Helper()
	key := []byte("multi-session-key")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key}, us)
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go serve(s, 0, 65535, al, nil)
			go serveDgrams(s, 1, 65535, al, time.Minute)
		}
	}()
	nobody, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := nobody.LocalAddr().String()
	nobody.Close()
	var list []*wat.Session
	for i := 0; i < n+dead; i++ {
		addr := us.Addr().String()
		if i >= n {
			addr = deadAddr
		}
		uc, err := wat.NewUDPClient(addr)
		if err != nil {
			t.Fatal(err)
		}
		s, err := wat.NewSession(wat.Config{Key: key}, uc)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, s)
	}
	tun := newTunnel(list)
	t.Cleanup(tun.Close)
	for _, s := range list[:n] {
		waitFor(t, "session alive", 5*time.Second, s.Alive)
	}
	return tun
}

func streamsOf(s *wat.Session) int {
	n, _ := s.Load()
	return n
}

func TestMultiSessionSpreadsStreams(t *testing.T) {
	tun := newMultiRig(t, 4, 0, newAllow("", ""))
	for i := 0; i < 8; i++ {
		if _, err := tun.pick().OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	for i, s := range tun.list {
		if n := streamsOf(s); n != 2 {
			t.Errorf("session %d has %d streams, want 2 (8 streams over 4 sessions)", i, n)
		}
	}
	// A busier session is skipped until the others catch up.
	for i := 0; i < 3; i++ {
		tun.list[0].OpenStream()
	}
	for i := 0; i < 3; i++ {
		if s := tun.pick(); s == tun.list[0] {
			t.Fatalf("pick %d chose the session with the most streams", i)
		} else {
			s.OpenStream()
		}
	}
	if st := tun.stats(); st.Streams != 14 {
		t.Errorf("aggregate streams %d, want 14", st.Streams)
	}
}

func TestMultiSessionAvoidsDeadSession(t *testing.T) {
	tun := newMultiRig(t, 2, 1, newAllow("", ""))
	dead := tun.list[2]
	if dead.Alive() {
		t.Fatal("the dead session is alive")
	}
	for i := 0; i < 12; i++ {
		s := tun.pick()
		if s == dead {
			t.Fatalf("pick %d chose the dead session (it has the fewest streams, but is not alive)", i)
		}
		s.OpenStream()
	}
	if !tun.alive() || tun.up() != 2 {
		t.Fatalf("alive %v up %d, want true and 2", tun.alive(), tun.up())
	}
	// The flow whose hash lands on the dead session moves to a live one, and stays there.
	for id := uint64(1); id < 200; id += 2 {
		s := tun.forFlow(id)
		if s == dead {
			t.Fatalf("flow %d mapped to the dead session", id)
		}
		if tun.forFlow(id) != s {
			t.Fatalf("flow %d moved between calls", id)
		}
	}
}

func TestMultiSessionSpeedTestUsesAll(t *testing.T) {
	tun := newMultiRig(t, 3, 0, newAllow("", ""))
	var before [3]uint64
	for i, s := range tun.list {
		before[i] = s.Stats().BytesIn
	}
	const size = 6 << 20
	res := runSpeedTest(tun, "down", size, 1, nil)
	if !res.OK || res.Sessions != 3 || res.Bytes != size || res.MBps <= 0 {
		t.Fatalf("speed test: %+v", res)
	}
	for i, s := range tun.list {
		if got := s.Stats().BytesIn - before[i]; got < size/3*9/10 {
			t.Errorf("session %d received %d bytes, want about %d (a third)", i, got, size/3)
		}
	}
	if up := runSpeedTest(tun, "up", 3<<20, 1, nil); !up.OK || up.Sessions != 3 {
		t.Fatalf("upload speed test: %+v", up)
	}
	// One session: exactly the single-stream test of earlier versions, plus "sessions": 1.
	one := newMultiRig(t, 1, 0, newAllow("", ""))
	if r := runSpeedTest(one, "down", 1<<20, 1, nil); !r.OK || r.Sessions != 1 {
		t.Fatalf("single-session speed test: %+v", r)
	}
}

func TestMultiSessionUDPFlowSticks(t *testing.T) {
	tun := newMultiRig(t, 4, 0, newAllow("", ""))
	hit := map[*wat.Session]int{}
	for id := uint64(1); id < 4000; id += 2 { // flow ids are odd
		s := tun.forFlow(id)
		for k := 0; k < 3; k++ {
			if tun.forFlow(id) != s {
				t.Fatalf("flow %d is not stable", id)
			}
		}
		hit[s]++
	}
	for i, s := range tun.list {
		if hit[s] < 300 { // 2000 flows over 4 sessions: ~500 each
			t.Errorf("session %d got %d of 2000 flows", i, hit[s])
		}
	}
	// End to end: two senders, each flow's datagrams all go out on its own session, and the replies come back.
	port := echoUDP(t)
	al := allowUDP(port)
	tun = newMultiRig(t, 3, 0, al)
	dc := newDgramClient(tun, time.Minute)
	l, err := dc.listen("127.0.0.1:0", port)
	if err != nil {
		t.Fatal(err)
	}
	var sentBefore [3]uint64
	for i, s := range tun.list {
		sentBefore[i] = s.Stats().DgramSent
	}
	for _, tag := range []byte{'P', 'Q'} {
		if got, wrong := sender(t, l.Addr(), tag, 200); got < 190 || wrong != 0 {
			t.Fatalf("sender %c: got %d of 200, wrong %d", tag, got, wrong)
		}
	}
	dc.mu.Lock()
	want := map[*wat.Session]uint64{}
	for id := range dc.byID {
		want[tun.forFlow(id)] += 200
	}
	dc.mu.Unlock()
	for i, s := range tun.list {
		got := s.Stats().DgramSent - sentBefore[i]
		if got > want[s] || got < want[s]*9/10 { // a full send queue may drop a few; another session never sends any
			t.Errorf("session %d sent %d datagrams, want %d (its flows' share)", i, got, want[s])
		}
	}
}

// A flow keeps the session it was placed on, even one that is not its hash home, and moves only when that session is
// down; otherwise a session that flaps back to life reorders the flow's datagrams.
func TestMultiSessionUDPFlowKeepsItsSession(t *testing.T) {
	tun := newMultiRig(t, 2, 1, newAllow("", "")) // list[2] never comes alive
	dc := newDgramClient(tun, time.Minute)
	f := &cflow{id: 7, l: &udpListener{c: dc}}
	home := f.session()
	if home == nil || !home.Alive() {
		t.Fatalf("a new flow got a dead session")
	}
	if f.session() != home {
		t.Fatal("the flow changed session between datagrams")
	}
	other := tun.list[0]
	if other == home {
		other = tun.list[1]
	}
	f.sess = other // pinned by hand: a live session is kept even when the hash points elsewhere
	if got := f.session(); got != other {
		t.Fatal("a live pinned session was re-picked")
	}
	f.sess = tun.list[2]
	if got := f.session(); got == tun.list[2] || !got.Alive() {
		t.Fatal("a dead session was kept")
	}
}
