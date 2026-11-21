// Scepter latch tests (3.5.0, phase A item 5): the CI drill — unit inactive → latch up → authenticated cockpit
// contact → latch down — over a real wss pool carrier on loopback, plus the keyed-proof rejection paths. The
// drill needs no raw socket and no root (it rides TCP/TLS like carrier_http_test.go), so it also runs on the
// Windows dev checkout; the CI root job runs it too (plan A.5 "latch drill ... as a CI root-job test").

package wat

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestLatchDrill: arm the latch exactly as cmd/wattun does (wss pool server, key-derived path, one session),
// contact it with the proof, run scepter commands on the live session, and prove the listener stood down: a
// fresh dial to the port is refused while the contact's session keeps serving.
func TestLatchDrill(t *testing.T) {
	pair := testPairing(CapFull)
	state, err := NewScepterState(pair, &fakeSource{}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.journal.Close() })
	key := LatchKey(pair)
	ps, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Path: LatchPath(pair), Secure: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Server: true, Key: key, Pairing: pair, Logf: func(string, ...any) {}}
	srv := NewServer(cfg, ps)
	srv.MaxSessions = 1
	t.Cleanup(srv.Close)
	contact := make(chan *Session, 1)
	go func() { // cmd/wattun's accept: first contact stands the listener down, then serves the session
		s, ok := <-srv.New
		if !ok {
			close(contact)
			return
		}
		ps.StopListen()
		contact <- s
		go serveLatchTest(s, state, key)
	}()

	c := dialLatchClient(t, ps.Addr().String(), pair)
	if c.Hello["ver"] != Version {
		t.Fatalf("latch hello ver = %v, want %s", c.Hello["ver"], Version)
	}
	if p, code := c.Call("state.get", nil); code != CodeOK || p["ver"] != Version {
		t.Fatalf("state.get over the latch: code %d", code)
	}
	// The listener is down: a fresh TCP dial to the port must be refused (nothing accepts anymore), while the
	// contact's own session keeps answering — StopListen must not have cut it.
	if conn, err := net.DialTimeout("tcp", ps.Addr().String(), 2*time.Second); err == nil {
		conn.Close()
		t.Fatal("latch listener still accepting after first contact")
	}
	if _, code := c.Call("scepter.ping", nil); code != CodeOK {
		t.Fatalf("ping on the live latch session after stand-down: code %d", code)
	}
	select { // the server side saw the session (the accept goroutine handed it over)
	case s := <-contact:
		if s == nil {
			t.Fatal("no latch session reached the server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no latch session reached the server")
	}
	if state.Recent()[len(state.Recent())-1].Cmd != "scepter.ping" {
		t.Fatalf("recent commands after the drill: %+v", state.Recent())
	}
}

// serveLatchTest is cmd/wattun serveLatch's sid-0 branch: the proof gate, then the normal command loop.
func serveLatchTest(s *Session, state *ScepterState, key []byte) {
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		if st.ID() != 0 {
			st.Reset() // this test's latch carries management only
			continue
		}
		go ServeScepterLatch(st, state, key)
	}
}

func dialLatchClient(t *testing.T, addr string, pair *PairingConfig) *ScepterClient {
	t.Helper()
	pc, err := NewWSPoolClient(addr, 2, HTTPClientOptions{Path: LatchPath(pair), Secure: true})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(Config{Key: LatchKey(pair), Pairing: pair, Logf: func(string, ...any) {}}, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	c, err := DialScepterLatch(sess, LatchKey(pair))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestLatchProofReject: a contact without knowledge of the pairing key gets one denied line, a reset stream
// and no command served — the latch is the one place a stranger can reach, so nothing else may happen.
func TestLatchProofReject(t *testing.T) {
	pair := testPairing(CapFull)
	state, err := NewScepterState(pair, &fakeSource{}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.journal.Close() })
	good := LatchKey(pair)
	other := testPairing(CapTunnel) // a DIFFERENT credential: another UUID + key, no knowledge of ours
	other.Key[0] ^= 1
	bad := LatchKey(other)
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{Pairing: pair})
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go serveLatchTest(srv, state, good)
	st, err := cli.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	// Hand-write the proof line with the wrong key: the decoder path DialScepterLatch would take never gets
	// there (it computes the proof from the right key), so this is the stranger's own dialer.
	ts := time.Now().Unix()
	b, err := json.Marshal(ScepterRequest{ID: "x", V: scepterV, Cmd: "latch.proof",
		Args: map[string]any{"ts": ts, "proof": LatchProof(bad, ts)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	d := newScepterDecoder(st)
	if _, code := d.next(); code != -1 && code != CodeBadRequest {
		// after Reset the stream read errors; the denied line may or may not win the race with the reset
		t.Logf("post-reject read code %d", code)
	}
	if len(state.Recent()) != 0 {
		t.Fatalf("rejected contact executed commands: %+v", state.Recent())
	}
}

// TestLatchStaleProof: the right key but an old timestamp (a replayed capture) is denied, and the derived
// key/path belong to this credential alone.
func TestLatchStaleProof(t *testing.T) {
	key := LatchKey(testPairing(CapFull))
	if latchProofOK(key, time.Now().Add(-time.Hour).Unix(), LatchProof(key, time.Now().Add(-time.Hour).Unix()), time.Now()) {
		t.Fatal("an hour-old proof must be stale")
	}
	other := testPairing(CapTunnel) // same fixed UUID/key as every testPairing: make it a different credential
	other.Key[0] ^= 1
	if latchProofOK(key, time.Now().Unix(), LatchProof(LatchKey(other), time.Now().Unix()), time.Now()) {
		t.Fatal("another credential's proof must not verify")
	}
	if !latchProofOK(key, time.Now().Unix(), LatchProof(key, time.Now().Unix()), time.Now()) {
		t.Fatal("a fresh proof with the right key must verify")
	}
	if LatchPath(other) == LatchPath(testPairing(CapFull)) || string(LatchKey(other)) == string(key) {
		t.Fatal("the latch key and path must depend on the pairing key")
	}
}
