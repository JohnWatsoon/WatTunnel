package wat

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Token algebra: right key/method/path/bucket verifies, everything an attacker can vary does not (audit 2026-11-18).
func TestProbeGuardToken(t *testing.T) {
	key := ProbeGuardKey([]byte("psk"))
	now := time.Now()
	tok := probeGuardToken(key, "GET", "/wat", now)

	req := httptest.NewRequest("GET", "/wat", nil)
	req.Header.Set(probeGuardHdr, tok)
	if !probeGuardOK(key, req, now) {
		t.Fatal("valid token rejected")
	}
	if !probeGuardOK(key, req, now.Add(4*time.Minute)) || !probeGuardOK(key, req, now.Add(-4*time.Minute)) {
		t.Fatal("token must survive +-4 min of clock skew")
	}
	if probeGuardOK(key, req, now.Add(11*time.Minute)) {
		t.Fatal("token must die past the +-5 min window")
	}
	if probeGuardOK(ProbeGuardKey([]byte("other")), req, now) {
		t.Fatal("token minted under another key accepted")
	}
	wrong := httptest.NewRequest("GET", "/elsewhere", nil)
	wrong.Header.Set(probeGuardHdr, tok)
	if probeGuardOK(key, wrong, now) {
		t.Fatal("token for another path accepted")
	}
	post := httptest.NewRequest("POST", "/wat", nil)
	post.Header.Set(probeGuardHdr, tok)
	if probeGuardOK(key, post, now) {
		t.Fatal("GET token accepted on POST")
	}
	empty := httptest.NewRequest("GET", "/wat", nil)
	if probeGuardOK(key, empty, now) {
		t.Fatal("missing token accepted")
	}
	for _, junk := range []string{"", "zz", "00112233445566778899aabbccddeeff", "AAAAAAAAAAAAAAAAAAAAAAAAAA==", tok + "x"} {
		e := httptest.NewRequest("GET", "/wat", nil)
		e.Header.Set(probeGuardHdr, junk)
		if probeGuardOK(key, e, now) {
			t.Fatalf("junk token %q accepted", junk)
		}
	}
}

// A guarded ws server hands a tokenless websocket probe to the decoy - never a 101 - and accepts the stamped
// client (3.3.8; before the guard the probe got a real tunnel upgrade, audit 2026-11-18).
func TestProbeGuardWs(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "decoy")
	}))
	defer origin.Close()
	key := ProbeGuardKey([]byte("guard-key"))
	ps, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Path: "/tunnel-secret", Decoy: origin.URL, ProbeGuard: key})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	// exactly the header shape wsServerUpgrade accepts, minus the token
	req, _ := http.NewRequest("GET", "http://"+ps.Addr().String()+"/tunnel-secret", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Add("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "decoy" {
		t.Fatalf("tokenless ws probe got status %d body %q, want the decoy", resp.StatusCode, b)
	}

	cli, err := NewWSPoolClient(ps.Addr().String(), 1, HTTPClientOptions{Path: "/tunnel-secret", ProbeGuard: key})
	if err != nil {
		t.Fatalf("guarded ws client could not dial: %v", err)
	}
	cli.Close()
}

// A guarded h2 pair carries traffic end to end: the same token stamps every POST, and the server demands it
// before its 200 (an h2 prober without the token gets the nginx pages, never the tunnel).
func TestProbeGuardH2Echo(t *testing.T) {
	key := ProbeGuardKey([]byte("guard-key"))
	ps, err := NewH2PoolServer("127.0.0.1:0", HTTPServerOptions{Path: "/tunnel-secret", ProbeGuard: key})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	srv := NewServer(Config{Key: []byte("pool-key")}, ps)
	srv.IdleTimeout = 5 * time.Second
	defer srv.Close()
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

	// tokenless POST must not get the tunnel's 200 (over h1 it would also fail the ProtoMajor check, so this
	// only proves the fallback page; the real h2 rejection is covered by the client pair below)
	res, err := http.Post("http://"+ps.Addr().String()+"/tunnel-secret", "application/octet-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == 200 && res.Header.Get("Content-Type") == "application/octet-stream" {
		t.Fatal("tokenless POST got the tunnel response")
	}

	pio, err := NewH2PoolClient(ps.Addr().String(), 1, HTTPClientOptions{Path: "/tunnel-secret", ProbeGuard: key})
	if err != nil {
		t.Fatalf("guarded h2 client could not dial: %v", err)
	}
	cli, err := NewSession(Config{Key: []byte("pool-key")}, pio)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer st.CloseWrite()
	msg := "probe-guard-echo"
	if _, err := st.Write([]byte{'E'}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	type echoRes struct {
		n   int
		err error
	}
	ch := make(chan echoRes, 1)
	buf := make([]byte, len(msg))
	go func() {
		n, err := io.ReadFull(st, buf)
		ch <- echoRes{n, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("echo read: %v", r.err)
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch: %q", buf)
		}
	case <-time.After(9 * time.Second):
		t.Fatal("guarded h2 echo timed out")
	}
}
