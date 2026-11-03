package wat

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestECHLadderThroughRelay: -ech ladder with every direct DoH server dead must fetch the config through
// the ladder hook (the tunnel DNS relay's client-side shape) and complete an ECH handshake with it.
func TestECHLadderThroughRelay(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	dohServers = []string{"http://127.0.0.1:1/dns-query"} // dead: the direct rung always fails
	key, cfg := echKey(t, 9, "public.example")
	list := echList(cfg)
	var relayed atomic.Int32
	ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
	defer ln.Close()
	seen := echServe(ln)
	e, err := newTLSEngine(TLSClientOptions{ServerName: "inner.example", ECH: "ladder",
		ECHLadder: func(q []byte) ([]byte, error) {
			relayed.Add(1)
			return dnsHTTPSAnswer(q, list), nil
		}, Logf: func(string, ...any) {}}, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s := <-seen; !s.accepted {
		t.Fatal("ECH not accepted although the relay supplied the config")
	}
	if relayed.Load() != 1 {
		t.Fatalf("%d relayed queries, want 1", relayed.Load())
	}
}

// TestECHLadderFallsBackNoECH: the relay hook also fails -> connect without ECH, try again soon (errTTL),
// exactly like a failed auto lookup. The tunnel must come up regardless.
func TestECHLadderFallsBackNoECH(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	dohServers = []string{"http://127.0.0.1:1/dns-query"}
	ln, addr := echTLSListener(t, nil)
	defer ln.Close()
	seen := echServe(ln)
	e, _ := newTLSEngine(TLSClientOptions{ServerName: "inner.example", ECH: "ladder",
		ECHLadder: func([]byte) ([]byte, error) { return nil, errNoECH }, Logf: func(string, ...any) {}}, "")
	c, err := e.dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s := <-seen; s.accepted {
		t.Fatal("ECH accepted without any config?")
	}
}

// TestECHLadderDirectFirst: a working direct DoH server must answer before the relay is consulted.
func TestECHLadderDirectFirst(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	key, cfg := echKey(t, 3, "public.example")
	list := echList(cfg)
	var relayed atomic.Int32
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		w.Write(dnsHTTPSAnswer(q, list))
	}))
	defer doh.Close()
	dohServers = []string{doh.URL}
	ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
	defer ln.Close()
	seen := echServe(ln)
	e, _ := newTLSEngine(TLSClientOptions{ServerName: "inner.example", ECH: "ladder",
		ECHLadder: func([]byte) ([]byte, error) { relayed.Add(1); return nil, errNoECH },
		Logf:      func(string, ...any) {}}, "")
	c, err := e.dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-seen
	if relayed.Load() != 0 {
		t.Fatal("relay consulted although direct DoH worked")
	}
}

// TestECHLadderOldServer: a pre-2.9.0 server treats port 53 as a local service dial that fails and resets
// the stream — the relay hook's error must surface as a clean fallback, never a hung dial. Pinned via the
// hook error path (a hung stream is the field failure this test guards against).
func TestECHLadderOldServer(t *testing.T) {
	q, err := buildDNSQuery("inner.example", dnsTypeHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		s := &echState{mode: "ladder", ladder: func([]byte) ([]byte, error) {
			time.Sleep(50 * time.Millisecond) // an old server's reset arrives as a read error, not a hang
			return nil, net.ErrClosed
		}}
		_, err := s.ladderThrough("inner.example")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ladderThrough succeeded on a failed relay")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ladderThrough hung on a failed relay")
	}
	_ = q
}
