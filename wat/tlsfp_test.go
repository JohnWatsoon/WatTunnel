package wat

import (
	"bytes"
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type recWriter struct{ chunks [][]byte }

func (r *recWriter) Write(p []byte) (int, error) {
	r.chunks = append(r.chunks, append([]byte(nil), p...))
	return len(p), nil
}

func TestWriteFragments(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefg"), 10) // 70 bytes
	var w recWriter
	n, err := writeFragments(&w, data, 8, 0)
	if err != nil || n != 70 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(w.chunks) != 9 {
		t.Fatalf("%d chunks, want 9", len(w.chunks))
	}
	var all []byte
	for i, c := range w.chunks {
		if len(c) > 8 || (i < 8 && len(c) != 8) {
			t.Fatalf("chunk %d has %d bytes", i, len(c))
		}
		all = append(all, c...)
	}
	if !bytes.Equal(all, data) {
		t.Fatal("fragments do not reassemble")
	}
	w = recWriter{}
	writeFragments(&w, data[:5], 8, 0)
	writeFragments(&w, data, 0, 0)
	if len(w.chunks) != 2 {
		t.Fatalf("short or unfragmented writes must stay whole, got %d chunks", len(w.chunks))
	}
}

// TestWriteFragmentsSNISplit: n = -1 splits directly through the TLS SNI domain name.
func TestWriteFragmentsSNISplit(t *testing.T) {
	hello := FakeClientHello("mci.ir")
	var w recWriter
	n, err := writeFragments(&w, hello, -1, 0)
	if err != nil || n != len(hello) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(w.chunks) != 2 {
		t.Fatalf("want exactly 2 chunks for mid-SNI split, got %d", len(w.chunks))
	}
	off := sniExtOffset(hello)
	if off <= 0 {
		t.Fatal("no SNI extension in hello")
	}
	if len(w.chunks[0]) != off+10 {
		t.Fatalf("chunk 0 len %d, want off+10 (%d)", len(w.chunks[0]), off+10)
	}
	if !bytes.Equal(append(w.chunks[0], w.chunks[1]...), hello) {
		t.Fatal("chunks do not reassemble back into hello")
	}
}

// pipeRec is a net.Conn that records its writes.
type pipeRec struct {
	net.Conn
	w recWriter
}

func (p *pipeRec) Write(b []byte) (int, error) { return p.w.Write(b) }

func TestFragConnFirstWriteOnly(t *testing.T) {
	pr := &pipeRec{}
	fc := newFragConn(pr, 10)
	fc.(*fragConn).gap = 0
	fc.Write(make([]byte, 35))
	fc.Write(make([]byte, 35))
	if len(pr.w.chunks) != 5 || len(pr.w.chunks[4]) != 35 {
		t.Fatalf("want 4 fragments then one whole write, got %d chunks", len(pr.w.chunks))
	}
	if newFragConn(pr, 0) != net.Conn(pr) {
		t.Fatal("frag 0 must not wrap")
	}
}

// writes seen by the TCP connection under the TLS layer
type segRec struct {
	net.Conn
	mu   sync.Mutex
	segs []int
}

func (s *segRec) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.segs = append(s.segs, len(p))
	s.mu.Unlock()
	return s.Conn.Write(p)
}

// the ClientHello of a real handshake really leaves in small segments
func TestFragHandshake(t *testing.T) {
	for _, fp := range []string{"go", "chrome"} {
		t.Run(fp, func(t *testing.T) {
			ln, addr := echTLSListener(t, nil)
			defer ln.Close()
			echServe(ln)
			e, err := newTLSEngine(TLSClientOptions{ServerName: "example.com", Fingerprint: fp, Frag: 7}, "")
			if err != nil {
				t.Fatal(err)
			}
			var rec *segRec
			e.dialF = func(ctx context.Context, a string) (net.Conn, error) {
				c, err := net.Dial("tcp", a)
				rec = &segRec{Conn: c}
				return rec, err
			}
			c, err := e.dial(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.segs) < 20 || rec.segs[0] != 7 {
				t.Fatalf("ClientHello went out as %v", rec.segs)
			}
			for _, s := range rec.segs[:15] {
				if s > 7 {
					t.Fatalf("segment of %d bytes in %v", s, rec.segs)
				}
			}
		})
	}
}

func TestPeerSet(t *testing.T) {
	addrs, err := SplitPeers("188.114.97.6:443, [2a06:98c1:3121::7]:443")
	if err != nil || len(addrs) != 2 || addrs[1] != "[2a06:98c1:3121::7]:443" {
		t.Fatalf("%v %v", addrs, err)
	}
	if _, err := SplitPeers("1.2.3.4"); err == nil {
		t.Fatal("host without port accepted")
	}
	ps := newPeerSet(addrs)
	home := map[string]int{}
	for i := 0; i < 8; i++ {
		home[addrs[ps.order(i)[0]]]++
	}
	if home[addrs[0]] != 4 || home[addrs[1]] != 4 {
		t.Fatalf("slots not spread evenly: %v", home)
	}
	ps.mark(0, false)
	if o := ps.order(0); o[0] != 1 || o[1] != 0 {
		t.Fatalf("a failed address must go last, got %v", o)
	}
	ps.mark(0, true)
	if o := ps.order(0); o[0] != 0 {
		t.Fatalf("recovered address must be home again, got %v", o)
	}
	if e := ps.edges(); !e[0].Up || e[1].Up {
		t.Fatalf("edges %+v", e)
	}
}

// a dead first address (here a refused port, like a missing v6 route) must not delay the working one by a backoff
func TestMultiPeerSkipsDeadAtOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	pc, err := NewTCPPoolClient(deadAddr+","+ln.Addr().String(), 1) // slot 0 is homed on the dead one
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	t0 := time.Now()
	for pc.Conns() < 1 {
		if time.Since(t0) > 2*time.Second {
			t.Fatal("slot never reached the live address")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if d := time.Since(t0); d > 90*time.Millisecond {
		t.Fatalf("took %v, the slot waited for a backoff", d)
	}
	e := pc.Edges()
	if len(e) != 2 || e[0].Up || !e[1].Up {
		t.Fatalf("edges %+v", e)
	}
}

// slots really dial different addresses
func TestMultiPeerPoolDialsAll(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	var lns []net.Listener
	var addrs []string
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		lns = append(lns, ln)
		addrs = append(addrs, ln.Addr().String())
		go func(a string) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				got[a]++
				mu.Unlock()
				go func() { time.Sleep(2 * time.Second); c.Close() }()
			}
		}(ln.Addr().String())
	}
	pc, err := NewTCPPoolClient(strings.Join(addrs, ","), 6)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := got[addrs[0]] >= 3 && got[addrs[1]] >= 3
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connections per address: %v", got)
}

// ---------------------------------------------------------------- ALPN

// An h2 + http/1.1 TLS server: what a CDN looks like.
func alpnServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

type connStater interface{ ConnectionState() utls.ConnectionState }

func TestALPNPerCarrierUnderChrome(t *testing.T) {
	srv := alpnServer(t)
	addr := srv.Listener.Addr().String()
	for _, tc := range []struct{ alpn, want string }{{"http/1.1", "http/1.1"}, {"h2", "h2"}} {
		e, err := newTLSEngine(TLSClientOptions{ServerName: "cdn.example.com", Fingerprint: "chrome"}, tc.alpn)
		if err != nil {
			t.Fatal(err)
		}
		c, err := e.dial(context.Background(), addr)
		if err != nil {
			t.Fatalf("%s: %v", tc.alpn, err)
		}
		if got := c.(connStater).ConnectionState().NegotiatedProtocol; got != tc.want {
			t.Fatalf("alpn %s: negotiated %q", tc.alpn, got)
		}
		c.Close()
	}
	// stdlib too
	e, _ := newTLSEngine(TLSClientOptions{ServerName: "cdn.example.com"}, "http/1.1")
	c, err := e.dial(context.Background(), addr)
	if err != nil || c.(*tls.Conn).ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatalf("stdlib ws alpn: %v", err)
	}
	c.Close()
}

func TestALPNH2RequiredFailsClearly(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.StartTLS() // http/1.1 only
	defer srv.Close()
	for _, fp := range []string{"go", "chrome"} {
		e, _ := newTLSEngine(TLSClientOptions{ServerName: "x.example.com", Fingerprint: fp}, "h2")
		_, err := e.dial(context.Background(), srv.Listener.Addr().String())
		if err == nil || !strings.Contains(err.Error(), "h2") {
			t.Fatalf("fp %s: want a clear h2 error, got %v", fp, err)
		}
	}
}

// The tunnel itself, wss/h2/grpc/tls, with every fingerprint's ClientHello (and fragmentation).
func TestHTTPCarriersFingerprints(t *testing.T) {
	for _, fp := range []string{"chrome", "firefox", "safari", "edge", "random"} {
		for _, f := range []string{"wss", "h2", "grpc"} {
			if fp != "chrome" && f != "wss" {
				continue
			}
			t.Run(fp+"/"+f, func(t *testing.T) {
				r := newHTTPRig(t, f)
				r.tlsOpt = TLSClientOptions{Fingerprint: fp, Frag: 100}
				c := r.client(t)
				poolBulk(t, r.poolRig, c, 1<<20)
			})
		}
	}
}

func TestTLSCarrierFingerprint(t *testing.T) {
	r := newPoolRig(t, 0, true)
	r.tlsOpt = TLSClientOptions{Fingerprint: "chrome", Frag: 64}
	pio := r.pio(t)
	fp, _, _, ok := pio.TLSInfo()
	if !ok || fp != "chrome" {
		t.Fatalf("TLSInfo %q %v", fp, ok)
	}
	cli, err := NewSession(Config{Key: r.key}, tapClient{pio, r.tap})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	poolBulk(t, r, cli, 1<<20)
	if _, mode, ech, _ := pio.TLSInfo(); mode != "chrome+frag" || ech {
		t.Fatalf("tls_mode %q ech %v", mode, ech)
	}
}

func TestWSOverH2CapableServerIsHTTP11(t *testing.T) {
	r := newHTTPRig(t, "wss") // the server offers h2 and http/1.1
	r.tlsOpt = TLSClientOptions{Fingerprint: "chrome"}
	cli := r.client(t)
	poolBulk(t, r.poolRig, cli, 256<<10)
}

// ---------------------------------------------------------------- ECH

// ech test material -----------------------------------------------------

// echConfig builds one ECHConfig (version fe0d) for an X25519 key.
func echConfig(id byte, pub []byte, publicName string) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 0x0001) // AES-128-GCM
	c = append(c, 64, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // extensions
	out := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

func echKey(t *testing.T, id byte, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := echConfig(id, priv.PublicKey().Bytes(), publicName)
	return tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: priv.Bytes(), SendAsRetry: true}, cfg
}

func echList(cfgs ...[]byte) []byte {
	b := bytes.Join(cfgs, nil)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// echTLSListener is a TLS 1.3 listener with the given ECH keys.
func echTLSListener(t *testing.T, keys []tls.EncryptedClientHelloKey) (net.Listener, string) {
	t.Helper()
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, EncryptedClientHelloKeys: keys}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ln, ln.Addr().String()
}

type echSeen struct {
	accepted bool
	sni      string
}

func echServe(ln net.Listener) chan echSeen {
	ch := make(chan echSeen, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				if tc.Handshake() == nil {
					st := tc.ConnectionState()
					ch <- echSeen{st.ECHAccepted, st.ServerName}
				}
				time.Sleep(200 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	return ch
}

func TestECHStaticAllFingerprints(t *testing.T) {
	for _, fp := range []string{"go", "chrome", "firefox"} {
		t.Run(fp, func(t *testing.T) {
			key, cfg := echKey(t, 7, "public.example")
			ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
			defer ln.Close()
			seen := echServe(ln)
			e, err := newTLSEngine(TLSClientOptions{ServerName: "inner.example", Fingerprint: fp,
				ECH: base64.StdEncoding.EncodeToString(echList(cfg))}, "http/1.1")
			if err != nil {
				t.Fatal(err)
			}
			c, err := e.dial(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := <-seen
			if !s.accepted || s.sni != "inner.example" {
				t.Fatalf("server saw %+v", s)
			}
			if _, mode, on := e.info(); !on || mode != fp+"+ech" {
				t.Fatal("info does not report ECH")
			}
		})
	}
}

// A stale config is rejected; the server's retry configs are used for the redial.
func TestECHRetryConfigs(t *testing.T) {
	for _, fp := range []string{"go", "chrome"} {
		t.Run(fp, func(t *testing.T) {
			real, _ := echKey(t, 9, "public.example")
			_, stale := echKey(t, 3, "public.example") // a key the server does not have
			ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{real})
			defer ln.Close()
			seen := echServe(ln)
			e, _ := newTLSEngine(TLSClientOptions{ServerName: "inner.example", Fingerprint: fp,
				ECH: base64.StdEncoding.EncodeToString(echList(stale))}, "")
			c, err := e.dial(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for {
				s := <-seen
				if s.accepted {
					if s.sni != "inner.example" {
						t.Fatalf("sni %q", s.sni)
					}
					return
				}
			}
		})
	}
}

// auto, nothing published: continue without ECH
func TestECHAutoNoRecord(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		m := append([]byte(nil), q[:2]...)
		m = append(m, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
		m = append(m, q[12:]...)
		w.Write(m)
	}))
	defer doh.Close()
	dohServers = []string{doh.URL}
	ln, addr := echTLSListener(t, nil)
	defer ln.Close()
	seen := echServe(ln)
	var logs []string
	e, _ := newTLSEngine(TLSClientOptions{ServerName: "inner.example", ECH: "auto", Logf: func(f string, a ...any) { logs = append(logs, f) }}, "")
	for i := 0; i < 2; i++ {
		c, err := e.dial(context.Background(), addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if s := <-seen; s.accepted {
			t.Fatal("ECH accepted without a config?")
		}
	}
	if len(logs) != 1 {
		t.Fatalf("want one note, got %v", logs)
	}
}

// auto, a published config: found through DoH and used
func TestECHAutoViaDoH(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	key, cfg := echKey(t, 5, "public.example")
	list := echList(cfg)
	var queries int
	var qmu sync.Mutex
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qmu.Lock()
		queries++
		qmu.Unlock()
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		w.Write(dnsHTTPSAnswer(q, list))
	}))
	defer doh.Close()
	dohServers = []string{"http://127.0.0.1:1/dns-query", doh.URL} // the first one is down: fallback
	ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
	defer ln.Close()
	seen := echServe(ln)
	e, _ := newTLSEngine(TLSClientOptions{ServerName: "inner.example", ECH: "auto", Fingerprint: "chrome"}, "http/1.1")
	for i := 0; i < 3; i++ {
		c, err := e.dial(context.Background(), addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if s := <-seen; !s.accepted || s.sni != "inner.example" {
			t.Fatalf("server saw %+v", s)
		}
	}
	if queries != 1 {
		t.Fatalf("%d DoH queries for 3 dials, want 1 (cached)", queries)
	}
}

// dnsHTTPSAnswer builds a response to query q with one HTTPS record: priority 1, target ".", alpn=h2, ech=list.
func dnsHTTPSAnswer(q, list []byte) []byte {
	m := append([]byte(nil), q[:2]...)
	m = append(m, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
	m = append(m, q[12:]...)
	var rd []byte
	rd = binary.BigEndian.AppendUint16(rd, 1)
	rd = append(rd, 0) // target "."
	rd = binary.BigEndian.AppendUint16(rd, 1)
	rd = binary.BigEndian.AppendUint16(rd, 3)
	rd = append(rd, 2, 'h', '2')
	rd = binary.BigEndian.AppendUint16(rd, svcParamECH)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(list)))
	rd = append(rd, list...)
	m = append(m, 0xc0, 0x0c) // owner: pointer to the question name
	m = binary.BigEndian.AppendUint16(m, dnsTypeHTTPS)
	m = binary.BigEndian.AppendUint16(m, 1)
	m = binary.BigEndian.AppendUint32(m, 300)
	m = binary.BigEndian.AppendUint16(m, uint16(len(rd)))
	return append(m, rd...)
}

func TestParseHTTPSECH(t *testing.T) {
	q, err := buildDNSQuery("www.example.com", dnsTypeHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if q[len(q)-4] != 0 || q[len(q)-3] != dnsTypeHTTPS {
		t.Fatal("bad query type")
	}
	_, cfg := echKey(t, 1, "cloudflare-ech.com")
	list := echList(cfg)
	got, err := parseHTTPSECH(dnsHTTPSAnswer(q, list), q)
	if err != nil || !bytes.Equal(got, list) {
		t.Fatalf("got %x err %v", got, err)
	}
	if _, err := parseHTTPSECH(dnsHTTPSAnswer(q, list), append([]byte{9, 9}, q[2:]...)); err == nil {
		t.Fatal("id mismatch accepted")
	}
	// no answers
	empty := append(append([]byte(nil), q[:2]...), 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
	empty = append(empty, q[12:]...)
	if _, err := parseHTTPSECH(empty, q); err == nil {
		t.Fatal("empty answer accepted")
	}
	// NXDOMAIN
	nx := append([]byte(nil), empty...)
	nx[3] = 0x83
	if _, err := parseHTTPSECH(nx, q); err == nil || !strings.Contains(err.Error(), "rcode") {
		t.Fatalf("nxdomain: %v", err)
	}
	// truncated garbage never panics
	full := dnsHTTPSAnswer(q, list)
	for i := 0; i < len(full); i++ {
		parseHTTPSECH(full[:i], nil)
	}
}

func TestParseECHFlag(t *testing.T) {
	_, cfg := echKey(t, 1, "x.example")
	l := echList(cfg)
	for _, s := range []string{base64.StdEncoding.EncodeToString(l), base64.RawStdEncoding.EncodeToString(l), base64.URLEncoding.EncodeToString(l)} {
		m, got, err := ParseECHFlag(s)
		if err != nil || m != "static" || !bytes.Equal(got, l) {
			t.Fatalf("%v %v", m, err)
		}
	}
	for _, s := range []string{"", "off"} {
		if m, _, _ := ParseECHFlag(s); m != "off" {
			t.Fatal(m)
		}
	}
	if m, _, _ := ParseECHFlag("auto"); m != "auto" {
		t.Fatal("auto")
	}
	for _, bad := range []string{"%%%", base64.StdEncoding.EncodeToString([]byte("not a config list"))} {
		if _, _, err := ParseECHFlag(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := NormFingerprint("netscape"); err == nil {
		t.Fatal("bad fingerprint accepted")
	}
}

// ECH and ClientHello fragmentation together: the fragmented hello must still carry ECH and be accepted.
func TestECHWithFrag(t *testing.T) {
	for _, fp := range []string{"go", "chrome"} {
		t.Run(fp, func(t *testing.T) {
			key, cfg := echKey(t, 7, "public.example")
			ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
			defer ln.Close()
			seen := echServe(ln)
			e, err := newTLSEngine(TLSClientOptions{ServerName: "inner.example", Fingerprint: fp, Frag: 100,
				ECH: base64.StdEncoding.EncodeToString(echList(cfg))}, "http/1.1")
			if err != nil {
				t.Fatal(err)
			}
			var rec *segRec
			e.dialF = func(ctx context.Context, a string) (net.Conn, error) {
				c, err := net.Dial("tcp", a)
				rec = &segRec{Conn: c}
				return rec, err
			}
			c, err := e.dial(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := <-seen
			if !s.accepted || s.sni != "inner.example" {
				t.Fatalf("server saw %+v", s)
			}
			if _, mode, on := e.info(); !on || mode != fp+"+ech+frag" {
				t.Fatalf("info mode %q ech %v", mode, on)
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.segs) < 3 || rec.segs[0] != 100 {
				t.Fatalf("ClientHello went out as %v", rec.segs)
			}
		})
	}
}

// DoH: the four servers are raced, so a dead or hanging one costs nothing; a lookup that later fails keeps the last
// good config (stale-while-error).
func TestECHDoHRaceAndStale(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	_, cfg := echKey(t, 5, "public.example")
	list := echList(cfg)
	var down atomic.Bool
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "blocked", 503)
			return
		}
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		w.Write(dnsHTTPSAnswer(q, list))
	}))
	defer good.Close()
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer hang.Close()
	dohServers = []string{hang.URL, "http://127.0.0.1:1/dns-query", hang.URL, good.URL}
	t0 := time.Now()
	got, err := FetchECHConfigList(context.Background(), "inner.example")
	if err != nil || !bytes.Equal(got, list) {
		t.Fatalf("%x %v", got, err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("hanging servers delayed the answer by %v", d)
	}

	s := &echState{mode: "auto", m: map[string]*echEntry{}, inflight: map[string]chan struct{}{}}
	e := &tlsEngine{noted: map[string]bool{}}
	if !bytes.Equal(s.get(context.Background(), "inner.example", e), list) {
		t.Fatal("no config")
	}
	down.Store(true)
	s.m["inner.example"].next = time.Now().Add(-time.Second) // expired
	if !bytes.Equal(s.get(context.Background(), "inner.example", e), list) {
		t.Fatal("expired config not served while refreshing")
	}
	for i := 0; i < 100; i++ { // the background refresh fails and must keep the config
		s.mu.Lock()
		busy := s.inflight["inner.example"] != nil
		s.mu.Unlock()
		if !busy {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Equal(s.get(context.Background(), "inner.example", e), list) {
		t.Fatal("a failed refresh dropped the known config")
	}
}

// -ech-cache: written after a DoH fetch, and used by a new engine while DoH is unreachable.
func TestECHCacheFile(t *testing.T) {
	old := dohServers
	defer func() { dohServers = old }()
	key, cfg := echKey(t, 7, "public.example")
	list := echList(cfg)
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		w.Write(dnsHTTPSAnswer(q, list))
	}))
	dohServers = []string{doh.URL}
	file := filepath.Join(t.TempDir(), "x.ech")
	opts := TLSClientOptions{ServerName: "inner.example", ECH: "auto", ECHCache: file}
	e, err := newTLSEngine(opts, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ech.get(context.Background(), "inner.example", e); !bytes.Equal(got, list) {
		t.Fatal("DoH config not returned")
	}
	b, err := os.ReadFile(file)
	if err != nil || strings.TrimSpace(string(b)) != "inner.example "+base64.StdEncoding.EncodeToString(list) {
		t.Fatalf("cache file %q, %v", b, err)
	}
	doh.Close() // DoH unreachable now
	e2, _ := newTLSEngine(opts, "http/1.1")
	if got := e2.ech.get(context.Background(), "inner.example", e2); !bytes.Equal(got, list) {
		t.Fatal("cached config not used")
	}
	// and it really works for a handshake
	ln, addr := echTLSListener(t, []tls.EncryptedClientHelloKey{key})
	defer ln.Close()
	seen := echServe(ln)
	c, err := e2.dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s := <-seen; !s.accepted {
		t.Fatal("ECH not accepted with the cached config")
	}
	// a broken cache path never fails anything
	bad := opts
	bad.ECHCache = filepath.Join(t.TempDir(), "no", "dir", "x")
	e3, _ := newTLSEngine(bad, "")
	e3.ech.get(context.Background(), "inner.example", e3)
}

// TestSmallClientHello pins -tls-small-ch: the option drops the post-quantum hybrid key share, which is what makes
// the ClientHello ~1.5 KB. A DPI that drops large hellos (measured live 2026-10-22) needs the classical offer instead.
func TestSmallClientHello(t *testing.T) {
	big := TLSClientOptions{ServerName: "example.com"}
	if got := big.config().CurvePreferences; got != nil {
		t.Fatalf("default client pins curves %v; it must leave the Go default (with the hybrid) alone", got)
	}
	small := TLSClientOptions{ServerName: "example.com", NoPQ: true}
	got := small.config().CurvePreferences
	if len(got) != 2 || got[0] != tls.X25519 || got[1] != tls.CurveP256 {
		t.Fatalf("small hello curves = %v, want [X25519 P-256]", got)
	}
	// And the option must not break a real handshake.
	srv := alpnServer(t)
	defer srv.Close()
	e, err := newTLSEngine(small, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.dial(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("handshake with the small hello: %v", err)
	}
	c.Close()
}

// -tls-small-ch must shrink the browser presets too: they offer X25519MLKEM768, which pushes the hello past 1 KB.
func TestSmallClientHelloUnderFingerprint(t *testing.T) {
	helloLen := func(fp string, noPQ bool) int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		got := make(chan int, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- -1
				return
			}
			defer c.Close()
			var h [5]byte
			if _, err := io.ReadFull(c, h[:]); err != nil {
				got <- -1
				return
			}
			got <- 5 + int(binary.BigEndian.Uint16(h[3:]))
		}()
		e, err := newTLSEngine(TLSClientOptions{Fingerprint: fp, NoPQ: noPQ}, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		e.handshakeUTLS(ctx, raw, "example.com", nil) // fails: the listener only reads the hello
		raw.Close()
		return <-got
	}
	for _, fp := range []string{"chrome", "firefox", "edge"} {
		big, small := helloLen(fp, false), helloLen(fp, true)
		t.Logf("%s: hello %d B, with NoPQ %d B", fp, big, small)
		if small <= 0 || small > 700 || small > big {
			t.Fatalf("%s: NoPQ hello is %d B (default %d B), want <= 700 and not larger", fp, small, big)
		}
	}
}
