package wat

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// httpRig is a real Server on a loopback ws/wss/h2/h2c/grpc listener; the pool underneath is the tcp pool's.
type httpRig struct {
	*poolRig
	flavor string
	path   string
	stop   chan struct{}
	tlsOpt TLSClientOptions // client TLS tuning under test
}

// shut closes the server and the rig's accept goroutine (srv.New is never closed).
func (r *httpRig) shut() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.srv.Close()
}

func newHTTPPS(t *testing.T, flavor, path string) *TCPPoolServer {
	t.Helper()
	so := HTTPServerOptions{Path: path, Secure: flavor == "wss" || flavor == "h2" || flavor == "grpc"}
	var ps *TCPPoolServer
	var err error
	switch flavor {
	case "ws", "wss":
		ps, err = NewWSPoolServer("127.0.0.1:0", so)
	case "h2", "h2c":
		ps, err = NewH2PoolServer("127.0.0.1:0", so)
	case "grpc":
		ps, err = NewGRPCPoolServer("127.0.0.1:0", so)
	}
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func newHTTPRig(t *testing.T, flavor string) *httpRig {
	t.Helper()
	ps := newHTTPPS(t, flavor, "/wat")
	r := &poolRig{ps: ps, addr: ps.Addr().String(), tap: &sizeTap{}, key: []byte("pool-key")}
	srv := NewServer(Config{Key: r.key}, tapServer{ps, r.tap})
	srv.IdleTimeout = 5 * time.Second
	r.srv = srv
	stop := make(chan struct{})
	go func() {
		for {
			var s *Session
			select {
			case s = <-srv.New:
			case <-stop:
				return
			}
			go func(s *Session) { // datagram echo (TestHTTPCarriersDatagrams)
				for {
					select {
					case d := <-s.Datagrams():
						s.SendDatagram(d.Flow, d.Port, d.Data)
					case <-s.Done():
						return
					}
				}
			}(s)
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
	hr := &httpRig{poolRig: r, flavor: flavor, path: "/wat", stop: stop}
	t.Cleanup(hr.shut)
	return hr
}

func (r *httpRig) pio(t *testing.T) *TCPPoolClient {
	t.Helper()
	o := HTTPClientOptions{Path: r.path, Host: "cdn.example.com", Headers: map[string]string{"X-Test": "1"},
		Secure: r.flavor == "wss" || r.flavor == "h2" || r.flavor == "grpc", TLS: r.tlsOpt}
	var c *TCPPoolClient
	var err error
	switch r.flavor {
	case "ws", "wss":
		c, err = NewWSPoolClient(r.addr, 8, o)
	case "h2", "h2c":
		c, err = NewH2PoolClient(r.addr, 8, o)
	case "grpc":
		c, err = NewGRPCPoolClient(r.addr, 8, o)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *httpRig) client(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(Config{Key: r.key}, tapClient{r.pio(t), r.tap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestHTTPCarriersBulk(t *testing.T) {
	for _, f := range []string{"ws", "wss", "h2", "h2c", "grpc"} {
		t.Run(f, func(t *testing.T) {
			r := newHTTPRig(t, f)
			poolBulk(t, r.poolRig, r.client(t), 3<<20)
		})
	}
}

func TestWSManyStreams(t *testing.T) {
	r := newHTTPRig(t, "ws")
	cli := r.client(t)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			udpEcho(t, cli, 100+(i%10)*20000, byte(i))
		}(i)
	}
	waitOrFail(t, &wg, 9*time.Second)
}

func TestWSKillConnsMidTransfer(t *testing.T) {
	r := newHTTPRig(t, "ws")
	pio := r.pio(t)
	cli, err := NewSession(Config{Key: r.key}, pio)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	stop := make(chan struct{})
	go func() {
		for _, d := range []time.Duration{150, 400} {
			select {
			case <-time.After(d * time.Millisecond):
				r.ps.kill(3)
			case <-stop:
				return
			}
		}
	}()
	poolBulk(t, r.poolRig, cli, 4<<20)
	close(stop)
	deadline := time.Now().Add(5 * time.Second)
	for pio.Conns() < 8 || r.ps.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: client %d, server %d conns", pio.Conns(), r.ps.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWSNon404(t *testing.T) {
	r := newHTTPRig(t, "ws")
	base := "http://" + r.addr
	for _, p := range []string{"/", "/wat/x", "/other"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 404 // anything but the front page, like an nginx with its default site (3.0.2)
		if p == "/" {
			want = 200
		}
		if resp.StatusCode != want {
			t.Fatalf("GET %s = %d, want %d", p, resp.StatusCode, want)
		}
	}
	// the right path without upgrade headers looks the same, and so does an upgrade on the wrong path
	for _, p := range []string{"/wat", "/nope"} {
		req, _ := http.NewRequest("GET", base+p, nil)
		if p == "/nope" {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("GET %s = %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestHTTPNoGoroutineLeak(t *testing.T) {
	http.DefaultClient.CloseIdleConnections()
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	for _, f := range []string{"ws", "wss", "h2", "h2c", "grpc"} {
		r := newHTTPRig(t, f)
		cli := r.client(t)
		udpEcho(t, cli, 200000, 5)
		cli.Close()
		r.shut()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	var n int
	for i := 0; i < 50; i++ {
		if n = runtime.NumGoroutine(); n <= base+2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	t.Fatalf("goroutines %d, baseline %d\n%s", n, base, buf[:runtime.Stack(buf, true)])
}

func TestHTTPClientHostFallback(t *testing.T) {
	// Explicit Host takes priority
	o1 := HTTPClientOptions{Host: "custom.host", TLS: TLSClientOptions{ServerName: "sni.host"}}
	if got := o1.host("1.2.3.4:443"); got != "custom.host" {
		t.Fatalf("want custom.host, got %s", got)
	}

	// ServerName used when Host empty (prevents leaking raw peer IP to CDNs)
	o2 := HTTPClientOptions{TLS: TLSClientOptions{ServerName: "sni.host"}}
	if got := o2.host("1.2.3.4:443"); got != "sni.host" {
		t.Fatalf("want sni.host, got %s", got)
	}

	// Peer address used when both Host and ServerName empty
	o3 := HTTPClientOptions{}
	if got := o3.host("1.2.3.4:443"); got != "1.2.3.4:443" {
		t.Fatalf("want 1.2.3.4:443, got %s", got)
	}
}

// TestHTTPCarriersDatagrams: 30 datagrams of 800 B, echoed by the server, with no bulk traffic. The field (2.11.0)
// saw 13/30 on h2, 16/30 on grpc and 28/30 on h2c; on loopback every one must come back.
func TestHTTPCarriersDatagrams(t *testing.T) {
	for _, f := range []string{"ws", "wss", "h2", "h2c", "grpc"} {
		t.Run(f, func(t *testing.T) {
			r := newHTTPRig(t, f)
			cli, err := NewSession(Config{Key: r.key}, r.pio(t)) // the pool itself, as in production (the tap hides Backlogger)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cli.Close)
			seen, n := collect(cli)
			for i := 0; i < 30; i++ {
				if !cli.SendDatagram(1, 9000, dg(uint64(i), 800)) {
					t.Fatalf("datagram %d refused", i)
				}
				time.Sleep(20 * time.Millisecond)
			}
			deadline := time.Now().Add(3 * time.Second)
			for n.Load() < 30 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if got := n.Load(); got != 30 || dupes(seen) != 0 {
				var miss []int
				for i := 0; i < 30; i++ {
					if _, ok := seen.Load(uint64(i)); !ok {
						miss = append(miss, i)
					}
				}
				st := cli.Stats()
				t.Logf("missing %v", miss)
				t.Fatalf("%s: %d/30 echoed (dupes %d); client dropped=%d dgram_dropq=%d", f, got, dupes(seen), st.Dropped, st.DgramDropQueue)
			}
		})
	}
}

// TestHTTPCamouflageNginx verifies that probing an HTTP carrier server at / or an unknown path
// returns an authentic Nginx response with Server: nginx header and Nginx HTML.
func TestHTTPCamouflageNginx(t *testing.T) {
	ps, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Path: "/tunnel-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	addr := ps.Addr().String()
	res, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Server") != "nginx" {
		t.Fatalf("/ should return 200 with Server: nginx, got status %d header %q", res.StatusCode, res.Header.Get("Server"))
	}

	res404, err := http.Get("http://" + addr + "/unknown-scanner-path")
	if err != nil {
		t.Fatal(err)
	}
	defer res404.Body.Close()
	if res404.StatusCode != 404 || res404.Header.Get("Server") != "nginx" {
		t.Fatalf("scanner path should return 404 with Server: nginx, got status %d", res404.StatusCode)
	}
}

// TestHTTPDecoy: with -decoy every request that is not a tunnel request, the tunnel path without the upgrade
// headers included, is proxied to the decoy origin with its Host and no X-Forwarded-For (3.3.6).
func TestHTTPDecoy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" {
			t.Errorf("X-Forwarded-For leaked: %q", r.Header.Get("X-Forwarded-For"))
		}
		io.WriteString(w, "decoy "+r.Host+" "+r.URL.Path)
	}))
	defer origin.Close()
	if _, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Decoy: "ftp://x"}); err == nil {
		t.Fatal("accepted a non-http decoy")
	}
	ps, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Path: "/tunnel-secret", Decoy: origin.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	oh := strings.TrimPrefix(origin.URL, "http://")
	for _, p := range []string{"/unknown-scanner-path", "/tunnel-secret"} {
		res, err := http.Get("http://" + ps.Addr().String() + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if want := "decoy " + oh + " " + p; res.StatusCode != 200 || string(b) != want || res.Header.Get("Server") == "nginx" {
			t.Fatalf("%s: status %d body %q, want %q", p, res.StatusCode, b, want)
		}
	}
}

// TestRealisticSelfSignedCert verifies that throwaway certificates no longer leak CN=localhost or 10-year validity.
func TestRealisticSelfSignedCert(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x509Cert.Subject.CommonName == "localhost" {
		t.Fatal("self-signed cert must not use CN=localhost (active scanner fingerprint)")
	}
	days := int(x509Cert.NotAfter.Sub(x509Cert.NotBefore).Hours() / 24)
	if days > 100 {
		t.Fatalf("validity %d days is too long (scanner fingerprint), want standard ~90 days", days)
	}
}
