package wat

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// CDN-compatible carriers: ws/wss (WebSocket), h2/h2c (one full-duplex HTTP/2 POST per pool connection) and grpc
// (the same with gun-style gRPC framing). Each is only a stream transport for the tcp pool: the client side is a
// PoolDialFunc, the server side a net.Listener that hands accepted streams to the pool server, so queueing, drop,
// redial and pool grouping are the tcp pool's. HTTP/2 uses the standard library's built-in implementation (no new
// module dependency).

// HTTPClientOptions configures the ws/h2/grpc client carriers.
type HTTPClientOptions struct {
	Path     string                           // request path (grpc: the service name, the request goes to <Path>/Tun)
	Host     string                           // Host header / :authority (default: the peer address)
	Headers  map[string]string                // extra request headers
	Secure   bool                             // TLS (wss, h2, grpc over TLS); false = ws, h2c
	DialHook func(net.Conn) (net.Conn, error) // dial hook on raw TCP socket before TLS/framing (fake-SNI)
	TLS      TLSClientOptions
}

// HTTPServerOptions configures the ws/h2/grpc server carriers.
type HTTPServerOptions struct {
	Path     string
	Secure   bool   // serve TLS
	CertFile string // empty with KeyFile empty = self-signed in memory
	KeyFile  string
	Decoy    string // http(s) URL every non-tunnel request is reverse-proxied to (3.3.6); empty = the nginx pages
}

func normPath(p string) string {
	if p == "" {
		p = "/wat"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func (o HTTPClientOptions) host(peer string) string {
	if o.Host != "" {
		return o.Host
	}
	if o.TLS.ServerName != "" {
		return o.TLS.ServerName
	}
	return peer
}

// engine is the TLS client for this carrier: SNI from -sni, else the Host name, ALPN fixed per carrier.
func (o HTTPClientOptions) engine(alpn string) (*tlsEngine, error) {
	t := o.TLS
	if t.DialHook == nil && o.DialHook != nil {
		t.DialHook = o.DialHook
	}
	if t.ServerName == "" && o.Host != "" {
		t.ServerName, _, _ = strings.Cut(o.Host, ":")
	}
	return newTLSEngine(t, alpn)
}

// ---------------------------------------------------------------- websocket

// NewWSPoolClient is the ws (o.Secure false) or wss pool client. The TLS side asks for http/1.1 only: a CDN that
// picked h2 could not upgrade the connection to a WebSocket.
func NewWSPoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	addrs, err := SplitPeers(peer)
	if err != nil {
		return nil, err
	}
	path := normPath(o.Path)
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: o.TLS.LocalAddr}
	var eng *tlsEngine
	if o.Secure {
		if eng, err = o.engine("http/1.1"); err != nil {
			return nil, err
		}
	}
	c, err := newSlotClient(addrs, conns, func(ctx context.Context, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var c net.Conn
		var err error
		if eng != nil {
			c, err = eng.dial(ctx, addr)
		} else {
			c, err = d.DialContext(ctx, "tcp", addr)
			if err == nil && o.DialHook != nil {
				c, err = o.DialHook(c)
			}
		}
		if err != nil {
			return nil, err
		}
		w, err := wsClientHandshake(ctx, c, o.host(addr), path, o.Secure, o.Headers)
		if err != nil {
			c.Close()
			return nil, err
		}
		return w, nil
	})
	if c != nil && eng != nil {
		c.tlsFn = eng.info
	}
	return c, err
}

// NewWSPoolServer serves the pool over WebSocket on o.Path; any other request gets the nginx pages (or o.Decoy).
func NewWSPoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	path := normPath(o.Path)
	return newHTTPPoolServer(addr, o, func(l *httpListener) http.Handler {
		return pathMux(path, l.decoy, func(w http.ResponseWriter, r *http.Request) bool {
			c, ok := wsServerUpgrade(w, r)
			if c != nil {
				l.push(c)
			}
			return ok
		})
	})
}

// ---------------------------------------------------------------- listener that serves an http.Server

// httpListener is the net.Listener the pool server accepts from: HTTP handlers push finished streams into it.
type httpListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
	srv  *http.Server
	wg   sync.WaitGroup

	decoy http.Handler // non-nil with HTTPServerOptions.Decoy: answers every request that is not ours
	once  sync.Once
}

func (l *httpListener) push(c net.Conn) {
	// The 30 s bound (not a shorter one): closing here kills a FINISHED stream, so the session
	// resends everything it held and the client redials — amplifying the very overload that
	// stalled the consumer. 30 s exceeds any legitimate accept stall; a genuinely stuck server
	// still reclaims the conn and the slot (audit 2026-10-22).
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	case <-time.After(30 * time.Second):
		c.Close()
	}
}

func (l *httpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *httpListener) Addr() net.Addr { return l.addr }

func (l *httpListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.srv.Close()
		l.wg.Wait()
	})
	return nil
}

const (
	nginxWelcomeHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
	nginx404HTML = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`
)

// pathMux answers path with h (which returns false when the request is not ours) and everything else, and anything
// h refuses, with the default pages of an nginx with server_tokens off (the same 200 at / and 404 elsewhere), so a prober that asks for a web page finds a web server.
// A non-nil decoy answers all of those instead (3.3.6).
func pathMux(path string, decoy http.Handler, h func(http.ResponseWriter, *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && h(w, r) {
			return
		}
		if decoy != nil {
			decoy.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, nginxWelcomeHTML)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, nginx404HTML)
	})
}

// decoyProxy reverse-proxies to raw: Host rewritten to the decoy's, no X-Forwarded-* added, 10 s to connect and to
// the response headers, the body streamed as it arrives.
func decoyProxy(raw string) (http.Handler, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("decoy must be an http:// or https:// URL with a host, got %q", raw)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(u) },
		Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second},
		ErrorLog: log.New(io.Discard, "", 0),
	}, nil
}

func newHTTPPoolServer(addr string, o HTTPServerOptions, mk func(*httpListener) http.Handler) (*TCPPoolServer, error) {
	var cert tls.Certificate
	var err error
	var decoy http.Handler
	if o.Decoy != "" {
		if decoy, err = decoyProxy(o.Decoy); err != nil {
			return nil, err
		}
	}
	if o.Secure {
		if o.CertFile != "" || o.KeyFile != "" {
			cert, err = tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		} else {
			cert, err = SelfSignedCert()
		}
		if err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &httpListener{ch: make(chan net.Conn, 64), done: make(chan struct{}), addr: ln.Addr(), decoy: decoy}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetHTTP2(o.Secure)
	protos.SetUnencryptedHTTP2(!o.Secure)
	l.srv = &http.Server{Handler: mk(l), ReadHeaderTimeout: 10 * time.Second, Protocols: &protos,
		// Go's default 1 MB receive window per stream caps one h2 pool conn at ~11 MB/s on a 90 ms path (field 2026-10-27:
		// forward h2/grpc upload 19-24 MB/s, reverse download 32, against 37-49 for tcp/tls/ws).
		HTTP2:    &http.HTTP2Config{MaxReceiveBufferPerStream: 8 << 20, MaxReceiveBufferPerConnection: 32 << 20},
		ErrorLog: log.New(io.Discard, "", 0)}
	var serve func() error
	if o.Secure {
		l.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		serve = func() error { return l.srv.ServeTLS(ln, "", "") }
	} else {
		serve = func() error { return l.srv.Serve(ln) }
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// The HTTP server died (accept failure, TLS misconfig): close the pool listener so Accept
			// returns net.ErrClosed instead of blocking forever on a listener nothing feeds (audit
			// 2026-10-22: the error used to be discarded and the carrier looked up but never worked).
			log.Printf("wat: %s http pool server failed: %v", l.addr, err)
			l.Close()
		}
	}()
	return newPoolServer(l), nil
}

// ---------------------------------------------------------------- h2 / grpc stream

type h2Addr struct{ s string }

func (a h2Addr) Network() string { return "h2" }
func (a h2Addr) String() string  { return a.s }

// h2Conn adapts one HTTP/2 request/response pair to a net.Conn: Read is the peer's body, Write the own body.
type h2Conn struct {
	r       io.Reader
	w       io.Writer
	flush   func()
	closeFn func()
	mu      sync.Mutex // serialises Write against the handler returning
	closed  atomic.Bool
	done    chan struct{}
	local   net.Addr
	remote  net.Addr
	timer   atomic.Pointer[time.Timer]
}

func newH2Conn(r io.Reader, w io.Writer, flush, closeFn func(), local, remote net.Addr) *h2Conn {
	return &h2Conn{r: r, w: w, flush: flush, closeFn: closeFn, done: make(chan struct{}), local: local, remote: remote}
}

func (c *h2Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *h2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.w.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *h2Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.done)
		if c.closeFn != nil {
			c.closeFn()
		}
	}
	return nil
}

func (c *h2Conn) LocalAddr() net.Addr  { return c.local }
func (c *h2Conn) RemoteAddr() net.Addr { return c.remote }
func (c *h2Conn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline only supports what the pool needs: a bound on the hello. Expiry closes the stream.
func (c *h2Conn) SetReadDeadline(t time.Time) error {
	if old := c.timer.Swap(nil); old != nil {
		old.Stop()
	}
	if !t.IsZero() {
		c.timer.Store(time.AfterFunc(time.Until(t), func() { c.Close() }))
	}
	return nil
}
func (c *h2Conn) SetWriteDeadline(time.Time) error { return nil }

// wait blocks the server handler until the stream is closed (locally or by the peer), then waits briefly for an
// in-flight Write so the ResponseWriter is never used after the handler returns.
func (c *h2Conn) wait(ctx context.Context) {
	select {
	case <-c.done:
	case <-ctx.Done():
		c.Close()
	}
	locked := make(chan struct{})
	go func() { c.mu.Lock(); c.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
	}
}

// ---------------------------------------------------------------- h2 client / server

// h2 (and h2c) through a CDN such as Cloudflare does not work: the carrier is one full-duplex streaming POST whose
// response headers only arrive once the server has seen the request, but Cloudflare talks HTTP/1.1 to the origin
// (except for gRPC) and buffers the request body until it ends, so the call never completes. Not fixable on our
// side; use grpc (Cloudflare streams it when the zone has gRPC enabled) or wss.
func newH2Client(peer string, conns int, o HTTPClientOptions, grpc bool) (*TCPPoolClient, error) {
	addrs, err := SplitPeers(peer)
	if err != nil {
		return nil, err
	}
	path := normPath(o.Path)
	if grpc {
		path += "/Tun"
	}
	scheme := "http"
	var eng *tlsEngine
	if o.Secure {
		scheme = "https"
		if eng, err = o.engine("h2"); err != nil {
			return nil, err
		}
	}
	c, err := newSlotClient(addrs, conns, func(ctx context.Context, addr string) (net.Conn, error) {
		url, host := scheme+"://"+addr+path, o.host(addr)
		var rt http.RoundTripper
		var closeTr func()
		var tcpConn atomic.Pointer[net.Conn]
		if eng != nil && eng.useUTLS() {
			// utls connections are not *tls.Conn, which net/http needs to see to speak h2 over them; the x/net
			// HTTP/2 transport has no such limit. The engine has already insisted on ALPN h2.
			tr := &http2.Transport{DialTLSContext: func(ctx context.Context, _, a string, _ *tls.Config) (net.Conn, error) {
				c, err := eng.dial(ctx, a)
				if err == nil {
					tcpConn.Store(&c)
				}
				return c, err
			}}
			rt, closeTr = tr, func() {
				tr.CloseIdleConnections()
				if cp := tcpConn.Load(); cp != nil {
					(*cp).Close()
				}
			}
		} else {
			var protos http.Protocols
			protos.SetHTTP2(o.Secure)
			protos.SetUnencryptedHTTP2(!o.Secure)
			dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: o.TLS.LocalAddr}
			tr := &http.Transport{Protocols: &protos, DisableKeepAlives: true, ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, netw, a string) (net.Conn, error) {
					c, err := dialer.DialContext(ctx, netw, a)
					if err != nil {
						return nil, err
					}
					if o.DialHook != nil {
						return o.DialHook(c)
					}
					return c, nil
				}}
			if eng != nil {
				tr.DialTLSContext = func(ctx context.Context, _, a string) (net.Conn, error) { return eng.dial(ctx, a) }
			}
			rt, closeTr = tr, tr.CloseIdleConnections
		}
		rctx, cancel := context.WithCancel(ctx)
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(rctx, "POST", url, pr)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Host, req.ContentLength = host, -1
		for k, v := range o.Headers {
			req.Header.Set(k, v)
		}
		if grpc {
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
		} else {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		t := time.AfterFunc(10*time.Second, cancel) // bounds the connect; headers arrive as soon as the server accepts
		resp, err := (&http.Client{Transport: rt}).Do(req)
		if !t.Stop() && err == nil {
			err = context.DeadlineExceeded
		}
		if err == nil && resp.StatusCode != 200 {
			resp.Body.Close()
			err = errors.New("h2: server answered " + resp.Status)
		}
		if err != nil {
			cancel()
			pw.Close()
			closeTr()
			return nil, err
		}
		var rd io.Reader = resp.Body
		var wr io.Writer = pw
		c := newH2Conn(rd, wr, nil, func() {
			pw.CloseWithError(io.EOF)
			cancel()
			resp.Body.Close()
			closeTr()
		}, h2Addr{"client"}, h2Addr{addr})
		if grpc {
			return newGRPCConn(c), nil
		}
		return c, nil
	})
	if c != nil && eng != nil {
		c.tlsFn = eng.info
	}
	return c, err
}

// NewH2PoolClient is the h2 (o.Secure) or h2c pool client: every pool connection is one POST on its own TCP connection.
func NewH2PoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	return newH2Client(peer, conns, o, false)
}

// NewGRPCPoolClient is NewH2PoolClient with gun-style gRPC framing on path <Path>/Tun.
func NewGRPCPoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	return newH2Client(peer, conns, o, true)
}

func h2Server(addr string, o HTTPServerOptions, grpc bool) (*TCPPoolServer, error) {
	path := normPath(o.Path)
	if grpc {
		path += "/Tun"
	}
	return newHTTPPoolServer(addr, o, func(l *httpListener) http.Handler {
		return pathMux(path, l.decoy, func(w http.ResponseWriter, r *http.Request) bool {
			fl, ok := w.(http.Flusher)
			if !ok || r.Method != "POST" || r.ProtoMajor < 2 {
				return false
			}
			if grpc {
				if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
					return false
				}
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status")
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(200)
			fl.Flush()
			ra, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
			var rem net.Addr = h2Addr{r.RemoteAddr}
			if ra != nil {
				rem = ra
			}
			c := newH2Conn(r.Body, w, fl.Flush, nil, l.addr, rem)
			var sc net.Conn = c
			if grpc {
				sc = newGRPCConn(c)
			}
			l.push(sc)
			c.wait(r.Context())
			if grpc {
				w.Header().Set("Grpc-Status", "0")
			}
			return true
		})
	})
}

// NewH2PoolServer serves the pool over HTTP/2 POST streams on o.Path (h2c unless o.Secure).
func NewH2PoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	return h2Server(addr, o, false)
}

// NewGRPCPoolServer serves the pool as a gun-style gRPC service at <Path>/Tun.
func NewGRPCPoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	return h2Server(addr, o, true)
}

// ---------------------------------------------------------------- grpc framing

const grpcMaxMsg = 1 << 20

// grpcWriteMsg is the largest gRPC message one Write emits. The pool hands the carrier up to 64 KB per flush, so 32 KB
// means two messages (two HTTP/2 DATA writes) per flush. WAT_GRPC_MSG (bytes, 4 KB-1 MB, 3.0.0) overrides it for an
// A/B against the weak grpc download; any peer accepts up to grpcMaxMsg.
var grpcWriteMsg = func() int {
	if n, err := strconv.Atoi(os.Getenv("WAT_GRPC_MSG")); err == nil && n >= 4<<10 && n <= grpcMaxMsg-16 {
		return n
	}
	return 32 << 10
}()

// grpcConn wraps a net.Conn so Write emits gRPC messages (flag 0, uint32 length, protobuf field 1 = the bytes, as
// Xray's gun Hunk) and Read unwraps them.
type grpcConn struct {
	net.Conn
	br   *bufio.Reader
	rem  []byte
	mu   sync.Mutex
	wbuf []byte // message assembly, reused under mu
	rbuf []byte // message receive buffer, reused once rem is consumed (Read is never called concurrently)
}

func newGRPCConn(c net.Conn) *grpcConn {
	return &grpcConn{Conn: c, br: bufio.NewReaderSize(c, poolBufSize)}
}

func (g *grpcConn) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := min(len(p), grpcWriteMsg)
		var vb [binary.MaxVarintLen32]byte
		vl := binary.PutUvarint(vb[:], uint64(n))
		pb := 1 + vl + n
		g.mu.Lock()
		buf := g.wbuf[:0]
		buf = append(buf, 0)
		buf = binary.BigEndian.AppendUint32(buf, uint32(pb))
		buf = append(buf, 0x0a)
		buf = append(buf, vb[:vl]...)
		buf = append(buf, p[:n]...)
		g.wbuf = buf[:0]
		_, err := g.Conn.Write(buf)
		g.mu.Unlock()
		if err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

func (g *grpcConn) Read(p []byte) (int, error) {
	for len(g.rem) == 0 {
		var h [5]byte
		if _, err := io.ReadFull(g.br, h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[1:])
		if h[0] != 0 || n > grpcMaxMsg {
			return 0, errors.New("grpc: bad message")
		}
		if n == 0 {
			continue
		}
		// The hunk is 0x0a, a varint length and the bytes. The payload goes straight into the caller's buffer
		// when it fits (v2.4.0): no staging copy per message.
		pre, err := g.br.Peek(min(int(n), 1+binary.MaxVarintLen32))
		if err != nil {
			return 0, err
		}
		if pre[0] != 0x0a {
			return 0, errors.New("grpc: unexpected field")
		}
		l, vn := binary.Uvarint(pre[1:])
		if vn <= 0 || uint64(n)-1-uint64(vn) != l {
			return 0, errors.New("grpc: bad hunk")
		}
		g.br.Discard(1 + vn)
		if l == 0 {
			continue
		}
		if int(l) <= len(p) {
			if _, err := io.ReadFull(g.br, p[:l]); err != nil {
				return 0, err
			}
			return int(l), nil
		}
		var msg []byte
		if l <= 64<<10 { // our own messages are <= 32 KiB; a larger one is not worth keeping a buffer for
			if uint32(cap(g.rbuf)) < uint32(l) {
				g.rbuf = make([]byte, 64<<10)
			}
			msg = g.rbuf[:l]
		} else {
			msg = make([]byte, l)
		}
		if _, err := io.ReadFull(g.br, msg); err != nil {
			return 0, err
		}
		g.rem = msg
	}
	n := copy(p, g.rem)
	g.rem = g.rem[n:]
	return n, nil
}
