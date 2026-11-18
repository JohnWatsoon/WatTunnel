package wat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Client-side TLS tuning for the TLS-based carriers (tls, wss, h2, grpc), engine 2.2.0. Nothing here touches the
// wire format or the server: it only changes how the client's TLS ClientHello looks to a middlebox.
//
//	Fingerprint  which browser's ClientHello to imitate (utls), instead of Go's easily recognised one
//	ECH          Encrypted Client Hello: the real SNI travels inside the encrypted inner hello
//	Frag         split the ClientHello into small TCP segments
//
// Every TLS client path goes through tlsEngine, so each carrier gets the same behaviour and the ALPN is set per
// carrier: ws/wss must end up on http/1.1 (a CDN that picked h2 would not upgrade a WebSocket), h2/grpc must end up
// on h2, and the plain tls carrier keeps whatever the fingerprint offers.

// Fingerprint names accepted by -fp.
var fingerprintNames = []string{"go", "chrome", "firefox", "safari", "edge", "random"}

// NormFingerprint validates a -fp value ("" = go) and returns its canonical name.
func NormFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "go", nil
	}
	for _, n := range fingerprintNames {
		if s == n {
			return s, nil
		}
	}
	return "", fmt.Errorf("-fp must be one of %s, got %q", strings.Join(fingerprintNames, "|"), s)
}

func utlsID(fp string) utls.ClientHelloID {
	switch fp {
	case "chrome":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	}
	return utls.HelloChrome_Auto
}

// pinVerifier is the -tls-pin check, shared by the stdlib and utls configs.
func pinVerifier(pin []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("tls: no server certificate")
		}
		sum := sha256.Sum256(raw[0])
		if !bytes.Equal(sum[:], pin) {
			return errors.New("tls: server certificate does not match the pinned fingerprint")
		}
		return nil
	}
}

// ---------------------------------------------------------------- ClientHello fragmentation

// writeFragments writes p to w in chunks of n bytes with a short gap between them.
// When n < 0 (e.g. -1), it performs an intelligent split directly inside the TLS ClientHello SNI extension,
// so neither segment carries a parseable server_name field.
func writeFragments(w io.Writer, p []byte, n int, gap time.Duration) (int, error) {
	if n == 0 || len(p) == 0 {
		return w.Write(p)
	}
	if n < 0 {
		if off := sniExtOffset(p); off > 0 && off+10 < len(p) {
			cut := off + 10 // first letter of domain in segment 1, remainder in segment 2
			m1, err := w.Write(p[:cut])
			if err != nil {
				return m1, err
			}
			if gap > 0 {
				time.Sleep(gap)
			}
			m2, err := w.Write(p[cut:])
			return m1 + m2, err
		}
		n = 40 // fallback if no SNI extension is located
	}
	if len(p) <= n {
		return w.Write(p)
	}
	sent := 0
	for sent < len(p) {
		end := min(sent+n, len(p))
		m, err := w.Write(p[sent:end])
		sent += m
		if err != nil {
			return sent, err
		}
		if end < len(p) && gap > 0 {
			time.Sleep(gap)
		}
	}
	return sent, nil
}

// fragConn splits the first Write (the TLS ClientHello) into frag-byte TCP segments.
type fragConn struct {
	net.Conn
	frag  int
	gap   time.Duration
	first atomic.Bool
}

func newFragConn(c net.Conn, frag int) net.Conn {
	if frag == 0 {
		return c
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return &fragConn{Conn: c, frag: frag, gap: time.Millisecond}
}

func (f *fragConn) Write(p []byte) (int, error) {
	if f.first.CompareAndSwap(false, true) {
		return writeFragments(f.Conn, p, f.frag, f.gap)
	}
	return f.Conn.Write(p)
}

// ---------------------------------------------------------------- engine

// tlsEngine dials and handshakes TLS client connections for one pool client.
type tlsEngine struct {
	o     TLSClientOptions
	alpn  string // "" (keep the fingerprint's / none), "http/1.1" or "h2"
	fp    string // canonical fingerprint, "go" = the standard library
	uid   utls.ClientHelloID
	ech   *echState
	echOn atomic.Bool  // the newest connection used ECH
	mode  atomic.Value // string: how the newest successful connection was made, e.g. "chrome+ech+frag"
	logf  func(string, ...any)
	dialF func(ctx context.Context, addr string) (net.Conn, error) // test seam: the TCP dial

	notedMu sync.Mutex
	noted   map[string]bool
}

func newTLSEngine(o TLSClientOptions, alpn string) (*tlsEngine, error) {
	fp, err := NormFingerprint(o.Fingerprint)
	if err != nil {
		return nil, err
	}
	if o.Frag < -1 || o.Frag > 1<<14 {
		return nil, fmt.Errorf("-tls-frag must be -1..16384 (-1 = mid-SNI split), got %d", o.Frag)
	}
	e := &tlsEngine{o: o, alpn: alpn, fp: fp, logf: o.Logf, noted: map[string]bool{}}
	if fp == "random" { // one browser per process, like a real client sticks to its own
		fp = []string{"chrome", "firefox", "safari", "edge"}[rand.IntN(4)]
		e.fp = fp
	}
	e.uid = utlsID(fp)
	if e.ech, err = newECHState(o.ECH, o.ECHCache); err != nil {
		return nil, err
	}
	e.ech.ladder = o.ECHLadder // -ech ladder's second rung (2.9.0); nil = behave as auto
	return e, nil
}

func (e *tlsEngine) note(key, format string, a ...any) {
	if e.logf == nil {
		return
	}
	e.notedMu.Lock()
	seen := e.noted[key]
	e.noted[key] = true
	e.notedMu.Unlock()
	if !seen {
		e.logf(format, a...)
	}
}

// info is what /stats reports: the effective fingerprint and whether the newest connection used ECH.
func (e *tlsEngine) info() (fp, mode string, ech bool) {
	mode, _ = e.mode.Load().(string)
	if mode == "" { // no connection has succeeded yet: report what is configured, marked as such
		mode = e.fp
		if e.ech != nil && e.ech.mode != "off" {
			mode += "+ech"
		}
		if e.o.Frag != 0 {
			mode += "+frag"
		}
		mode += " (not connected yet)"
	}
	return e.fp, mode, e.echOn.Load()
}

func (e *tlsEngine) useUTLS() bool { return e.fp != "go" }

// sniFor is the name sent in the ClientHello for a connection to addr: the configured name, else the host part of
// addr when that is a name (not an IP), else none.
func (e *tlsEngine) sniFor(addr string) string {
	if e.o.ServerName != "" {
		return e.o.ServerName
	}
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	return h
}

// dial opens a TCP connection to addr and runs the TLS handshake, retrying once with the server's ECH retry
// configs when it rejected ours.
func (e *tlsEngine) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: e.o.LocalAddr}
	sni := e.sniFor(addr)
	for attempt := 0; ; attempt++ {
		list := e.ech.get(ctx, sni, e) // before the TCP dial: a slow lookup must not leave an idle connection waiting
		var raw net.Conn
		var err error
		if e.dialF != nil {
			raw, err = e.dialF(ctx, addr)
		} else {
			raw, err = d.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, err
		}
		if e.o.DialHook != nil {
			raw, err = e.o.DialHook(raw)
			if err != nil {
				raw.Close()
				return nil, err
			}
		}
		c, accepted, err := e.handshake(ctx, raw, sni, list)
		if err == nil {
			e.echOn.Store(accepted)
			m := e.fp
			if accepted {
				m += "+ech"
			}
			if e.o.Frag != 0 {
				m += "+frag"
			}
			e.mode.Store(m)
			return c, nil
		}
		raw.Close()
		if attempt == 0 && len(list) > 0 {
			var rej []byte
			var se *tls.ECHRejectionError
			var ue *utls.ECHRejectionError
			switch {
			case errors.As(err, &se):
				rej = se.RetryConfigList
			case errors.As(err, &ue):
				rej = ue.RetryConfigList
			default:
				return nil, err
			}
			if e.ech.rejected(sni, rej, e) {
				continue
			}
		}
		return nil, err
	}
}

func (e *tlsEngine) checkALPN(proto string) error {
	switch e.alpn {
	case "h2":
		if proto != "h2" {
			return fmt.Errorf("tls: server did not negotiate h2 (got %q); this carrier needs HTTP/2", proto)
		}
	case "http/1.1":
		if proto != "" && proto != "http/1.1" {
			return fmt.Errorf("tls: server negotiated %q, this carrier needs http/1.1", proto)
		}
	}
	return nil
}

func (e *tlsEngine) handshake(ctx context.Context, raw net.Conn, sni string, echList []byte) (net.Conn, bool, error) {
	c, ok, err := e.handshake1(ctx, raw, sni, echList)
	if err != nil && e.alpn != "" && strings.Contains(err.Error(), "application protocol") {
		err = fmt.Errorf("%w (this carrier needs %s, which the server does not offer)", err, e.alpn)
	}
	return c, ok, err
}

func (e *tlsEngine) handshake1(ctx context.Context, raw net.Conn, sni string, echList []byte) (net.Conn, bool, error) {
	conn := newFragConn(raw, e.o.Frag)
	if e.useUTLS() && (len(echList) == 0 || utlsECHWorks) {
		return e.handshakeUTLS(ctx, conn, sni, echList)
	}
	if e.useUTLS() {
		e.note("fp-ech", "tls: -fp %s is ignored while ECH is in use (the standard library does the handshake)", e.fp)
	}
	cfg := e.o.config()
	cfg.ServerName = sni
	if e.alpn != "" {
		cfg.NextProtos = []string{e.alpn}
	}
	if len(echList) > 0 {
		cfg.EncryptedClientHelloConfigList = echList
		if !e.o.Verify { // a rejected ECH is otherwise checked against the system roots whatever InsecureSkipVerify says
			// (the retry that follows is pinned like any connection; this certificate is the public name's)
			cfg.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }
		}
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, false, err
	}
	st := tc.ConnectionState()
	if err := e.checkALPN(st.NegotiatedProtocol); err != nil {
		tc.Close()
		return nil, false, err
	}
	return tc, st.ECHAccepted, nil
}

// utlsECHWorks says whether utls's own ECH support is used when -fp is not go and ECH is on (see tlsfp_test.go).
const utlsECHWorks = true

func (e *tlsEngine) handshakeUTLS(ctx context.Context, conn net.Conn, sni string, echList []byte) (net.Conn, bool, error) {
	cfg := &utls.Config{ServerName: sni, InsecureSkipVerify: !e.o.Verify}
	if len(e.o.PinSHA256) > 0 {
		cfg.VerifyPeerCertificate = pinVerifier(e.o.PinSHA256)
	}
	if len(echList) > 0 {
		cfg.EncryptedClientHelloConfigList = echList
		if !e.o.Verify {
			cfg.EncryptedClientHelloRejectionVerify = func(utls.ConnectionState) error { return nil }
		}
	}
	spec, err := utls.UTLSIdToSpec(e.uid)
	if err != nil {
		return nil, false, err
	}
	if e.o.NoPQ { // -tls-small-ch must hold under -fp too: the browser presets offer X25519MLKEM768, ~1.2 KB of key share
		stripPQ(&spec)
	}
	if e.alpn != "" {
		protos := []string{e.alpn}
		if e.alpn == "h2" {
			protos = []string{"h2", "http/1.1"}
		}
		found := false
		for _, x := range spec.Extensions {
			if a, ok := x.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = protos
				found = true
			}
		}
		if !found {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: protos})
		}
	}
	uc := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, false, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, false, err
	}
	st := uc.ConnectionState()
	if err := e.checkALPN(st.NegotiatedProtocol); err != nil {
		uc.Close()
		return nil, false, err
	}
	return uc, st.ECHAccepted, nil
}

// stripPQ removes the post-quantum hybrid groups (and their key shares) from a browser preset, so the hello stays
// classical like the stdlib path of -tls-small-ch. The padding extension is left alone: it only fills a short hello up
// to 512 bytes.
func stripPQ(spec *utls.ClientHelloSpec) {
	// 3.3.8: classic-curve ALLOWLIST, not a denylist. The old 3-ID list (X25519MLKEM768, X25519Kyber768Draft00,
	// X25519Kyber768Draft00Old) could not know about future PQ groups — Go 1.26 already ships
	// SecP256r1MLKEM768 (0x11eb) / SecP384r1MLKEM1024 (0x11ed) and utls has P256Kyber768Draft00 (0xfe32);
	// any of those leaking into a -no-pq hello bloats it past 1 KB again, which is exactly what
	// -no-pq exists to prevent (live test 2026-10-22: 1474 B hellos vanish, 250-512 B pass).
	pq := func(c utls.CurveID) bool {
		switch c {
		case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521:
			return false
		}
		return true
	}
	for _, x := range spec.Extensions {
		switch ext := x.(type) {
		case *utls.SupportedCurvesExtension:
			keep := ext.Curves[:0:0]
			for _, c := range ext.Curves {
				if !pq(c) {
					keep = append(keep, c)
				}
			}
			ext.Curves = keep
		case *utls.KeyShareExtension:
			keep := ext.KeyShares[:0:0]
			for _, ks := range ext.KeyShares {
				if !pq(ks.Group) {
					keep = append(keep, ks)
				}
			}
			ext.KeyShares = keep
		}
	}
}

// ---------------------------------------------------------------- peers

// SplitPeers splits a -peer value into its host:port addresses (comma separated, at least one).
func SplitPeers(peer string) ([]string, error) {
	var out []string
	for _, a := range strings.Split(peer, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("no peer address")
	}
	return out, nil
}

// peerSet orders the addresses a pool slot tries: slot i starts at address i%n (so the slots spread evenly), then the
// others in turn. An address that failed recently goes last, so a dead one costs a dial only when nothing else works;
// a slot moves on to the next address right after a dial error and backs off only when every address failed.
type peerSet struct {
	addrs []string
	mu    sync.Mutex
	fail  []time.Time // last failed dial per address
	up    []int8      // 0 never tried, 1 last dial worked, -1 last dial failed
}

const peerAvoid = 30 * time.Second

func newPeerSet(addrs []string) *peerSet {
	return &peerSet{addrs: addrs, fail: make([]time.Time, len(addrs)), up: make([]int8, len(addrs))}
}

// order lists the address indexes slot should try, in order.
func (p *peerSet) order(slot int) []int {
	n := len(p.addrs)
	p.mu.Lock()
	defer p.mu.Unlock()
	var good, bad []int
	for k := 0; k < n; k++ {
		i := (slot + k) % n
		if !p.fail[i].IsZero() && time.Since(p.fail[i]) < peerAvoid {
			bad = append(bad, i)
		} else {
			good = append(good, i)
		}
	}
	return append(good, bad...)
}

func (p *peerSet) mark(i int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		p.up[i], p.fail[i] = 1, time.Time{}
	} else {
		p.up[i], p.fail[i] = -1, time.Now()
	}
}

// EdgeStat is the health of one peer address of a pool client: Up is whether the last dial to it worked.
type EdgeStat struct {
	Addr string `json:"addr"`
	Up   bool   `json:"up"`
}

func (p *peerSet) edges() []EdgeStat {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]EdgeStat, len(p.addrs))
	for i, a := range p.addrs {
		out[i] = EdgeStat{a, p.up[i] == 1}
	}
	return out
}
