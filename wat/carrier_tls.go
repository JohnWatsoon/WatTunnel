package wat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// The tls carrier is the tcp pool with every connection wrapped in TLS 1.3, so the traffic looks like HTTPS to a
// middlebox. It adds no security of its own: the session already authenticates every datagram with the PSK, which is
// why the client skips chain verification by default (pin a certificate fingerprint to also authenticate the server).

// TLSClientOptions tunes the client side of the tls carrier.
type TLSClientOptions struct {
	ServerName string // SNI sent in the ClientHello
	Verify     bool   // verify the server certificate chain (default: off, the PSK authenticates the peer)
	PinSHA256  []byte // if set, the server's leaf certificate DER must hash to this

	// Client-side tuning, engine 2.2.0 (the server and the wire format are unchanged); see tlsfp.go and ech.go.
	Fingerprint string                           // go (default), chrome, firefox, safari, edge, random
	ECH         string                           // off (default), auto, ladder, or a base64 ECHConfigList
	ECHCache    string                           // ech auto: file keeping the last good ECHConfigList across restarts (2.2.3)
	ECHLadder   func([]byte) ([]byte, error)     // ech ladder (2.9.0): raw DNS query in, answer out, through the tunnel
	DialHook    func(net.Conn) (net.Conn, error) // dial hook on the raw TCP socket before TLS handshake (fake-SNI)
	LocalAddr   net.Addr                         // client local address for multi-homing / dual-WAN bonding
	Frag        int                              // split the ClientHello into this many bytes per TCP segment (0 = off)
	NoPQ        bool                             // skip the post-quantum hybrid key share, keeping the ClientHello small (2.10.4; also under -fp chrome|edge, 2.10.8)
	Logf        func(string, ...any)             // optional: one-time notes (ECH lookups, fallbacks)
}

func (o TLSClientOptions) config() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: o.ServerName, InsecureSkipVerify: !o.Verify}
	if o.NoPQ {
		// Go 1.24+ offers X25519MLKEM768 by default, which makes the ClientHello ~1.5 KB. Some DPIs
		// drop such large hellos outright (measured on a live Iranian path 2026-10-22: 1474 B and
		// 1812 B hellos vanished while 250-512 B ones passed untouched), so this keeps the offer
		// classical for paths where a small hello is the difference between blocked and connected.
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	if len(o.PinSHA256) > 0 {
		cfg.VerifyPeerCertificate = pinVerifier(o.PinSHA256)
	}
	return cfg
}

// NewTLSPoolClient is NewTCPPoolClient with TLS 1.3 on every connection.
func NewTLSPoolClient(peer string, conns int, o TLSClientOptions) (*TCPPoolClient, error) {
	addrs, err := SplitPeers(peer)
	if err != nil {
		return nil, err
	}
	// No ALPN of our own: the tls carrier's server has none, so a fingerprint keeps the browser's offer.
	eng, err := newTLSEngine(o, "")
	if err != nil {
		return nil, err
	}
	c, err := newSlotClient(addrs, conns, func(ctx context.Context, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return eng.dial(ctx, addr)
	})
	if c != nil {
		c.tlsFn = eng.info
	}
	return c, err
}

// NewTLSPoolServer listens on addr with the given certificate and key files; empty files mean a fresh in-memory
// self-signed ECDSA certificate.
func NewTLSPoolServer(addr, certFile, keyFile string) (*TCPPoolServer, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" || keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	} else {
		cert, err = SelfSignedCert()
	}
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newPoolServer(tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})), nil
}

// SelfSignedCert makes an ECDSA P-256 certificate with realistic 90-day validity.
func SelfSignedCert() (tls.Certificate, error) {
	return SelfSignedCertDomain("")
}

// randomHost is a throwaway hostname like "kdmqzvtoa.com": a certificate that names a real site's domain or
// organization would claim an identity it cannot prove, and a fixed name is itself a fingerprint.
func randomHost() string {
	var b [16]byte
	crand.Read(b[:])
	n := 7 + int(b[0])%5
	name := make([]byte, n)
	for i := range name {
		name[i] = 'a' + b[1+i]%26
	}
	return string(name) + [...]string{".com", ".net", ".org", ".io"}[b[15]%4]
}

// SelfSignedCertDomain builds a throwaway certificate for domain (a random hostname when empty), valid 90 days, no
// localhost name and no organization.
func SelfSignedCertDomain(domain string) (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return tls.Certificate{}, err
	}
	if domain == "" {
		domain = randomHost()
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: domain},
		DNSNames:  []string{domain},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}
