package panel

// Certificate tiers (plan D5). 1: self-signed, made on first start, never needs the network (default). 2: the
// owner's own PEM pair (a Cloudflare origin certificate, one from certbot elsewhere). 3: ACME for a domain,
// best effort, run only when the owner asks: it binds port 80 for the seconds of the check (the one opt-in
// exception to "no common ports") and keeps the working certificate when it fails. 4: a private CA limited by
// an X.509 name constraint to this server's own IPs, so installing it on a phone removes the warning without
// letting it vouch for any other site. The listener reads the certificate through GetCertificate, so every
// change takes effect without a restart.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

type certStore struct {
	mu                  sync.Mutex
	cert                *tls.Certificate
	notAfter, notBefore time.Time
}

func (c *certStore) load(certFile, keyFile string) error {
	kp, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cert, c.notAfter, c.notBefore = &kp, leaf.NotAfter, leaf.NotBefore
	c.mu.Unlock()
	return nil
}

func (c *certStore) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert, nil
}

// renewDue: less than a third of the certificate's lifetime is left (30 of 90 days, 2 of 6 for an IP).
func (c *certStore) renewDue(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.notAfter.Sub(now) < c.notAfter.Sub(c.notBefore)/3
}

func (c *certStore) lifetime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.notAfter.Sub(c.notBefore)
}

func (c *certStore) expires() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.notAfter
}

// CertInfo is what Settings shows about the certificate in use.
type CertInfo struct {
	Kind        string    `json:"kind"`
	Subject     string    `json:"subject"`
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	HasCA       bool      `json:"has_ca"`
}

func certInfo(cfg *Config) CertInfo {
	ci := CertInfo{Kind: cfg.CertKind, Fingerprint: CertFingerprint(cfg.CertFile)}
	if b, err := os.ReadFile(cfg.CertFile); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				ci.Subject, ci.Issuer, ci.NotAfter = c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter
				ci.Names = append(ci.Names, c.DNSNames...)
				for _, ip := range c.IPAddresses {
					ci.Names = append(ci.Names, ip.String())
				}
			}
		}
	}
	_, err := os.Stat(caFile(cfg))
	ci.HasCA = err == nil
	return ci
}

func confDir(cfg *Config) string { return filepath.Dir(cfg.file) }
func caFile(cfg *Config) string  { return filepath.Join(confDir(cfg), ".panel-ca.crt") }

// useOwnerCert checks and installs the owner's PEM pair (tier 2).
func useOwnerCert(cfg *Config, certPEM, keyPEM []byte) error {
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("the certificate and key do not match or do not parse: %v", err)
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("that certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	return installPair(cfg, "owner", certPEM, keyPEM)
}

// installPair writes a pair next to panel.conf and points the config at it.
func installPair(cfg *Config, kind string, certPEM, keyPEM []byte) error {
	dir := confDir(cfg)
	cf, kf := filepath.Join(dir, ".panel-"+kind+".crt"), filepath.Join(dir, ".panel-"+kind+".key")
	if err := os.WriteFile(kf+".tmp", keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cf+".tmp", certPEM, 0o644); err != nil {
		return err
	}
	if err := os.Rename(kf+".tmp", kf); err != nil {
		return err
	}
	if err := os.Rename(cf+".tmp", cf); err != nil {
		return err
	}
	cfg.CertFile, cfg.KeyFile, cfg.CertKind = cf, kf, kind
	return nil
}

// useSelfSigned goes back to tier 1 (the self-signed pair made on first start, remade if missing).
func useSelfSigned(cfg *Config) error {
	dir := confDir(cfg)
	cfg.CertFile, cfg.KeyFile, cfg.CertKind, cfg.ACMEName = filepath.Join(dir, ".panel.crt"), filepath.Join(dir, ".panel.key"), "self", ""
	return EnsureCert(cfg.CertFile, cfg.KeyFile, localIPs())
}

func newKey() (*ecdsa.PrivateKey, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

// usePrivateCA makes (or reuses) a CA that may only vouch for IPS, then a server certificate it signs (tier 4).
// The CA's name is the panel title, never the product name.
func usePrivateCA(cfg *Config, ips []net.IP) error {
	if len(ips) == 0 {
		return errors.New("this server has no public IP to put in the certificate")
	}
	dir := confDir(cfg)
	caCrt, caKey := caFile(cfg), filepath.Join(dir, ".panel-ca.key")
	var ca *x509.Certificate
	var caPriv *ecdsa.PrivateKey
	if b, err := os.ReadFile(caCrt); err == nil {
		kb, kerr := os.ReadFile(caKey)
		cb, _ := pem.Decode(b)
		kbl, _ := pem.Decode(kb)
		if kerr == nil && cb != nil && kbl != nil {
			ca, _ = x509.ParseCertificate(cb.Bytes)
			caPriv, _ = x509.ParseECPrivateKey(kbl.Bytes)
		}
	}
	if ca == nil || caPriv == nil || !sameIPs(ca.PermittedIPRanges, ips) {
		k, kp, err := newKey()
		if err != nil {
			return err
		}
		var ranges []*net.IPNet
		for _, ip := range ips {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
		tpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: cfg.Title + " CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
			MaxPathLenZero: true, PermittedIPRanges: ranges, PermittedDNSDomainsCritical: true,
			PermittedDNSDomains: []string{"invalid"}, // no DNS names at all: only the IPs above
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			return err
		}
		if err := os.WriteFile(caKey, kp, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(caCrt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return err
		}
		ca, _ = x509.ParseCertificate(der)
		caPriv = k
	}
	k, kp, err := newKey()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: ips[0].String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 397), // browsers cap leaf life
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caPriv)
	if err != nil {
		return err
	}
	return installPair(cfg, "ca", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), kp)
}

func sameIPs(r []*net.IPNet, ips []net.IP) bool {
	if len(r) != len(ips) {
		return false
	}
	for i := range r {
		if !r[i].IP.Equal(ips[i]) {
			return false
		}
	}
	return true
}

// acmeHTTPAddr is where the HTTP-01 check is answered, acmeALPNAddr the TLS-ALPN-01 check when port 80 is taken
// (on an Iran server a tunnel often forwards :80); a test points them elsewhere.
var (
	acmeHTTPAddr = ":80"
	acmeALPNAddr = ":443"
)

// acmeDirectory is Let's Encrypt production; a test points it at a fake.
var acmeDirectory = acme.LetsEncryptURL

// useACME gets a certificate for DOMAIN with the HTTP-01 check (tier 3), or the TLS-ALPN-01 check on port 443 when
// port 80 is taken. The port is bound only while the check runs. On any failure the current certificate stays.
func useACME(ctx context.Context, cfg *Config, domain string, say func(string, ...any)) error {
	ip := net.ParseIP(domain)
	ids, opts := acme.DomainIDs(domain), []acme.OrderOption(nil)
	if ip != nil {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return errors.New("an IP certificate needs this server's public IP")
		}
		// Let's Encrypt issues IP certificates only under its 6-day "shortlived" profile; the scheduler renews
		// at a third of the lifetime left, so it renews about every 4 days.
		ids, opts = acme.IPIDs(domain), []acme.OrderOption{acme.WithOrderIssuanceProfile("shortlived")}
	}
	tokens := sync.Map{}                         // http-01: path -> key authorization
	var alpnCert atomic.Pointer[tls.Certificate] // tls-alpn-01: the one challenge certificate
	kind, port := "http-01", "80"
	ln, err := net.Listen("tcp", acmeHTTPAddr)
	if err == nil {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v, ok := tokens.Load(r.URL.Path); ok {
				w.Write([]byte(v.(string)))
				return
			}
			notFound(w, r)
		}), ReadHeaderTimeout: 5 * time.Second}
		go srv.Serve(ln)
		defer srv.Close()
	} else {
		e80 := err
		kind, port = "tls-alpn-01", "443"
		if ln, err = net.Listen("tcp", acmeALPNAddr); err != nil {
			return fmt.Errorf("ports 80 and 443 are both busy (%v; %v): the check needs one of them for a few seconds. Free one (stop the tunnel port on it for a minute), or use your own certificate", e80, err)
		}
		tl := tls.NewListener(ln, &tls.Config{NextProtos: []string{acme.ALPNProto}, MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c := alpnCert.Load(); c != nil {
					return c, nil
				}
				return nil, errors.New("no check running")
			}})
		go func() {
			for {
				c, err := tl.Accept()
				if err != nil {
					return
				}
				go func() { // the handshake is the whole check
					c.SetDeadline(time.Now().Add(10 * time.Second))
					c.(*tls.Conn).Handshake()
					c.Close()
				}()
			}
		}()
		defer tl.Close()
	}
	say("Port %s is open for the check.", port)

	ak, _, err := newKey()
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: ak, DirectoryURL: acmeDirectory}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("the certificate service did not answer: %v", err)
	}
	order, err := cl.AuthorizeOrder(ctx, ids, opts...)
	if err != nil {
		return err
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == kind {
				ch = c
			}
		}
		if ch == nil {
			return fmt.Errorf("the certificate service offered no %s check", kind)
		}
		body, err := cl.HTTP01ChallengeResponse(ch.Token) // the key authorization, for either check
		if err != nil {
			return err
		}
		if kind == "http-01" {
			tokens.Store(cl.HTTP01ChallengePath(ch.Token), body)
		} else {
			c, err := alpnChallengeCert(body, domain)
			if err != nil {
				return err
			}
			alpnCert.Store(&c)
		}
		say("Asking the certificate service to check %s ...", domain)
		if _, err := cl.Accept(ctx, ch); err != nil {
			return err
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("the check failed (does %s point at this server, and is port %s open in the firewall?): %v", domain, port, err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	k, kp, err := newKey()
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrFor(domain), k)
	if err != nil {
		return err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	var chain []byte
	for _, d := range ders {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	if err := installPair(cfg, "acme", chain, kp); err != nil {
		return err
	}
	cfg.ACMEName = domain
	say("Certificate issued for %s.", domain)
	return nil
}

// alpnChallengeCert is the TLS-ALPN-01 certificate (RFC 8737): self-signed for NAME (a DNS name, or an IP as RFC
// 8738 allows), with the critical acmeIdentifier extension holding SHA-256 of the key authorization. Built here
// because acme.TLSALPN01ChallengeCert puts every name in DNSNames, which an IP check refuses.
func alpnChallengeCert(keyAuth, name string) (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	ext, err := asn1.Marshal(sum[:])
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}, Critical: true, Value: ext}}}
	if ip := net.ParseIP(name); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func csrFor(name string) *x509.CertificateRequest {
	if ip := net.ParseIP(name); ip != nil {
		return &x509.CertificateRequest{IPAddresses: []net.IP{ip}}
	}
	return &x509.CertificateRequest{DNSNames: []string{name}}
}
