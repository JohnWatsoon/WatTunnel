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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

type certStore struct {
	mu       sync.Mutex
	cert     *tls.Certificate
	notAfter time.Time
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
	c.cert, c.notAfter = &kp, leaf.NotAfter
	c.mu.Unlock()
	return nil
}

func (c *certStore) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert, nil
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

// acmeHTTPAddr is where the HTTP-01 check is answered; a test points it elsewhere.
var acmeHTTPAddr = ":80"

// acmeDirectory is Let's Encrypt production; a test points it at a fake.
var acmeDirectory = acme.LetsEncryptURL

// useACME gets a certificate for DOMAIN with the HTTP-01 check (tier 3). Port 80 is bound only while the check
// runs and refused if something else holds it. On any failure the current certificate stays.
func useACME(ctx context.Context, cfg *Config, domain string, say func(string, ...any)) error {
	if net.ParseIP(domain) != nil {
		return errors.New("give a domain name that points at this server (IP certificates are not supported here)")
	}
	ln, err := net.Listen("tcp", acmeHTTPAddr)
	if err != nil {
		return fmt.Errorf("port 80 is busy or not allowed (%v): the check needs it for a few seconds", err)
	}
	tokens := sync.Map{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := tokens.Load(r.URL.Path); ok {
			w.Write([]byte(v.(string)))
			return
		}
		notFound(w, r)
	}), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()
	say("Port 80 is open for the check.")

	ak, _, err := newKey()
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: ak, DirectoryURL: acmeDirectory}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("the certificate service did not answer: %v", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(domain))
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
			if c.Type == "http-01" {
				ch = c
			}
		}
		if ch == nil {
			return errors.New("the certificate service offered no HTTP check")
		}
		body, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return err
		}
		tokens.Store(cl.HTTP01ChallengePath(ch.Token), body)
		say("Asking the certificate service to check %s ...", domain)
		if _, err := cl.Accept(ctx, ch); err != nil {
			return err
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("the check failed (does %s point at this server, and is port 80 open in the firewall?): %v", domain, err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	k, kp, err := newKey()
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, k)
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
